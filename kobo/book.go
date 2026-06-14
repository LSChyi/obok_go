package kobo

import (
	"archive/zip"
	"bytes"
	"crypto/aes"
	"database/sql"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"io"
	"path"
	"strings"

	"github.com/andreburgaud/crypt2go/ecb"
	"github.com/andreburgaud/crypt2go/padding"
	"github.com/h2non/filetype"
)

type BookType int

const (
	BookTypeKepub BookType = iota
	BookTypeDRMFree
)

type Book struct {
	VolumeID       string
	Title          string
	Author         string
	Series         string
	FilePath       string
	Type           BookType
	EncryptedFiles map[string]*File
}

func (b *Book) buildEncryptedFiles(db *sql.DB) error {
	b.EncryptedFiles = make(map[string]*File)

	if b.Type == BookTypeDRMFree {
		return nil
	}

	rows, err := db.Query(fmt.Sprintf("SELECT elementid, elementkey FROM content_keys,content WHERE volumeid = '%s' AND volumeid = contentid", b.VolumeID))
	if err != nil {
		return fmt.Errorf("failed at building book encrypted file: %v", err)
	}
	defer rows.Close()

	for rows.Next() {
		var elementID, elementKey string

		if err := rows.Scan(&elementID, &elementKey); err != nil {
			return err
		}

		key, err := base64.StdEncoding.DecodeString(elementKey)
		if err != nil {
			return fmt.Errorf("failed at decode base64 element key: %w", err)
		}

		b.EncryptedFiles[elementID] = &File{
			Name: elementID,
			Key:  key,
		}
	}

	if err := rows.Err(); err != nil {
		return err
	}

	return b.buildMIME()
}

func (b *Book) buildMIME() error {
	zin, err := zip.OpenReader(b.FilePath)
	if err != nil {
		return err
	}
	defer zin.Close()

	readFile := func(name string) ([]byte, error) {
		for _, f := range zin.File {
			if f.Name == name {
				rc, err := f.Open()
				if err != nil {
					return nil, err
				}
				defer rc.Close()
				return io.ReadAll(rc)
			}
		}
		return nil, fmt.Errorf("file not found")
	}

	// 1. Read and parse META-INF/container.xml
	containerData, err := readFile("META-INF/container.xml")
	if err != nil {
		return err
	}

	var container Container
	if err := xml.Unmarshal(containerData, &container); err != nil {
		return err
	}

	if len(container.Rootfiles) == 0 {
		return nil
	}

	opfFile := container.Rootfiles[0].FullPath

	// Python: basedir = re.sub('[^/]+$', '', opffile)
	// path.Dir extracts the directory part cleanly.
	// If opfFile is "OEBPS/content.opf", basedir becomes "OEBPS".
	baseDir := path.Dir(opfFile)
	if baseDir == "." {
		baseDir = ""

	} else {
		baseDir = baseDir + "/"
	}

	// 2. Read and parse the OPF file
	opfData, err := readFile(opfFile)
	if err != nil {
		return err
	}

	var opf Package
	if err := xml.Unmarshal(opfData, &opf); err != nil {
		return err
	}

	// 3. Process the items
	for _, item := range opf.Items {
		href := item.Href

		// Python: if not c.match(href): (checking if it doesn't start with '/')
		if !strings.HasPrefix(href, "/") {
			href = baseDir + href
		}

		// Update books we've found from the DB
		if fileInfo, exists := b.EncryptedFiles[href]; exists {
			fileInfo.MIMEType = item.MediaType
		}
	}

	return nil
}

type File struct {
	Name     string
	MIMEType string
	Key      []byte
}

func (f *File) Decrypt(key, rawContent []byte) ([]byte, error) {
	decryptedKey, err := AESHelper(key, f.Key, false)
	if err != nil {
		return nil, fmt.Errorf("failed at decrypting file key: %w", err)
	}
	pageDecrypted, err := AESHelper(decryptedKey, rawContent, true)
	if err != nil {
		return nil, fmt.Errorf("failed at decrypting file content: %w", err)
	}

	if err := f.check(pageDecrypted); err != nil {
		return nil, fmt.Errorf("decrypted content is invalid: %w", err)
	}
	return pageDecrypted, nil
}

func (f *File) check(content []byte) error {
	switch f.MIMEType {
	case "application/xhtml+xml":
		return validateApplicationXHTML(content)
	default:
		fileType, err := filetype.Match(content)
		if err != nil {
			return fmt.Errorf("file MIME is %s, but encounter error while detecting: %w", f.MIMEType, err)
		}
		if f.MIMEType != fileType.MIME.Value {
			return fmt.Errorf("file MIME is %s, but get %s", f.MIMEType, fileType)
		}
		return nil
	}
}

func AESHelper(key, ct []byte, unpad bool) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}
	mode := ecb.NewECBDecrypter(block)
	pt := make([]byte, len(ct))
	mode.CryptBlocks(pt, ct)
	if unpad {
		padder := padding.NewPkcs7Padding(mode.BlockSize())
		pt, err = padder.Unpad(pt)
		if err != nil {
			return nil, fmt.Errorf("failed to unpad: %w", err)
		}
	}
	return pt, nil
}

func validateApplicationXHTML(contents []byte) error {
	textOffset := 0
	stride := 1

	if len(contents) >= 3 && bytes.Equal(contents[:3], []byte("\xef\xbb\xbf")) {
		textOffset = 3
	} else if len(contents) >= 2 && bytes.Equal(contents[:2], []byte("\xfe\xff")) {
		textOffset = 3 // Keeping textoffset=3 as per your original code logic, though 2 is typically expected for UTF-16 BE BOM
		stride = 2
	} else if len(contents) >= 2 && bytes.Equal(contents[:2], []byte("\xff\xfe")) {
		textOffset = 2
		stride = 2
	}

	for i := 0; i < 5; i++ {
		idx := textOffset + (i * stride)
		if idx >= len(contents) {
			break
		}
		char := contents[idx]
		if char < 32 || char > 127 {
			return fmt.Errorf("Bad character at %d, value %d\n", idx, char)
		}
	}

	return nil
}

type Container struct {
	XMLName   xml.Name   `xml:"container"`
	Rootfiles []Rootfile `xml:"rootfiles>rootfile"`
}

type Rootfile struct {
	FullPath string `xml:"full-path,attr"`
}

type Package struct {
	XMLName xml.Name `xml:"package"`
	Items   []Item   `xml:"manifest>item"`
}

type Item struct {
	MediaType string `xml:"media-type,attr"`
	Href      string `xml:"href,attr"`
}
