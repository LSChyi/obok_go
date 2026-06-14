package kobo

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"

	_ "github.com/ncruces/go-sqlite3/driver"
)

var (
	KoboHashKeys = [][]byte{
		[]byte("88b3a2e13"),
		[]byte("XzUhGYdFp"),
		[]byte("NoCanLook"),
		[]byte("QJhwzAtXL"),
	}
)

type Library struct {
	koboDir string
	koboDB  *sql.DB
	bookDir string

	onceGetBooks func() ([]*Book, error)
	keys         [][]byte
	userIDs      []string
}

func NewLibrary() (l *Library, err error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	koboDir := filepath.Join(home, "Library", "Application Support", "Kobo", "Kobo Desktop Edition")
	koboDB := filepath.Join(koboDir, "Kobo.sqlite")
	bookDir := filepath.Join(koboDir, "kepub")

	db, err := sql.Open("sqlite3", "file:"+koboDB)
	if err != nil {
		return nil, err
	}

	ret := &Library{
		koboDir: koboDir,
		koboDB:  db,
		bookDir: bookDir,
	}
	ret.onceGetBooks = sync.OnceValues(ret.getBooks)

	return ret, nil
}

func (l *Library) Close() error {
	return l.koboDB.Close()
}

func (l *Library) Books() ([]*Book, error) {
	return l.onceGetBooks()
}

func (l *Library) UserKeys() ([][]byte, error) {
	if len(l.keys) != 0 {
		return l.keys, nil
	}

	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("failed at getting mac addresses (building user keys): %v", err)
	}

	macAddrs := make([]string, 0, len(interfaces))
	for _, iface := range interfaces {
		if len(iface.HardwareAddr) == 0 {
			continue
		}
		macAddrs = append(macAddrs, strings.ToUpper(iface.HardwareAddr.String()))
	}

	userIDs, err := l.UserIDs()
	if err != nil {
		return nil, fmt.Errorf("failed to get user IDs for building keys: %v", err)
	}

	ret := make([][]byte, 0, len(macAddrs))
	for _, mac := range macAddrs {
		for _, hash := range KoboHashKeys {
			h := sha256.New()
			h.Write(append(hash, []byte(mac)...))
			deviceID := hex.EncodeToString(h.Sum(nil))

			for _, id := range userIDs {
				h := sha256.New()
				h.Write(append([]byte(deviceID), []byte(id)...))
				userKey := hex.EncodeToString(h.Sum(nil))
				hexKey, err := hex.DecodeString(userKey[32:])
				if err != nil {
					return nil, fmt.Errorf("failed to build key: %v", err)
				}
				//if hex.EncodeToString(hexKey) == "5fec4a2ea04ac5de5de71f23358c8bdb" {
				ret = append(ret, hexKey)
				//}
			}
		}
	}

	l.keys = ret
	return ret, nil
}

func (l *Library) UserIDs() ([]string, error) {
	if len(l.userIDs) != 0 {
		return l.userIDs, nil
	}

	ids := make([]string, 0)

	rows, err := l.koboDB.Query("SELECT UserID from user")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		id := ""
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("failed to get user ID: %v", err)
		}
		ids = append(ids, id)
	}
	l.userIDs = ids
	return l.userIDs, nil
}

func (l *Library) getBooks() ([]*Book, error) {
	kepubBooks, err := l.buildKepubBooks()
	if err != nil {
		return nil, err
	}

	encryptedVolumeIDs := make(map[string]struct{})
	for _, book := range kepubBooks {
		encryptedVolumeIDs[book.VolumeID] = struct{}{}
	}
	drmFreeBooks, err := l.buildDRMFreeBooks(encryptedVolumeIDs)
	if err != nil {
		return nil, err
	}

	books := append(kepubBooks, drmFreeBooks...)
	for _, b := range books {
		if err := b.buildEncryptedFiles(l.koboDB); err != nil {
			return nil, fmt.Errorf("failed at building encrypted file for book %s: %v", b.Title, err)
		}
	}

	return books, nil
}

func (l *Library) buildKepubBooks() ([]*Book, error) {
	books := make([]*Book, 0)

	rows, err := l.koboDB.Query("SELECT DISTINCT volumeid, Title, Attribution, Series FROM content_keys, content WHERE contentid = volumeid")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		book := new(Book)
		var series sql.NullString
		if err := rows.Scan(&book.VolumeID, &book.Title, &book.Author, &series); err != nil {
			return nil, fmt.Errorf("failed to scan book row: %w", err)
		}
		book.Series = series.String
		book.FilePath = filepath.Join(l.bookDir, book.VolumeID)
		book.Type = BookTypeKepub
		books = append(books, book)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return books, nil
}

func (l *Library) buildDRMFreeBooks(encryptedVolumeIDs map[string]struct{}) ([]*Book, error) {
	books := make([]*Book, 0)

	entries, err := os.ReadDir(l.bookDir)
	if err != nil {
		return nil, err
	}

	for _, entry := range entries {
		// targeting on entry that is not in encryptedVolumeIDs
		if _, ok := encryptedVolumeIDs[entry.Name()]; ok {
			continue
		}

		row, err := l.koboDB.Query(fmt.Sprintf("SELECT Title, Attribution, Series FROM content WHERE ContentID = '%s'", entry.Name()))
		if err != nil {
			return nil, err
		}
		defer row.Close()

		for row.Next() {
			book := new(Book)
			var series sql.NullString
			if err := row.Scan(&book.Title, &book.Author, &series); err != nil {
				return nil, err
			}
			book.Series = series.String
			book.VolumeID = entry.Name()
			book.FilePath = filepath.Join(l.bookDir, book.VolumeID)
			book.Type = BookTypeDRMFree
			books = append(books, book)
		}
	}

	return books, nil
}
