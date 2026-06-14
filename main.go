package main

import (
	"archive/zip"
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"runtime"

	"obok/kobo"

	"github.com/schollz/progressbar/v3"
	"golang.org/x/sync/errgroup"
)

func main() {
	l, err := kobo.NewLibrary()
	if err != nil {
		log.Fatal(err)
	}
	defer l.Close()

	if err := decryptBooks(l); err != nil {
		log.Fatal(err)
	}
}

func decryptBooks(l *kobo.Library) error {
	books, err := l.Books()
	if err != nil {
		return err
	}

	userKeys, err := l.UserKeys()
	if err != nil {
		return err
	}

	bar := progressbar.Default(int64(len(books)))
	g, _ := errgroup.WithContext(context.Background())
	g.SetLimit(runtime.NumCPU())
	for _, book := range books {
		g.Go(func() error {
			if err := decryptBook("tmp", userKeys, book); err != nil {
				log.Printf("Failed decrypting for book %s: %v", book.Title, err)
			}
			bar.Add(1)
			return nil
		})
	}
	return g.Wait()
}

func decryptBook(rootDir string, userKeys [][]byte, book *kobo.Book) error {
	dat, err := os.ReadFile(book.FilePath)
	if err != nil {
		return err
	}

	if book.Type == kobo.BookTypeDRMFree {
		return os.WriteFile(filepath.Join(rootDir, book.Title+".epub"), dat, 0644)
	}

	r, err := zip.NewReader(bytes.NewReader(dat), int64(len(dat)))
	if err != nil {
		return err
	}

	files := make([]*File, 0, len(r.File))
	for _, f := range r.File {
		rc, err := f.Open()
		if err != nil {
			return fmt.Errorf("failed at opening compressed file from book %s: %w", book.Title, err)
		}
		defer rc.Close()

		content, err := io.ReadAll(rc)
		if err != nil {
			return fmt.Errorf("failed at extracting compressing file from book %s: %w", book.Title, err)
		}

		file := &File{
			Name:       f.Name,
			RawContent: content,
		}
		files = append(files, file)
	}

	key, err := findValidKey(userKeys, book, files)
	if err != nil {
		return err
	}

	for _, file := range files {
		if koboFile, ok := book.EncryptedFiles[file.Name]; ok {
			content, err := koboFile.Decrypt(key, file.RawContent)
			if err != nil {
				return err
			}
			file.Content = content
		} else {
			file.Content = file.RawContent
		}
	}

	buf := new(bytes.Buffer)
	w := zip.NewWriter(buf)
	for _, file := range files {
		f, err := w.Create(file.Name)
		if err != nil {
			return fmt.Errorf("failed at creating zip content: %w", err)
		}
		if _, err = f.Write(file.Content); err != nil {
			return fmt.Errorf("failed at compressing zip content: %w", err)
		}
	}

	if err := w.Close(); err != nil {
		return fmt.Errorf("failed at completing the zip file: %w", err)
	}

	if err := os.WriteFile(filepath.Join(rootDir, book.Title+".epub"), buf.Bytes(), 0644); err != nil {
		return err
	}

	return nil
}

type File struct {
	Name       string
	RawContent []byte
	Content    []byte
}

func (f *File) WriteRawFile(rootDir string) error {
	if err := f.prepareWriteFile(rootDir); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(rootDir, f.Name), f.RawContent, 0644); err != nil {
		return err
	}
	return nil
}

func (f *File) WriteFile(rootDir string) error {
	if err := f.prepareWriteFile(rootDir); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(rootDir, f.Name), f.Content, 0644); err != nil {
		return err
	}
	return nil
}

func (f *File) prepareWriteFile(rootDir string) error {
	dirPath := filepath.Dir(f.Name)
	if dirPath != "" {
		if err := os.MkdirAll(filepath.Join(rootDir, dirPath), 0755); err != nil {
			return err
		}
	}
	return nil
}

func findValidKey(keys [][]byte, book *kobo.Book, files []*File) ([]byte, error) {
	var minFile *File
	var testKoboFile *kobo.File
	for _, f := range files {
		if koboFile, ok := book.EncryptedFiles[f.Name]; ok {
			if minFile == nil {
				minFile = f
				testKoboFile = koboFile
				continue
			}

			if len(minFile.RawContent) > len(f.RawContent) {
				minFile = f
				testKoboFile = koboFile
			}
		}
	}

	for _, key := range keys {
		if _, err := testKoboFile.Decrypt(key, minFile.RawContent); err != nil {
			continue
		}
		return key, nil
	}
	return nil, fmt.Errorf("No key matched")
}
