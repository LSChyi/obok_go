package main

import (
	"context"
	"log"
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

	bar := progressbar.Default(int64(len(books)))
	g, _ := errgroup.WithContext(context.Background())
	g.SetLimit(runtime.NumCPU())
	for _, book := range books {
		g.Go(func() error {
			if err := l.DecryptBook("tmp", book); err != nil {
				log.Printf("Failed decrypting for book %s: %v", book.Title, err)
			}
			bar.Add(1)
			return nil
		})
	}
	return g.Wait()
}
