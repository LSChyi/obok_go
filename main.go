package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"runtime"

	"github.com/LSChyi/obok_go/kobo"

	"github.com/schollz/progressbar/v3"
	"golang.org/x/sync/errgroup"
)

func main() {
	var numRoutine int
	var saveRoot string
	var allBook bool
	var conservative bool

	flag.IntVar(&numRoutine, "n", runtime.NumCPU(), "Number of routine to use for decryption, default = number of CPU")
	flag.StringVar(&saveRoot, "o", "epub", "Output root directory path")
	flag.BoolVar(&allBook, "a", true, "Decrypt all books")
	flag.BoolVar(&conservative, "c", false, "Conservative (decrypt and check for all content)")
	flag.Parse()

	l, err := kobo.NewLibrary()
	if err != nil {
		log.Fatal(err)
	}
	defer l.Close()

	if err := os.MkdirAll(saveRoot, 0755); err != nil {
		log.Fatalf("Failed to create output root directory: %v", err)
	}

	books, err := l.Books()
	if err != nil {
		log.Fatalf("Failed to get books: %v", err)
	}

	if !allBook {
		books = selectBook(books)
	}

	if err := decryptBooks(l, books, numRoutine, saveRoot, conservative); err != nil {
		log.Fatalf("Failed at decrypting books: %v", err)
	}
	log.Printf("Complete decrypting %d books", len(books))
}

func decryptBooks(l *kobo.Library, books []*kobo.Book, numRoutine int, saveRoot string, conservative bool) error {
	bar := progressbar.Default(int64(len(books)))
	g, _ := errgroup.WithContext(context.Background())
	g.SetLimit(numRoutine)
	for _, book := range books {
		g.Go(func() error {
			if conservative {
				if err := l.ConservativeDecryptBook(saveRoot, book); err != nil {
					log.Printf("Failed decrypting for book %s: %v", book.Title, err)
				}
			} else {
				if err := l.DecryptBook(saveRoot, book); err != nil {
					log.Printf("Failed decrypting for book %s: %v", book.Title, err)
				}
			}
			bar.Add(1)
			return nil
		})
	}
	return g.Wait()
}

func selectBook(books []*kobo.Book) ([]*kobo.Book) {
	fmt.Println("Please select an item from the list by entering its index:")
	for index, book := range books {
		fmt.Printf("[%d] %s\n", index, book.Title)
	}

	var selection int
	for {
		fmt.Print("\nEnter index: ")

		// 4. Read user input and check if it's a valid integer
		_, err := fmt.Scanf("%d", &selection)
		if err != nil {
			fmt.Println("Invalid input. Please enter a valid number.")
			// Clear the input buffer to prevent infinite loops on bad input
			var discard string
			fmt.Scanln(&discard)
			continue
		}

		// 5. Validate if the index is within the slice bounds
		if selection < 0 || selection >= len(books) {
			fmt.Printf("Error: Index out of bounds. Please choose between 0 and %d.\n", len(books)-1)
			continue
		}

		return books[selection:selection+1]
	}
}
