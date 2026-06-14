# obok GO
This is a porting from the [DeDRM_tools for Kobo](https://github.com/apprenticeharper/DeDRM_tools/blob/master/Other_Tools/Kobo/obok.py). The original Python implementation suffers from some issues:

- No active maintenance, and Python3 would give warnings like `SyntaxWarning: "\s" is an invalid escape sequence.`
- Not easy to support parallelism due to non-pickleable objects like sqlite3 connections.
- Low performance of using Python to do low-level byte operations.

This implementation utilizes the power of Go routines to run computation-intensive tasks, and also uses more aggressive decryption logic to speed up the process.

## Usage
Currently, this implementation only supports the macOS platform. Users must first install the Kobo desktop app, and use the app to download books. Then, run the main program:

```
$ go run main.go
```

## Options

```
$ go run main.go -h
Usage of ./obok_go:
  -a    Decrypt all books (default true)
  -c    Conservative (decrypt and check for all content)
  -n int
        Number of routine to use for decryption, default = number of CPU
  -o string
        Output root directory path (default "epub")
```
