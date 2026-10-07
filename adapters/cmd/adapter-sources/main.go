// adapter-sources consumes one user-selected source grant in a separate process.
package main

import (
	"adapters/connections"
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"time"
)

func main() { os.Exit(run()) }
func run() int {
	fs := flag.NewFlagSet("adapter-sources", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	dir := fs.String("state-dir", os.Getenv("JPACK_CONNECTIONS_DIR"), "")
	principal := fs.String("principal", "", "")
	provider := fs.String("provider", "", "")
	if fs.Parse(os.Args[1:]) != nil || fs.NArg() != 0 {
		return 2
	}
	open, read := connections.OpenNotionStore, connections.ReadNotion
	switch *provider {
	case "notion":
	case "web-search":
		open, read = connections.OpenSearchStore, connections.ReadSearch
	case "obsidian":
		open, read = connections.OpenObsidianStore, connections.ReadObsidian
	case "aws-s3":
		open, read = connections.OpenS3Store, connections.ReadS3
	default:
		return 2
	}
	s, err := open(*dir, *principal)
	if err != nil {
		fmt.Fprintln(os.Stderr, "private-storage-unavailable")
		return 1
	}
	defer s.Close()
	limit := 4096
	if *provider == "aws-s3" || *provider == "web-search" {
		limit = 16 << 10
	} // a 1024-byte key may be JSON-escaped up to sixfold
	raw, err := io.ReadAll(io.LimitReader(os.Stdin, int64(limit+1)))
	if err != nil || len(raw) > limit {
		fmt.Fprintln(os.Stderr, "invalid-request")
		return 1
	}
	// A retained S3 file may be read with the operator's OCR processor, whose
	// deadline is at most 120 seconds; the local plan gives the source 150.
	// The other providers read text only and keep their deadline.
	timeout := 55 * time.Second
	if *provider == "aws-s3" {
		timeout = 140 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	out, err := read(ctx, s, raw)
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		return 1
	}
	if _, err = os.Stdout.Write(out); err != nil {
		return 1
	}
	return 0
}
