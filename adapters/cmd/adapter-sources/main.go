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

// readContext is the context a read is given: 55 seconds. Launched with
// --document-processing (S3 only: the other providers read text), a retained
// file may be read with the operator's OCR processor, and has the envelope
// the local plan gives for it. Launched with --long-search, a search
// connection's timeout may be up to SearchMaxTimeoutSeconds; otherwise a
// longer one ends here, at 55 seconds, as search-timeout, before the plan's
// ordinary 60.
func readContext(processing, longSearch bool) (context.Context, context.CancelFunc) {
	ctx, timeout := context.Background(), 55*time.Second
	if processing {
		ctx, timeout = connections.WithDocumentProcessing(ctx), connections.ProcessingAdapterTimeout
	}
	if longSearch {
		timeout = connections.SearchAdapterTimeout
	}
	return context.WithTimeout(ctx, timeout)
}
func run() int {
	fs := flag.NewFlagSet("adapter-sources", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	dir := fs.String("state-dir", os.Getenv("JPACK_CONNECTIONS_DIR"), "")
	principal := fs.String("principal", "", "")
	provider := fs.String("provider", "", "")
	processing := fs.Bool("document-processing", false, "")
	longSearch := fs.Bool("long-search", false, "")
	if fs.Parse(os.Args[1:]) != nil || fs.NArg() != 0 || *processing && *provider != "aws-s3" || *longSearch && *provider != "web-search" {
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
	ctx, cancel := readContext(*processing, *longSearch)
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
