// adapter-gmail consumes a user-selected read grant; no credential is a request argument.
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
	fs := flag.NewFlagSet("adapter-gmail", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	dir := fs.String("state-dir", os.Getenv("JPACK_CONNECTIONS_DIR"), "")
	principal := fs.String("principal", "", "")
	if fs.Parse(os.Args[1:]) != nil || fs.NArg() != 0 {
		return 2
	}
	ctx, cancel := context.WithTimeout(context.Background(), 55*time.Second)
	defer cancel()
	s, err := connections.OpenGmailStore(*dir, *principal)
	if err != nil {
		fmt.Fprintln(os.Stderr, "private-storage-unavailable")
		return 1
	}
	defer s.Close()
	raw, err := io.ReadAll(io.LimitReader(os.Stdin, 4097))
	if err != nil || len(raw) > 4096 {
		fmt.Fprintln(os.Stderr, "invalid-request")
		return 1
	}
	out, err := connections.ReadGmail(ctx, s, raw)
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		return 1
	}
	if _, err = os.Stdout.Write(out); err != nil {
		return 1
	}
	return 0
}
