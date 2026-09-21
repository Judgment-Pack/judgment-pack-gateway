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
	case "obsidian":
		open, read = connections.OpenObsidianStore, connections.ReadObsidian
	default:
		return 2
	}
	s, err := open(*dir, *principal)
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
	ctx, cancel := context.WithTimeout(context.Background(), 55*time.Second)
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
