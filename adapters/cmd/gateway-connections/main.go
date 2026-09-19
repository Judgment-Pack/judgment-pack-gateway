// gateway-connections serves provider controls over a parent's private pipe.
package main

import (
	"adapters/connections"
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"io"
	"os"
	"time"
)

func main() { os.Exit(run()) }
func run() int {
	fs := flag.NewFlagSet("gateway-connections", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	dir := fs.String("state-dir", "", "")
	principal := fs.String("principal", "", "")
	provider := fs.String("provider", "google-drive", "")
	disabled := fs.Bool("disabled", false, "")
	if fs.Parse(os.Args[1:]) != nil || fs.NArg() != 0 || (*provider != "google-drive" && *provider != "gmail") {
		return 2
	}
	client, err := publisherClient(publisherRegistration)
	if err != nil {
		return 2
	}
	open := connections.OpenStore
	if *provider == "gmail" {
		open = connections.OpenGmailStore
	}
	s, err := open(*dir, *principal)
	if err != nil {
		return 1
	}
	defer s.Close()
	if !*disabled && client.ID != "" {
		if err := s.EnsureClient(client); err != nil {
			return 1
		}
	}
	b := connections.New(s, *disabled)
	if *provider == "gmail" {
		b = connections.NewGmail(s, *disabled)
	}
	defer b.Close()
	scan := bufio.NewScanner(os.Stdin)
	scan.Buffer(make([]byte, 4096), 64<<10)
	enc := json.NewEncoder(os.Stdout)
	for scan.Scan() {
		var r struct {
			ID     string          `json:"id"`
			Method string          `json:"method"`
			Params json.RawMessage `json:"params"`
		}
		if json.Unmarshal(scan.Bytes(), &r) != nil || len(r.ID) > 64 {
			return 2
		}
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Second)
		result, err := b.Handle(ctx, r.Method, r.Params)
		cancel()
		out := response(r.ID, result, err)
		if enc.Encode(out) != nil {
			return 1
		}
	}
	if scan.Err() != nil {
		return 1
	}
	return 0
}

// Failed operations must never include partial metadata or grants.
func response(id string, result any, err error) map[string]any {
	out := map[string]any{"id": id}
	if err != nil {
		out["error"] = err.Error()
	} else {
		out["result"] = result
	}
	return out
}
