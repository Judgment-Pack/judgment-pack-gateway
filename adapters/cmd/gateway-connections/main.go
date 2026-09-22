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
	catalog := fs.Bool("catalog", false, "")
	catalogV3 := fs.Bool("catalog-v3", false, "")
	localPlan := fs.Bool("local-plan", false, "")
	disabled := fs.Bool("disabled", false, "")
	if fs.Parse(os.Args[1:]) != nil || fs.NArg() != 0 {
		return 2
	}
	if *catalog || *catalogV3 || *localPlan {
		// Discovery must never open custody, configure a publisher, or consume
		// stdin. Refuse mixed modes rather than silently ignoring their flags.
		if fs.NFlag() != 1 {
			return 2
		}
		var output any = connections.ConnectionCatalog()
		if *catalogV3 {
			output = connections.ConnectionCatalogV3()
		}
		if *localPlan {
			output = connections.ConnectionLocalPlan()
		}
		if json.NewEncoder(os.Stdout).Encode(output) != nil {
			return 1
		}
		return 0
	}
	if _, ok := connections.LookupProvider(*provider); !ok {
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
	if *provider == "notion" {
		open = connections.OpenNotionStore
	}
	if *provider == "obsidian" {
		open = connections.OpenObsidianStore
	}
	if *provider == "aws-s3" {
		open = connections.OpenS3Store
	}
	s, err := open(*dir, *principal)
	if err != nil {
		return 1
	}
	defer s.Close()
	if !*disabled && client.ID != "" && (*provider == "google-drive" || *provider == "gmail") {
		if err := s.EnsureClient(client); err != nil {
			return 1
		}
	}
	b := connections.New(s, *disabled)
	if *provider == "gmail" {
		b = connections.NewGmail(s, *disabled)
	}
	if *provider == "notion" {
		b = connections.NewNotion(s, *disabled)
	}
	if *provider == "obsidian" {
		b = connections.NewObsidian(s, *disabled)
	}
	if *provider == "aws-s3" {
		b = connections.NewS3(s, *disabled)
	}
	defer b.Close()
	scan := bufio.NewScanner(os.Stdin)
	scan.Buffer(make([]byte, 4096), connections.ControlLineBytes)
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
		if writeResponse(os.Stdout, out, r.ID) != nil {
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

// Refuse a page that does not fit; never emit an incomplete JSON control line.
func writeResponse(w io.Writer, out map[string]any, id string) error {
	raw, err := json.Marshal(out)
	if err != nil || len(raw)+1 > connections.ControlLineBytes {
		raw, err = json.Marshal(response(id, nil, connections.Error("response-too-large")))
		if err != nil {
			return err
		}
	}
	_, err = w.Write(append(raw, '\n'))
	return err
}
