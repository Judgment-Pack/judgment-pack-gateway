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
		// Discovery must never configure a publisher, consume stdin, or create,
		// lock or write anything. The local plan alone reads custody: whether
		// the document-processing settings under JPACK_CONNECTIONS_DIR name a
		// processor, and whether a search connection there has a timeout the
		// ordinary envelope does not carry, as they stand when it is asked. Refuse mixed modes rather
		// than silently ignoring their flags.
		if fs.NFlag() != 1 {
			return 2
		}
		var output any = connections.ConnectionCatalog()
		if *catalogV3 {
			output = connections.ConnectionCatalogV3()
		}
		if *localPlan {
			dir := os.Getenv("JPACK_CONNECTIONS_DIR")
			output = connections.ConnectionLocalPlanFor(connections.ProcessingConfigured(dir), connections.SearchNeedsLongEnvelope(dir))
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
	if *provider == "web-search" {
		open = connections.OpenSearchStore
	}
	if *provider == "document-processing" {
		open = connections.OpenProcessingStore
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
	if *provider == "web-search" {
		b = connections.NewSearch(s, *disabled)
	}
	if *provider == "document-processing" {
		b = connections.NewProcessing(s, *disabled)
		_ = os.Setenv("JPACK_CONNECTIONS_DIR", *dir)
	}
	defer b.Close()
	scan := bufio.NewScanner(os.Stdin)
	// The scanner's bound counts the line's ending, which is one byte or two,
	// and one byte more, so that a line a byte past its method's bound is
	// read and refused by name. A longer line ends the pipe.
	scan.Buffer(make([]byte, 4096), connections.StorageLineBytes+3)
	for scan.Scan() {
		var r struct {
			ID     string          `json:"id"`
			Method string          `json:"method"`
			Params json.RawMessage `json:"params"`
		}
		if json.Unmarshal(scan.Bytes(), &r) != nil || len(r.ID) > 64 {
			return 2
		}
		ctx, cancel := requestContext(*provider, r.Method)
		var result any
		var err error
		bound := requestBound(r.Method)
		if *provider == "document-processing" && r.Method == "test" {
			bound = connections.StorageLineBytes
		}
		if len(scan.Bytes()) > bound {
			err = connections.ErrRequest
		} else {
			result, err = b.Handle(ctx, r.Method, r.Params)
		}
		cancel()
		out := response(r.ID, result, err)
		if writeResponseLimit(os.Stdout, out, r.ID, r.Method) != nil {
			return 1
		}
	}
	if scan.Err() != nil {
		return 1
	}
	return 0
}

// requestContext is the context one request is given: 50 seconds; a
// document-processing test 140; a search connection's test the search's own
// deadline, at most SearchMaxTimeoutSeconds, and time to report it.
func requestContext(provider, method string) (context.Context, context.CancelFunc) {
	timeout := 50 * time.Second
	if provider == "document-processing" && method == "test" {
		timeout = 140 * time.Second
	}
	if provider == "web-search" && method == "test" {
		timeout = connections.SearchAdapterTimeout
	}
	return context.WithTimeout(context.Background(), timeout)
}

// requestBound is the most a request's line may hold. Only a request that
// carries a file's content has the larger bound.
func requestBound(method string) int {
	if connections.StorageUpload(method) {
		return connections.StorageLineBytes
	}
	return connections.ControlLineBytes
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
	return writeResponseLimit(w, out, id, "")
}
func writeResponseLimit(w io.Writer, out map[string]any, id, method string) error {
	limit := connections.ControlLineBytes
	if method == "files-read" {
		limit = connections.StorageLineBytes
	} else if method == "files-list" {
		limit = connections.StorageMetadataBytes
	}
	raw, err := json.Marshal(out)
	if err != nil || len(raw)+1 > limit {
		raw, err = json.Marshal(response(id, nil, connections.Error("response-too-large")))
		if err != nil {
			return err
		}
	}
	_, err = w.Write(append(raw, '\n'))
	return err
}
