//go:build gateway_acquisition_fixture

// This program is a separate test harness, never a release command. Its two
// bundle filenames select the adapter role; each descriptor names this file's
// actual digest, not the released adapter it replaces in the disposable bundle.
package main

import (
	"adapters/connections"
	"adapters/websource"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func main() {
	role := strings.TrimSuffix(filepath.Base(os.Args[0]), ".exe")
	os.Exit(run(role, os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func run(role string, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	switch role {
	case "adapter-web":
		if len(args) == 1 && args[0] == "--describe-research" {
			raw, err := websource.DescribeAcquisitionFixture()
			return result(raw, err, stdout, stderr)
		}
		if len(args) != 0 {
			return 2
		}
		raw, err := boundedInput(stdin, 8192)
		if err != nil {
			return result(nil, websource.ErrRequest, stdout, stderr)
		}
		ctx, cancel := context.WithTimeout(context.Background(), websource.Timeout)
		defer cancel()
		out, err := websource.ReadAcquisitionFixture(ctx, raw)
		return result(out, err, stdout, stderr)
	case "adapter-sources":
		return runSearch(args, stdin, stdout, stderr)
	default:
		return 2
	}
}

func runSearch(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	values := map[string]string{}
	describe, long := false, false
	for index := 0; index < len(args); index++ {
		name := args[index]
		if _, duplicate := values[name]; duplicate {
			return 2
		}
		switch name {
		case "--describe-research":
			describe = true
			values[name] = "true"
		case "--long-search":
			long = true
			values[name] = "true"
		case "--state-dir", "--principal", "--provider":
			index++
			if index == len(args) || args[index] == "" || strings.HasPrefix(args[index], "--") || len(args[index]) > 4096 {
				return 2
			}
			values[name] = args[index]
		default:
			return 2
		}
	}
	if values["--provider"] != "web-search" || values["--principal"] != "desk-local" || describe && long {
		return 2
	}
	dir := values["--state-dir"]
	if dir == "" {
		dir = os.Getenv("JPACK_CONNECTIONS_DIR")
	}
	if !filepath.IsAbs(dir) {
		return 2
	}
	raw, err := boundedInput(stdin, 16<<10)
	if err != nil {
		return result(nil, connections.ErrRequest, stdout, stderr)
	}
	store, err := connections.OpenSearchStore(dir, "desk-local")
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "private-storage-unavailable")
		return 1
	}
	defer store.Close()
	if describe {
		out, err := connections.DescribeSearchAcquisitionFixture(store, raw)
		return result(out, err, stdout, stderr)
	}
	timeout := 55 * time.Second
	if long {
		timeout = connections.SearchAdapterTimeout
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	out, err := connections.ReadSearchAcquisitionFixture(ctx, store, raw)
	return result(out, err, stdout, stderr)
}

func boundedInput(stdin io.Reader, maximum int64) ([]byte, error) {
	raw, err := io.ReadAll(io.LimitReader(stdin, maximum+1))
	if err != nil || int64(len(raw)) > maximum {
		return nil, connections.ErrRequest
	}
	return raw, nil
}

func result(raw []byte, err error, stdout, stderr io.Writer) int {
	if err != nil {
		// Every called path uses bounded host-authored refusal tokens. Never
		// print a requested URL, transport diagnostic or fixture credentials.
		_, _ = fmt.Fprintln(stderr, websource.RefusalLine(err))
		return 1
	}
	if _, err := stdout.Write(raw); err != nil {
		return 1
	}
	return 0
}
