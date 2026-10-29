package mcp

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestRelativeCustomerCommandResolvesInWorkspace(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("requires a native filesystem sandbox and shell")
	}
	withoutLoaderVariables(t)
	original := t.TempDir()
	workspace := t.TempDir()
	t.Chdir(original)
	script := func(text string) []byte {
		return []byte("#!/bin/sh\nprintf '%s\\n' '{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"executed\":\"" + text + "\"}}'\ncat >/dev/null\n")
	}
	if err := os.WriteFile(filepath.Join(original, "server"), script("original"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workspace, "server"), script("workspace"), 0700); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	srv, err := startServer(ctx, Config{Customer: true, Command: []string{"./server"}, SandboxWorkspace: workspace}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.stop()
	got, err := srv.rpc.call(ctx, "initialize", map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	cwdDigest, err := executableDigest(filepath.Join(original, "server"))
	if err != nil {
		t.Fatal(err)
	}
	workspaceDigest, err := executableDigest(filepath.Join(workspace, "server"))
	if err != nil {
		t.Fatal(err)
	}
	// A relative command word resolves against the workspace, the directory
	// the server runs in, never the adapter's own working directory: the
	// file digested and the file executed are the workspace's.
	if srv.identity.Digest != workspaceDigest || srv.identity.Digest == cwdDigest {
		t.Fatal("reported digest does not identify the resolved command")
	}
	if string(got) != `{"executed":"workspace"}` {
		t.Fatalf("customer command executed a different file from the one digested: %s", got)
	}
}
