package main

import (
	"os"
	"reflect"
	"strings"
	"testing"
)

func TestParseServeOptions(t *testing.T) {
	tests := []struct {
		name        string
		args        []string
		wantOptions serveOptions
		wantErr     string
	}{
		{
			name:    "missing required arguments",
			args:    []string{},
			wantErr: "usage: gateway serve",
		},
		{
			name:    "unknown option",
			args:    []string{"store", "seed", "authority", "registry", "--bogus"},
			wantErr: `unknown option "--bogus"`,
		},
		{
			name:    "source without following value",
			args:    []string{"store", "seed", "authority", "registry", "--source"},
			wantErr: "--source requires",
		},
		{
			name:    "port without following value",
			args:    []string{"store", "seed", "authority", "registry", "--port"},
			wantErr: "--port requires",
		},
		{
			name:    "source value without equals",
			args:    []string{"store", "seed", "authority", "registry", "--source", "cmd"},
			wantErr: "--source expects NAME=CMD",
		},
		{
			name:    "source with empty name",
			args:    []string{"store", "seed", "authority", "registry", "--source", "=cmd"},
			wantErr: "--source name must not be empty",
		},
		{
			name:    "source with empty command",
			args:    []string{"store", "seed", "authority", "registry", "--source", "name="},
			wantErr: "--source command must not be empty",
		},
		{
			name:    "unexpected positional argument",
			args:    []string{"store", "seed", "authority", "registry", "extra"},
			wantErr: `unexpected argument "extra"`,
		},
		{
			name: "valid repeated sources and port",
			args: []string{
				"store", "seed", "authority", "registry",
				"--source", "screen=/bin/sh",
				"--source", "quote=echo hi",
				"--port", "9000",
			},
			wantOptions: serveOptions{
				sources: map[string][]string{
					"screen": {"/bin/sh"},
					"quote":  {"echo", "hi"},
				},
				port: "9000",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, msg, ok := parseServeOptions(tt.args)
			if tt.wantErr != "" {
				if ok {
					t.Fatalf("parseServeOptions() accepted invalid args %v", tt.args)
				}
				if !strings.Contains(msg, tt.wantErr) {
					t.Fatalf("parseServeOptions() error = %q, want containing %q", msg, tt.wantErr)
				}
				return
			}
			if !ok {
				t.Fatalf("parseServeOptions() rejected valid args %v: %s", tt.args, msg)
			}
			if got.port != tt.wantOptions.port {
				t.Fatalf("port = %q, want %q", got.port, tt.wantOptions.port)
			}
			if !reflect.DeepEqual(got.sources, tt.wantOptions.sources) {
				t.Fatalf("sources = %v, want %v", got.sources, tt.wantOptions.sources)
			}
		})
	}
}

func TestCmdServeRejectsMalformedOptions(t *testing.T) {
	null, err := os.CreateTemp(t.TempDir(), "stderr")
	if err != nil {
		t.Fatal(err)
	}
	oldStderr := os.Stderr
	os.Stderr = null
	t.Cleanup(func() {
		os.Stderr = oldStderr
		null.Close()
	})

	for _, tt := range []struct {
		name string
		args []string
	}{
		{name: "unknown option", args: []string{"store", "seed", "authority", "registry", "--bogus"}},
		{name: "source missing value", args: []string{"store", "seed", "authority", "registry", "--source"}},
		{name: "port missing value", args: []string{"store", "seed", "authority", "registry", "--port"}},
		{name: "source no equals", args: []string{"store", "seed", "authority", "registry", "--source", "cmd"}},
		{name: "empty source name", args: []string{"store", "seed", "authority", "registry", "--source", "=cmd"}},
		{name: "empty source command", args: []string{"store", "seed", "authority", "registry", "--source", "name="}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := cmdServe(tt.args); got != 2 {
				t.Fatalf("cmdServe() = %d, want 2", got)
			}
		})
	}
}
