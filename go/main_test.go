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
			name:    "duplicate port option",
			args:    []string{"store", "seed", "authority", "registry", "--port", "8787", "--port", "9000"},
			wantErr: "duplicate --port option",
		},
		{
			name:    "port is a service name",
			args:    []string{"store", "seed", "authority", "registry", "--port", "http"},
			wantErr: "is not a number between 1 and 65535",
		},
		{
			name:    "port carries a host",
			args:    []string{"store", "seed", "authority", "registry", "--port", "localhost:9000"},
			wantErr: "is not a number between 1 and 65535",
		},
		{
			// "-1" is not "--"-prefixed, so it is consumed as the --port value
			// and rejected by validatePort rather than as an unknown option --
			// which gives the operator the message about the port, not about a
			// flag they did not write.
			name:    "port is negative",
			args:    []string{"store", "seed", "authority", "registry", "--port", "-1"},
			wantErr: "is not a number between 1 and 65535",
		},
		{
			name:    "port is above the range",
			args:    []string{"store", "seed", "authority", "registry", "--port", "65536"},
			wantErr: "is not a number between 1 and 65535",
		},
		{
			name:    "port zero asks the kernel to choose",
			args:    []string{"store", "seed", "authority", "registry", "--port", "0"},
			wantErr: "is not a number between 1 and 65535",
		},
		{
			name:    "port is empty",
			args:    []string{"store", "seed", "authority", "registry", "--port", ""},
			wantErr: "--port must not be empty",
		},
		{
			name:    "port has surrounding space",
			args:    []string{"store", "seed", "authority", "registry", "--port", " 8787"},
			wantErr: "is not a number between 1 and 65535",
		},
		{
			name:    "port has a sign",
			args:    []string{"store", "seed", "authority", "registry", "--port", "+8787"},
			wantErr: "is not a number between 1 and 65535",
		},
		{
			name: "port at the top of the range is accepted",
			args: []string{"store", "seed", "authority", "registry", "--port", "65535"},
			wantOptions: serveOptions{
				sources: map[string][]string{},
				port:    "65535",
			},
		},
		{
			name: "port at the bottom of the range is accepted",
			args: []string{"store", "seed", "authority", "registry", "--port", "1"},
			wantOptions: serveOptions{
				sources: map[string][]string{},
				port:    "1",
			},
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
			name: "duplicate source name",
			args: []string{
				"store", "seed", "authority", "registry",
				"--source", "screen=echo hi",
				"--source", "screen=/bin/sh",
			},
			wantErr: `duplicate source "screen"`,
		},
		{
			name:    "unexpected positional argument",
			args:    []string{"store", "seed", "authority", "registry", "extra"},
			wantErr: `unexpected argument "extra"`,
		},
		{
			name: "required arguments only",
			args: []string{"store", "seed", "authority", "registry"},
			wantOptions: serveOptions{
				sources: map[string][]string{},
				port:    "8787",
			},
		},
		{
			name: "port only",
			args: []string{"store", "seed", "authority", "registry", "--port", "9000"},
			wantOptions: serveOptions{
				sources: map[string][]string{},
				port:    "9000",
			},
		},
		{
			name: "port before source",
			args: []string{
				"store", "seed", "authority", "registry",
				"--port", "9000",
				"--source", "screening=echo ok",
			},
			wantOptions: serveOptions{
				sources: map[string][]string{
					"screening": {"echo", "ok"},
				},
				port: "9000",
			},
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
		{
			name: "duplicate source name",
			args: []string{
				"store", "seed", "authority", "registry",
				"--source", "screen=echo hi",
				"--source", "screen=/bin/sh",
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := cmdServe(tt.args); got != 2 {
				t.Fatalf("cmdServe() = %d, want 2", got)
			}
		})
	}
}
