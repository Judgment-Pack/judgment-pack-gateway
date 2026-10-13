package mcp

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"os"
	"path/filepath"
	"regexp"
	"testing"
	"time"

	"adapters/internal/fakemcp"
)

// updateGolden rewrites the stdio form's golden records from the code as it
// stands. It is for the commit that changes those records on purpose, and
// none other: the remote form was added beside the stdio form without one.
var updateGolden = flag.Bool("update-golden", false, "rewrite testdata/stdio-golden from the code as it stands")

// observedStamp is the one member of a record that moves with the clock.
var observedStamp = regexp.MustCompile(`"observedAt":"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z"`)

// The stdio form's records, byte for byte: the envelope and the check report
// for an image and for a command, an error result enveloped for an
// executor, a probe, a descriptors capture and a failed check, each against
// the fake server as it answers by default. What moves from run to run --
// the stamp of the answer, and for a command the test binary's path and
// digest -- is put in place before the comparison and nowhere else.
func TestTheStdioFormsRecordsAreByteForByteWhatTheyWere(t *testing.T) {
	self, err := os.ReadFile(os.Args[0])
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(self)
	selfDigest := "sha256:" + hex.EncodeToString(sum[:])
	normalize := func(out []byte) []byte {
		out = observedStamp.ReplaceAll(out, []byte(`"observedAt":"OBSERVED"`))
		out = bytes.ReplaceAll(out, []byte(selfDigest), []byte("sha256:SELF"))
		return bytes.ReplaceAll(out, []byte(`"`+os.Args[0]+`"`), []byte(`"SELF"`))
	}
	saved := now
	now = func() time.Time { return time.Date(2026, 9, 15, 1, 2, 3, 400, time.UTC) }
	t.Cleanup(func() { now = saved })
	ctx := func(t *testing.T) context.Context {
		c, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		t.Cleanup(cancel)
		return c
	}
	for _, tc := range []struct {
		name string
		run  func(t *testing.T) []byte
	}{
		{"acquire-image", func(t *testing.T) []byte {
			cfg := image(fake(t))
			cfg.Endpoint = "warehouse.internal:5432"
			cfg.Tools = []string{"query"}
			out, err := Acquire(ctx(t), cfg, query("select 1"))
			if err != nil {
				t.Fatal(err)
			}
			return out
		}},
		{"acquire-command", func(t *testing.T) []byte {
			cfg := fake(t)
			out, err := Acquire(ctx(t), cfg, query("select 2"))
			if err != nil {
				t.Fatal(err)
			}
			return out
		}},
		{"acquire-error-result", func(t *testing.T) []byte {
			cfg := image(fake(t))
			cfg.ErrorResults = true
			result := filepath.Join(t.TempDir(), "result.json")
			if err := os.WriteFile(result, []byte(`{"content":[{"type":"text","text":"refused: not permitted"}],"isError":true}`), 0o600); err != nil {
				t.Fatal(err)
			}
			t.Setenv(fakemcp.EnvResult, result)
			out, err := Acquire(ctx(t), cfg, query("update t set x = 1"))
			if err != nil {
				t.Fatal(err)
			}
			return out
		}},
		{"check-image", func(t *testing.T) []byte {
			cfg := image(fake(t))
			cfg.Tools = []string{"query"}
			cfg.Probe = "query"
			out, err := Check(ctx(t), cfg)
			if err != nil {
				t.Fatal(err)
			}
			return out
		}},
		{"check-command", func(t *testing.T) []byte {
			out, err := Check(ctx(t), fake(t))
			if err != nil {
				t.Fatal(err)
			}
			return out
		}},
		{"check-descriptors", func(t *testing.T) []byte {
			cfg := image(fake(t))
			cfg.Tools = []string{"query"}
			cfg.Descriptors = &DescriptorTarget{Platform: "warehouse", Binding: "postgres@" + testDigest}
			out, err := Check(ctx(t), cfg)
			if err != nil {
				t.Fatal(err)
			}
			return out
		}},
		{"check-failed", func(t *testing.T) []byte {
			cfg := image(fake(t))
			cfg.Tools = []string{"drop_table"}
			_, err := Check(ctx(t), cfg)
			if err == nil {
				t.Fatal("a check for a tool the server does not offer succeeded")
			}
			return FailedCheck(err.Error())
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := normalize(tc.run(t))
			path := filepath.Join("testdata", "stdio-golden", tc.name+".json")
			if *updateGolden {
				if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, got, 0o644); err != nil {
					t.Fatal(err)
				}
				return
			}
			want, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("the stdio form's record moved:\n got %s\nwant %s", got, want)
			}
		})
	}
}
