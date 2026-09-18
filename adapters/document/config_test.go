package document

import (
	"fmt"
	"math"
	"os"
	"strings"
	"testing"
	"time"

	"adapters/attachment"
)

// Every bound is accepted up to the ceiling adapters/README.md states for it
// and refused one past it.
func TestConfigCeilings(t *testing.T) {
	for _, c := range []struct {
		name      string
		atCeiling func(*Config)
		pastIt    func(*Config)
	}{
		{"max-bytes", func(c *Config) { c.MaxBytes = 1 << 30 }, func(c *Config) { c.MaxBytes = 1<<30 + 1 }},
		{"max-pages", func(c *Config) { c.MaxPages = 1_000_000 }, func(c *Config) { c.MaxPages = 1_000_001 }},
		{"max-text", func(c *Config) { c.MaxText = 1 << 30 }, func(c *Config) { c.MaxText = 1<<30 + 1 }},
		{"max-inflate", func(c *Config) { c.MaxInflate = 4 << 30 }, func(c *Config) { c.MaxInflate = 4<<30 + 1 }},
		{"ocr-max-output", func(c *Config) { c.OCRMaxOutput = 1 << 30 }, func(c *Config) { c.OCRMaxOutput = 1<<30 + 1 }},
		{"max-output", func(c *Config) { c.MaxOutput = 1 << 40 }, func(c *Config) { c.MaxOutput = 1<<40 + 1 }},
		{"timeout", func(c *Config) { c.Timeout = 10 * time.Minute }, func(c *Config) { c.Timeout = 10*time.Minute + time.Millisecond }},
	} {
		cfg := DefaultConfig()
		c.atCeiling(&cfg)
		if err := cfg.Check(); err != nil {
			t.Errorf("%s at its ceiling: %v", c.name, err)
		}
		cfg = DefaultConfig()
		c.pastIt(&cfg)
		if cfg.Check() == nil {
			t.Errorf("%s past its ceiling is accepted", c.name)
		}
	}
	// The values a first review found accepted: one overflowed the read
	// bound, the other wrote a record outside the canonical domain.
	for name, cfg := range map[string]Config{
		"max-bytes 6917529027641081856": func() Config { c := DefaultConfig(); c.MaxBytes = 6917529027641081856; return c }(),
		"max-bytes 2^63 - 1":            func() Config { c := DefaultConfig(); c.MaxBytes = math.MaxInt64; return c }(),
		"max-inflate 9007199254740992":  func() Config { c := DefaultConfig(); c.MaxInflate = 9007199254740992; return c }(),
		"max-pages 2^53":                func() Config { c := DefaultConfig(); c.MaxPages = 1 << 53; return c }(),
		"timeout of the longest duration": func() Config {
			c := DefaultConfig()
			c.Timeout = math.MaxInt64 / time.Millisecond * time.Millisecond
			return c
		}(),
	} {
		if cfg.Check() == nil {
			t.Errorf("%s is accepted", name)
		}
	}
}

// Every bound at its ceiling at once yields a record the check admits, and
// a read bound within the canonical domain.
func TestBoundsAtTheirCeilingsStayCanonical(t *testing.T) {
	cfg := Config{MaxBytes: 1 << 30, MaxPages: 1_000_000, MaxText: 1 << 30, MaxInflate: 4 << 30, OCRMaxOutput: 1 << 30, MaxOutput: 1 << 40, Timeout: 10 * time.Minute}
	if err := cfg.Check(); err != nil {
		t.Fatal(err)
	}
	bound, ok := ReadBound(cfg)
	if !ok || bound != 4*((1<<30+2)/3)+65536 || bound > 1<<53-1 {
		t.Fatalf("read bound %d %v", bound, ok)
	}
	rec := processed(t, cfg, mustParse(t, cfg, requestJSON("a.txt", "text/plain", []byte("hello"), "")), nil)
	b := rec.Processing.Bounds
	if b.MaxBytes != 1<<30 || b.MaxPages != 1_000_000 || b.MaxTextBytes != 1<<30 || b.MaxInflateBytes != 4<<30 || b.MaxOcrOutputBytes != 1<<30 || b.TimeoutMs != 600_000 {
		t.Fatalf("bounds %+v", b)
	}
	if rec.Processing.Status != attachment.StatusComplete {
		t.Fatalf("%+v", rec.Processing)
	}
}

// The read bound is computed without overflow: a max-bytes whose read bound
// an int64 cannot hold has none, and a request read under it is refused as
// the adapter's own failure, never as a request past a negative bound.
func TestReadBoundDoesNotOverflow(t *testing.T) {
	for _, maxBytes := range []int64{6917529027641081856, math.MaxInt64, math.MaxInt64 / 4 * 3, 0, -1} {
		cfg := DefaultConfig()
		cfg.MaxBytes = maxBytes
		if bound, ok := ReadBound(cfg); ok {
			t.Errorf("max-bytes %d: read bound %d", maxBytes, bound)
		}
		_, err := parse(t, cfg, requestJSON("a.txt", "text/plain", []byte("hi"), ""))
		if code := refusalCode(err); code != "adapter-failed" {
			t.Errorf("max-bytes %d: refused %q (%v)", maxBytes, code, err)
		}
	}
	// The largest max-bytes whose read bound, and the one byte read past it,
	// an int64 holds, and the smallest past it: one more byte is one more
	// group of four, and would take the byte read past the bound to 2^63.
	groups := int64((math.MaxInt64 - 65536 - 1) / 4)
	cfg := DefaultConfig()
	cfg.MaxBytes = 3 * groups
	if bound, ok := ReadBound(cfg); !ok || bound != 4*groups+65536 || bound == math.MaxInt64 {
		t.Errorf("max-bytes %d: read bound %d %v", cfg.MaxBytes, bound, ok)
	}
	cfg.MaxBytes = 3*groups + 1
	if bound, ok := ReadBound(cfg); ok {
		t.Errorf("max-bytes %d: read bound %d", cfg.MaxBytes, bound)
	}
}

// adapters/README.md states each bound's ceiling with the value Check holds
// it to.
func TestREADMEStatesTheCeilings(t *testing.T) {
	raw, err := os.ReadFile("../README.md")
	if err != nil {
		t.Fatal(err)
	}
	size := func(n int64) string {
		for _, u := range []struct {
			unit  string
			scale int64
		}{{"TiB", 1 << 40}, {"GiB", 1 << 30}, {"MiB", 1 << 20}} {
			if n >= u.scale && n%u.scale == 0 {
				return fmt.Sprintf("%d %s", n/u.scale, u.unit)
			}
		}
		return fmt.Sprintf("%d bytes", n)
	}
	for flag, ceiling := range map[string]string{
		"--max-bytes":      size(maxBytesCeiling),
		"--max-pages":      "1,000,000",
		"--max-text":       size(maxTextCeiling),
		"--max-inflate":    size(maxInflateCeiling),
		"--ocr-max-output": size(ocrMaxOutputCeiling),
		"--max-output":     size(maxOutputCeiling),
		"--timeout":        fmt.Sprintf("%d minutes", int(timeoutCeiling/time.Minute)),
	} {
		var row []string
		for _, line := range strings.Split(string(raw), "\n") {
			if cells := strings.Split(strings.TrimSpace(line), " | "); len(cells) == 3 && cells[0] == "| `"+flag+"`" {
				row = cells
			}
		}
		if row == nil {
			t.Errorf("adapters/README.md has no ceiling for %s", flag)
			continue
		}
		if got := strings.TrimSuffix(row[2], " |"); !strings.HasPrefix(got, ceiling) {
			t.Errorf("%s: adapters/README.md says %q, Check holds %q", flag, got, ceiling)
		}
	}
	if maxPagesCeiling != 1_000_000 {
		t.Errorf("max-pages ceiling %d", maxPagesCeiling)
	}
}
