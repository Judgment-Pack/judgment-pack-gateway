package pdf

import (
	"fmt"
	"strings"
	"testing"
)

// Regression from the independent Codex review: a full set of narrow codespaces
// must not widen early and consume the prefix of a longer mapped code.
func TestReadsInferredCodespacesAtExactLimit(t *testing.T) {
	for _, count := range []int{63, 64} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			var enc strings.Builder
			fmt.Fprintf(&enc, "begincmap\n%d begincidchar\n", count+1)
			for i := 0; i < count; i++ {
				fmt.Fprintf(&enc, "<%02X> %d\n", 2*i, 5+i)
			}
			enc.WriteString("<0100> 200\nendcidchar\nendcmap\n")
			cm := parseCMap([]byte(enc.String()), &fontBudget{}, nil)
			if cm == nil {
				t.Errorf("prefix-free %d one-byte singleton runs plus <0100> rejected; all runs fit the per-length cap %d", count, maxInferredCodespaces)
			}
			uni := "begincmap\n2 beginbfchar\n<00> <0058>\n<0100> <0059>\nendbfchar\nendcmap\n"
			data, _ := readsCIDFont(enc.String(), uni, "000100", 5, 123)
			r := extract(t, data)
			if r.Fatal != nil || len(r.Pages) != 1 {
				t.Fatalf("unexpected document outcome %+v", r)
			}
			if r.Pages[0].Text != "XY" || r.Pages[0].Unmapped != 0 {
				t.Errorf("got text=%q unmapped=%d, want XY with zero unmapped", r.Pages[0].Text, r.Pages[0].Unmapped)
			}
		})
	}
}

func TestReadsInferredCodespacesStayWithinLimit(t *testing.T) {
	for _, c := range []struct {
		n, count  int
		low, high uint32
	}{{3, 58, 0x8181e9, 0xc09d25}, {4, 56, 0x818181e9, 0xc09d9d25}} {
		runs := make([]codeRun, 0, c.count+1)
		for i := 0; i < c.count; i++ {
			v := uint32(2 * i)
			runs = append(runs, codeRun{v, v})
		}
		runs = append(runs, codeRun{c.low, c.high})
		spans := codespacesCovering(c.n, runs)
		if len(spans) > maxInferredCodespaces {
			t.Errorf("%d-byte sources retain %d spans past cap %d", c.n, len(spans), maxInferredCodespaces)
		}
	}
}
