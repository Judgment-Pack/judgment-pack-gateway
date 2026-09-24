package pdf

import (
	"context"
	"fmt"
	"math/rand"
	"reflect"
	"strings"
	"testing"
)

// scanCases are files built around the places where reading a header
// backwards from its keyword could part from the expression: every byte of
// whitespace it admits and one it does not, whitespace longer than a part,
// numbers and generations at and past their lengths, the keyword followed by
// a word and by no word and by the end of the file, keywords back to back,
// and files that end part of the way through a header.
func scanCases() [][]byte {
	cases := []string{
		"",
		"obj",
		"objobj",
		"1 0 obj",
		"1 0 obj ",
		"1 0 objx",
		"1 0 obj_",
		"1 0 obj1",
		"1 0 obj<<",
		"1 0 obj\x80",
		"1 0 objobj",
		"1 0 obj1 0 obj",
		"1 0 obj 2 0 obj",
		"1 0 obj\n2 0 obj\n3 1 obj",
		"1 0 obj2 0 obj3 0 obj",
		"1\v0 obj",
		"1 0\vobj",
		"1 0 ob",
		"1 0 ",
		"1 0",
		"1 ",
		"1",
		" 0 obj",
		"1 obj",
		"1  obj",
		"1 0 0 obj",
		"x1 0 obj",
		"a 1 0 obj",
		"1234567890 0 obj",
		"12345678901 0 obj",
		"123456789012345 0 obj",
		"x12345678901 0 obj",
		"1 12345 obj",
		"1 123456 obj",
		"1 1234567890 obj",
		"12345678901 123456 obj",
		"%PDF-1.7\n1 0 obj<< >>endobj\n2 0 obj<< >>endobj\ntrailer<< /Root 1 0 R >>",
		"4 0 obj\n\x00\f\t\r 5 0 obj",
	}
	for _, space := range []string{" ", "\t", "\r", "\n", "\f", "\x00"} {
		cases = append(cases, "1"+space+"0"+space+"obj", "7"+strings.Repeat(space, 3)+"65535"+space+"obj")
	}
	// Whitespace longer than any part the tests cut the file into.
	cases = append(cases,
		"1"+strings.Repeat(" ", 300)+"0"+strings.Repeat("\n", 300)+"obj",
		strings.Repeat("\x00", 200)+"12"+strings.Repeat("\t", 200)+"3 obj"+strings.Repeat(" ", 200))
	// A header at every offset from a part's edge.
	for shift := 0; shift < 12; shift++ {
		cases = append(cases, strings.Repeat("x", shift)+"12 0 obj"+strings.Repeat("y", shift)+"345 67 obj")
	}
	out := make([][]byte, len(cases))
	for i, c := range cases {
		out[i] = []byte(c)
	}
	return out
}

// sameScan reports where scanning data in parts of part bytes, for at most
// limit matches, finds other than the expression finds; limit -1 is every
// match.
func sameScan(data []byte, part, limit int) error {
	want := objHeader.FindAllSubmatchIndex(data, limit)
	got, examined, stopped := scanHeaders(data, limit, part, func() bool { return false })
	if stopped {
		return fmt.Errorf("the scan stopped with no deadline to stop it")
	}
	if len(got) != len(want) || (len(want) > 0 && !reflect.DeepEqual(got, want)) {
		return fmt.Errorf("parts of %d, limit %d: %v, the expression finds %v", part, limit, got, want)
	}
	if limit < 0 && examined < len(data) {
		return fmt.Errorf("parts of %d: the whole scan examined %d of %d bytes", part, examined, len(data))
	}
	return nil
}

// Scanning a file part by part finds exactly what the expression finds in it
// whole -- the same matches, in the same order, with the same numbers and
// generations -- wherever the parts are cut, and stops at the same count.
func TestTheScanFindsWhatTheExpressionFinds(t *testing.T) {
	cases := scanCases()
	random := rand.New(rand.NewSource(155))
	const alphabet = "0123456789 \t\r\n\f\x00objx_<"
	for i := 0; i < 400; i++ {
		b := make([]byte, random.Intn(80))
		for j := range b {
			b[j] = alphabet[random.Intn(len(alphabet))]
		}
		cases = append(cases, b)
	}
	for _, data := range cases {
		for part := 1; part <= len(data)+1; part++ {
			if err := sameScan(data, part, -1); err != nil {
				t.Fatalf("%q: %v", data, err)
			}
		}
		for limit := 1; limit <= 4; limit++ {
			for _, part := range []int{1, 2, 3, 7, 1 << 10} {
				if err := sameScan(data, part, limit); err != nil {
					t.Fatalf("%q: %v", data, err)
				}
			}
		}
	}
}

// The same, over files the fuzzer makes, cut into parts of every size up to
// sixty-four bytes and scanned for every match or for a few.
func FuzzScanMatchesTheExpression(f *testing.F) {
	for i, data := range scanCases() {
		f.Add(data, uint8(i), uint8(0))
		f.Add(data, uint8(0), uint8(1))
	}
	f.Fuzz(func(t *testing.T, data []byte, part, limit uint8) {
		n := -1
		if limit > 0 {
			n = int(limit % 8)
			if n == 0 {
				n = -1
			}
		}
		if err := sameScan(data, int(part%64)+1, n); err != nil {
			t.Fatalf("%q: %v", data, err)
		}
	})
}

// The scan for object headers reads the deadline before it begins and between
// the parts of the file it examines. A file with no startxref reads no
// deadline before the scan, so a deadline that has already passed when the
// file is opened is the scan's first reading, and it examines none of the
// file; one that passes at the scan's second reading stops it within the first
// part. The file is several parts long, so a scan that did not read the
// deadline between them would examine it all.
func TestTheScanReadsTheDeadlineBetweenParts(t *testing.T) {
	data := scanned(20000)
	if len(data) < 2*scanBytesPerCheck {
		t.Fatalf("the file is %d bytes, less than two parts", len(data))
	}
	var seen []int
	scanObserved = func(examined int) { seen = append(seen, examined) }
	defer func() { scanObserved = nil }()
	passed, cancel := context.WithCancel(context.Background())
	cancel()
	for _, c := range []struct {
		name     string
		ctx      context.Context
		timedOut bool
		atMost   int
		atLeast  int
	}{
		{"a deadline that has passed when the file is opened", passed, true, 0, 0},
		{"a deadline that passes at the scan's second reading of it", newCountdown(1), true, scanBytesPerCheck + len(objKeyword) - 1, scanBytesPerCheck},
		{"no deadline", context.Background(), false, 2 * len(data), len(data)},
	} {
		t.Run(c.name, func(t *testing.T) {
			seen = nil
			r := &Result{}
			_, stop := openDocument(c.ctx, data, testOptions(), r)
			if len(seen) != 1 {
				t.Fatalf("the scan ran %d times", len(seen))
			}
			t.Logf("the scan examined %d of %d bytes", seen[0], len(data))
			if seen[0] > c.atMost || seen[0] < c.atLeast {
				t.Fatalf("the scan examined %d bytes of %d, want %d to %d", seen[0], len(data), c.atLeast, c.atMost)
			}
			if c.timedOut != r.TimedOut || (c.timedOut && stop == nil) {
				t.Fatalf("timedOut %v stop %v, want timedOut %v", r.TimedOut, stop, c.timedOut)
			}
		})
	}
}
