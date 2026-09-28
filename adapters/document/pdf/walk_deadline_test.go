package pdf

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"
)

// walkSelfNaming are page trees a node of which names, among its kids, a node
// the walk stands under: a root that names itself and nothing else, a node
// that names the root after the two pages it holds, each more often than the
// deadline is read between; and a node and its parent that each name the root
// one time fewer than that, so that the kids passed over between two readings
// are passed over under two nodes. passed is how many kids the walk passes
// over, pages how many pages it has counted when it comes to the first of
// them, and readings how many readings of the deadline the file makes it
// take as it passes them.
func walkSelfNaming() []struct {
	name                    string
	data                    []byte
	passed, pages, readings int
} {
	const long = 3*entriesPerCheck + 10
	const short = entriesPerCheck - 1
	page := func(parent, content, font int) string {
		return fmt.Sprintf("<< /Type /Page /Parent %d 0 R /Contents %d 0 R /Resources << /Font << /F1 %d 0 R >> >> >>", parent, content, font)
	}
	const font = "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"
	return []struct {
		name                    string
		data                    []byte
		passed, pages, readings int
	}{
		{"a root that names itself", tabled([]string{
			"<< /Type /Catalog /Pages 2 0 R >>",
			"<< /Type /Pages /Count 0 /Kids [" + strings.Repeat(" 2 0 R", long) + " ] >>",
		}, 0), long, 0, 3},
		{"a node that names the root, after two pages", tabled([]string{
			"<< /Type /Catalog /Pages 2 0 R >>",
			"<< /Type /Pages /Count 2 /Kids [3 0 R] >>",
			"<< /Type /Pages /Parent 2 0 R /Count 2 /Kids [4 0 R 5 0 R" + strings.Repeat(" 2 0 R", long) + " ] >>",
			page(3, 6, 8),
			page(3, 7, 8),
			readsStreamObject("", shown("ONE", 700)),
			readsStreamObject("", shown("TWO", 700)),
			font,
		}, 0), long, 2, 3},
		{"a node and its parent that each name the root", tabled([]string{
			"<< /Type /Catalog /Pages 2 0 R >>",
			"<< /Type /Pages /Count 1 /Kids [3 0 R" + strings.Repeat(" 2 0 R", short) + " ] >>",
			"<< /Type /Pages /Parent 2 0 R /Count 1 /Kids [4 0 R" + strings.Repeat(" 2 0 R", short) + " ] >>",
			page(3, 5, 6),
			readsStreamObject("", shown("ONE", 700)),
			font,
		}, 0), 2 * short, 1, 1},
	}
}

// kidsDeadline counts the kids the walk passes over, as it passes them and
// apart from where it reads the deadline, and passes at the nth reading made
// once the walk has begun passing over kids, and at every reading after it;
// with n zero it never passes. most is the most kids passed over between two
// readings, and after the kids passed over once the deadline has passed.
type kidsDeadline struct {
	context.Context
	n                           int
	began, expired              bool
	reads                       int
	steps, stretch, most, after int
}

func (c *kidsDeadline) stepped(loop string, n int) {
	if loop != "kids passed over" {
		return
	}
	c.began = true
	c.steps += n
	c.stretch += n
	c.most = max(c.most, c.stretch)
	if c.expired {
		c.after += n
	}
}

func (c *kidsDeadline) Err() error {
	c.stretch = 0
	if c.began && c.n > 0 {
		c.reads++
		if c.reads >= c.n {
			c.expired = true
		}
	}
	if c.expired {
		return context.DeadlineExceeded
	}
	return nil
}

func (c *kidsDeadline) Deadline() (time.Time, bool) { return time.Time{}, false }

// walkUnder reads the file under a deadline that passes at the nth reading
// made once the walk has begun passing over kids.
func walkUnder(data []byte, n int) (*Result, *kidsDeadline) {
	ctx := &kidsDeadline{Context: context.Background(), n: n}
	loopStepped = ctx.stepped
	defer func() { loopStepped = nil }()
	return Extract(ctx, data, testOptions()), ctx
}

// The walk passes over no more than entriesPerCheck kids that name a node it
// stands under between two readings of the deadline, whether it passes them
// under one node or, a node ended, goes on passing them under its parent.
// With time left it passes over every one of them and the document is what
// it is without them: a tree with no page, or the pages the tree holds.
func TestTheWalkReadsTheDeadlineAsItPassesOverKids(t *testing.T) {
	for _, c := range walkSelfNaming() {
		t.Run(c.name, func(t *testing.T) {
			r, ctx := walkUnder(c.data, 0)
			t.Logf("%d kids passed over, at most %d between two readings", ctx.steps, ctx.most)
			if ctx.steps != c.passed {
				t.Fatalf("the walk passed over %d kids, and the file names %d", ctx.steps, c.passed)
			}
			if ctx.most > entriesPerCheck {
				t.Fatalf("the walk passed over %d kids between two readings of the deadline, at most %d", ctx.most, entriesPerCheck)
			}
			if r.TimedOut || r.PageCount != c.pages || len(r.Pages) != c.pages {
				t.Fatalf("timedOut %v count %d pages %d, under a deadline that never passes", r.TimedOut, r.PageCount, len(r.Pages))
			}
			if c.pages == 0 && (r.Fatal == nil || r.Fatal.Code != "pdf-malformed") {
				t.Fatalf("fatal %+v: a tree that holds no page, read to its end, is malformed", r.Fatal)
			}
			if c.pages != 0 && r.Fatal != nil {
				t.Fatalf("fatal %+v", r.Fatal)
			}
		})
	}
}

// A deadline that passes while the walk passes over such kids ends the walk
// at the reading that finds it passed, the first the walk makes there or a
// later one: no kid is passed over after it, and the record says the
// deadline, with the pages counted before it, and names no defect of the
// file -- a tree the walk did not reach the end of is not known to hold no
// page.
func TestADeadlineMetPassingOverKidsEndsTheWalkThere(t *testing.T) {
	for _, c := range walkSelfNaming() {
		for n := 1; n <= c.readings; n++ {
			t.Run(fmt.Sprintf("%s, at reading %d", c.name, n), func(t *testing.T) {
				r, ctx := walkUnder(c.data, n)
				if !ctx.expired {
					t.Fatalf("the walk made %d readings of the deadline as it passed over %d kids, and the file makes it take %d", ctx.reads, ctx.steps, c.readings)
				}
				if ctx.after != 0 {
					t.Fatalf("the walk passed over %d kids after a reading found the deadline passed", ctx.after)
				}
				if ctx.steps > n*entriesPerCheck {
					t.Fatalf("the walk passed over %d kids before reading %d found the deadline passed, at most %d", ctx.steps, n, n*entriesPerCheck)
				}
				want := fmt.Sprintf("the deadline passed while the page tree was walked, after %d pages were counted", c.pages)
				if r.Fatal != nil || !r.TimedOut || !r.Truncated || r.PageCount != c.pages || len(r.Pages) != 0 ||
					len(r.Problems) != 1 || r.Problems[0].Code != "timeout" || r.Problems[0].Message != want {
					t.Fatalf("fatal %+v timedOut %v truncated %v count %d pages %d problems %+v", r.Fatal, r.TimedOut, r.Truncated, r.PageCount, len(r.Pages), r.Problems)
				}
			})
		}
	}
}
