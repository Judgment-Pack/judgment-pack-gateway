package pdf

import (
	"context"
	"fmt"
	"strings"
	"testing"
)

// walkSelfNaming are page trees a node of which names, among its kids, a node
// the walk stands under, more often than the deadline is read between: a root
// that names itself and nothing else, and a node that names the root after
// the two pages it holds. passed is how many kids the walk passes over, and
// pages how many pages it has counted when it comes to them.
func walkSelfNaming() []struct {
	name          string
	data          []byte
	passed, pages int
} {
	const passed = 3*entriesPerCheck + 10
	page := func(content int) string {
		return fmt.Sprintf("<< /Type /Page /Parent 3 0 R /Contents %d 0 R /Resources << /Font << /F1 8 0 R >> >> >>", content)
	}
	return []struct {
		name          string
		data          []byte
		passed, pages int
	}{
		{"a root that names itself", tabled([]string{
			"<< /Type /Catalog /Pages 2 0 R >>",
			"<< /Type /Pages /Count 0 /Kids [" + strings.Repeat(" 2 0 R", passed) + " ] >>",
		}, 0), passed, 0},
		{"a node that names the root, after two pages", tabled([]string{
			"<< /Type /Catalog /Pages 2 0 R >>",
			"<< /Type /Pages /Count 2 /Kids [3 0 R] >>",
			"<< /Type /Pages /Parent 2 0 R /Count 2 /Kids [4 0 R 5 0 R" + strings.Repeat(" 2 0 R", passed) + " ] >>",
			page(6),
			page(7),
			readsStreamObject("", shown("ONE", 700)),
			readsStreamObject("", shown("TWO", 700)),
			"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
		}, 0), passed, 2},
	}
}

// walkPassedOver reads the file under ctx and returns the kids the walk
// passed over and the most of them it passed over between two readings of
// the deadline, counted as it passes them and not as it reads the deadline.
func walkPassedOver(data []byte, ctx *rebuildDeadline) (r *Result, steps, most int) {
	stretch := 0
	ctx.onRead = func() { stretch = 0 }
	loopStepped = func(loop string, n int) {
		ctx.stepped(loop, n)
		if loop != "kids passed over" {
			return
		}
		steps += n
		stretch += n
		most = max(most, stretch)
	}
	defer func() { loopStepped = nil }()
	return Extract(ctx, data, testOptions()), steps, most
}

// The walk passes over no more than entriesPerCheck kids that name a node it
// stands under between two readings of the deadline. With time left it
// passes over every one of them and the document is what it is without them:
// a tree with no page, or the pages the tree holds.
func TestTheWalkReadsTheDeadlineAsItPassesOverKids(t *testing.T) {
	for _, c := range walkSelfNaming() {
		t.Run(c.name, func(t *testing.T) {
			r, steps, most := walkPassedOver(c.data, &rebuildDeadline{Context: context.Background()})
			t.Logf("%d kids passed over, at most %d between two readings", steps, most)
			if steps != c.passed {
				t.Fatalf("the walk passed over %d kids, and the file names %d", steps, c.passed)
			}
			if most > entriesPerCheck {
				t.Fatalf("the walk passed over %d kids between two readings of the deadline, at most %d", most, entriesPerCheck)
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
// there: no kid is passed over after the reading that found it passed, and
// the record says the deadline, with the pages counted before it, and names
// no defect of the file -- a tree the walk did not reach the end of is not
// known to hold no page.
func TestADeadlineMetPassingOverKidsEndsTheWalkThere(t *testing.T) {
	for _, c := range walkSelfNaming() {
		t.Run(c.name, func(t *testing.T) {
			ctx := &rebuildDeadline{Context: context.Background(), loop: "kids passed over"}
			r, steps, _ := walkPassedOver(c.data, ctx)
			if !ctx.expired {
				t.Fatalf("the deadline was never read after the walk began passing over kids")
			}
			if ctx.after != 0 {
				t.Fatalf("the walk passed over %d kids after a reading found the deadline passed", ctx.after)
			}
			if steps >= entriesPerCheck {
				t.Fatalf("the walk passed over %d kids before the reading that found the deadline passed, fewer than %d", steps, entriesPerCheck)
			}
			want := fmt.Sprintf("the deadline passed while the page tree was walked, after %d pages were counted", c.pages)
			if r.Fatal != nil || !r.TimedOut || !r.Truncated || r.PageCount != c.pages || len(r.Pages) != 0 ||
				len(r.Problems) != 1 || r.Problems[0].Code != "timeout" || r.Problems[0].Message != want {
				t.Fatalf("fatal %+v timedOut %v truncated %v count %d pages %d problems %+v", r.Fatal, r.TimedOut, r.Truncated, r.PageCount, len(r.Pages), r.Problems)
			}
		})
	}
}
