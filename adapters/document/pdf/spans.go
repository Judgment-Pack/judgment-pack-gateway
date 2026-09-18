package pdf

import (
	"container/heap"
	"sort"
)

// span is the codes from lo to hi, inclusive, and the position of what
// declared them among everything else declared.
type span struct {
	lo, hi uint32
	order  int32
}

// firstSpans finds, among spans declared in an order, the first one that
// holds a code, in time logarithmic in their number however they overlap. It
// is the union of the spans cut into disjoint segments in ascending order,
// each carrying the order of the first span that holds all of it.
type firstSpans []span

// indexSpans indexes spans. A span whose hi is below its lo holds no code.
// The index has at most twice as many segments as there are spans.
func indexSpans(spans []span) firstSpans {
	byLo := make([]int32, 0, len(spans))
	for i, s := range spans {
		if s.hi >= s.lo {
			byLo = append(byLo, int32(i))
		}
	}
	sort.Slice(byLo, func(a, b int) bool { return spans[byLo[a]].lo < spans[byLo[b]].lo })
	// A sweep up the codes: active holds the spans begun at or before the
	// code at, the first declared on top; one that has ended is dropped when
	// it reaches the top.
	active := &spanHeap{spans: spans}
	var out firstSpans
	next := 0
	var at uint64
	for next < len(byLo) || active.Len() > 0 {
		if active.Len() == 0 {
			at = uint64(spans[byLo[next]].lo)
		}
		for next < len(byLo) && uint64(spans[byLo[next]].lo) <= at {
			heap.Push(active, byLo[next])
			next++
		}
		for active.Len() > 0 && uint64(active.top().hi) < at {
			heap.Pop(active)
		}
		if active.Len() == 0 {
			continue
		}
		first := active.top()
		// The segment runs to the end of the first span, or to just before
		// the next span begins, which may have been declared before it.
		end := uint64(first.hi)
		if next < len(byLo) && uint64(spans[byLo[next]].lo) <= end {
			end = uint64(spans[byLo[next]].lo) - 1
		}
		// A segment of the span that made the last one extends it: the two are
		// adjacent, since the span holds every code between them and a span
		// first there would have made a segment between them.
		if k := len(out) - 1; k >= 0 && out[k].order == first.order {
			out[k].hi = uint32(end)
		} else {
			out = append(out, span{lo: uint32(at), hi: uint32(end), order: first.order})
		}
		at = end + 1
	}
	return out
}

// find returns the order of the first span that holds code.
func (x firstSpans) find(code uint32) (int, bool) {
	i := sort.Search(len(x), func(i int) bool { return x[i].hi >= code })
	if i < len(x) && x[i].lo <= code {
		return int(x[i].order), true
	}
	return 0, false
}

// spanHeap holds indexes of spans, the least order on top.
type spanHeap struct {
	spans   []span
	indexes []int32
}

func (h *spanHeap) Len() int { return len(h.indexes) }
func (h *spanHeap) Less(a, b int) bool {
	return h.spans[h.indexes[a]].order < h.spans[h.indexes[b]].order
}
func (h *spanHeap) Swap(a, b int) { h.indexes[a], h.indexes[b] = h.indexes[b], h.indexes[a] }
func (h *spanHeap) Push(x any)    { h.indexes = append(h.indexes, x.(int32)) }
func (h *spanHeap) Pop() any {
	last := h.indexes[len(h.indexes)-1]
	h.indexes = h.indexes[:len(h.indexes)-1]
	return last
}
func (h *spanHeap) top() span { return h.spans[h.indexes[0]] }
