package main

// The maintenance gate both of the engine's serving processes carry --
// the signer's, at the one place an acquisition or an action is admitted,
// and the MCP server's, in front of its forwards -- and the stream their
// reports travel on (docs/design/mcp-server.md, "Rotation").

import (
	"errors"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"time"
)

// errAdmissionClosed is the refusal of a closed gate.
var errAdmissionClosed = errors.New("admission is closed for maintenance; nothing was admitted")

// unavailable is a refusal of admission for maintenance, which the
// signer's HTTP surface answers 503.
type unavailable struct{ error }

// admissionGate is a process's maintenance gate. Its state changes under
// the owner's lock, which the owner also holds when it admits and when an
// admitted thing finishes, so no admission and no closure interleave:
// what the gate let in before a closure is exactly what the closure waits
// for.
type admissionGate struct {
	closed     bool
	generation uint64        // closures so far
	closing    chan struct{} // closed when the gate closes, replaced when it reopens
	pending    int           // admitted and not finished
	current    *gateClosure
}

// gateClosure is one closure: it is drained when nothing admitted before
// it is pending, and ends either way when the gate reopens first.
type gateClosure struct {
	generation uint64
	done       chan struct{} // closed when drained, or when the gate reopens first
	drained    bool
	// unresolved counts, at the MCP server, the forwards that ended without
	// an answer since the last drain: what its drain cannot vouch for, and
	// the signer's closure can
	unresolved int
}

func newAdmissionGate() admissionGate {
	return admissionGate{closing: make(chan struct{})}
}

// closeLocked closes the gate: a new closure, or the current one and
// false if it was closed already.
func (g *admissionGate) closeLocked() (*gateClosure, bool) {
	if g.closed {
		return g.current, false
	}
	g.closed = true
	g.generation++
	close(g.closing)
	c := &gateClosure{generation: g.generation, done: make(chan struct{})}
	g.current = c
	if g.pending == 0 {
		c.drained = true
		close(c.done)
	}
	return c, true
}

// openLocked reopens the gate, ending a closure that had not drained.
func (g *admissionGate) openLocked() (*gateClosure, bool) {
	if !g.closed {
		return nil, false
	}
	g.closed = false
	g.closing = make(chan struct{})
	c := g.current
	select {
	case <-c.done:
	default:
		close(c.done)
	}
	return c, true
}

// admitLocked counts one admission, or refuses it when the gate is closed.
func (g *admissionGate) admitLocked() bool {
	if g.closed {
		return false
	}
	g.pending++
	return true
}

// finishLocked counts one admitted thing finished, draining a closure that
// waited for it; it returns that closure when this finish drained it.
func (g *admissionGate) finishLocked() *gateClosure {
	g.pending--
	if g.closed && g.pending == 0 && g.current != nil {
		select {
		case <-g.current.done:
		default:
			g.current.drained = true
			close(g.current.done)
			return g.current
		}
	}
	return nil
}

// operatorGate is what a process exposes to its operator's controls.
type operatorGate interface {
	closeAdmission() <-chan struct{}
	openAdmission()
}

// gateReports says a gate's transitions on the control lines of a
// diagnostics stream, each at the moment it happens -- its methods are
// called under the owner's lock, and queueing a control line never waits
// -- so the stream keeps the order of the gate's own changes, and every
// line names its closure.
type gateReports struct {
	reports     *diagnosticStream
	who         string                    // what every line begins with
	outstanding string                    // what pending counts
	drainedWord func(*gateClosure) string // what a drain vouches for
}

// closed reports a closure: a fresh one and its count, or, asked for
// again, where it stands; and its drain, when it drained at once.
func (r gateReports) closed(c *gateClosure, fresh bool, pending int) {
	switch {
	case fresh:
		r.reports.controlf("%s: admission closed (closure %d); %d %s", r.who, c.generation, pending, r.outstanding)
		if c.drained {
			r.drained(c)
		}
	case c.drained:
		r.reports.controlf("%s: admission is closed (closure %d) and drained", r.who, c.generation)
	default:
		r.reports.controlf("%s: admission is closed (closure %d); %d %s", r.who, c.generation, pending, r.outstanding)
	}
}

// drained reports a closure's drain.
func (r gateReports) drained(c *gateClosure) {
	r.reports.controlf("%s: closure %d drained: %s", r.who, c.generation, r.drainedWord(c))
}

// opened reports a reopening, and the end of a closure it cut short.
func (r gateReports) opened(c *gateClosure) {
	if !c.drained {
		r.reports.controlf("%s: closure %d ended: admission reopened before it drained", r.who, c.generation)
	}
	r.reports.controlf("%s: admission open; closure %d is over", r.who, c.generation)
}

// diagnosticStream is a process's diagnostics, on one writer of their own
// that nothing else waits for. Control lines -- what an operator acts on:
// a gate closed, a closure drained -- are never dropped and keep their
// order, since there is one per operator signal; traffic lines -- what the
// process says about its calls -- are dropped past a buffer and counted,
// and the count is said when the stream drains.
type diagnosticStream struct {
	out       func() io.Writer
	traffic   chan string
	dropped   atomic.Int64
	mu        sync.Mutex
	control   []string
	wake      chan struct{}
	once      sync.Once
	queued    atomic.Int64
	delivered atomic.Int64
}

func newDiagnosticStream(out func() io.Writer) *diagnosticStream {
	return &diagnosticStream{out: out, traffic: make(chan string, 256), wake: make(chan struct{}, 1)}
}

func (d *diagnosticStream) start() { d.once.Do(func() { go d.deliver() }) }

// trafficf queues a traffic line, or drops and counts it.
func (d *diagnosticStream) trafficf(format string, args ...any) {
	d.start()
	select {
	case d.traffic <- fmt.Sprintf(format, args...):
		d.queued.Add(1)
	default:
		d.dropped.Add(1)
	}
}

// controlf queues a control line; it is never dropped.
func (d *diagnosticStream) controlf(format string, args ...any) {
	d.start()
	d.mu.Lock()
	d.control = append(d.control, fmt.Sprintf(format, args...))
	d.queued.Add(1)
	d.mu.Unlock()
	select {
	case d.wake <- struct{}{}:
	default:
	}
}

func (d *diagnosticStream) deliver() {
	for {
		d.mu.Lock()
		lines := d.control
		d.control = nil
		d.mu.Unlock()
		for _, line := range lines {
			fmt.Fprintln(d.out(), line)
			d.delivered.Add(1)
		}
		if n := d.dropped.Swap(0); n > 0 {
			fmt.Fprintf(d.out(), "%d diagnostics were dropped; the stream was not draining\n", n)
		}
		select {
		case line := <-d.traffic:
			fmt.Fprintln(d.out(), line)
			d.delivered.Add(1)
		case <-d.wake:
		}
	}
}

// flush waits, at most the given time, for what was queued before it to
// be written: what a process says as it ends reaches the stream if the
// stream drains, and the process ends either way.
func (d *diagnosticStream) flush(within time.Duration) bool {
	target := d.queued.Load()
	deadline := time.Now().Add(within)
	for d.delivered.Load() < target {
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(5 * time.Millisecond)
	}
	return true
}
