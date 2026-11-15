package main

// An orderly hand-over between instances on the PostgreSQL kind
// (docs/adr/0035-several-instances-on-one-postgresql-database.md, option D;
// docs/postgresql-store.md, "One instance per database"). One instance still
// serves a database at a time, by the start lease (store_pg_lease.go); what
// this adds is the order a roll-out needs, the new instance started before
// the old one is stopped:
//
//   - a start whose storage.startWaitSeconds is set (engineVersion 25), and
//     that finds the lease held, listens on its address at once and answers
//     every request 503, with Retry-After and a fixed body, while it polls
//     the lease every renewal interval; it takes the lease once the database's
//     clock says it was released or expired, then makes the start's checks
//     and serves on the listener it bound, which it never closed in between.
//     Where its address is in use, as it is by the instance it takes over
//     from on the same host, it waits without listening -- nothing answers
//     -- and binds the address once it holds the lease, which that instance
//     releases only after it stopped listening. Each poll reads the row and takes it only where it is not live, so a
//     waiting instance holds no row and writes nothing. When the wait runs
//     out the start is refused with the last poll's start-lease-held;
//   - the stop signal of an instance that holds the lease closes its gate
//     for the stop: from then each acquisition is answered 503, with
//     Retry-After, and nothing is admitted; what it admitted finishes,
//     within the operation's time limit (storage.operationSeconds); only
//     then does serving end, the sources still running being killed and the
//     requests still open answered, and the lease is released, its expiry
//     set to the database's now, so the waiting instance takes it at its
//     next poll. From the first signal on -- while a start waits or makes
//     its checks, or during the drain -- a second signal ends the process
//     at once: a lease it held then expires as a crashed instance's does.
//
// Sessions the stopped instance left open stay open: the next instance does
// not continue them (SPEC.md §6). They are sealed after the interruption
// (SPEC.md §3c; ADR-0035, the third step; seal_open_pg.go) by the next start
// where sealOpenAtStart is set, once it holds the lease and before it
// serves, or by gateway seal-open --config while no instance serves.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"runtime"
	"strconv"
	"sync"
	"syscall"
	"time"
)

// errStoppedWaiting is a start the stop signal ended while it waited for
// the lease, which it never held.
var errStoppedWaiting = errors.New("stopped while waiting for the start lease; this instance held no lease and wrote nothing")

// waitingBody is the one answer of an instance that waits for the lease.
var waitingBody = []byte(`{"error":"this gateway instance is not serving yet: it serves once it holds the database's start lease, which another instance holds; send the request again"}`)

// kindRun is how serve --config runs on the PostgreSQL kind: the lease's
// periods, the stop signal and what gives the signals back their default,
// how the listener is bound, and where the start says what it does. A test
// gives it shorter periods, a stop of its own and a listener it bound.
type kindRun struct {
	period, every time.Duration
	stopped       context.Context
	restore       func()
	bind          func(listen string, said io.Writer) (net.Listener, error)
	said          io.Writer
}

// retryAfterOf is a Retry-After, in whole seconds and at least one, of the
// lease's renewal interval: a waiting instance polls the lease that often.
func retryAfterOf(every time.Duration) int {
	return max(1, int((every+time.Second-1)/time.Second))
}

// runOnKind is serve --config on the PostgreSQL kind, until the stop.
func runOnKind(cfg engineConfig, seed []byte, sources map[string]sourceSpec, identity *identityConfig, delegation *delegationService, r kindRun) int {
	if r.restore != nil {
		// from the first stop signal on -- while the start waits, makes its
		// checks, or drains -- a second one ends the process at once
		go func() {
			<-r.stopped.Done()
			r.restore()
		}()
	}
	var front *waitingFront
	if cfg.storage.startWait > 0 {
		bound, err := r.bind(cfg.listen, r.said)
		switch {
		case err == nil:
			front = serveWaiting(bound, r.every)
			fmt.Fprintf(r.said, "start: listening on %s; until this instance serves, every request is answered 503 with Retry-After %d\n", bound.Addr(), retryAfterOf(r.every))
		case addressInUse(err):
			// the instance it takes over from, on this host and address:
			// that one stops listening before it releases the lease
			// (serveOn's Shutdown closes the listener, and kindStart.stop
			// releases the lease after serving ended), so the address is
			// bound below once the lease is held
			fmt.Fprintf(r.said, "start: %s is in use, as it is by an instance on this host that serves the database; this instance waits without listening, and binds it once it holds the start lease\n", cfg.listen)
		default:
			fmt.Fprintln(r.said, "start:", err)
			return 1
		}
	}
	started, err := startOnKind(cfg, seed, sources, identity, r)
	var listener net.Listener
	if front != nil {
		listener = front.handOver()
		if err != nil {
			listener.Close()
		}
	}
	if errors.Is(err, errStoppedWaiting) {
		fmt.Fprintln(r.said, "stop:", err)
		return 0
	}
	if err != nil {
		fmt.Fprintln(r.said, "start:", err)
		return 1
	}
	defer started.stop(r.said)
	if listener == nil {
		// as before the member, or where the address was in use: bound
		// once the start holds the lease
		if listener, err = r.bind(cfg.listen, r.said); err != nil {
			fmt.Fprintln(r.said, "serve:", err)
			return 1
		}
	}
	return serveUntilStopped(started.service, cfg, delegation, started.keep, serveStop{
		stopped: r.stopped, restore: r.restore, drain: cfg.storage.operation,
		retryAfter: retryAfterOf(r.every), listener: listener, said: r.said,
	})
}

// wsaAddrInUse is Windows' WSAEADDRINUSE, the error of a bind to an address
// in use there, which package syscall does not name.
const wsaAddrInUse = syscall.Errno(10048)

// addressInUse says whether a bind failed because the address is in use.
func addressInUse(err error) bool {
	var errno syscall.Errno
	return errors.Is(err, syscall.EADDRINUSE) ||
		(runtime.GOOS == "windows" && errors.As(err, &errno) && errno == wsaAddrInUse)
}

// waitForStartLease takes the lease as takeStartLease does. Where wait is
// not zero and another instance's lease is live, it polls the lease again
// every renewal interval, until it holds it (waited then says it polled
// more than once), until wait has passed -- the last poll's refusal,
// start-lease-held, is the start's -- or until stopped ends
// (errStoppedWaiting). Whether a lease is live is the database's clock's
// to say, in each poll's statement; a poll that is refused holds nothing.
func (k *pgKind) waitForStartLease(stopped context.Context, holder string, period, every, wait time.Duration, said io.Writer) (lease *pgStartLease, waited bool, err error) {
	began := time.Now()
	until := began.Add(wait)
	for {
		lease, err = k.takeStartLease(holder, period, every)
		if err == nil || wait == 0 || !errors.Is(err, errStartLeaseHeld) {
			if err == nil && waited {
				fmt.Fprintf(said, "start: the start lease was released or expired, and this instance took it after waiting %s\n", time.Since(began).Round(time.Second))
			}
			return lease, waited, err
		}
		left := time.Until(until)
		if left <= 0 {
			return nil, waited, err
		}
		if !waited {
			fmt.Fprintf(said, "start: waiting up to %s for the start lease, polled every %s: %v\n", wait, every, err)
			waited = true
		}
		pause := time.NewTimer(min(every, left))
		select {
		case <-stopped.Done():
			pause.Stop()
			return nil, waited, errStoppedWaiting
		case <-pause.C:
		}
	}
}

// waitingFront answers every request of the listener 503 while the start
// waits for the lease and makes its checks.
type waitingFront struct {
	listener *handoverListener
	server   *http.Server
	served   chan struct{}
}

// serveWaiting serves the waiting answer on l, which it keeps open for the
// service (handOver).
func serveWaiting(l net.Listener, every time.Duration) *waitingFront {
	h := newHandoverListener(l)
	retry := strconv.Itoa(retryAfterOf(every))
	server := listenerServer(l.Addr(), http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Retry-After", retry)
		w.Header().Set("Content-Type", "application/json")
		// no connection outlives the waiting answer, so none is closed
		// under a caller when the service takes the listener over
		w.Header().Set("Connection", "close")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write(waitingBody)
	}))
	server.WriteTimeout = openRouteWriteTimeout
	f := &waitingFront{listener: h, server: server, served: make(chan struct{})}
	view := h.view()
	go func() {
		defer close(f.served)
		_ = server.Serve(view)
	}()
	return f
}

// handOver ends the waiting answer, the requests it is answering answered
// first, and returns the listener, open: a connection made meanwhile waits
// for the next server to take it.
func (f *waitingFront) handOver() net.Listener {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := f.server.Shutdown(ctx); err != nil {
		_ = f.server.Close()
	}
	<-f.served
	return f.listener
}

// handoverListener is a listener served by one server at a time: the
// waiting answer's, then the service's. One goroutine accepts from the
// listener the start bound, and each server takes what it accepted, the
// waiting answer's through a view; a view's Close detaches its server and
// closes nothing, so a caller who connects while the service takes over is
// not refused. The listener's own Close, the service's server's, closes
// the bound listener.
type handoverListener struct {
	net.Listener
	accepted chan acceptedConn
	// back holds a connection a detached view took from accepted as it was
	// detached, for the next server; one view is ever detached
	back   chan acceptedConn
	closed chan struct{}
	once   sync.Once
}

type acceptedConn struct {
	conn net.Conn
	err  error
}

func newHandoverListener(l net.Listener) *handoverListener {
	h := &handoverListener{Listener: l, accepted: make(chan acceptedConn), back: make(chan acceptedConn, 1), closed: make(chan struct{})}
	go h.acceptLoop()
	return h
}

// acceptLoop hands each accepted connection, or each failed accept, to the
// server taking them; a server that retries a failed accept paces it.
func (h *handoverListener) acceptLoop() {
	for {
		c, err := h.Listener.Accept()
		if errors.Is(err, net.ErrClosed) {
			return
		}
		select {
		case h.accepted <- acceptedConn{c, err}:
		case <-h.closed:
			if c != nil {
				c.Close()
			}
			return
		}
	}
}

// take is the next accepted connection for a server: a view's, until it is
// detached, or the service's (detached nil). A connection that reaches a
// view as it is detached -- the two ready at once, of which select takes
// either -- is put back for the service's server, so once a view is
// detached every connection goes to the service's server.
func (h *handoverListener) take(detached <-chan struct{}) (net.Conn, error) {
	select {
	case <-detached:
		return nil, net.ErrClosed
	default:
	}
	select {
	case a := <-h.back:
		return a.conn, a.err
	case a := <-h.accepted:
		select {
		case <-detached:
			h.back <- a
			return nil, net.ErrClosed
		default:
		}
		return a.conn, a.err
	case <-h.closed:
		return nil, net.ErrClosed
	case <-detached:
		return nil, net.ErrClosed
	}
}

func (h *handoverListener) Accept() (net.Conn, error) { return h.take(nil) }

func (h *handoverListener) Close() error {
	err := net.ErrClosed
	h.once.Do(func() {
		close(h.closed)
		err = h.Listener.Close()
		select {
		case a := <-h.back:
			if a.conn != nil {
				a.conn.Close()
			}
		default:
		}
	})
	return err
}

func (h *handoverListener) view() *handoverView {
	return &handoverView{h: h, detached: make(chan struct{})}
}

// handoverView is one server's use of the listener until it is detached.
type handoverView struct {
	h        *handoverListener
	detached chan struct{}
	once     sync.Once
}

func (v *handoverView) Accept() (net.Conn, error) { return v.h.take(v.detached) }
func (v *handoverView) Addr() net.Addr            { return v.h.Addr() }
func (v *handoverView) Close() error {
	v.once.Do(func() { close(v.detached) })
	return nil
}

// drainOnStop is the stop of an instance that holds the start lease: at
// the stop signal it closes the gate for the stop, so that each acquisition
// is answered 503 with Retry-After and nothing more is admitted; it waits
// up to the drain for what was admitted to finish; and then it ends the
// service's lifetime, upon which serveOn kills the sources still running
// and waits for the requests still open, and the lease is released after
// (kindStart.stop).
func (g *gatewayService) drainOnStop(s serveStop) {
	select {
	case <-g.ctx.Done():
		return
	case <-s.stopped.Done():
	}
	if s.restore != nil {
		s.restore()
	}
	drained, pending := g.closeForStop(s.retryAfter)
	fmt.Fprintf(s.said, "stop: admitting nothing more; waiting up to %s for %d acquisitions in flight, then releasing the start lease\n", s.drain, pending)
	limit := time.NewTimer(s.drain)
	defer limit.Stop()
	select {
	case <-drained:
	case <-limit.C:
		fmt.Fprintf(s.said, "stop: the acquisitions still in flight after %s are cancelled\n", s.drain)
	case <-g.ctx.Done():
	}
	g.cancel()
}
