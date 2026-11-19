package main

// The receipt sink (engineVersion 35; ADR-0049; SPEC.md §6a): every receipt
// /acquire mints is delivered to one endpoint the configuration fixes, and
// acknowledged by it, before /acquire answers. The delivery is one POST of
// the receipt's canonical bytes, their digest and the payload's digest (the
// payload itself only where the configuration asks for it and the source
// keeps its payload); the acknowledgment is one short body naming that
// digest. A receipt the sink has not acknowledged is held, in order, and
// delivered again before anything else of its session proceeds: the next
// acquisition's source does not run, and the session is not sealed, until
// it is acknowledged. Nothing is answered to a caller that the sink has not
// acknowledged, and a refusal for it is one fixed sentence whatever went
// wrong.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"sync"
	"syscall"
	"time"
)

// receiptSinkVersion is the engine configuration version that admits
// receiptSink (ADR-0049): 35, the version after the assertion algorithm
// (34). engine.go lists it in engineVersions, so a merge that keeps another
// change's 35 without renumbering one of them does not compile.
const receiptSinkVersion = "35"

const (
	// receiptSinkAttempts is how many times one receipt is sent before the
	// acquisition is refused: the first send and two more.
	receiptSinkAttempts = 3
	// receiptSinkAttemptTimeout bounds one send whole: the connection, TLS,
	// the request, the answer's headers and its body.
	receiptSinkAttemptTimeout = 5 * time.Second
	// maxReceiptSinkAcknowledgment bounds the acknowledgment's body; one
	// longer is not read past the bound and is no acknowledgment.
	maxReceiptSinkAcknowledgment = 512
	// maxReceiptSinkURL bounds the configured url.
	maxReceiptSinkURL = 2048
	// receiptNotForwardedCode is the code the refusal carries.
	receiptNotForwardedCode = "receipt_not_forwarded"
	// receiptDeliveryVersion is the delivery request's form.
	receiptDeliveryVersion = "1"
)

// receiptSinkBackoff is the wait before the second and the third send.
var receiptSinkBackoff = []time.Duration{250 * time.Millisecond, 500 * time.Millisecond}

// receiptSinkSpec is the configuration's receiptSink member.
type receiptSinkSpec struct {
	url     string
	payload bool
}

// parseReceiptSink holds receiptSink to its form: {"url": …} with an
// optional "payload", true or false. The url is https, or plain http to a
// loopback address written as one -- 127.0.0.0/8 in dotted decimal or
// [::1] -- so that a plain-http sink is reached without a name being
// resolved. It carries no user, query or fragment. A refusal repeats no
// value it was given.
func parseReceiptSink(v value) (*receiptSinkSpec, error) {
	obj, ok := v.(*vObject)
	if !ok {
		return nil, errors.New("receiptSink is an object")
	}
	if err := exactlyMembers(obj, map[string]bool{"url": true, "payload": false}, "receiptSink"); err != nil {
		return nil, err
	}
	raw, _ := obj.get("url")
	text, ok := raw.(vString)
	if !ok || text == "" || len(text) > maxReceiptSinkURL {
		return nil, fmt.Errorf("receiptSink: url is a string of 1 to %d bytes", maxReceiptSinkURL)
	}
	if err := holdReceiptSinkURL(string(text)); err != nil {
		return nil, fmt.Errorf("receiptSink: %v", err)
	}
	spec := &receiptSinkSpec{url: string(text)}
	if value, present := obj.get("payload"); present {
		on, ok := value.(vBool)
		if !ok {
			return nil, errors.New("receiptSink: payload, when present, is true or false")
		}
		spec.payload = bool(on)
	}
	return spec, nil
}

// holdReceiptSinkURL is the url's rule.
func holdReceiptSinkURL(text string) error {
	u, err := url.Parse(text)
	if err != nil || u.Opaque != "" || u.Host == "" {
		return errors.New("url is not an absolute http or https URL")
	}
	if u.User != nil {
		return errors.New("url carries a user")
	}
	if u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawFragment != "" {
		return errors.New("url carries a query or a fragment")
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		if !receiptSinkLoopback(u.Hostname()) {
			return errors.New("url is plain http to a host that is not a loopback address written as one (127.0.0.0/8 or [::1]); plain http is accepted only there, and https everywhere")
		}
		return nil
	}
	return errors.New("url is not an absolute http or https URL")
}

// receiptSinkLoopback is a loopback address written as one: never a name,
// which a resolver could answer otherwise.
func receiptSinkLoopback(host string) bool {
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// receiptNotForwarded is the refusal of an acquisition, or of a seal, whose
// receipt the sink did not acknowledge: unreachable, past its deadline, or
// answering anything but the acknowledgment. One sentence for every cause,
// naming nothing the sink said.
type receiptNotForwarded struct{}

func (receiptNotForwarded) Error() string {
	return "receipt not forwarded: the receipt sink did not acknowledge a receipt of this session; nothing was answered, and the receipt is held to be delivered again before the session's next acquisition or seal"
}

// heldReceipt is a receipt minted and not yet acknowledged: its index in
// the session, the delivery request's bytes, and the digest the
// acknowledgment names.
type heldReceipt struct {
	index  int64
	body   []byte
	digest string
}

// forwardQueue is a session's receipts held for the sink, in index order.
// They are added under the gateway's lock in the same hold that stamps
// them, so the order is the stamp's. send is held for the whole of a
// delivery, so one delivery at a time goes to the sink for the session,
// oldest first; mu guards held alone. The lock order is the gateway's, then
// mu; send is never held beside the gateway's lock.
type forwardQueue struct {
	send sync.Mutex
	mu   sync.Mutex
	held []heldReceipt
}

func (q *forwardQueue) add(r heldReceipt) {
	q.mu.Lock()
	q.held = append(q.held, r)
	q.mu.Unlock()
}

// unacknowledged is whether the queue holds a receipt; false for none.
func (q *forwardQueue) unacknowledged() bool {
	if q == nil {
		return false
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.held) > 0
}

// receiptForwarder delivers to the configured sink.
type receiptForwarder struct {
	url            string
	payload        bool
	client         *http.Client
	attemptTimeout time.Duration
	backoff        []time.Duration
}

func newReceiptForwarder(spec *receiptSinkSpec) *receiptForwarder {
	plain := false
	if u, err := url.Parse(spec.url); err == nil && u.Scheme == "http" {
		plain = true
	}
	dialer := &net.Dialer{Timeout: receiptSinkAttemptTimeout}
	if plain {
		// held after the address is chosen too: a plain-http sink is a
		// loopback peer, whatever reached the dial
		dialer.Control = func(_, address string, _ syscall.RawConn) error {
			host, _, err := net.SplitHostPort(address)
			if err != nil || !receiptSinkLoopback(host) {
				return errors.New("a plain-http receipt sink is reached only at a loopback address")
			}
			return nil
		}
	}
	transport := &http.Transport{
		Proxy:                 nil, // no proxy from the environment
		DialContext:           dialer.DialContext,
		TLSHandshakeTimeout:   receiptSinkAttemptTimeout,
		ResponseHeaderTimeout: receiptSinkAttemptTimeout,
		MaxIdleConnsPerHost:   2,
		IdleConnTimeout:       60 * time.Second,
		ForceAttemptHTTP2:     true,
	}
	return &receiptForwarder{
		url:     spec.url,
		payload: spec.payload,
		client: &http.Client{
			Transport: transport,
			// a redirect is an answer that is not the acknowledgment
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
		attemptTimeout: receiptSinkAttemptTimeout,
		backoff:        receiptSinkBackoff,
	}
}

// receiptDigestOf is the digest a receipt is acknowledged by: SHA-256 over
// its canonical bytes, the line under receipts/ without its line feed.
func receiptDigestOf(stored *vObject) string {
	sum := sha256.Sum256(canon(stored))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// held is the receipt at index, ready for the sink: the delivery request
// {"deliveryVersion", "payload"?, "payloadDigest", "receipt",
// "receiptDigest"} in canonical form. The payload is carried only where the
// configuration asks for it and the source keeps its payload: a payload the
// gateway does not keep (ADR-0028) is not kept at the sink either.
func (f *receiptForwarder) held(index int64, stored *vObject, payloadDigest string, payload value, notRetained bool) heldReceipt {
	digest := receiptDigestOf(stored)
	request := newObject()
	request.set("deliveryVersion", vString(receiptDeliveryVersion))
	if f.payload && !notRetained {
		request.set("payload", payload)
	}
	request.set("payloadDigest", vString(payloadDigest))
	request.set("receipt", stored)
	request.set("receiptDigest", vString(digest))
	return heldReceipt{index: index, body: canon(request), digest: digest}
}

// deliver sends, oldest first, every receipt q holds up to and including
// the one at index upTo, and drops each once it is acknowledged. It stops
// at the first that is not, which stays held with every one after it, and
// is refused. A receipt another delivery has sent already is not sent
// again.
func (f *receiptForwarder) deliver(ctx context.Context, q *forwardQueue, upTo int64) error {
	if q == nil {
		return nil
	}
	q.send.Lock()
	defer q.send.Unlock()
	for {
		q.mu.Lock()
		if len(q.held) == 0 || q.held[0].index > upTo {
			q.mu.Unlock()
			return nil
		}
		next := q.held[0]
		q.mu.Unlock()
		if !f.deliverOne(ctx, next) {
			return receiptNotForwarded{}
		}
		q.mu.Lock()
		q.held = q.held[1:]
		q.mu.Unlock()
	}
}

// deliverOne sends one receipt up to receiptSinkAttempts times, waiting
// the backoff between, and reports whether it was acknowledged.
func (f *receiptForwarder) deliverOne(ctx context.Context, r heldReceipt) bool {
	for attempt := 0; attempt < receiptSinkAttempts; attempt++ {
		if attempt > 0 && attempt-1 < len(f.backoff) {
			wait := time.NewTimer(f.backoff[attempt-1])
			select {
			case <-ctx.Done():
				wait.Stop()
				return false
			case <-wait.C:
			}
		}
		if f.attempt(ctx, r) {
			return true
		}
	}
	return false
}

// attempt is one send under the per-send deadline: acknowledged only by a
// 200 whose body, read to at most maxReceiptSinkAcknowledgment bytes, is
// the acknowledgment of this receipt's digest.
func (f *receiptForwarder) attempt(parent context.Context, r heldReceipt) bool {
	ctx, cancel := context.WithTimeout(parent, f.attemptTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, f.url, bytes.NewReader(r.body))
	if err != nil {
		return false
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := f.client.Do(request)
	if err != nil {
		return false
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, maxReceiptSinkAcknowledgment+1))
	if err != nil || len(body) > maxReceiptSinkAcknowledgment || response.StatusCode != http.StatusOK {
		return false
	}
	return acknowledges(body, r.digest)
}

// acknowledges is whether body is exactly {"acknowledged":"<digest>"}, with
// at most one line feed after it.
func acknowledges(body []byte, digest string) bool {
	want := `{"acknowledged":"` + digest + `"}`
	return string(body) == want || string(body) == want+"\n"
}

// --- the service's side ---------------------------------------------------

// forwardingContext is what a delivery runs under: the service's lifetime,
// so a stop ends a delivery in flight, which is then refused.
func (g *gatewayService) forwardingContext() context.Context {
	if g.ctx != nil {
		return g.ctx
	}
	return context.Background()
}

// redeliver sends what the session holds for the sink before anything else
// of it proceeds; nil with no sink, or nothing held. The caller holds the
// session's admission and not the gateway's lock.
func (g *gatewayService) redeliver(sessionID string) error {
	if g.forwarder == nil {
		return nil
	}
	g.mu.Lock()
	var q *forwardQueue
	if state, seen := g.sessions[sessionID]; seen {
		q = state.forward
	}
	g.mu.Unlock()
	return g.forwarder.deliver(g.forwardingContext(), q, math.MaxInt64)
}

// redeliverReached is redeliver for a seal, for a session the caller
// reaches alone (ADR-0037): one it does not reach is answered by the seal
// as one the gateway does not hold, and is not delivered for.
func (g *gatewayService) redeliverReached(sessionID string, reach scopeReach) error {
	if g.forwarder == nil {
		return nil
	}
	g.mu.Lock()
	var q *forwardQueue
	if state, seen := g.sessions[sessionID]; seen && reach.holds(state.scope) {
		q = state.forward
	}
	g.mu.Unlock()
	return g.forwarder.deliver(g.forwardingContext(), q, math.MaxInt64)
}
