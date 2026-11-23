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
	"sort"
	"strconv"
	"strings"
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
	// seals is receiptSink.seals (sealSinkVersion; seal_sink.go): each seal
	// is delivered to the sink too, after the session's receipts. It is
	// implied by deliveryVersion "3".
	seals bool
	// deliveryV3 is receiptSink.deliveryVersion "3" (sinkDeliveryV3Version;
	// sink_delivery_v3.go): every delivery is a "3" envelope, and action
	// receipts are delivered too.
	deliveryV3 bool
	// refusalEntries is receiptSink.refusalEntries, valid under "3" alone
	// and true when absent there: false declines refusal entries
	// (ADR-0059 section 9, condition C11).
	refusalEntries bool
}

// parseReceiptSink holds receiptSink to its form: {"url": …} with an
// optional "payload", true or false, and from sealSinkVersion an optional
// "seals", true or false, which a file of an earlier version is refused by
// name for. From sinkDeliveryV3Version it takes "deliveryVersion", the string
// "3" alone, which implies seals and so refuses the member beside it, and,
// beside it alone, "refusalEntries", true or false (ADR-0059 section 9). The url is https, or plain http to a
// loopback address written as one -- 127.0.0.0/8 in dotted decimal or
// [::1] -- so that a plain-http sink is reached without a name being
// resolved. It carries no user, query or fragment. A refusal repeats no
// value it was given.
func parseReceiptSink(v value, version string) (*receiptSinkSpec, error) {
	obj, ok := v.(*vObject)
	if !ok {
		return nil, errors.New("receiptSink is an object")
	}
	if err := exactlyMembers(obj, map[string]bool{"url": true, "payload": false, "seals": false, "deliveryVersion": false, "refusalEntries": false}, "receiptSink"); err != nil {
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
	if value, present := obj.get("deliveryVersion"); present {
		if !versionAtLeast(version, sinkDeliveryV3Version) {
			return nil, fmt.Errorf("receiptSink: deliveryVersion is a version-%s member; engineVersion %s has no deliveryVersion", sinkDeliveryV3Version, version)
		}
		if text, ok := value.(vString); !ok || string(text) != sinkDeliveryV3 {
			return nil, errors.New(`receiptSink: deliveryVersion, when present, is the string "3"; versions "1" and "2" are chosen by its absence and by seals`)
		}
		spec.deliveryV3 = true
		// seals are always forwarded under "3", and refusal entries unless
		// declined below
		spec.seals = true
		spec.refusalEntries = true
	}
	if value, present := obj.get("refusalEntries"); present {
		if !spec.deliveryV3 {
			return nil, errors.New(`receiptSink: refusalEntries is a member of deliveryVersion "3"; a receiptSink without deliveryVersion "3" has no refusalEntries`)
		}
		on, ok := value.(vBool)
		if !ok {
			return nil, errors.New("receiptSink: refusalEntries, when present, is true or false")
		}
		spec.refusalEntries = bool(on)
	}
	if value, present := obj.get("seals"); present {
		if spec.deliveryV3 {
			return nil, errors.New(`receiptSink: seals is implied by deliveryVersion "3"`)
		}
		if !versionAtLeast(version, sealSinkVersion) {
			return nil, fmt.Errorf("receiptSink: seals is a version-%s member; engineVersion %s has no seals", sealSinkVersion, version)
		}
		on, ok := value.(vBool)
		if !ok {
			return nil, errors.New("receiptSink: seals, when present, is true or false")
		}
		spec.seals = bool(on)
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
	// seal is a seal held for the sink (seal_sink.go), at sealIndex, which
	// is refused with its own sentence; acknowledged, where set, runs once
	// the sink has acknowledged it: the seal's forwarding marker removed.
	seal         bool
	acknowledged func()
}

// refusal is the fixed sentence a delivery stopped at r is refused with.
func (r heldReceipt) refusal() error {
	if r.seal {
		return sealNotForwarded{}
	}
	return receiptNotForwarded{}
}

// forwardQueue is a session's receipts held for the sink, in index order.
// They are added under the gateway's lock in the same hold that stamps
// them, so the order is the stamp's. send is a one-place semaphore held for
// the whole of a delivery, so one delivery at a time goes to the sink for the
// session, oldest first; it is waited for under the context and one
// attempt's deadline, never without bound (see deliver). mu guards held
// alone. The lock order is the gateway's, then mu; send is never held beside
// the gateway's lock.
type forwardQueue struct {
	send chan struct{} // a token in it is a delivery in flight
	mu   sync.Mutex
	held []heldReceipt
}

func newForwardQueue() *forwardQueue {
	return &forwardQueue{send: make(chan struct{}, 1)}
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

// heldRefusal is the refusal deliver up to upTo answers while the sink
// acknowledges nothing: the sentence of the first receipt q holds, where it
// is at or below upTo; nil for none. It sends nothing and changes nothing.
// The caller may hold the gateway's lock.
func (q *forwardQueue) heldRefusal(upTo int64) error {
	if q == nil {
		return nil
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	if len(q.held) == 0 || q.held[0].index > upTo {
		return nil
	}
	return q.held[0].refusal()
}

// receiptForwarder delivers to the configured sink.
type receiptForwarder struct {
	url            string
	payload        bool
	seals          bool
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
		seals:   spec.seals,
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
// again. A delivery already in flight for the session is waited for under
// ctx and for at most one attempt's deadline: past that the caller is
// refused with the fixed sentence, so requests queued behind a sink that is
// down end together, not one after another. The sentence is the first
// held item's own (refusal): a seal waiting behind its session's seal
// delivery is refused with the seal's sentence, and the receipt's sentence
// is the answer where nothing is held.
func (f *receiptForwarder) deliver(ctx context.Context, q *forwardQueue, upTo int64) error {
	if q == nil {
		return nil
	}
	behind := func() error {
		if refused := q.refusal(); refused != nil {
			return refused
		}
		return receiptNotForwarded{}
	}
	wait := time.NewTimer(f.attemptTimeout)
	defer wait.Stop()
	select {
	case q.send <- struct{}{}:
	case <-ctx.Done():
		return behind()
	case <-wait.C:
		return behind()
	}
	defer func() { <-q.send }()
	for {
		q.mu.Lock()
		if len(q.held) == 0 || q.held[0].index > upTo {
			q.mu.Unlock()
			return nil
		}
		next := q.held[0]
		q.mu.Unlock()
		if !f.deliverOne(ctx, next) {
			return next.refusal()
		}
		q.mu.Lock()
		q.held = q.held[1:]
		q.mu.Unlock()
		if next.acknowledged != nil {
			next.acknowledged()
		}
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

// redeliver sends the receipts the session holds for the sink before
// anything else of it proceeds; nil with no sink, or nothing held. A seal
// held after them (seal_sink.go) is delivered by the session's next seal,
// not by an acquisition or an action, which its seal refuses. The caller
// holds the session's admission and not the gateway's lock.
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
	return g.forwarder.deliver(g.forwardingContext(), q, sealIndex-1)
}

// redeliverReached is redeliver for a seal, the session's held seal
// included, for a session the caller reaches alone (ADR-0037): one it does not reach is answered by the seal
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
	return g.forwarder.deliver(g.forwardingContext(), q, sealIndex)
}

// --- a session left open ----------------------------------------------------

// sealOpenSink is the receipt sink a seal after an interruption (seal-open,
// and the start's sealOpenAtStart) delivers to before it seals a session:
// a receipt held in a stopped or crashed process's memory is gone with it,
// but every receipt is in the store, so each acquisition receipt the store
// holds is delivered again, oldest first, and the sink, which keeps one receipt once
// per digest, takes one it has acknowledged before as it did.
type sealOpenSink struct {
	forwarder *receiptForwarder
	ctx       context.Context
}

// deliver sends each acquisition receipt the store holds of the session t
// names, oldest first, and reports whether the sink acknowledged them all.
// A receipt that cannot be read back is no acknowledgment either. The
// payload goes where the configuration asks for it and the store keeps one.
// A receipt of another kind, the action receipt /act stores in the same
// chain, is not delivered: the sink takes acquisition receipts alone
// (SPEC.md §6a), as the delivery before /acquire answers does.
func (s *sealOpenSink) deliver(st sealOpenStore, t sealOpenTarget) bool {
	reading, refusal, err := st.reading(t.sessionID)
	if err != nil || refusal != "" {
		return false
	}
	type stored struct {
		index int64
		bytes []byte
	}
	var all []stored
	for _, name := range reading.names {
		index, err := strconv.ParseInt(strings.TrimSuffix(name, ".json"), 10, 64)
		if err != nil {
			return false
		}
		data, err := reading.read(name)
		if err != nil {
			return false
		}
		all = append(all, stored{index, data})
	}
	sort.Slice(all, func(i, j int) bool { return all[i].index < all[j].index })
	queue := newForwardQueue()
	for _, r := range all {
		parsed, err := parseJSON(r.bytes)
		if err != nil {
			return false
		}
		receipt, ok := parsed.(*vObject)
		if !ok {
			return false
		}
		// a receipt that names no kind (versions 1 and 2) is an acquisition
		if kind, present := receipt.get("kind"); present {
			name, isString := kind.(vString)
			if !isString {
				return false
			}
			if name != "acquisition" {
				continue
			}
		}
		digest, ok := memberString(receipt, "resultDigest")
		if !ok {
			return false
		}
		notRetained := false
		if artifact, present := memberString(receipt, "artifact"); present && artifact == artifactNotRetained {
			notRetained = true
		}
		var payload value
		if s.forwarder.payload && !notRetained {
			if hexSum, ok := strings.CutPrefix(digest, "sha256:"); ok {
				if data, found, err := st.payload(t.sessionID, hexSum); err != nil {
					return false
				} else if found {
					if payload, err = parseJSON(data); err != nil {
						return false
					}
				}
			}
		}
		// a payload the store no longer holds (a removal, SPEC.md §1.3a) is
		// carried as the one a source that keeps none is: not at all
		queue.add(s.forwarder.held(r.index, receipt, digest, payload, notRetained || payload == nil))
	}
	return s.forwarder.deliver(s.ctx, queue, math.MaxInt64) == nil
}
