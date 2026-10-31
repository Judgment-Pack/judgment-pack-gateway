package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"slices"
	"time"
)

// Admission (RFC 0030 §2, "Authoritative state" and "When admission
// happens"; SPEC.md §11.5): the check made immediately before a delegated
// call is dispatched, against the bytes, the gateway's time, and the issuing
// host's state, which the gateway reads at each admission and never from a
// copy. A read that cannot be made, or answered as anything but its stated
// forms, refuses: it fails closed, as the connection custody's owner read
// does (SPEC.md §10 rule 3).

const (
	admissionTimeout        = 5 * time.Second
	maxAdmissionAnswer      = 4096
	refusalAdmissionUnknown = "admission-unknown"
	refusalStandingUnknown  = "standing-unknown"
)

// The refusals an issuing host may answer, steps 8 to 12 but the gateway's
// own (SPEC.md §11.5).
var hostRefusals = []string{"expired", "agent-unregistered", "software-mismatch", "not-issued", "revoked", "subject-mismatch", "subject-unauthorized"}

// The refusals of steps 8 to 10, which precede the gateway's own part of
// step 11.
var beforeScope = []string{"expired", "agent-unregistered", "software-mismatch", "not-issued", "revoked"}

var scopeReasons = []string{"source", "tool", "effect", "limit-unknown", "limit"}

// admissionClient makes the reads: HTTPS alone, no redirect followed, five
// seconds. roots, when not nil, replaces the system's roots (a test seam).
func admissionClient(roots *x509.CertPool) *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}
	return &http.Client{
		Timeout:   admissionTimeout,
		Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// delegatedSender is who a request on a delegated scope is, as the sender
// table authenticated it (SPEC.md §11.8): the run's actor through its
// credential, or the subject, the issuing host or an operator through a
// token. issuer and subject are the identity it authenticated as, which a
// read-back's reconciler records.
type delegatedSender struct {
	kind            string // actor, subject, host, operator
	issuer, subject string
	scope           reservationScope
	credential      *boundCredential // the actor's alone
}

// reservationScope is what a delegated action key is scoped to: the
// delegation's subject, its root actor and the issuing host, under this
// gateway's authority.
type reservationScope struct {
	sub       principalRef
	rootActor string
	host      string
}

func (s reservationScope) value() *vObject {
	v := newObject()
	v.set("sub", s.sub.value())
	v.set("rootActor", vString(s.rootActor))
	v.set("host", vString(s.host))
	return v
}

// parseReservationScope reads the /act member reservation, or a recorded
// scope.json: exactly sub, rootActor and host.
func parseReservationScope(v value) (reservationScope, bool) {
	obj, ok := exactObject(v, "sub", "rootActor", "host")
	if !ok {
		return reservationScope{}, false
	}
	subV, _ := obj.get("sub")
	sub, ok := parsePrincipalRef(subV)
	root, ok2 := memberString(obj, "rootActor")
	host, ok3 := memberString(obj, "host")
	if !ok || !ok2 || !ok3 || !isOpaqueID(root) || !isFlatTokenString(host) {
		return reservationScope{}, false
	}
	return reservationScope{sub: sub, rootActor: root, host: host}, true
}

// reconcilerMember is the sender a read-back records (SPEC.md §11.7).
func (s *delegatedSender) reconcilerMember() *vObject {
	v := newObject()
	v.set("kind", vString(s.kind))
	v.set("issuer", vString(s.issuer))
	v.set("subject", vString(s.subject))
	return v
}

// delegationMember is the receipt's delegation member for a call admitted at
// t (SPEC.md §11.7).
func (c *delegationChain) delegationMember(t time.Time) *vObject {
	leaf := c.leaf()
	v := newObject()
	v.set("id", vString(leaf.id))
	v.set("host", vString(leaf.host))
	v.set("actor", vString(leaf.agent))
	v.set("subject", leaf.sub.value())
	v.set("chain", c.digests())
	v.set("admittedAt", vString(delegationTime(t)))
	return v
}

// delegatedCall is one call's scope as admission reads it.
type delegatedCall struct {
	source, tool, effect string
	count                bool
}

// post makes one read to a host: the body in canon, the host's credential,
// and an answer of 200 within maxAdmissionAnswer bytes that the canon parser
// reads as an object, or nil.
func (d *delegationService) post(host *delegationHost, body *vObject) *vObject {
	req, err := http.NewRequest(http.MethodPost, host.admission, bytes.NewReader(canon(body)))
	if err != nil {
		return nil
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+host.bearer)
	resp, err := d.client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK || resp.Request == nil || resp.Request.URL.Scheme != "https" {
		return nil
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxAdmissionAnswer+1))
	if err != nil || len(data) > maxAdmissionAnswer {
		return nil
	}
	v, err := parseJSON(data)
	if err != nil {
		return nil
	}
	obj, _ := v.(*vObject)
	return obj
}

// readBody is the body common to the two reads.
func (d *delegationService) readBody(host *delegationHost, audience string) *vObject {
	body := newObject()
	body.set("readVersion", vString("1"))
	body.set("host", vString(host.host))
	a := newObject()
	a.set("kind", vString("gateway"))
	a.set("name", vString(audience))
	body.set("audience", a)
	return body
}

// admissionReadAt is the admission read for a chain at time t, naming the
// call, or none for a binding: nil when the host admits, the host's refusal
// otherwise, and admission-unknown for anything else.
func (d *delegationService) admissionReadAt(host *delegationHost, audience string, chain *delegationChain, call *delegatedCall, t time.Time) *delegationRefusal {
	body := d.readBody(host, audience)
	body.set("chain", chain.digests())
	if call == nil {
		body.set("call", vNull{})
	} else {
		c := newObject()
		c.set("source", vString(call.source))
		c.set("tool", vString(call.tool))
		c.set("effect", vString(call.effect))
		c.set("count", vBool(call.count))
		body.set("call", c)
	}
	body.set("at", vString(delegationTime(t)))
	unknown := refuse(refusalAdmissionUnknown, "the issuing host's admission could not be read")
	answer := d.post(host, body)
	if answer == nil {
		return unknown
	}
	verdict, _ := memberString(answer, "admission")
	switch {
	case verdict == "admit" && len(answer.byName) == 1:
		return nil
	case verdict != "refuse":
		return unknown
	}
	refusal, _ := memberString(answer, "refusal")
	if refusal == refusalOutOfScope && call != nil {
		reason, _ := memberString(answer, "reason")
		if len(answer.byName) != 3 || !slices.Contains(scopeReasons, reason) {
			return unknown
		}
		return &delegationRefusal{name: refusalOutOfScope, scopeReason: reason, reason: "the issuing host answers that the call is outside the scope (" + reason + ")"}
	}
	if len(answer.byName) != 2 || !slices.Contains(hostRefusals, refusal) {
		return unknown
	}
	return refuse(refusal, "the issuing host answers %s", refusal)
}

// admissionRead is admissionReadAt for the audience the binding's chain is
// held under: the gateway's own authority, which bind is given.
func (d *delegationService) admissionRead(host *delegationHost, chain *delegationChain, call *delegatedCall, t time.Time) *delegationRefusal {
	return d.admissionReadAt(host, d.audience, chain, call, t)
}

// standingRead asks the issuing host whether a subject is still a current
// principal (SPEC.md §11.8, spec #284 NC5): "current", "removed", or "" for
// anything else.
func (d *delegationService) standingRead(host *delegationHost, sub principalRef) string {
	body := d.readBody(host, d.audience)
	body.set("standing", sub.value())
	answer := d.post(host, body)
	if answer == nil || len(answer.byName) != 1 {
		return ""
	}
	standing, _ := memberString(answer, "standing")
	if standing != "current" && standing != "removed" {
		return ""
	}
	return standing
}

// admitDelegated admits one call dispatched by the run's actor immediately
// before it is dispatched (SPEC.md §11.5), and answers the receipt's
// delegation member. count is false only where the call will not be
// dispatched.
func (d *delegationService) admitDelegated(s *delegatedSender, call delegatedCall) (*vObject, *delegationRefusal) {
	if s == nil || s.kind != "actor" || s.credential == nil {
		return nil, refuse(refusalActorOnly, "only the run's actor dispatches under a delegation")
	}
	t := d.now().UTC().Truncate(time.Millisecond)
	// Step 0 again: a revocation, or the expiry, may have landed since the
	// request was authenticated.
	if !d.live(s.credential, t) {
		return nil, refuse(refusalCredentialMismatch, "the credential is no longer live at this gateway")
	}
	// Steps 1 to 7 again, on the bound bytes and the keys pinned now.
	chainV, err := parseJSON(s.credential.chain.canonical)
	if err != nil {
		return nil, refuse(refusalMalformed, "the bound chain cannot be read")
	}
	chain, refusal := verifyDelegationChain(chainV, d.keys)
	if refusal != nil {
		return nil, refusal
	}
	if r := chain.timeRefusal(t); r != nil {
		return nil, r
	}
	host := d.hosts[s.credential.host]
	if host == nil {
		return nil, refuse(refusalCredentialMismatch, "the credential's host is no longer configured")
	}
	own := chain.scopeRefusal(d.audience, call.source, call.tool, call.effect)
	call.count = call.count && own == nil
	answer := d.admissionReadAt(host, d.audience, chain, &call, t)
	switch {
	case answer != nil && slices.Contains(beforeScope, answer.name):
		return nil, answer
	case answer != nil && answer.name == refusalAdmissionUnknown:
		return nil, answer
	case own != nil:
		return nil, own
	case answer != nil:
		return nil, answer
	}
	return chain.delegationMember(t), nil
}

// senderFor is the sender table's row for a request on a delegated scope
// made with a token (SPEC.md §11.8): the subject, the issuing host or an
// operator, in that order, or nil, which refuses as
// action-key-unauthenticated. The subject's row reads its standing.
func (d *delegationService) senderFor(who *caller, scope reservationScope) (*delegatedSender, *delegationRefusal) {
	unauthenticated := refuse(refusalKeyUnauthenticated, "")
	host := d.hosts[scope.host]
	if who == nil || who.delegated != nil || host == nil {
		return nil, unauthenticated
	}
	sender := &delegatedSender{issuer: who.issuer, subject: who.subject, scope: scope}
	switch {
	case who.issuer == scope.sub.issuer && who.subject == scope.sub.subject:
		switch d.standingRead(host, scope.sub) {
		case "current":
		case "removed":
			return nil, unauthenticated
		default:
			return nil, refuse(refusalStandingUnknown, "the issuing host's standing for the subject could not be read")
		}
		sender.kind = "subject"
	case who.subject == host.requester:
		sender.kind = "host"
	case d.operators[who.subject]:
		sender.kind = "operator"
	default:
		return nil, unauthenticated
	}
	return sender, nil
}

// attachDelegation makes the service the enforcing host of delegated calls
// under d, its audience the gateway's authority; nil leaves it as it was.
func (g *gatewayService) attachDelegation(d *delegationService) {
	if d == nil {
		return
	}
	d.audience = g.authority
	g.delegation = d
}

// The action-key refusals of the sender table (SPEC.md §11.8).
const (
	refusalKeyUnauthenticated = "action-key-unauthenticated"
	refusalActorOnly          = "action-key-actor-only"
)
