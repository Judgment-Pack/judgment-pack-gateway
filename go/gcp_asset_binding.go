package main

// A binding's live operation of the gcp-asset shape (engineVersion 29,
// gateway #488, docs/adr/0039-a-read-only-asset-inventory-connection-for-configuration-drift.md
// and its Amendment): the engine derives `<platform>/live` as
// adapter-gcp-asset, the read-only Cloud Asset Inventory adapter, started
// as every engine source is, and receipted as an http source is, since its
// envelope is that shape's: one list call per acquisition, its page
// projected, and the caller's to page. The adapter obtains its own two
// narrow tokens, holds each to the scopes it was granted, and runs the
// write check; the signer holds the list token as the adapter sealed it,
// as for a token step, and reads none of it.
//
// What the signer adds is the order and the closure. A request is held to
// the configured parents, content types and asset types before any token
// is obtained for it, after the caller's reach to the source's scope
// identifier (acquisitionHeld). The check runs at the start, before
// anything is served, and again with every token obtained after it, before
// that token is used. A read-only refusal -- at the start, on a refresh, or
// on a page that binds the source's own principal at a resource -- closes
// the source for every request after it, and the start, the engine's
// stderr and /posture say so; a closed source serves nothing until the
// engine restarts. A check that could not finish -- a call of it brought
// back no answer, because the adapter's own time or the request's ended or
// the connection failed -- is no refusal: the adapter exits 1, which fails
// that start or refresh and closes nothing. The adapter is handed its time
// as --timeout: what is left of the acquisition's, less a margin for its
// start and its report.

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// The shape, its adapter and what the adapter is handed.
const (
	gcpAssetShape   = "gcp-asset"
	gcpAssetAdapter = "adapter-gcp-asset"
	// gcpAssetSealedTokenVariable is the variable an acquisition is handed
	// the sealed list token in (adapters/gcpasset, SealedTokenVariable). A
	// platform of the shape may not set it in its environment.
	gcpAssetSealedTokenVariable = "ADAPTER_GCP_ASSET_SEALED_TOKEN"
)

// The members of a gcp-asset operation, and their values.
const (
	// artifactRetained is the artifact a platform of the shape gives to
	// keep its payloads, which it does not keep by default (decision 5).
	artifactRetained         = "retained"
	gcpAssetContentResource  = "RESOURCE"
	gcpAssetContentIAMPolicy = "IAM_POLICY"
	gcpAssetCountUsers       = "count-users"
	// maxGCPAssetParents and maxGCPAssetTypes are the adapter's bounds
	// (adapters/gcpasset, maxParents and maxAssetTypes).
	maxGCPAssetParents = 64
	maxGCPAssetTypes   = 32
	// The adapter's request bounds (adapters/gcpasset, ParseRequest).
	maxGCPAssetPageToken = 8192
	maxGCPAssetPageSize  = 1000
	// gcpAssetRunMargin is what of the acquisition's time the adapter is
	// not handed, at most: the margin for its start and its report, so it
	// ends its own run before the signer would kill it.
	gcpAssetRunMargin = 5 * time.Second
)

// The token sources a platform's credentials.live.tokenSource names
// (Amendment A3). Federation is not among them: the impersonation call it
// rests on grants no scope narrower than cloud-platform, which A2 never
// requests.
const (
	gcpAssetTokenMetadata = "metadata"
	gcpAssetTokenKey      = "key"
)

// The read-only refusals (decision 3, Amendment A2), by the names the
// adapter reports them under; sourceExitRefused is the status it reports
// one by (adapters/gcpasset, RefusedStatus).
const (
	sourceExitRefused            = 9
	refusalCredentialScope       = "credential-scope-unknown"
	refusalCredentialCanWrite    = "credential-can-write"
	refusalCredentialBoundAtRsrc = "credential-bound-at-resource"
	// maxRefusalReport bounds the report the signer reads beside status 9;
	// maxRefusalSubject the subject in it (adapters/gcpasset, maxSubject).
	maxRefusalReport  = 4096
	maxRefusalSubject = 1024
)

var (
	gcpAssetProjectForm   = regexp.MustCompile(`^projects/[a-z][a-z0-9-]{4,28}[a-z0-9]$`)
	gcpAssetFolderForm    = regexp.MustCompile(`^folders/[0-9]+$`)
	gcpAssetTypeForm      = regexp.MustCompile(`^[a-z][a-z0-9-]*(\.[a-z][a-z0-9-]*)*\.googleapis\.com/[A-Z][A-Za-z0-9]*$`)
	gcpAssetPageTokenForm = regexp.MustCompile(`^[\x21-\x7e]+$`)
)

// gcpAssetOperation is a live operation of the gcp-asset shape as the
// binding fixes it. Nothing here is a secret.
type gcpAssetOperation struct {
	// parents are the projects a request may name, each
	// projects/<project-id>; a folder waits for gateway #489.
	parents []string
	// assetTypes are the asset types a request may name, an explicit list;
	// the adapter refuses at the start one it has no projection for.
	assetTypes []string
	// contentTypes are RESOURCE, IAM_POLICY or both.
	contentTypes []string
	// countUsers is members: "count-users", off when absent.
	countUsers bool
}

var gcpAssetOperationMembers = map[string]bool{
	"shape": true, "licence": true, "parents": true, "assetTypes": true, "contentTypes": true, "members": false,
}

// parseGCPAssetOperation holds a gcp-asset operation to its shape: exactly
// the members above; parents each projects/<project-id>, a folder refused
// by name; asset types each of the platform's form; content types among
// RESOURCE and IAM_POLICY; each list without a repeat, and none with a
// comma, which the adapter's command line would split; members, when
// present, "count-users". A binding of the shape names no write, no
// endpoint and no tool, so it has none of those members to give. A refusal
// names the member by its place and repeats no value.
func parseGCPAssetOperation(op *vObject, name string, o *operation) error {
	if err := exactlyMembers(op, gcpAssetOperationMembers, "operation "+name); err != nil {
		return err
	}
	g := &gcpAssetOperation{}
	var err error
	if g.parents, err = httpStrings(op, "parents", name, maxGCPAssetParents); err != nil {
		return err
	}
	for i, parent := range g.parents {
		switch {
		case gcpAssetFolderForm.MatchString(parent):
			return fmt.Errorf("operation %s: parents[%d] is a folder, and this version reads projects only, each projects/<project-id>", name, i)
		case !gcpAssetProjectForm.MatchString(parent):
			return fmt.Errorf("operation %s: parents[%d] is not projects/<project-id>", name, i)
		case contains(g.parents[:i], parent):
			return fmt.Errorf("operation %s: parents[%d] repeats an earlier parent", name, i)
		}
	}
	if g.assetTypes, err = httpStrings(op, "assetTypes", name, maxGCPAssetTypes); err != nil {
		return err
	}
	for i, t := range g.assetTypes {
		switch {
		case !gcpAssetTypeForm.MatchString(t):
			return fmt.Errorf("operation %s: assetTypes[%d] is not an asset type, <service>.googleapis.com/<Kind>, and no pattern stands for one", name, i)
		case contains(g.assetTypes[:i], t):
			return fmt.Errorf("operation %s: assetTypes[%d] repeats an earlier asset type", name, i)
		}
	}
	if g.contentTypes, err = httpStrings(op, "contentTypes", name, 2); err != nil {
		return err
	}
	for i, c := range g.contentTypes {
		switch {
		case c != gcpAssetContentResource && c != gcpAssetContentIAMPolicy:
			return fmt.Errorf("operation %s: contentTypes[%d] is neither %s nor %s", name, i, gcpAssetContentResource, gcpAssetContentIAMPolicy)
		case contains(g.contentTypes[:i], c):
			return fmt.Errorf("operation %s: contentTypes[%d] repeats an earlier content type", name, i)
		}
	}
	if _, present := op.get("members"); present {
		if s, ok := memberString(op, "members"); !ok || s != gcpAssetCountUsers {
			return fmt.Errorf("operation %s: members, when present, is %q; absent, a binding's members are carried as written", name, gcpAssetCountUsers)
		}
		g.countUsers = true
	}
	o.gcpAsset = g
	return nil
}

// serves is whether the operation serves the content type.
func (g gcpAssetOperation) serves(contentType string) bool {
	return contains(g.contentTypes, contentType)
}

// parseGCPAssetTokenSource reads credentials.<op>.tokenSource: a
// version-29 member of the live operation's credentials alone, an object
// of exactly kind, "metadata" or "key". A refusal names the member and
// repeats no value.
func parseGCPAssetTokenSource(v value, name, op, version string) (string, error) {
	where := "engine configuration: platform " + name + ": credentials." + op + ".tokenSource"
	if !versionAtLeast(version, "29") {
		return "", fmt.Errorf("%s is a version-29 member; engineVersion %s has no tokenSource", where, version)
	}
	if op != "live" {
		return "", fmt.Errorf("%s: a token source is a live operation's of the gcp-asset shape alone", where)
	}
	obj, err := requireObject(v, "tokenSource")
	if err != nil {
		return "", fmt.Errorf("%s: %v", where, err)
	}
	if err := exactlyMembers(obj, map[string]bool{"kind": true}, "platform "+name+" credentials."+op+".tokenSource"); err != nil {
		return "", err
	}
	kind, ok := memberString(obj, "kind")
	if !ok || (kind != gcpAssetTokenMetadata && kind != gcpAssetTokenKey) {
		return "", fmt.Errorf("%s: kind is %q, the metadata server of the platform's own compute, or %q, a service account's key in the live credentials file", where, gcpAssetTokenMetadata, gcpAssetTokenKey)
	}
	return kind, nil
}

// gcpAssetPlatformMatch holds a platform to its binding where either is of
// the gcp-asset shape: the shape is a version-29 one; its platform names a
// token source, and only its platform does; it names no grant, since an
// acquisition names no tool; no endpoint, since the adapter fixes the
// platform's; no write, since the binding has none and a read-only source
// would read as one that writes; and artifact "retained", which keeps the
// payloads the shape does not keep by default, only on a platform of the
// shape.
func gcpAssetPlatformMatch(p platformConfig, b binding, version string) error {
	if b.live == nil || b.live.gcpAsset == nil {
		if p.tokenSource != "" {
			return fmt.Errorf("credentials.live names a tokenSource, and binding %s's live operation is not of the gcp-asset shape, which alone takes one", p.binding)
		}
		if p.artifactRetained {
			return fmt.Errorf("artifact %q keeps the payloads a platform of the gcp-asset shape does not keep by default, and binding %s is not of that shape; a platform that keeps its payloads gives no artifact", artifactRetained, p.binding)
		}
		return nil
	}
	if !versionAtLeast(version, "29") {
		return fmt.Errorf("binding %s serves live by the gcp-asset shape, a version-29 shape; engineVersion %s has none", p.binding, version)
	}
	if p.write {
		return fmt.Errorf("sets write: true, and binding %s serves live by the gcp-asset shape, a read-only source with no write operation; remove write: true", p.binding)
	}
	if p.tokenSource == "" {
		return fmt.Errorf("binding %s serves live by the gcp-asset shape, and credentials.live names no tokenSource: {\"kind\": %q} or {\"kind\": %q}", p.binding, gcpAssetTokenMetadata, gcpAssetTokenKey)
	}
	if p.tokenStep != nil {
		return fmt.Errorf("credentials.live names a tokenStep, and binding %s serves live by the gcp-asset shape, whose adapter obtains its own tokens (tokenSource)", p.binding)
	}
	if p.grant != nil {
		return fmt.Errorf("names a grant, and binding %s serves live by the gcp-asset shape, whose acquisitions name no tool, so a delegation's scope admits none and the grant would admit nothing; remove grant", p.binding)
	}
	if p.endpoint != "" {
		return fmt.Errorf("names an endpoint, and binding %s serves live by the gcp-asset shape, whose endpoints the adapter fixes; remove endpoint", p.binding)
	}
	return nil
}

// gcpAssetSourceArgv is adapter-gcp-asset's command line, each flag and
// its value one word: the configured parents, asset types and content
// types, the member reduction where the binding asks for it, the
// platform's credentials file for live and the token source.
func gcpAssetSourceArgv(adapter string, op gcpAssetOperation, credentials, tokenSource string) []string {
	argv := []string{adapter, "--parents=" + strings.Join(op.parents, ","), "--asset-types=" + strings.Join(op.assetTypes, ","),
		"--content-types=" + strings.Join(op.contentTypes, ",")}
	if op.countUsers {
		argv = append(argv, "--members="+gcpAssetCountUsers)
	}
	return append(argv, "--credentials="+credentials, "--token-source="+tokenSource)
}

// gcpAssetSource is what the signer holds of a gcp-asset source while the
// engine runs: the configured set a request is held to, and whether the
// source serves. One is made per derived source and shared by every copy
// of its sourceSpec.
type gcpAssetSource struct {
	op          gcpAssetOperation
	tokenSource string
	// retained is artifact "retained": the operator keeps the payloads.
	retained bool

	mu sync.Mutex
	// checked is whether the start's check passed; checks counts the
	// checks that passed, the start's and each refresh's.
	checked bool
	checks  int
	// closed is the refusal that closed the source, nil while it serves.
	closed *readOnlyRefusal
}

func newGCPAssetSource(op gcpAssetOperation, tokenSource string, retained bool) *gcpAssetSource {
	return &gcpAssetSource{op: op, tokenSource: tokenSource, retained: retained}
}

// readOnlyRefusal is a read-only refusal as the adapter reported it: one of
// the three reasons, or "" for a report out of its form, which refuses all
// the same; the subject, "" where there is none; and where it was met,
// "start", "refresh" or "page".
type readOnlyRefusal struct {
	reason, subject, on string
}

// sentence is the refusal for a reader: the reason, and the subject
// quoted as text from outside is. Nothing else: no token, no digest of one
// and no part of one is ever in a report.
func (r readOnlyRefusal) sentence() string {
	subject := fmt.Sprintf("%q", requestText(r.subject))
	switch {
	case r.reason == refusalCredentialCanWrite && r.subject != "":
		return refusalCredentialCanWrite + ": the credential holds " + subject + ", a write permission, on a configured project"
	case r.reason == refusalCredentialCanWrite:
		return refusalCredentialCanWrite + ": the platform answered the write check with neither a grant nor none, and a credential not shown to be read-only is refused"
	case r.reason == refusalCredentialScope:
		return refusalCredentialScope + ": the scopes a token was granted could not be shown to be the one requested alone"
	case r.reason == refusalCredentialBoundAtRsrc && r.subject != "":
		return refusalCredentialBoundAtRsrc + ": " + subject + " binds the source's own principal, or allUsers or allAuthenticatedUsers, to a role outside the read-only list"
	case r.reason == refusalCredentialBoundAtRsrc:
		return refusalCredentialBoundAtRsrc + ": a page bound the source's own principal, or allUsers or allAuthenticatedUsers, to a role outside the read-only list"
	}
	return "the adapter refused the credential as not read-only, and its report of why was out of its form"
}

// gcpAssetRefusedRun is a run of a gcp-asset source that exited with
// sourceExitRefused: the refusal its report gave, the reason "" where the
// report was out of its form, missing or past its bound.
type gcpAssetRefusedRun struct {
	refusal readOnlyRefusal
	failed  error
}

func (e *gcpAssetRefusedRun) Error() string { return "source failed: " + e.refusal.sentence() }

// sourceClosed is an acquisition of a gcp-asset source refused because a
// read-only refusal closed the source, by this acquisition or before it.
type sourceClosed struct {
	source  string
	refusal readOnlyRefusal
}

func (e *sourceClosed) Error() string {
	return fmt.Sprintf("source %s is closed: %s; it serves no request until the engine restarts, and nothing was retained or minted", e.source, e.refusal.sentence())
}

// readOnlyRefusalReport reads adapter-gcp-asset's stdout beside
// sourceExitRefused: exactly {"refused": {"reason": R, "subject": S}}, R
// one of the three refusals and S null or a string of at most
// maxRefusalSubject printable ASCII bytes, the whole at most
// maxRefusalReport bytes with nothing before or after it. Anything else is
// a refusal all the same, of no stated reason: status 9 is the adapter
// refusing the credential, and a report that does not say why does not
// make it read-only.
func readOnlyRefusalReport(stdout []byte) readOnlyRefusal {
	unstated := readOnlyRefusal{}
	if len(stdout) == 0 || len(stdout) > maxRefusalReport || isJSONSpace(stdout[0]) || isJSONSpace(stdout[len(stdout)-1]) {
		return unstated
	}
	v, err := parseJSON(stdout)
	if err != nil {
		return unstated
	}
	outer, ok := v.(*vObject)
	if !ok || exactlyMembers(outer, map[string]bool{"refused": true}, "refusal report") != nil {
		return unstated
	}
	raw, _ := outer.get("refused")
	report, ok := raw.(*vObject)
	if !ok || exactlyMembers(report, map[string]bool{"reason": true, "subject": true}, "refusal report") != nil {
		return unstated
	}
	reason, ok := memberString(report, "reason")
	if !ok || (reason != refusalCredentialScope && reason != refusalCredentialCanWrite && reason != refusalCredentialBoundAtRsrc) {
		return unstated
	}
	r := readOnlyRefusal{reason: reason}
	switch subject, _ := report.get("subject"); s := subject.(type) {
	case vNull:
	case vString:
		if s == "" || len(s) > maxRefusalSubject || !printableASCII(string(s)) {
			return unstated
		}
		r.subject = string(s)
	default:
		return unstated
	}
	return r
}

// refusedIfClosed is the closure's refusal, nil while the source serves.
func (s *gcpAssetSource) refusedIfClosed(source string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed != nil {
		return &sourceClosed{source: source, refusal: *s.closed}
	}
	return nil
}

// close closes the source with the refusal met on, the first refusal
// alone kept, and says the closure on the engine's stderr once, unless it
// is the start's, which the start says. What it returns is the
// acquisition's refusal.
func (g *gatewayService) closeGCPAsset(source string, s *gcpAssetSource, r readOnlyRefusal, on string) error {
	s.mu.Lock()
	first := s.closed == nil
	if first {
		r.on = on
		s.closed = &r
	}
	closed := *s.closed
	s.mu.Unlock()
	if first && on != "start" {
		g.reports.controlf("serve: source %s closed on a %s: %s", source, on, closed.sentence())
	}
	return &sourceClosed{source: source, refusal: closed}
}

// gcpAssetToken obtains the source's sealed list token by the adapter's
// --token-only, which answers one only once both tokens are held to their
// scopes and the write check found no write permission on any configured
// project: the check, met on the start or on a refresh. A refusal closes
// the source; a check that passed is counted; a check that could not
// finish (status 1), or any other failure, fails this token alone.
func (g *gatewayService) gcpAssetToken(ctx context.Context, timeout time.Duration, source string, spec sourceSpec, on string) (string, int, error) {
	sealed, expiresIn, err := g.obtainToken(ctx, timeout, source, gcpAssetTimed(ctx, timeout, spec))
	var refused *gcpAssetRefusedRun
	if errors.As(err, &refused) {
		return "", 0, g.closeGCPAsset(source, spec.gcpAsset, refused.refusal, on)
	}
	if err == nil {
		spec.gcpAsset.mu.Lock()
		spec.gcpAsset.checks++
		spec.gcpAsset.mu.Unlock()
	}
	return sealed, expiresIn, err
}

// gcpAssetTimed is spec with --timeout appended to its command line: the
// time left on ctx -- the source's timeout where ctx has no deadline --
// less gcpAssetRunMargin, or less half the time left where half is the
// smaller. The adapter
// then ends a check it cannot complete itself, and says so (status 1),
// rather than being killed before it can; its own default is shorter than
// the signer's timeout, and too short for the most projects it is given.
func gcpAssetTimed(ctx context.Context, timeout time.Duration, spec sourceSpec) sourceSpec {
	left := timeout
	if deadline, ok := ctx.Deadline(); ok {
		left = time.Until(deadline)
	}
	run := max((left - min(gcpAssetRunMargin, left/2)).Truncate(time.Millisecond), time.Millisecond)
	timed := spec
	timed.argv = append(append([]string(nil), spec.argv...), "--timeout="+run.String())
	return timed
}

// The refusals of a request before any token is obtained for it, each one
// fixed sentence; the parent's names the parent the request gave, the
// caller's own text, quoted as such text is.
const (
	errGCPAssetParentNotConfigured = "source %s: parent-not-configured: %q is not a parent this source serves; no token was requested"
	errGCPAssetRequestNotAdmitted  = "source %s: the request is not one this source takes: %s; no token was requested"
)

var gcpAssetRequestMembers = map[string]bool{"parent": true, "contentType": true, "assetTypes": true, "pageToken": false, "pageSize": false, "readTime": false}

// gcpAssetAdmits holds a request to the source's form and configuration, as
// the adapter holds it, before any token is obtained for it, so a request
// the adapter would refuse costs the platform no token and no write check:
// an object of the members above; the parent first, among the configured
// ones (parent-not-configured); then the content type and the asset types,
// each among the configured ones and none twice; a page token null or of
// the adapter's form; a page size from 1 to its bound; a read time in
// RFC 3339.
func gcpAssetAdmits(source string, op gcpAssetOperation, stdin []byte) error {
	refused := func(why string) error { return fmt.Errorf(errGCPAssetRequestNotAdmitted, source, why) }
	args, err := parseJSON(stdin)
	if err != nil {
		return refused("not one JSON value in the canonical domain")
	}
	request, ok := args.(*vObject)
	if !ok {
		return refused("not an object")
	}
	if err := exactlyMembers(request, gcpAssetRequestMembers, "request"); err != nil {
		return refused(err.Error())
	}
	parent, ok := memberString(request, "parent")
	if !ok {
		return refused("parent must be a string")
	}
	if !contains(op.parents, parent) {
		return fmt.Errorf(errGCPAssetParentNotConfigured, source, requestText(parent))
	}
	contentType, ok := memberString(request, "contentType")
	if !ok || !op.serves(contentType) {
		return refused("contentType is not one this source serves")
	}
	raw, _ := request.get("assetTypes")
	types, ok := raw.(vArray)
	if !ok || len(types) == 0 || len(types) > maxGCPAssetTypes {
		return refused(fmt.Sprintf("assetTypes must be an array of 1 to %d strings", maxGCPAssetTypes))
	}
	seen := map[vString]bool{}
	for i, item := range types {
		t, ok := item.(vString)
		if !ok || !contains(op.assetTypes, string(t)) {
			return refused(fmt.Sprintf("assetTypes[%d] is not one this source serves", i))
		}
		if seen[t] {
			return refused(fmt.Sprintf("assetTypes[%d] repeats an earlier asset type", i))
		}
		seen[t] = true
	}
	if raw, present := request.get("pageToken"); present {
		if _, isNull := raw.(vNull); !isNull {
			token, ok := raw.(vString)
			if !ok || len(token) > maxGCPAssetPageToken || !gcpAssetPageTokenForm.MatchString(string(token)) {
				return refused(fmt.Sprintf("pageToken must be null or a string of 1 to %d printable ASCII characters without spaces", maxGCPAssetPageToken))
			}
		}
	}
	if raw, present := request.get("pageSize"); present {
		if n, ok := raw.(vInt); !ok || n < 1 || n > maxGCPAssetPageSize {
			return refused(fmt.Sprintf("pageSize must be an integer from 1 to %d", maxGCPAssetPageSize))
		}
	}
	if raw, present := request.get("readTime"); present {
		s, ok := raw.(vString)
		if !ok || len(s) > 64 {
			return refused("readTime must be an RFC 3339 timestamp")
		}
		if _, err := time.Parse(time.RFC3339Nano, string(s)); err != nil {
			return refused("readTime must be an RFC 3339 timestamp")
		}
	}
	return nil
}

// runGCPAssetSource runs an acquisition of a gcp-asset source: refused
// while the source is closed; held to the source's form and configuration
// before any token is obtained; then handed the sealed list token -- the
// one held, or one --token-only obtains, which is the refresh's check --
// and run once, as a token step's acquisition is, its token failures read
// as that step reads them. A read-only refusal, of the token's check or of
// the page, closes the source, and the acquisition is refused with it.
func (g *gatewayService) runGCPAssetSource(source string, spec sourceSpec, stdin []byte) (value, string, string, error) {
	s := spec.gcpAsset
	if err := s.refusedIfClosed(source); err != nil {
		return nil, "", "", err
	}
	if err := gcpAssetAdmits(source, s.op, stdin); err != nil {
		return nil, "", "", err
	}
	ctx, timeout, cancel := g.sourceRunContext(source, spec)
	defer cancel()
	key := tokenKey{source: source, scope: spec.scope}
	for attempt := 0; ; attempt++ {
		sealed, err := g.tokens.obtain(ctx, key, func() (string, int, error) { return g.gcpAssetToken(ctx, timeout, source, spec, "refresh") })
		if err != nil {
			if ctx.Err() != nil && errors.Is(err, ctx.Err()) {
				err = acquisitionEnded(ctx, timeout)
			}
			return nil, "", "", err
		}
		// A refusal met by another acquisition's refresh while this one
		// held a token closes the source for this one too.
		if err := s.refusedIfClosed(source); err != nil {
			return nil, "", "", err
		}
		run := gcpAssetTimed(ctx, timeout, spec)
		run.env = append(append([]string(nil), spec.env...), gcpAssetSealedTokenVariable+"="+sealed)
		result, digest, observedAt, err := g.runOnce(ctx, timeout, source, run, stdin)
		var refused *gcpAssetRefusedRun
		if errors.As(err, &refused) {
			g.tokens.drop(key, sealed)
			return nil, "", "", g.closeGCPAsset(source, s, refused.refusal, "page")
		}
		switch exitCodeOf(err) {
		case tokenExitRejectedBySource:
			g.tokens.drop(key, sealed)
			return nil, "", "", fmt.Errorf(errTokenRejected, source)
		case tokenExitSealUnusable:
			g.tokens.drop(key, sealed)
			if attempt == 0 {
				continue
			}
			return nil, "", "", fmt.Errorf(errTokenRefused, source)
		case tokenExitNoCredential:
			g.tokens.drop(key, sealed)
			return nil, "", "", fmt.Errorf(errTokenNoCredential, source)
		case tokenExitRefused:
			g.tokens.drop(key, sealed)
			return nil, "", "", fmt.Errorf(errTokenRefused, source)
		}
		return result, digest, observedAt, err
	}
}

// gcpAssetSourceNames are the gcp-asset sources, in name order.
func gcpAssetSourceNames(sources map[string]sourceSpec) []string {
	var names []string
	for name, spec := range sources {
		if spec.gcpAsset != nil {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names
}

// gcpAssetStart is the start's check of every gcp-asset source, in name
// order, before anything is served: a sealed list token obtained, which
// the adapter answers only once both tokens are held to their scopes and
// the write check found no write permission on any configured project,
// and held for the first acquisition. A refusal, or a check that did not
// complete, refuses the start, said by name; a source that passed has its
// lines said on said.
func (g *gatewayService) gcpAssetStart(said io.Writer) error {
	for _, name := range gcpAssetSourceNames(g.sources) {
		spec := g.sources[name]
		ctx, timeout, cancel := g.sourceRunContext(name, spec)
		_, err := g.tokens.obtain(ctx, tokenKey{source: name, scope: spec.scope}, func() (string, int, error) {
			return g.gcpAssetToken(ctx, timeout, name, spec, "start")
		})
		cancel()
		var closed *sourceClosed
		switch {
		case errors.As(err, &closed):
			return fmt.Errorf("source %s: %s; the engine does not start with a source whose credential is not shown to be read-only", name, closed.refusal.sentence())
		case err != nil:
			return fmt.Errorf("source %s: the read-only check did not complete: %v; the engine does not start with a source whose credential is not shown to be read-only", name, err)
		}
		spec.gcpAsset.mu.Lock()
		spec.gcpAsset.checked = true
		spec.gcpAsset.mu.Unlock()
		for _, line := range gcpAssetStartLines(name, spec) {
			fmt.Fprintln(said, "start:", line)
		}
	}
	return nil
}

// gcpAssetStartLines are what the start says of a gcp-asset source whose
// check passed: its token source, the check, its artifact, and whether the
// bindings of its own principal at a resource are checked.
func gcpAssetStartLines(name string, spec sourceSpec) []string {
	s := spec.gcpAsset
	source := "the metadata server of the platform's own compute, with no key on disk"
	if s.tokenSource == gcpAssetTokenKey {
		source = "a service account's key in the live credentials file, the least preferred source"
	}
	artifact := fmt.Sprintf("artifact %q, the shape's default: its result is returned and digested, and no payload is kept", artifactNotRetained)
	if s.retained {
		artifact = fmt.Sprintf("artifact %q, set by the operator: its payloads are kept in the store, which this shape does not do by default", artifactRetained)
	}
	bindings := "resource-bindings: checked on every IAM_POLICY page a caller reads; a role outside the read-only list granted at a resource to the source's own principal, or to allUsers or allAuthenticatedUsers, closes the source; a grant through a group, or on an asset type the source does not serve, is not seen"
	if !s.op.serves(gcpAssetContentIAMPolicy) {
		bindings = "resource-bindings: unchecked: the platform serves no IAM_POLICY, so a role granted the source's own principal on one resource below a project is not seen"
	}
	return []string{
		fmt.Sprintf("source %s: token source %s: %s", name, s.tokenSource, source),
		fmt.Sprintf("source %s: write check passed on the %d configured projects, and runs again with every token obtained after this one; a refusal then closes the source", name, len(s.op.parents)),
		fmt.Sprintf("source %s: %s", name, artifact),
		fmt.Sprintf("source %s: %s", name, bindings),
	}
}

// describeGCPAssetCheck reads adapter-gcp-asset's check report: the token
// source it names must be the source's, and its write check must have run
// on as many projects as the source was given; the line names the
// endpoint, the token source and the write list.
func describeGCPAssetCheck(report []byte, spec sourceSpec) (string, error) {
	who, raw, err := checkedAdapter(report)
	if err != nil {
		return "", err
	}
	var check struct {
		Endpoint    string `json:"endpoint"`
		TokenSource string `json:"tokenSource"`
		WriteCheck  struct {
			List        string `json:"list"`
			Permissions int    `json:"permissions"`
			Parents     int    `json:"parents"`
		} `json:"writeCheck"`
	}
	if err := json.Unmarshal(raw, &check); err != nil {
		return "", errors.New("the adapter's report is not a check report")
	}
	if check.TokenSource != spec.gcpAsset.tokenSource {
		return "", errors.New("the token source the adapter reports is not the one the source was given")
	}
	if check.WriteCheck.List == "" || check.WriteCheck.Permissions < 1 || check.WriteCheck.Parents != len(spec.gcpAsset.op.parents) {
		return "", errors.New("the adapter does not report a write check of every project the source was given")
	}
	return fmt.Sprintf("%s: endpoint %s, token source %s; write check %s: none of %d permissions granted on %d projects",
		who, requestText(check.Endpoint), spec.gcpAsset.tokenSource, requestText(check.WriteCheck.List), check.WriteCheck.Permissions, check.WriteCheck.Parents), nil
}

// The posture of the gcp-asset sources (docs/design/engine-config.md,
// "What the engine reports: /posture").
const protectionReadOnlyCredentials = "read-only-credentials"

// readOnlyCredentialsLines is the line a configuration with some gcp-asset
// source adds, its state judged over all of them, as every protection
// line is, and naming none: enforced where every one serves IAM_POLICY, so
// the bindings of its own principal at a resource are checked on every
// IAM_POLICY page read; partial where some serve none, whose resource
// bindings are unchecked. Every one is checked at the start and with every
// token after it, and closed on a refusal. What "checked" covers is said
// with it: a grant to the principal itself or to allUsers or
// allAuthenticatedUsers, not one through a group, whose membership no
// read-only call resolves. Its counts -- the sources, those serving
// IAM_POLICY, those closed -- are of the sources the reach takes, every
// one where it is nil: how many sources other scopes hold, and whether one
// was refused, is not the caller's to learn.
func readOnlyCredentialsLines(sources map[string]sourceSpec, reach *scopeReach) []postureLine {
	names := gcpAssetSourceNames(sources)
	if len(names) == 0 {
		return nil
	}
	servingAll := true
	reached, checked, closed := 0, 0, 0
	for _, name := range names {
		s := sources[name].gcpAsset
		iamPolicy := s.op.serves(gcpAssetContentIAMPolicy)
		servingAll = servingAll && iamPolicy
		if reach != nil && !reach.holds(sources[name].scope) {
			continue
		}
		reached++
		if iamPolicy {
			checked++
		}
		s.mu.Lock()
		if s.closed != nil {
			closed++
		}
		s.mu.Unlock()
	}
	state := postureEnforced
	if !servingAll {
		state = posturePartial
	}
	return []postureLine{{protectionReadOnlyCredentials, state, fmt.Sprintf(
		"%d of the %d read-only sources this caller reaches serve IAM_POLICY and check, on each IAM_POLICY page read, the roles granted at a resource to their own principal or to allUsers or allAuthenticatedUsers, not a grant through a group; every one is checked for a write permission at the start and with every token after it, and closed on a refusal; %d of them closed",
		checked, reached, closed)}}
}

// readOnlySourcePosture is one gcp-asset source in the report: its token
// source; its check, "passed", "refused" or "not-run" where the start has
// not run it (gateway posture, which starts nothing); whether it serves,
// "serving", "closed", or "not-started"; the refusal that closed it, its
// reason and where it was met, and nothing of its subject; its artifact;
// and its resource bindings, "checked" or "unchecked".
type readOnlySourcePosture struct {
	source, tokenSource, writeCheck, state, artifact, resourceBindings string
	refusal                                                            *readOnlyRefusal
}

// readOnlySourcePostures are the gcp-asset sources the reach takes, every
// one where it is nil, in name order.
func readOnlySourcePostures(sources map[string]sourceSpec, reach *scopeReach) []readOnlySourcePosture {
	var out []readOnlySourcePosture
	for _, name := range gcpAssetSourceNames(sources) {
		spec := sources[name]
		if reach != nil && !reach.holds(spec.scope) {
			continue
		}
		s := spec.gcpAsset
		p := readOnlySourcePosture{source: name, tokenSource: s.tokenSource, writeCheck: "not-run", state: "not-started",
			artifact: artifactNotRetained, resourceBindings: "unchecked"}
		if s.retained {
			p.artifact = artifactRetained
		}
		if s.op.serves(gcpAssetContentIAMPolicy) {
			p.resourceBindings = "checked"
		}
		s.mu.Lock()
		if s.checked {
			p.writeCheck, p.state = "passed", "serving"
		}
		if s.closed != nil {
			closed := *s.closed
			p.state, p.refusal = "closed", &closed
			if closed.reason != refusalCredentialBoundAtRsrc {
				p.writeCheck = "refused"
			}
		}
		s.mu.Unlock()
		out = append(out, p)
	}
	return out
}

func (p readOnlySourcePosture) value() *vObject {
	entry := newObject()
	entry.set("source", vString(p.source))
	entry.set("tokenSource", vString(p.tokenSource))
	entry.set("writeCheck", vString(p.writeCheck))
	entry.set("state", vString(p.state))
	entry.set("artifact", vString(p.artifact))
	entry.set("resourceBindings", vString(p.resourceBindings))
	var refusal value = vNull{}
	if p.refusal != nil {
		r := newObject()
		var reason value = vNull{}
		if p.refusal.reason != "" {
			reason = vString(p.refusal.reason)
		}
		r.set("reason", reason)
		r.set("on", vString(p.refusal.on))
		refusal = r
	}
	entry.set("refusal", refusal)
	return entry
}

func (p readOnlySourcePosture) text() string {
	refusal := "none"
	if p.refusal != nil {
		refusal = cmp.Or(p.refusal.reason, "unstated") + " on " + p.refusal.on
	}
	return fmt.Sprintf("%s read-only token=%s writeCheck=%s state=%s artifact=%s resourceBindings=%s refusal=%s",
		p.source, p.tokenSource, p.writeCheck, p.state, p.artifact, p.resourceBindings, refusal)
}
