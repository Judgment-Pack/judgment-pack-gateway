package main

// The gateway service. It holds the signing seed, runs configured sources,
// signs and chains what they return, and seals sessions. A caller supplies a
// session id, a source name and arguments -- never a receipt. That is what keeps
// a model or agent structurally out of the proof path: a caller can assert
// anything, but it cannot manufacture the gateway's signature.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type sessionState struct {
	index    int64
	prev     string
	sealed   bool
	inFlight int // admitted acquisitions whose source has not finished
	// created is whether this process made the session's directory in the
	// store -- by an action's admission, which makes it before any executor
	// runs, or by a read's stamp that found none -- so every receipt there
	// is this process's own. An action is minted only into a session this
	// process created (executor.md): absence at admission is not ownership,
	// since another process could put the session there before the stamp,
	// and a receipt count is not either, since a read can recreate a receipt
	// an old session lost and count on from there. Made atomic by Mkdir:
	// two makers cannot both succeed.
	created bool
}

// sourceSpec is what the operator declared for one source: the command, the
// environment it is started with, and optionally the OS user it runs as.
//
// The environment is the whole of the separation between this process and a
// source (ADR-0001, determination 2). A source started with the gateway's own
// environment would see every variable the operator gave the gateway, so a
// credential placed there for one source would reach the signer's memory and
// every other source. So a source gets exactly what was declared for it:
// `KEY=VALUE` sets a variable; a bare `KEY` copies that one variable from the
// gateway's environment at spawn time, so a path can be passed through by
// name without the gateway ever holding what is behind it. PATH is copied
// unless declared, because a source that cannot find `/bin/sh` is not a
// source, and PATH carries no secret.
type sourceSpec struct {
	argv []string
	env  []string
	user string
	// shape is the adapter shape declared with --source-shape (SPEC.md §1.2a);
	// empty for a bare command, whose stdout is the result itself.
	shape string
	// check are the arguments a check of this source adds to the adapter's
	// command line, from the binding; nothing serve uses.
	check []string
	// tools and endpoint are the write binding's, for a write source only
	// (executor.md): the tools an executor may be asked for, and the
	// endpoint an action receipt names; /acquire reads neither.
	tools    []string
	endpoint string
}

// adapterShapes are the shapes --source-shape may declare: every shape of
// SPEC.md §1.2a but "command", which is what an undeclared source is.
var adapterShapes = map[string]bool{"airbyte": true, "mcp": true, "http": true}

// defaultMaxSourceOutput bounds what a source may write on stdout before the
// acquisition fails and the source is killed. One mebibyte matches
// maxRequestBody: the same order of magnitude as anything this gateway is
// meant to attest, and far below what a runaway source could otherwise grow
// this process by. Before this bound existed a source's output was read into
// memory without limit.
const defaultMaxSourceOutput int64 = 1 << 20

type gatewayService struct {
	store           *store
	registry        *registryWriter
	storeRoot       string
	regPath         string
	authority       string
	publicKey       ed25519.PublicKey
	keyID           string
	sources         map[string]sourceSpec
	maxSourceOutput int64
	// started counts the sources this service has started; a test reads it
	// to prove that a refusal came before any source ran. startedWith is the
	// command line the last one was started with, for a test that holds the
	// executor to the tool it was narrowed to.
	started     atomic.Int64
	startedWith atomic.Pointer[[]string]
	// beforeAdmit, when a test sets it, runs between an action's evidence
	// checks and its admission: the window in which another request may
	// have put the session on disk or sealed it, which admission's own
	// recheck must catch.
	beforeAdmit func()
	// beforeStamp, when a test sets it, runs in the last moment before a
	// read's stamp, under the lock: the window in which another process may
	// have put the session on disk, which the stamp's own exclusive Mkdir
	// must find rather than claim.
	beforeStamp func()
	// identity is who may call (serveOptions.identity); nil when no
	// issuer is configured, and every receipt then carries caller null.
	identity *identityConfig
	// receiptVersion is what acquire mints: "3" unless the operator asked
	// for "2" to keep a consumer not yet updated working (SPEC.md §1.2a).
	receiptVersion string
	// decisionRecords is where an action's cited decision record is looked
	// for (executor.md); empty refuses every action.
	decisionRecords string
	// ctx is the service's lifetime. Every source's context derives from it,
	// so shutting the service down cancels every source in flight; a source
	// in its own process group would otherwise outlive the gateway that
	// started it, since it no longer shares the terminal's signals.
	ctx    context.Context
	cancel context.CancelFunc
	// waitDelay bounds how long, after a source's context is cancelled or
	// the source has exited, the gateway keeps waiting for its stdout and
	// stderr to reach end of file. A descendant that escaped the source's
	// process group and holds a pipe would otherwise hold the acquisition.
	waitDelay time.Duration

	mu       sync.Mutex
	sessions map[string]*sessionState
	// gate is the signer's admission gate (docs/design/mcp-server.md,
	// "Rotation"): the one place every acquisition and every action is
	// admitted, so once it is closed nothing more is admitted, however
	// long a request was in transit to it, and sealing goes on; a closure
	// is drained when nothing admitted is in flight. Its state changes
	// under mu, which admission holds.
	gate admissionGate
	// reports is where the gate's transitions are said, on the signer's
	// stderr unless a test gives it another writer (reportsOut)
	reports    *diagnosticStream
	reportsOut io.Writer
	// beforeReadAdmit, when a test sets it, runs as an acquisition's
	// request is about to be admitted: where a request that was in transit
	// meets a closure; afterReadAdmit is told what admission decided
	beforeReadAdmit func()
	afterReadAdmit  func(error)
}

func newGatewayService(storeRoot string, seed []byte, authority, registryPath string,
	sources map[string]sourceSpec) (*gatewayService, error) {
	// A shape is one of §1.2a's or nothing: a receipt minted under any other
	// would be malformed to every verifier, so it is refused here, whatever
	// built the configuration.
	for name, spec := range sources {
		if spec.shape != "" && !adapterShapes[spec.shape] {
			return nil, fmt.Errorf("source %s: unknown adapter shape %q", name, spec.shape)
		}
	}
	// the registry's spelling is judged before the store is made: a start
	// that would refuse it leaves nothing behind (SPEC.md §4.1)
	if err := requirePlainSpelling(registryPath, true); err != nil {
		return nil, err
	}
	st, err := newStore(storeRoot, seed, authority)
	if err != nil {
		return nil, err
	}
	reg, err := newRegistryWriter(registryPath, seed)
	if err != nil {
		return nil, err
	}
	g := &gatewayService{
		store: st, registry: reg, storeRoot: storeRoot, regPath: registryPath,
		authority: authority, publicKey: st.publicKey, keyID: st.keyID,
		sources: sources, maxSourceOutput: defaultMaxSourceOutput,
		receiptVersion: receiptVersion3,
		waitDelay:      sourceWaitDelay,
		sessions:       map[string]*sessionState{},
		gate:           newAdmissionGate(),
	}
	g.reports = newDiagnosticStream(func() io.Writer {
		if g.reportsOut != nil {
			return g.reportsOut
		}
		return os.Stderr
	})
	g.bindLifetime(context.Background())
	return g, nil
}

// bindLifetime makes the service's lifetime end when parent ends, and gives
// the service its own way to end it: serveOn cancels it on every exit path,
// so a source in flight is killed whichever way serving stopped.
// gateReports says the signer's gate's transitions on its reports.
func (g *gatewayService) gateReports() gateReports {
	return gateReports{reports: g.reports, who: "serve", outstanding: "acquisitions and actions admitted and not finished",
		drainedWord: func(*gateClosure) string {
			return "nothing admitted is in flight, and nothing will be admitted until admission reopens"
		}}
}

// closeAdmission closes the signer's gate: from here no acquisition and no
// action is admitted, and sealing goes on. It returns the channel that
// closes when the closure ends -- drained, or reopened first -- and
// reports each, with the closure's number.
func (g *gatewayService) closeAdmission() <-chan struct{} {
	g.mu.Lock()
	defer g.mu.Unlock()
	c, fresh := g.gate.closeLocked()
	g.gateReports().closed(c, fresh, g.gate.pending)
	return c.done
}

// openAdmission reopens the signer's gate.
func (g *gatewayService) openAdmission() {
	g.mu.Lock()
	defer g.mu.Unlock()
	if c, fresh := g.gate.openLocked(); fresh {
		g.gateReports().opened(c)
	}
}

func (g *gatewayService) bindLifetime(parent context.Context) {
	g.ctx, g.cancel = context.WithCancel(parent)
}

// envGroupAnchor and anchorArg together select the anchor mode of this
// executable (spawn_unix.go). Both are required: an inherited variable alone
// must not turn an ordinary invocation into a process that swallows stdin
// and exits successfully, and main refuses to run at all with the variable
// set, so a stray marker is an error rather than a silent success.
const (
	envGroupAnchor = "GATEWAY_INTERNAL_GROUP_ANCHOR"
	anchorArg      = "_group-anchor"
)

// sourceEnvironment builds the environment a source is started with: the
// declared entries, resolved, and PATH copied from this process unless the
// operator declared one. A bare key that this process does not have is
// omitted rather than set empty, so a source can tell "not passed" from
// "passed empty".
//
// Two platform facts bound the claim. Windows environment names are
// case-insensitive and os/exec keeps the last of two spellings, so "Path"
// declared there is PATH declared, and is matched as such. And os/exec on
// Windows adds this process's SYSTEMROOT to any explicit environment that
// lacks it, because a Windows program cannot start without one; that single
// variable reaches a source there undeclared, and SECURITY.md says so.
func sourceEnvironment(spec sourceSpec) []string {
	env := make([]string, 0, len(spec.env)+1)
	pathDeclared := false
	for _, entry := range spec.env {
		key, _, found := strings.Cut(entry, "=")
		if sameEnvKey(key, "PATH") {
			pathDeclared = true
		}
		if found {
			env = append(env, entry)
			continue
		}
		if value, present := os.LookupEnv(entry); present {
			env = append(env, entry+"="+value)
		}
	}
	if !pathDeclared {
		if path, present := os.LookupEnv("PATH"); present {
			env = append(env, "PATH="+path)
		}
	}
	return env
}

// sameEnvKey compares environment variable names the way the platform does.
func sameEnvKey(a, b string) bool {
	if runtime.GOOS == "windows" {
		return strings.EqualFold(a, b)
	}
	return a == b
}

// sourceWaitDelay bounds how long, after a source's context is cancelled or
// the source has exited, the gateway keeps waiting for its stdout and stderr
// to reach end of file. A descendant the source left holding a pipe would
// otherwise hold the acquisition open indefinitely.
const sourceWaitDelay = 5 * time.Second

// boundedBuffer keeps at most limit bytes of what is written to it. The first
// write that would cross the limit records the overflow and calls stop once,
// which the caller wires to the source's context so the source is killed
// rather than left writing into a pipe nobody drains. Writes never fail: a
// writer that errored would make os/exec stop draining while the process is
// still alive, and a full pipe would then hold it until the timeout.
type boundedBuffer struct {
	limit      int64
	buf        bytes.Buffer
	overflowed bool
	stop       func()
}

func (b *boundedBuffer) Write(p []byte) (int, error) {
	room := b.limit - int64(b.buf.Len())
	if int64(len(p)) > room {
		if room > 0 {
			b.buf.Write(p[:room])
		}
		if !b.overflowed {
			b.overflowed = true
			if b.stop != nil {
				b.stop()
			}
		}
		return len(p), nil
	}
	return b.buf.Write(p)
}

// badRequest marks errors that are the caller's fault, so the handler can answer 400
// rather than 500.
type badRequest struct{ error }

// maxRequestBody bounds what /acquire and /seal will read before deciding
// anything. /seal carries one session id; /acquire carries a session id, a
// source name, and a caller-supplied `arguments` value, so /acquire is the one
// with a real payload and sets the number. One mebibyte is far above any
// argument object this gateway is meant to serve and far below a body worth
// buffering from an unauthenticated caller -- and there IS no authentication
// here, so the only thing standing between a request and this process's memory
// is this limit. listenAndServe already bounds header delivery with
// ReadHeaderTimeout; this is the same concern for the body.
const maxRequestBody = 1 << 20

// limitBody caps r.Body in place. http.MaxBytesReader needs the ResponseWriter
// to signal the client properly, so it can only be applied inside a handler.
func limitBody(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
}

func decodeSingleJSON(r io.Reader, dst any) error {
	decoder := json.NewDecoder(r)
	if err := decoder.Decode(dst); err != nil {
		return err
	}

	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return errors.New("request body must contain exactly one JSON value")
		}
		return fmt.Errorf("request body contains trailing content: %w", err)
	}
	return nil
}

func (g *gatewayService) acquire(sessionID, source string, arguments value, who *caller) (map[string]any, error) {
	if err := requireSession(sessionID); err != nil {
		return nil, badRequest{err} // refuse before running anything
	}
	spec, known := g.sources[source]
	if !known || strings.HasSuffix(source, "/write") {
		// A write source is the executor's alone (executor.md): a read
		// that writes is not a read, and /acquire names no such source.
		return nil, badRequest{fmt.Errorf("unknown source: %s", source)}
	}
	if spec.shape != "" && g.receiptVersion != receiptVersion3 {
		return nil, fmt.Errorf("source %s is an adapter and needs receipt version 3", source)
	}
	canonicalArgs := canon(arguments)

	// Admission happens BEFORE the source exists. Sources are slow, cost money
	// and can have operator-visible side effects, so "sealed" has to be decided
	// against the session state as it is now, not as it will be when a
	// subprocess finishes. Every path out of here releases the reservation; the
	// deferred release is registered before the mutex is taken again below, so
	// it runs after that unlock rather than deadlocking on it.
	// A seal is final across a restart too. This process's own seals are in
	// its session map, and admit refuses them under the lock; a seal an
	// earlier process wrote is in the registry alone, so a session this
	// process does not hold is looked up there before anything runs -- a
	// source started for a session whose count is already sealed could only
	// fail at its stamp, after whatever it did.
	if refusal := g.sealedElsewhere(sessionID); refusal != "" {
		return nil, badRequest{errors.New(refusal)}
	}
	if g.beforeReadAdmit != nil {
		g.beforeReadAdmit()
	}
	admitted := g.admit(sessionID)
	if g.afterReadAdmit != nil {
		g.afterReadAdmit(admitted)
	}
	if admitted != nil {
		return nil, admitted
	}
	defer g.release(sessionID)

	result, adapterDigest, observedAt, err := g.runSource(source, spec, canonicalArgs)
	if err != nil {
		return nil, err
	}

	g.mu.Lock()
	defer g.mu.Unlock()
	// The session is known because admission reserved it, and it cannot have
	// been sealed since: sealing refuses while an acquisition is in flight.
	state := g.sessions[sessionID]

	// An adapter's stdout is an envelope (SPEC.md §6): the result to attest
	// and the acquisition as the adapter recorded it. A defective envelope
	// fails the acquisition before anything is retained.
	var adapterEnvelope *envelope
	if spec.shape != "" {
		adapterEnvelope, err = parseEnvelope(result)
		if err != nil {
			return nil, fmt.Errorf("source %s: the adapter's result is not an envelope: %v", source, err)
		}
		result = adapterEnvelope.result
	}
	// The response carries the result as ordinary JSON. A result the
	// response cannot carry -- nested deeper than encoding/json will decode
	// -- is refused here, before anything is retained or minted, so no
	// receipt is ever stamped for an acquisition the caller cannot receive.
	var resultOut any
	if err := json.Unmarshal(canon(result), &resultOut); err != nil {
		return nil, fmt.Errorf("source %s: the result cannot be returned: %v", source, err)
	}
	// An artifact is content-addressed and may be shared by receipts, so
	// a failure after this point leaves it in place rather than removing
	// what another receipt may cite; nothing cites it until a receipt is
	// stamped.
	resultDigest, err := g.store.retain(canon(result))
	if err != nil {
		return nil, err
	}

	core := newObject()
	core.set("receiptVersion", vString(g.receiptVersion))
	core.set("sessionId", vString(sessionID))
	core.set("callIndex", vInt(state.index))
	if state.prev == "" {
		core.set("prevSignature", vNull{})
	} else {
		core.set("prevSignature", vString(state.prev))
	}
	core.set("source", vString(source))
	core.set("resultDigest", vString(resultDigest))
	core.set("servedAt", vString(nowStamp()))
	core.set("authority", vString(g.authority))
	var salts map[string]any
	if g.receiptVersion == receiptVersion3 {
		// SPEC.md §1.2a: a salted commitment to the arguments, the salt drawn
		// fresh, returned to the caller beside the receipt, and never
		// retained. A bare command is the "command" shape: bytes attested,
		// the acquisition recorded as far as a command can record it.
		salt, err := newSalt()
		if err != nil {
			return nil, err
		}
		core.set("argumentsCommitment", vString(commitmentOver(salt, "args:", canonicalArgs)))
		core.set("kind", vString("acquisition"))
		// SPEC.md §1.2a: the identity a verified token proved, or null.
		if who == nil {
			core.set("caller", vNull{})
		} else {
			identity := newObject()
			identity.set("issuer", vString(who.issuer))
			identity.set("subject", vString(who.subject))
			identity.set("tokenDigest", vString(who.tokenDigest))
			core.set("caller", identity)
		}
		salts = map[string]any{"args": hex.EncodeToString(salt)}
		if adapterEnvelope == nil {
			core.set("acquisition", commandAcquisition(spec, adapterDigest, observedAt))
		} else {
			acquisition, statementSalt, err := adapterAcquisition(spec.shape, adapterEnvelope)
			if err != nil {
				return nil, err
			}
			core.set("acquisition", acquisition)
			if statementSalt != nil {
				salts["statement"] = hex.EncodeToString(statementSalt)
			}
		}
	} else {
		mac := hmac.New(sha256.New, argumentsKey(g.store.seed))
		mac.Write(append([]byte("args:"), canonicalArgs...))
		core.set("argumentsDigest", vString("hmac-sha256:"+hex.EncodeToString(mac.Sum(nil))))
	}

	if g.beforeStamp != nil {
		g.beforeStamp()
	}
	stored, signature, made, err := g.store.stampOwning(core)
	if err != nil {
		return nil, err
	}
	state.index++
	state.prev = signature
	if made {
		// The stamp made the session's directory, exclusively: the session
		// is this process's own from here (sessionState.created). A
		// directory another process put there at any moment before the
		// stamp -- absence read earlier would not have seen it -- is found
		// by the same Mkdir and never taken for this process's own.
		state.created = true
	}

	// The receipt in the response is the stored receipt, whole: the same
	// members written under receipts/<session>/<index>.json, so the caller
	// holds everything the signature covers and can check it without reaching
	// into the store. The response body is ordinary JSON, not canon bytes; a
	// checking caller canonicalizes per §1.1 first (SPEC.md §6).
	var receiptOut any
	if err := json.Unmarshal(canon(stored), &receiptOut); err != nil {
		return nil, err
	}
	response := map[string]any{
		"result":  resultOut,
		"receipt": receiptOut,
	}
	if salts != nil {
		response["salts"] = salts
	}
	return response, nil
}

// newSalt draws the 32 random bytes one commitment is salted with.
// runSource starts one source as configured -- resolved once to the file
// that is digested, the canonical request on stdin, the declared environment
// and nothing else, the platform's user, its own process group -- waits for
// it under the service's bounds, and returns what it wrote as a canonical
// JSON value, the adapter digest a bare command's receipt names, and when
// the output was read. /acquire and /act share it: an action is a call
// through the same boundary as a read, and the receipt's claims about the
// process are the same claims.
func (g *gatewayService) runSource(source string, spec sourceSpec, stdin []byte) (result value, adapterDigest, observedAt string, err error) {
	ctx, cancel := context.WithTimeout(g.ctx, 30*time.Second)
	defer cancel()
	// The command is resolved once, here, to the file that will be started,
	// and that file is what a version 3 receipt digests -- os/exec would
	// otherwise give a relative Windows command its extension only at start,
	// after the digest. A bare name that resolves to the working directory
	// is refused, as os/exec refuses it.
	path, err := exec.LookPath(spec.argv[0])
	if err != nil {
		return nil, "", "", fmt.Errorf("source could not be started: %v", err)
	}
	if g.receiptVersion == receiptVersion3 && spec.shape == "" {
		// Digested before anything is started, so a failure here leaves
		// nothing to reap. It is the file at that path at that moment: a
		// replacement between this read and the start is not detected.
		adapterDigest, err = executableDigest(path)
		if err != nil {
			return nil, "", "", err
		}
	}
	cmd := exec.CommandContext(ctx, path, spec.argv[1:]...)
	// The source sees the command as configured, not as resolved.
	cmd.Args = append([]string{spec.argv[0]}, spec.argv[1:]...)
	cmd.Stdin = bytes.NewReader(stdin)
	// The declared environment and nothing else (sourceSpec). An explicit
	// slice is what stops os/exec from handing the child this process's
	// environment; an empty declaration is an empty environment, not an
	// inherited one.
	cmd.Env = sourceEnvironment(spec)
	group, err := prepareSourceProcess(cmd, spec.user)
	if err != nil {
		return nil, "", "", fmt.Errorf("source %s: %w", source, err)
	}
	cmd.WaitDelay = g.waitDelay
	// stdout is bounded and its overflow kills the source; stderr is bounded
	// and simply truncated, because only its first line is ever reported and
	// a chatty source is not a failed one.
	stdout := &boundedBuffer{limit: g.maxSourceOutput, stop: cancel}
	stderr := &boundedBuffer{limit: 4096}
	cmd.Stdout, cmd.Stderr = stdout, stderr
	// Start and Wait are separate so that a source that could not be started
	// at all -- the command gone, or the user switch refused by the kernel --
	// is reported as that, with the operating system's own reason, rather
	// than as an empty "source failed".
	g.started.Add(1)
	argv := append([]string(nil), cmd.Args...)
	g.startedWith.Store(&argv)
	if err := group.start(cmd); err != nil {
		group.reap()
		return nil, "", "", fmt.Errorf("source could not be started: %v", err)
	}
	waitErr := cmd.Wait()
	// Whatever Wait returned, nothing of the source's process group survives
	// the acquisition. os/exec stops watching the context once the direct
	// child has exited, so an overflow written by a descendant after that
	// cancels a context nobody acts on; the bounded wait then returns, and
	// this is what kills the descendant. The group's anchor is reaped last,
	// so the kill cannot reach a reused pid.
	group.reap()
	if stdout.overflowed {
		// Whether the kill landed first or the source exited on its own, the
		// output is not the output it produced.
		return nil, "", "", fmt.Errorf("source output exceeds %d bytes", g.maxSourceOutput)
	}
	if waitErr != nil {
		if errors.Is(waitErr, exec.ErrWaitDelay) {
			return nil, "", "", errors.New("source exited but left its output open past the deadline; a descendant is holding the pipe")
		}
		trimmed := stderr.buf.String()
		if len(trimmed) > 200 {
			trimmed = trimmed[:200]
		}
		return nil, "", "", fmt.Errorf("source failed: %s", trimmed)
	}
	observedAt = nowStamp()
	result, err = parseJSON(stdout.buf.Bytes())
	if err != nil {
		return nil, "", "", fmt.Errorf("source did not return a canonical JSON value: %w", err)
	}
	return result, adapterDigest, observedAt, nil

}

func newSalt() ([]byte, error) {
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("draw salt: %w", err)
	}
	return salt, nil
}

// commitmentOver is SPEC.md §1.2a's commitment: SHA-256 over the salt, the
// label, and the canonical value, as a digest string.
func commitmentOver(salt []byte, label string, canonical []byte) string {
	h := sha256.New()
	h.Write(salt)
	h.Write([]byte(label))
	h.Write(canonical)
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}

// commandAcquisition is the acquisition record a bare operator-configured
// command yields (SPEC.md §1.2a, shape "command"): the adapter is the command
// itself, named as configured and identified by the digest of the file it
// resolved to; nothing else about the acquisition is known, and every
// nullable member says so. observedAt is the gateway's own stamp of when the
// source's output was read, since a command records nothing.
func commandAcquisition(spec sourceSpec, digest, observedAt string) *vObject {
	adapter := newObject()
	adapter.set("name", vString(spec.argv[0]))
	adapter.set("version", vString(""))
	adapter.set("digest", vString(digest))
	a := newObject()
	a.set("adapter", adapter)
	a.set("shape", vString("command"))
	a.set("endpoint", vNull{})
	a.set("statement", vNull{})
	a.set("snapshot", vNull{})
	a.set("peerIdentity", vNull{})
	a.set("schema", vNull{})
	a.set("upstreamToken", vNull{})
	a.set("observedAt", vString(observedAt))
	return a
}

// envelope is what an adapter source writes on stdout (SPEC.md §6, "Adapter
// sources"): the result the gateway attests, the acquisition as the adapter
// recorded it, and whether the result is a page of items.
type envelope struct {
	result      value
	acquisition *vObject
	statement   *string
	page        bool
}

// envelopeMembers are the acquisition members an adapter reports. shape is
// the operator's and pageItems the gateway's; an envelope naming either is
// refused.
var envelopeMembers = map[string]bool{
	"adapter": true, "endpoint": true, "statement": true, "snapshot": true,
	"peerIdentity": true, "schema": true, "upstreamToken": true, "observedAt": true,
}

// parseEnvelope holds an adapter's stdout to SPEC.md §6 exactly: the three
// envelope members and no other, the eight acquisition members and no other,
// each of its stated type and form. Anything else is a refusal, never a
// member silently dropped or defaulted.
func parseEnvelope(v value) (*envelope, error) {
	obj, ok := v.(*vObject)
	if !ok {
		return nil, errors.New("not an object")
	}
	for _, name := range obj.names {
		switch name {
		case "acquisition", "result", "page":
		default:
			return nil, fmt.Errorf("unknown member %q", name)
		}
	}
	result, ok := obj.get("result")
	if !ok {
		return nil, errors.New(`missing member "result"`)
	}
	raw, ok := obj.get("acquisition")
	if !ok {
		return nil, errors.New(`missing member "acquisition"`)
	}
	acquisition, err := requireObject(raw, "acquisition")
	if err != nil {
		return nil, err
	}
	e := &envelope{result: result, acquisition: acquisition}
	if p, ok := obj.get("page"); ok {
		if b, isBool := p.(vBool); !isBool || !bool(b) {
			return nil, errors.New(`member "page" must be true when present`)
		}
		if _, isArray := result.(vArray); !isArray {
			return nil, errors.New("a page's result must be an array of items")
		}
		e.page = true
	}
	for _, name := range acquisition.names {
		if !envelopeMembers[name] {
			return nil, fmt.Errorf("acquisition member %q is not one an adapter reports", name)
		}
	}
	adapter, ok := acquisition.get("adapter")
	if !ok {
		return nil, errors.New(`missing member "adapter"`)
	}
	if err := validateAdapter(adapter, "adapter"); err != nil {
		return nil, err
	}
	// The verifier tolerates a member it does not know, since a signed one is
	// the signer's own; the signer tolerates nothing it did not ask for.
	for _, name := range adapter.(*vObject).names {
		switch name {
		case "name", "version", "digest":
		default:
			return nil, fmt.Errorf("adapter member %q is not one an adapter reports", name)
		}
	}
	for _, name := range []string{"endpoint", "snapshot", "peerIdentity", "upstreamToken", "statement"} {
		if err := nullableString(acquisition, name, nil); err != nil {
			return nil, err
		}
	}
	if err := nullableString(acquisition, "schema", isDigest); err != nil {
		return nil, err
	}
	if text, ok := memberString(acquisition, "statement"); ok {
		e.statement = &text
	}
	observedAt, err := requireString(acquisition, "observedAt")
	if err != nil {
		return nil, err
	}
	if !isStamp(observedAt) {
		return nil, errors.New(`member "observedAt" is not a stamp`)
	}
	return e, nil
}

// isStamp is the form nowStamp produces: UTC, whole seconds, fixed width.
func isStamp(s string) bool {
	t, err := time.Parse("2006-01-02T15:04:05Z", s)
	return err == nil && t.UTC().Format("2006-01-02T15:04:05Z") == s
}

// adapterAcquisition is the acquisition record for an adapter source
// (SPEC.md §1.2a, "Where the members come from"): the envelope's members as
// the adapter reported them, the shape as the operator declared it, the
// statement committed under a fresh salt, and the page items digested here.
func adapterAcquisition(shape string, e *envelope) (*vObject, []byte, error) {
	a := newObject()
	for _, name := range []string{"adapter", "endpoint", "snapshot", "peerIdentity", "schema", "upstreamToken", "observedAt"} {
		v, _ := e.acquisition.get(name)
		a.set(name, v)
	}
	a.set("shape", vString(shape))
	var salt []byte
	if e.statement == nil {
		a.set("statement", vNull{})
	} else {
		var err error
		if salt, err = newSalt(); err != nil {
			return nil, nil, err
		}
		a.set("statement", vString(commitmentOver(salt, "statement:", canon(vString(*e.statement)))))
	}
	if e.page {
		items := e.result.(vArray)
		digests := make(vArray, 0, len(items))
		for _, item := range items {
			sum := sha256.Sum256(canon(item))
			digests = append(digests, vString("sha256:"+hex.EncodeToString(sum[:])))
		}
		a.set("pageItems", digests)
	}
	return a, salt, nil
}

// executableDigest is the SHA-256 of the regular file at path, streamed, as a
// digest string. Anything but a regular file is refused by stat before it is
// opened, since opening a FIFO would block without a writer and nothing has
// been started yet that a timeout could cancel; a regular file swapped for a
// FIFO between the stat and the open is the replacement the acquisition does
// not detect.
func executableDigest(path string) (string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return "", fmt.Errorf("source executable could not be read for its digest: %w", err)
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("source executable %s is not a regular file", path)
	}
	file, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("source executable could not be read for its digest: %w", err)
	}
	defer file.Close()
	h := sha256.New()
	if _, err := io.Copy(h, file); err != nil {
		return "", fmt.Errorf("source executable could not be read for its digest: %w", err)
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
}

// sealedElsewhere is why a read may not be admitted into a session this
// process does not hold, or "": the session is sealed in the registry on
// disk -- by an earlier process, since this one's own seals are in its
// map -- or the registry could not be read, which is a refusal, never taken
// for the absence of a seal. A session this process holds is judged by
// its map alone, under admission's lock. Unlike an action (sessionOpen), a
// read may still continue an unsealed session the store holds from before
// this start: that is what it has always done, and it is unchanged.
func (g *gatewayService) sealedElsewhere(sessionID string) string {
	g.mu.Lock()
	_, held := g.sessions[sessionID]
	g.mu.Unlock()
	if held {
		return ""
	}
	seals, err := loadEngineSeals(g.regPath, g.publicKey)
	if err != nil {
		return "the registry could not be read"
	}
	if _, sealed := seals[sessionID]; sealed {
		return "session is sealed in the registry: " + sessionID
	}
	return ""
}

// admit reserves an acquisition against a session, refusing a sealed one before
// any source is constructed or started.
func (g *gatewayService) admit(sessionID string) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	// the gate first, before anything is made: a closed signer admits
	// nothing, whatever the request carries
	if g.gate.closed {
		return unavailable{errAdmissionClosed}
	}
	state, seen := g.sessions[sessionID]
	if !seen {
		state = &sessionState{}
		g.sessions[sessionID] = state
	}
	if state.sealed {
		return badRequest{fmt.Errorf("session is sealed: %s", sessionID)}
	}
	state.inFlight++
	g.gate.admitLocked()
	return nil
}

// release drops the reservation admit took.
//
// A session that admission created and that never produced a receipt is removed
// again. Before this change a session only entered the map once it had one, so
// leaving an empty one behind would let a caller seal a session whose only
// acquisition FAILED -- a zero-receipt phantom that verifies as a real sealed
// session. That is the hazard admitting early introduces, and the reason this
// is not simply a counter decrement.
func (g *gatewayService) release(sessionID string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	state, seen := g.sessions[sessionID]
	if !seen {
		return
	}
	state.inFlight--
	if c := g.gate.finishLocked(); c != nil {
		g.gateReports().drained(c)
	}
	// A session this process created stays known whatever it holds: its
	// directory is on disk and is this process's own (sessionState.created).
	if state.inFlight <= 0 && state.index == 0 && !state.sealed && !state.created {
		delete(g.sessions, sessionID)
	}
}

func (g *gatewayService) sealSession(sessionID string) (map[string]any, error) {
	if err := requireSession(sessionID); err != nil {
		return nil, badRequest{err}
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	state, seen := g.sessions[sessionID]
	if !seen {
		return nil, badRequest{fmt.Errorf("no such session: %s", sessionID)}
	}
	// A seal must not overtake work the gateway already admitted, or that
	// receipt would exist in the store while the sealed finalCount says it does
	// not. Refusing is the registered policy: the caller retries once the
	// in-flight acquisitions finish, and no registry record is written here.
	if state.inFlight > 0 {
		return nil, badRequest{fmt.Errorf(
			"session has %d acquisition(s) in flight, retry after they finish: %s",
			state.inFlight, sessionID)}
	}
	record, err := g.registry.seal(sessionID, state.index, nowStamp())
	if err != nil {
		// a seal that may be in the registry closes the session here too:
		// a reader of the registry may find it, and a session this process
		// holds is judged by its map, so the map must not stay open behind
		// a seal on disk. A retry of the seal finds the record, or writes it.
		if errors.As(err, new(sealMayBeWritten)) {
			state.sealed = true
		}
		return nil, badRequest{err}
	}
	state.sealed = true
	var out map[string]any
	if err := json.Unmarshal(canon(record), &out); err != nil {
		return nil, err
	}
	return out, nil
}

func (g *gatewayService) verify() (map[string]any, error) {
	rep, err := verifyWithRegistryAndRecords(g.storeRoot, g.regPath, g.authority, g.decisionRecords, g.publicKey)
	if err != nil {
		return nil, err
	}
	raw, err := rep.marshal()
	if err != nil {
		return nil, err
	}
	var out map[string]any
	return out, json.Unmarshal(raw, &out)
}

// publicKeyDocument is what a verifier fetches so it can check this gateway's
// receipts without being able to produce any. Obtaining the key HERE and then
// auditing this same gateway proves consistency, not authenticity (SPEC.md §5).
func (g *gatewayService) publicKeyDocument() map[string]any {
	return map[string]any{
		"algorithm": "ed25519", "keyId": g.keyID,
		"publicKey": hex.EncodeToString(g.publicKey), "authority": g.authority,
	}
}

func (g *gatewayService) handler() http.Handler {
	mux := http.NewServeMux()

	writeJSON := func(w http.ResponseWriter, code int, body any) {
		payload, err := json.Marshal(body)
		if err != nil {
			http.Error(w, `{"error":"encode"}`, http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		_, _ = w.Write(payload)
	}
	fail := func(w http.ResponseWriter, err error) {
		var down unavailable
		if errors.As(err, &down) {
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": err.Error()})
			return
		}
		var caller badRequest
		if errors.As(err, &caller) {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
	}

	// authenticate holds a request to the configured identity: a bearer
	// token the issuer signed, naming this engine, or 401 with why -- one
	// reason, never the token. With no identity configured every request
	// is admitted and no caller is recorded.
	authenticate := func(w http.ResponseWriter, r *http.Request) (*caller, bool) {
		if g.identity == nil {
			return nil, true
		}
		token := bearerToken(r.Header.Get("Authorization"))
		if token == "" {
			w.Header().Set("WWW-Authenticate", "Bearer")
			writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "a bearer token from the configured issuer is required"})
			return nil, false
		}
		who, err := verifyToken(token, *g.identity, time.Now())
		if err != nil {
			w.Header().Set("WWW-Authenticate", "Bearer")
			writeJSON(w, http.StatusUnauthorized, map[string]any{"error": err.Error()})
			return nil, false
		}
		return &who, true
	}

	mux.HandleFunc("/acquire", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeJSON(w, http.StatusNotFound, map[string]any{"error": "not found"})
			return
		}
		who, ok := authenticate(w, r)
		if !ok {
			return
		}
		limitBody(w, r)
		var body struct {
			Session   string          `json:"session"`
			Source    string          `json:"source"`
			Arguments json.RawMessage `json:"arguments"`
		}
		if err := decodeSingleJSON(r.Body, &body); err != nil {
			fail(w, badRequest{err})
			return
		}
		arguments := value(newObject())
		if len(body.Arguments) > 0 {
			parsed, err := parseJSON(body.Arguments)
			if err != nil {
				fail(w, badRequest{err})
				return
			}
			arguments = parsed
		}
		out, err := g.acquire(body.Session, body.Source, arguments, who)
		if err != nil {
			fail(w, err)
			return
		}
		writeJSON(w, http.StatusOK, out)
	})

	// An action (docs/design/executor.md): the same boundary as /acquire,
	// with an authenticated requester and a judgment that must exist before
	// any executor runs. A refusal names the step of the ladder it fell at.
	mux.HandleFunc("/act", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeJSON(w, http.StatusNotFound, map[string]any{"error": "not found"})
			return
		}
		who, ok := authenticate(w, r)
		if !ok {
			return
		}
		if who == nil {
			// No identity configured: nobody is a requester, and the body is
			// not read -- the ladder's first step, answered before the second
			// byte of the request.
			w.Header().Set("WWW-Authenticate", "Bearer")
			writeJSON(w, http.StatusUnauthorized, map[string]any{"error": errNoRequester.Error() + "; this engine has no identity configured", "refusedAt": "requester"})
			return
		}
		limitBody(w, r)
		// Every member is read at its own step of the ladder (act), the
		// string-valued ones included: a member of the wrong type is a
		// refusal at that step, not a decoding error ahead of the session's.
		var body struct {
			Session   json.RawMessage `json:"session"`
			Platform  json.RawMessage `json:"platform"`
			Tool      json.RawMessage `json:"tool"`
			Arguments json.RawMessage `json:"arguments"`
			Decision  json.RawMessage `json:"decision"`
			Cites     json.RawMessage `json:"cites"`
		}
		if err := decodeSingleJSON(r.Body, &body); err != nil {
			fail(w, badRequest{err})
			return
		}
		out, err := g.act(body.Session, body.Platform, body.Tool, body.Arguments, body.Decision, body.Cites, who)
		if err != nil {
			var refusal actRefusal
			if errors.As(err, &refusal) {
				// The ladder's first step is who is asking: with no identity
				// configured nobody is, and the answer is the one a missing
				// token gets.
				status := http.StatusBadRequest
				if refusal.step == "requester" {
					status = http.StatusUnauthorized
					w.Header().Set("WWW-Authenticate", "Bearer")
				}
				writeJSON(w, status, map[string]any{"error": refusal.reason, "refusedAt": refusal.step})
				return
			}
			fail(w, err)
			return
		}
		writeJSON(w, http.StatusOK, out)
	})

	mux.HandleFunc("/seal", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeJSON(w, http.StatusNotFound, map[string]any{"error": "not found"})
			return
		}
		if _, ok := authenticate(w, r); !ok {
			return
		}
		limitBody(w, r)
		var body struct {
			Session string `json:"session"`
		}
		if err := decodeSingleJSON(r.Body, &body); err != nil {
			fail(w, badRequest{err})
			return
		}
		out, err := g.sealSession(body.Session)
		if err != nil {
			fail(w, err)
			return
		}
		writeJSON(w, http.StatusOK, out)
	})

	// /registry and /publickey stay open: they are the anchors a verifier
	// fetches from the key holder, and a verifier holds no token.
	mux.HandleFunc("/verify", func(w http.ResponseWriter, r *http.Request) {
		if _, ok := authenticate(w, r); !ok {
			return
		}
		out, err := g.verify()
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, out)
	})

	mux.HandleFunc("/registry", func(w http.ResponseWriter, r *http.Request) {
		// The same classifier the verifier uses. The engine made its
		// registry at start, so an absent one is served as no registry at
		// all, never as the empty body an external verifier reads as "no
		// seals"; nor is a registry that is present and unreachable.
		data, present, err := readRegistryBytes(g.regPath)
		if err == nil && !present {
			err = fmt.Errorf("the registry the engine made at its start is not there: %s", g.regPath)
		}
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(data)
	})

	mux.HandleFunc("/publickey", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, g.publicKeyDocument())
	})

	return mux
}

// listenAndServe binds localhost only. This reference has no authentication and
// no access control; it is for self-hosting a trust root and demonstrating the
// mechanism, not a hardened public deployment.
func (g *gatewayService) listenAndServe(address string) error {
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "gateway on http://%s (authority %s, key %s)\n",
		listener.Addr(), g.authority, g.keyID)
	return g.serveOn(listener)
}

// serveOn serves until the service's lifetime ends -- the signal context
// cmdServe bound -- or until Serve fails. Either way it ends the lifetime,
// which kills every source in flight, then waits for every request in flight
// to be answered before it returns, so the process never exits under a
// handler. The grace allows for a source's pipe wait and for the answer to be
// written; a request still open when the grace expires is aborted, and the
// error returned says so.
func (g *gatewayService) serveOn(listener net.Listener) error {
	server := &http.Server{
		Handler:           g.handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
	}
	shutdown := make(chan error, 1)
	go func() {
		<-g.ctx.Done()
		grace := g.waitDelay + 10*time.Second
		graceCtx, cancel := context.WithTimeout(context.Background(), grace)
		defer cancel()
		err := server.Shutdown(graceCtx)
		if err != nil {
			_ = server.Close()
			err = fmt.Errorf("shutdown: the %s grace expired with requests still open, and they were aborted: %w", grace, err)
		}
		shutdown <- err
	}()
	serveErr := server.Serve(listener)
	g.cancel()
	shutdownErr := <-shutdown
	if !errors.Is(serveErr, http.ErrServerClosed) {
		return serveErr
	}
	return shutdownErr
}
