package main

// Service-level tests: the demonstration this repository exists to make, and the
// hardening around it. Ported from the Python reference when it was retired.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

var testSeed = []byte("judgment-pack-gateway-test-seed!") // exactly 32 bytes

const envSourceHelper = "GATEWAY_TEST_SOURCE_HELPER"

// Barrier channels for the admission tests. The helper announces that it has
// STARTED and then blocks until it is let go, so a test can hold a source
// mid-flight without asserting anything about timing.
const (
	envSourceReady = "GATEWAY_TEST_SOURCE_READY"
	envSourceWait  = "GATEWAY_TEST_SOURCE_WAIT"
	envSourceFail  = "GATEWAY_TEST_SOURCE_FAIL"
	// The helper echoes one variable by name, so a test can see what reached
	// the source's environment; and it can write a body of a stated size, so
	// a test can cross the output bound.
	envSourceEcho = "GATEWAY_TEST_SOURCE_ECHO"
	// envSourceEnvelope makes the helper write its value verbatim on stdout:
	// an adapter's envelope, or whatever a test needs a source to say.
	envSourceEnvelope = "GATEWAY_TEST_SOURCE_ENVELOPE"
	envSourceBig      = "GATEWAY_TEST_SOURCE_BIG"
	// After writing its body the helper can stay alive (hold), or leave a
	// grandchild behind that inherits stdout and stays alive (holder); it can
	// flood stderr with a stated number of bytes and fail; and it can report
	// whether a numbered descriptor reached it open.
	envSourceHold    = "GATEWAY_TEST_SOURCE_HOLD"
	envSourceHolder  = "GATEWAY_TEST_SOURCE_HOLDER"
	envSourceStderr  = "GATEWAY_TEST_SOURCE_STDERR"
	envSourceFdProbe = "GATEWAY_TEST_SOURCE_FD_PROBE"
	// With holder, the grandchild leaves the source's process group, so only
	// the bounded pipe wait can end the acquisition.
	envSourceEscape = "GATEWAY_TEST_SOURCE_ESCAPE"
	// Where the helper writes its grandchild's pid, so the test can kill a
	// holder the gateway did not reach. A process left holding the test
	// binary open makes `go test` unable to delete it on Windows.
	envSourceHolderPid = "GATEWAY_TEST_SOURCE_HOLDER_PID"
	// With holder: the parent exits at once without writing (quiet), and the
	// grandchild waits the stated milliseconds before writing (delay) -- the
	// overflow then arrives after the direct child has already exited.
	envSourceQuiet = "GATEWAY_TEST_SOURCE_QUIET"
	envSourceDelay = "GATEWAY_TEST_SOURCE_DELAY_MS"
	// The holder's pid, given to the grandchild so it can wait until it has
	// been reparented -- until its parent has really exited -- before it
	// writes; a late overflow is only late once the direct child is gone.
	envSourceParentPid = "GATEWAY_TEST_SOURCE_PARENT_PID"
	// The helper writes an array of the stated number of zeros: a result of
	// many values in few bytes.
	envSourceValues = "GATEWAY_TEST_SOURCE_VALUES"
	// The helper exits at once with the stated status, having written
	// nothing; or it writes the canonical arguments it was given on stdout,
	// so a request's own text comes back as the source's output.
	envSourceExit      = "GATEWAY_TEST_SOURCE_EXIT"
	envSourceEchoStdin = "GATEWAY_TEST_SOURCE_ECHO_STDIN"
)

// recordPid publishes a pid atomically: written whole to a sibling file and
// renamed into place, so a reader never sees a truncated record and two
// writers of the same value cannot erase each other.
func recordPid(path string, pid int) {
	tmp := fmt.Sprintf("%s.%d", path, os.Getpid())
	if err := os.WriteFile(tmp, []byte(strconv.Itoa(pid)), 0o600); err != nil {
		return
	}
	_ = os.Rename(tmp, path)
}

// helperEnv is the environment declared for the test source. The gateway no
// longer hands a source its own environment (ADR-0001), so every variable the
// helper reads is declared here by name and copied at spawn time -- which is
// what keeps t.Setenv working between acquisitions.
var helperEnv = []string{envSourceHelper, envSourceReady, envSourceWait, envSourceFail, envSourceEcho, envSourceEnvelope, envSourceBig, envSourceHold, envSourceHolder, envSourceStderr, envSourceFdProbe, envSourceEscape, envSourceHolderPid, envSourceQuiet, envSourceDelay, envSourceParentPid, envSourceValues, envSourceExit, envSourceEchoStdin}

// A barrier named in the ARGUMENTS rather than the environment. Every helper
// this process starts inherits the same environment, so an environment-named
// barrier holds all of them at once and cannot express "hold session A while
// session B keeps working". Arguments differ per acquisition, so they can.
const barrierArgPrefix = "barrier:"

const (
	startedFile = "started"
	releaseFile = "release"
)

// barrierArg builds the arguments value that puts one acquisition's source
// behind the barrier in dir.
func barrierArg(dir string) value { return vString(barrierArgPrefix + dir) }

// barrierDir reports the barrier directory a canonical arguments value names,
// if it names one. An ordinary arguments value does not, and its source runs
// straight through.
func barrierDir(arguments []byte) (string, bool) {
	var s string
	if err := json.Unmarshal(arguments, &s); err != nil {
		return "", false
	}
	return strings.CutPrefix(s, barrierArgPrefix)
}

// awaitFile blocks until path exists. It runs inside the helper process, where
// there is no *testing.T to fail; a helper that is never released is killed by
// the gateway's own subprocess timeout.
func awaitFile(path string) {
	for {
		if _, err := os.Stat(path); err == nil {
			return
		}
		time.Sleep(time.Millisecond)
	}
}

func TestMain(m *testing.M) {
	if os.Getenv(envSourceHelper) == "1" {
		// A holder's grandchild records its own pid first, before anything
		// else can happen to it, so the test can always find it.
		if pidFile := os.Getenv(envSourceHolderPid); pidFile != "" && os.Getenv(envSourceHold) == "1" {
			recordPid(pidFile, os.Getpid())
		}
		if parent := os.Getenv(envSourceParentPid); parent != "" {
			// Wait until the parent named here has exited and this process
			// has been reparented, so what follows happens after the direct
			// child is gone -- bounded, so a parent that never exits does not
			// hold this process forever.
			want, _ := strconv.Atoi(parent)
			deadline := time.Now().Add(10 * time.Second)
			for os.Getppid() == want && time.Now().Before(deadline) {
				time.Sleep(5 * time.Millisecond)
			}
		}
		arguments, _ := io.ReadAll(os.Stdin)
		if status := os.Getenv(envSourceExit); status != "" {
			n, _ := strconv.Atoi(status)
			os.Exit(n)
		}
		if os.Getenv(envSourceEchoStdin) == "1" {
			os.Stdout.Write(arguments)
			os.Exit(0)
		}
		if ready := os.Getenv(envSourceReady); ready != "" {
			_ = os.WriteFile(ready, []byte("started\n"), 0o600)
		}
		if dir, ok := barrierDir(arguments); ok {
			_ = os.WriteFile(filepath.Join(dir, startedFile), []byte("started\n"), 0o600)
			awaitFile(filepath.Join(dir, releaseFile))
		}
		if wait := os.Getenv(envSourceWait); wait != "" {
			awaitFile(wait)
		}
		if os.Getenv(envSourceFail) == "1" {
			fmt.Fprintln(os.Stderr, "source refused")
			os.Exit(1)
		}
		if count := os.Getenv(envSourceValues); count != "" {
			n, _ := strconv.Atoi(count)
			os.Stdout.WriteString("[" + strings.TrimSuffix(strings.Repeat("0,", n), ",") + "]")
			os.Exit(0)
		}
		if text := os.Getenv(envSourceEnvelope); text != "" {
			os.Stdout.WriteString(text)
			os.Exit(0)
		}
		if name := os.Getenv(envSourceEcho); name != "" {
			value, present := os.LookupEnv(name)
			out, _ := json.Marshal(map[string]any{"echo": value, "present": present})
			os.Stdout.Write(out)
			os.Exit(0)
		}
		if fd := os.Getenv(envSourceFdProbe); fd != "" {
			n, _ := strconv.Atoi(fd)
			_, statErr := os.NewFile(uintptr(n), "probe").Stat()
			out, _ := json.Marshal(map[string]any{"open": statErr == nil})
			os.Stdout.Write(out)
			os.Exit(0)
		}
		if size := os.Getenv(envSourceStderr); size != "" {
			n, _ := strconv.Atoi(size)
			os.Stderr.Write(bytes.Repeat([]byte("e"), n))
			os.Exit(1)
		}
		if size := os.Getenv(envSourceBig); size != "" {
			n, _ := strconv.Atoi(size)
			if os.Getenv(envSourceHolder) == "1" {
				// A descendant that inherits stdout and outlives this process.
				// Its environment is built explicitly so it does not itself
				// become a holder; it records its own pid at startup.
				grandchild := exec.Command(os.Args[0])
				grandchild.Env = []string{
					envSourceHelper + "=1", envSourceBig + "=" + size, envSourceHold + "=1",
					envSourceHolderPid + "=" + os.Getenv(envSourceHolderPid),
					envSourceDelay + "=" + os.Getenv(envSourceDelay),
					"PATH=" + os.Getenv("PATH"),
				}
				if os.Getenv(envSourceQuiet) == "1" {
					grandchild.Env = append(grandchild.Env, envSourceParentPid+"="+strconv.Itoa(os.Getpid()))
				}
				grandchild.Stdout = os.Stdout
				if os.Getenv(envSourceEscape) == "1" {
					detachFromProcessGroup(grandchild)
				}
				// Both record the pid: the parent as soon as it knows it, since
				// the group kill can reach the grandchild before it runs a
				// line; the grandchild as its first act, in case the parent is
				// gone. The parent's write precedes its own output, so nothing
				// the gateway does can race it.
				if err := grandchild.Start(); err == nil {
					if pidFile := os.Getenv(envSourceHolderPid); pidFile != "" {
						recordPid(pidFile, grandchild.Process.Pid)
					}
				}
				if os.Getenv(envSourceQuiet) == "1" {
					os.Exit(0)
				}
			}
			if ms := os.Getenv(envSourceDelay); ms != "" {
				d, _ := strconv.Atoi(ms)
				time.Sleep(time.Duration(d) * time.Millisecond)
			}
			fmt.Print(`{"pad":"`)
			os.Stdout.Write(bytes.Repeat([]byte("x"), n))
			fmt.Print(`"}`)
			if os.Getenv(envSourceHold) == "1" {
				time.Sleep(45 * time.Second)
			}
			os.Exit(0)
		}
		fmt.Print(`{"checkedSuccessfully":true,"status":"not_found"}`)
		os.Exit(0)
	}
	os.Exit(m.Run())
}

// waitForFile blocks until path exists. It fails the test rather than returning
// on a deadline, so a barrier that never opens is reported as the bug it is
// instead of silently becoming a race.
func waitForFile(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for {
		if _, err := os.Stat(path); err == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("barrier never opened: %s", path)
		}
		time.Sleep(time.Millisecond)
	}
}

func openBarrier(t *testing.T, path string) {
	t.Helper()
	if err := os.WriteFile(path, []byte("go\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func registryLines(t *testing.T, path string) int {
	t.Helper()
	raw, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return 0
	}
	if err != nil {
		t.Fatal(err)
	}
	return len(bytes.Split(bytes.TrimSpace(raw), []byte("\n"))) - boolToInt(len(bytes.TrimSpace(raw)) == 0)
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func testStore(t *testing.T) (*store, *registryWriter, string, string) {
	t.Helper()
	root := t.TempDir()
	storeRoot := filepath.Join(root, "store")
	registryPath := filepath.Join(root, "registry.jsonl")
	st, err := newStore(storeRoot, testSeed, "gateway:test")
	if err != nil {
		t.Fatal(err)
	}
	reg, err := newRegistryWriter(registryPath, testSeed, noHistory)
	if err != nil {
		t.Fatal(err)
	}
	return st, reg, storeRoot, registryPath
}

// stampSession attests `count` chained receipts, as the gateway would.
func stampSession(t *testing.T, st *store, sessionID string, count int64) {
	t.Helper()
	prev := ""
	for index := int64(0); index < count; index++ {
		payload := newObject()
		payload.set("session", vString(sessionID))
		payload.set("n", vInt(index))
		digest, err := st.retain(canon(payload))
		if err != nil {
			t.Fatal(err)
		}
		core := newObject()
		core.set("receiptVersion", vString(receiptVersion))
		core.set("sessionId", vString(sessionID))
		core.set("callIndex", vInt(index))
		if prev == "" {
			core.set("prevSignature", vNull{})
		} else {
			core.set("prevSignature", vString(prev))
		}
		core.set("source", vString("s"))
		core.set("argumentsDigest", vString("hmac-sha256:"+strings.Repeat("0", 64)))
		core.set("resultDigest", vString(digest))
		core.set("servedAt", vString("2026-07-31T00:00:00Z"))
		core.set("authority", vString("gateway:test"))
		_, signature, err := st.stamp(core)
		if err != nil {
			t.Fatal(err)
		}
		prev = signature
	}
}

func statuses(t *testing.T, storeRoot, registryPath string) (bool, map[string]int) {
	t.Helper()
	public := []byte(mustPublic(t))
	rep, err := verifyWithRegistry(storeRoot, registryPath, "gateway:test", public)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := rep.marshal()
	if err != nil {
		t.Fatal(err)
	}
	var decoded struct {
		OK       bool             `json:"ok"`
		Findings []map[string]any `json:"findings"`
	}
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	counts := map[string]int{}
	for _, f := range decoded.Findings {
		if s, ok := f["status"].(string); ok {
			counts[s]++
		}
	}
	return decoded.OK, counts
}

func mustPublic(t *testing.T) string {
	t.Helper()
	st, err := newStore(t.TempDir(), testSeed, "x")
	if err != nil {
		t.Fatal(err)
	}
	return string(st.publicKey)
}

func TestSealedStoreVerifies(t *testing.T) {
	st, reg, storeRoot, registryPath := testStore(t)
	stampSession(t, st, "sess-a", 3)
	if _, err := reg.seal("sess-a", 3, "2026-07-31T00:00:01Z"); err != nil {
		t.Fatal(err)
	}
	ok, counts := statuses(t, storeRoot, registryPath)
	if !ok {
		t.Fatalf("a sealed, intact store did not verify: %v", counts)
	}
}

// The demonstration: per-receipt verification PASSES the same stores the
// registry-anchored verification rejects.
func TestPerReceiptVerificationMissesWhatTheRegistryCatches(t *testing.T) {
	st, reg, storeRoot, registryPath := testStore(t)
	stampSession(t, st, "sess-a", 3)
	if _, err := reg.seal("sess-a", 3, "2026-07-31T00:00:01Z"); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(storeRoot, "receipts", "sess-a", "2.json")); err != nil {
		t.Fatal(err)
	}
	// Without the anchor: the truncated prefix is a valid chain. An empty
	// registry file, not the null device, which Windows names NUL -- a
	// device name a registry path may not have there (SPEC.md §4.1)
	empty := filepath.Join(t.TempDir(), "empty-registry.jsonl")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	inline, err := verifyWithRegistry(storeRoot, empty, "gateway:test", []byte(mustPublic(t)))
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := inline.marshal()
	if !bytes.Contains(raw, []byte("unregistered-session")) {
		t.Fatal("expected the anchor-less run to see only an unsealed session")
	}
	if bytes.Contains(raw, []byte("signature-mismatch")) || bytes.Contains(raw, []byte("chain-broken")) {
		t.Fatal("per-receipt verification should pass a truncated prefix")
	}
	// With the anchor: caught.
	ok, counts := statuses(t, storeRoot, registryPath)
	if ok || counts["tail-rollback"] != 1 {
		t.Fatalf("tail rollback not caught: ok=%v %v", ok, counts)
	}
}

func TestWholeSessionReplayIsUnregistered(t *testing.T) {
	st, _, storeRoot, registryPath := testStore(t)
	stampSession(t, st, "replayed", 2) // never sealed
	ok, counts := statuses(t, storeRoot, registryPath)
	if ok || counts["unregistered-session"] != 1 {
		t.Fatalf("replay not caught: ok=%v %v", ok, counts)
	}
}

func TestForgedSealIsDropped(t *testing.T) {
	st, _, storeRoot, registryPath := testStore(t)
	stampSession(t, st, "replayed", 2)
	forged := fmt.Sprintf(
		`{"finalCount":2,"keyId":"%s","sealedAt":"x","sessionId":"replayed","signature":"%s"}`,
		keyIDFor([]byte(mustPublic(t))), strings.Repeat("0", 128))
	if err := os.WriteFile(registryPath, []byte(forged+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	ok, counts := statuses(t, storeRoot, registryPath)
	if ok || counts["unregistered-session"] != 1 {
		t.Fatalf("a seal nobody could sign was honoured: ok=%v %v", ok, counts)
	}
}

func TestWholeSessionDeletionIsCaught(t *testing.T) {
	st, reg, storeRoot, registryPath := testStore(t)
	stampSession(t, st, "sess-a", 2)
	stampSession(t, st, "sess-b", 2)
	for _, name := range []string{"sess-a", "sess-b"} {
		if _, err := reg.seal(name, 2, "t"); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.RemoveAll(filepath.Join(storeRoot, "receipts", "sess-b")); err != nil {
		t.Fatal(err)
	}
	ok, counts := statuses(t, storeRoot, registryPath)
	if ok || counts["sealed-session-missing"] != 1 {
		t.Fatalf("deleted session not caught: ok=%v %v", ok, counts)
	}
}

func TestResealIsRefused(t *testing.T) {
	_, reg, _, _ := testStore(t)
	if _, err := reg.seal("sess-a", 3, "t"); err != nil {
		t.Fatal(err)
	}
	if _, err := reg.seal("sess-a", 1, "t"); err == nil {
		t.Fatal("append-only violated: a seal was shrunk")
	}
}

// A session id names a directory under the store, and verification discovers
// sessions by ENUMERATING it. A value that escaped would produce genuinely
// signed receipts verification could never see.
func TestSessionIdIsNotAPath(t *testing.T) {
	st, reg, _, _ := testStore(t)
	core := func(sessionID string) *vObject {
		o := newObject()
		o.set("receiptVersion", vString(receiptVersion))
		o.set("sessionId", vString(sessionID))
		o.set("callIndex", vInt(0))
		o.set("prevSignature", vNull{})
		o.set("source", vString("s"))
		o.set("argumentsDigest", vString("x"))
		o.set("resultDigest", vString("y"))
		o.set("servedAt", vString("t"))
		o.set("authority", vString("gateway:test"))
		return o
	}
	for _, bad := range []string{
		filepath.Join(t.TempDir(), "ESCAPED"), "../../TRAVERSED", "a/b", ".", "..",
		"", strings.Repeat("x", 129), "sess id",
	} {
		if _, _, err := st.stamp(core(bad)); err == nil {
			t.Fatalf("session id %q was accepted", bad)
		}
	}
	for _, good := range []string{"s1", "sess-a", "run_2026.07.31", strings.Repeat("A", 128)} {
		if _, _, err := st.stamp(core(good)); err != nil {
			t.Fatalf("legitimate session id %q was refused: %v", good, err)
		}
	}
	if _, err := reg.seal("../../ESCAPED", 1, "t"); err == nil {
		t.Fatal("the registry sealed an escaping session id")
	}
}

// --- the HTTP surface ------------------------------------------------------

func testService(t *testing.T) (*gatewayService, *httptest.Server) {
	t.Helper()
	t.Setenv(envSourceHelper, "1")
	root := t.TempDir()
	service, err := newGatewayService(
		filepath.Join(root, "store"), testSeed, "gateway:test",
		filepath.Join(root, "registry.jsonl"),
		map[string]sourceSpec{"screening": {argv: []string{os.Args[0]}, env: helperEnv}})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(service.handler())
	t.Cleanup(server.Close)
	return service, server
}

func post(t *testing.T, server *httptest.Server, path, body string) (int, map[string]any) {
	t.Helper()
	resp, err := http.Post(server.URL+path, "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var decoded map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&decoded)
	return resp.StatusCode, decoded
}

func TestAcquireSealVerifyRoundTrip(t *testing.T) {
	service, server := testService(t)

	code, first := post(t, server, "/acquire",
		`{"session":"http-1","source":"screening","arguments":{"q":"acme"}}`)
	if code != http.StatusOK {
		t.Fatalf("acquire failed: %d %v", code, first)
	}
	result := first["result"].(map[string]any)
	if result["status"] != "not_found" {
		t.Fatalf("unexpected result: %v", result)
	}
	receipt := first["receipt"].(map[string]any)
	if receipt["keyId"] != service.keyID {
		t.Fatal("receipt does not name the gateway's key")
	}
	// The response receipt is the complete stored object: every member the
	// signature covers, keyId and signature beside them (SPEC.md §6). A
	// version 3 receipt by default (SPEC.md §1.2a).
	for _, member := range []string{
		"receiptVersion", "sessionId", "callIndex", "prevSignature", "source",
		"argumentsCommitment", "resultDigest", "servedAt", "authority", "kind", "caller",
		"acquisition", "keyId", "signature",
	} {
		if _, present := receipt[member]; !present {
			t.Fatalf("the response receipt must carry %q; got %v", member, receipt)
		}
	}
	if len(receipt) != 14 {
		t.Fatalf("the response receipt carries the receipt's members and nothing else: %v", receipt)
	}
	if receipt["receiptVersion"] != "3" || receipt["kind"] != "acquisition" || receipt["caller"] != nil {
		t.Fatalf("a default receipt is version 3, an acquisition, with no caller: %v", receipt)
	}
	if receipt["prevSignature"] != nil {
		t.Fatalf("the first receipt of a session chains from null: %v", receipt["prevSignature"])
	}
	acquisition := receipt["acquisition"].(map[string]any)
	if acquisition["shape"] != "command" || acquisition["endpoint"] != nil || acquisition["upstreamToken"] != nil {
		t.Fatalf("a bare command is the command shape with nothing known about its acquisition: %v", acquisition)
	}
	// The salt comes back beside the receipt and nowhere else (SPEC.md §6).
	salts, ok := first["salts"].(map[string]any)
	if !ok {
		t.Fatalf("the acquire response must carry salts: %v", first)
	}
	if salt, _ := salts["args"].(string); !isLowerHexOfLen(salt, 64) {
		t.Fatalf("salts.args must be 32 bytes of lowercase hex: %v", salts)
	}
	if _, present := salts["statement"]; present {
		t.Fatal("a null statement has no salt")
	}
	// The caller supplied no receipt and cannot: nothing it sent appears as proof.
	encoded, _ := json.Marshal(receipt)
	if bytes.Contains(encoded, []byte("acme")) {
		t.Fatal("caller-supplied argument leaked into the receipt")
	}

	post(t, server, "/acquire", `{"session":"http-1","source":"screening","arguments":{"q":"beta"}}`)
	if code, body := post(t, server, "/seal", `{"session":"http-1"}`); code != http.StatusOK {
		t.Fatalf("seal failed: %d %v", code, body)
	}

	resp, err := http.Get(server.URL + "/verify")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var verdict map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&verdict)
	if verdict["ok"] != true {
		t.Fatalf("gateway does not verify its own store: %v", verdict)
	}
}

// A third party fetches the public key and checks everything with it -- holding
// no secret, and therefore unable to produce any receipt it just verified.
func TestThirdPartyVerifiesWithThePublicKeyAlone(t *testing.T) {
	service, server := testService(t)
	post(t, server, "/acquire", `{"session":"s1","source":"screening","arguments":{"q":"acme"}}`)
	post(t, server, "/seal", `{"session":"s1"}`)

	resp, err := http.Get(server.URL + "/publickey")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var document map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&document)
	if document["algorithm"] != "ed25519" {
		t.Fatalf("unexpected key document: %v", document)
	}
	public, err := hex.DecodeString(document["publicKey"].(string))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(public, testSeed) {
		t.Fatal("the published key is the secret")
	}
	report, err := verifyWithRegistry(service.storeRoot, service.regPath, "gateway:test", public)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := report.marshal()
	if !bytes.Contains(raw, []byte(`"ok":true`)) {
		t.Fatalf("third-party verification failed: %s", raw)
	}
}

// TestAcquireRefusesNonCanonicalArguments asserts that POST /acquire refuses payloads outside the canonical domain (SPEC.md §1.1) before starting the source subprocess or writing to the store.
func TestAcquireRefusesNonCanonicalArguments(t *testing.T) {
	for _, tc := range []struct {
		name      string
		arguments string
		wantCode  int
		wantErr   string
		wantRun   bool
	}{
		{
			name:      "outside canonical domain",
			arguments: `1.0`,
			wantCode:  http.StatusBadRequest,
			wantErr:   "non-integer number",
			wantRun:   false,
		},
		{
			name:      "exponent notation",
			arguments: `{"n":1e2}`,
			wantCode:  http.StatusBadRequest,
			wantErr:   "exponent notation",
			wantRun:   false,
		},
		{
			name:      "safe-integer range",
			arguments: `{"n":9007199254740992}`,
			wantCode:  http.StatusBadRequest,
			wantErr:   "safe-integer range",
			wantRun:   false,
		},
		{
			name:      "lone surrogate",
			arguments: `{"k":"\ud800"}`,
			wantCode:  http.StatusBadRequest,
			wantErr:   "lone surrogate",
			wantRun:   false,
		},
		{
			name:      "duplicate member name",
			arguments: `{"a":1,"a":2}`,
			wantCode:  http.StatusBadRequest,
			wantErr:   "duplicate member name",
			wantRun:   false,
		},
		{
			name:      "control - valid arguments",
			arguments: `{"q":"acme"}`,
			wantCode:  http.StatusOK,
			wantErr:   "",
			wantRun:   true,
		},
		{
			name:      "control - omitted arguments",
			arguments: ``,
			wantCode:  http.StatusOK,
			wantErr:   "",
			wantRun:   true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			svc, server := testService(t)
			marker := filepath.Join(t.TempDir(), "ran")
			t.Setenv(envSourceReady, marker)

			var requestBody string
			if tc.arguments != "" {
				requestBody = fmt.Sprintf(`{"session":"session-123","source":"screening","arguments":%s}`, tc.arguments)
			} else {
				requestBody = `{"session":"session-123","source":"screening"}`
			}

			statusCode, respBody := post(t, server, "/acquire", requestBody)

			if statusCode != tc.wantCode {
				t.Errorf("got status %d, want %d", statusCode, tc.wantCode)
			}

			if tc.wantErr != "" && !strings.Contains(fmt.Sprint(respBody), tc.wantErr) {
				t.Errorf("got body %v, want it to contain %q", respBody, tc.wantErr)
			}

			_, err := os.Stat(marker)
			if tc.wantRun {
				if err != nil {
					t.Errorf("expected script to run, but marker file check failed: %v", err)
				}
			} else {
				if !os.IsNotExist(err) {
					t.Errorf("expected script NOT to run, but marker file exists (or other err: %v)", err)
				}
			}

			entries, err := os.ReadDir(filepath.Join(svc.storeRoot, "receipts"))
			if err != nil {
				t.Fatalf("ReadDir failed: %v", err)
			}
			if tc.wantRun {
				if len(entries) != 1 {
					t.Errorf("expected 1 receipt, got %d", len(entries))
				}
			} else {
				if len(entries) != 0 {
					t.Errorf("expected 0 receipts, got %d", len(entries))
				}
			}
		})
	}
}

func TestEscapingSessionIsRejectedOverHTTP(t *testing.T) {
	service, server := testService(t)
	for _, bad := range []string{"../../TRAVERSED", "a/b", "/tmp/ESCAPED"} {
		body := fmt.Sprintf(`{"session":%q,"source":"screening","arguments":{}}`, bad)
		if code, _ := post(t, server, "/acquire", body); code != http.StatusBadRequest {
			t.Fatalf("session %q was not refused: %d", bad, code)
		}
	}
	entries, err := os.ReadDir(filepath.Join(service.storeRoot, "receipts"))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("a refused session still wrote receipts: %v", entries)
	}
}

func TestJSONBodiesRejectTrailingValuesAndAllowWhitespace(t *testing.T) {
	tests := []struct {
		name        string
		path        string
		body        string
		setup       func(*testing.T, *gatewayService, *httptest.Server)
		wantCode    int
		wantMessage string
		checkState  func(*testing.T, *gatewayService)
	}{
		{
			name:        "acquire rejects a second object",
			path:        "/acquire",
			body:        `{"session":"trailing-acquire","source":"screening","arguments":{}} {"extra":true}`,
			wantCode:    http.StatusBadRequest,
			wantMessage: "exactly one JSON value",
			checkState: func(t *testing.T, service *gatewayService) {
				entries, err := os.ReadDir(filepath.Join(service.storeRoot, "receipts"))
				if err != nil {
					t.Fatal(err)
				}
				if len(entries) != 0 {
					t.Fatalf("rejected acquire wrote receipts: %v", entries)
				}
			},
		},
		{
			name: "seal rejects a second value",
			path: "/seal",
			body: `{"session":"trailing-seal"} null`,
			setup: func(t *testing.T, _ *gatewayService, server *httptest.Server) {
				if code, _ := post(t, server, "/acquire", `{"session":"trailing-seal","source":"screening","arguments":{}}`); code != http.StatusOK {
					t.Fatalf("setup acquire failed: %d", code)
				}
			},
			wantCode:    http.StatusBadRequest,
			wantMessage: "exactly one JSON value",
			checkState: func(t *testing.T, service *gatewayService) {
				data, err := os.ReadFile(service.regPath)
				if err != nil && !os.IsNotExist(err) {
					t.Fatal(err)
				}
				if len(bytes.TrimSpace(data)) != 0 {
					t.Fatalf("rejected seal changed the registry: %s", data)
				}
			},
		},
		{
			name:     "acquire allows trailing whitespace",
			path:     "/acquire",
			body:     "{\"session\":\"whitespace-acquire\",\"source\":\"screening\",\"arguments\":{}} \t\r\n",
			wantCode: http.StatusOK,
		},
		{
			name: "seal allows trailing whitespace",
			path: "/seal",
			body: "{\"session\":\"whitespace-seal\"}\n\t",
			setup: func(t *testing.T, _ *gatewayService, server *httptest.Server) {
				if code, _ := post(t, server, "/acquire", `{"session":"whitespace-seal","source":"screening","arguments":{}}`); code != http.StatusOK {
					t.Fatalf("setup acquire failed: %d", code)
				}
			},
			wantCode: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			service, server := testService(t)
			if tt.setup != nil {
				tt.setup(t, service, server)
			}
			code, response := post(t, server, tt.path, tt.body)
			if code != tt.wantCode {
				t.Fatalf("unexpected status: got %d, want %d (%v)", code, tt.wantCode, response)
			}
			if tt.wantMessage != "" && !strings.Contains(fmt.Sprint(response["error"]), tt.wantMessage) {
				t.Fatalf("unexpected error: %v", response)
			}
			if tt.checkState != nil {
				tt.checkState(t, service)
			}
		})
	}
}

// The acquire response is evidence on its own: the receipt it carries is the
// complete signed object, byte-equivalent under §1.1 to the one the store
// holds, so a caller can check the signature it was handed without reaching
// into the store — and a tampered member fails that check.
func TestAcquireResponseReceiptVerifiesAlone(t *testing.T) {
	service, server := testService(t)
	resp, err := http.Post(server.URL+"/acquire", "application/json",
		strings.NewReader(`{"session":"alone-1","source":"screening","arguments":{"q":"solo"}}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("acquire failed: %d", resp.StatusCode)
	}
	// The receipt is captured as the raw bytes the wire carried, so §1.1's
	// rules are applied to what was actually received — a wire regression
	// emitting a float literal or a duplicate member is refused here rather
	// than silently normalized by a map decode.
	var envelope struct {
		Receipt json.RawMessage `json:"receipt"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&envelope); err != nil {
		t.Fatal(err)
	}
	canonical, err := canonText(envelope.Receipt)
	if err != nil {
		t.Fatalf("the response receipt must canonicalize per §1.1: %v", err)
	}
	var receipt map[string]any
	if err := json.Unmarshal(canonical, &receipt); err != nil {
		t.Fatal(err)
	}
	stored, err := os.ReadFile(filepath.Join(service.store.root, "receipts", "alone-1", "0.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(canonical, bytes.TrimSuffix(stored, []byte("\n"))) {
		t.Fatalf("the response receipt and the stored receipt must be one object:\nresponse %s\nstored   %s", canonical, stored)
	}

	// The signature checks from the response alone, under §1.2's coverage rule:
	// canon of the receipt with signature removed and every other member kept.
	signature, _ := receipt["signature"].(string)
	sig, err := hex.DecodeString(signature)
	if err != nil {
		t.Fatal(err)
	}
	unsigned := map[string]any{}
	for member, value := range receipt {
		if member != "signature" {
			unsigned[member] = value
		}
	}
	unsignedText, err := json.Marshal(unsigned)
	if err != nil {
		t.Fatal(err)
	}
	unsignedCanon, err := canonText(unsignedText)
	if err != nil {
		t.Fatal(err)
	}
	// The prefix is the one the receipt's own version names (SPEC.md §1.2a).
	prefix := receiptContext
	if receipt["receiptVersion"] == receiptVersion3 {
		prefix = receiptContext3
	}
	public := ed25519.PublicKey(mustPublic(t))
	if !ed25519.Verify(public, append([]byte(prefix), unsignedCanon...), sig) {
		t.Fatal("the signature must verify over the response receipt's own members")
	}

	// One flipped member and the same check fails: the signature covers what
	// the caller was handed, not a shape of it.
	unsigned["source"] = "somewhere-else"
	tamperedText, err := json.Marshal(unsigned)
	if err != nil {
		t.Fatal(err)
	}
	tamperedCanon, err := canonText(tamperedText)
	if err != nil {
		t.Fatal(err)
	}
	if ed25519.Verify(public, append([]byte(prefix), tamperedCanon...), sig) {
		t.Fatal("a tampered member must fail the check")
	}
}

// --- admission (issue #36) -------------------------------------------------
//
// Admission has to be linearized with sealing BEFORE a source runs. Sources are
// slow, cost money, and can have operator-visible side effects, so "this
// session is sealed" must be decided against the state as it is when the
// request arrives -- not as it will be when a subprocess finishes.

func TestAcquireAfterSealDoesNotStartTheSource(t *testing.T) {
	service, _ := testService(t)
	if _, err := service.acquire("race-sealed", "screening", vString("x"), nil); err != nil {
		t.Fatalf("first acquire: %v", err)
	}
	if _, err := service.sealSession("race-sealed"); err != nil {
		t.Fatalf("seal: %v", err)
	}

	// From here the source must never run. It announces itself by creating this
	// file, so "was it started" is a side effect rather than an inference.
	started := filepath.Join(t.TempDir(), "source-started")
	t.Setenv(envSourceReady, started)

	if _, err := service.acquire("race-sealed", "screening", vString("x"), nil); err == nil {
		t.Fatal("acquire on a sealed session must be refused")
	}
	if _, err := os.Stat(started); err == nil {
		t.Fatal("the source ran for an acquisition on a sealed session")
	}
}

// A seal the registry may hold closes the session in the process that
// asked for it, even when sealing failed after the record was written: the
// process judges a session it holds by its map, so the map must not stay
// open behind a seal on disk. A retry of the seal finds the record.
func TestASealThatMayBeWrittenClosesTheSession(t *testing.T) {
	service, _ := testService(t)
	if _, err := service.acquire("seal-unsynced", "screening", vString("x"), nil); err != nil {
		t.Fatalf("acquire: %v", err)
	}
	service.registry.sync = func(*os.File) error { return errors.New("the disk would not sync") }
	if _, err := service.sealSession("seal-unsynced"); err == nil || !strings.Contains(err.Error(), "would not sync") {
		t.Fatalf("a seal whose sync failed: %v", err)
	}
	service.registry.sync = func(f *os.File) error { return f.Sync() }
	seals, _, err := loadSeals(service.regPath, service.publicKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, onDisk := seals["seal-unsynced"]; !onDisk {
		t.Fatal("the stand-in failure left no record: the test tests nothing")
	}
	started := filepath.Join(t.TempDir(), "source-started")
	t.Setenv(envSourceReady, started)
	if _, err := service.acquire("seal-unsynced", "screening", vString("y"), nil); err == nil || !strings.Contains(err.Error(), "session is sealed") {
		t.Fatalf("an acquisition after a seal that may be written: %v", err)
	}
	if _, err := os.Stat(started); err == nil {
		t.Fatal("the source ran for a session whose seal may be written")
	}
	if _, err := service.sealSession("seal-unsynced"); err == nil || !strings.Contains(err.Error(), "already sealed") {
		t.Fatalf("a retry of the seal: %v", err)
	}
	// a write that fails with the record written whole but for its
	// newline leaves a seal a reader loads: the session is closed too
	if _, err := service.acquire("seal-unended", "screening", vString("x"), nil); err != nil {
		t.Fatal(err)
	}
	service.registry.write = func(f *os.File, line []byte) (int, error) {
		n, _ := f.Write(line[:len(line)-1])
		return n, errors.New("the disk filled before the newline")
	}
	if _, err := service.sealSession("seal-unended"); err == nil || !strings.Contains(err.Error(), "before the newline") {
		t.Fatalf("a seal whose newline was not written: %v", err)
	}
	service.registry.write = func(f *os.File, line []byte) (int, error) { return f.Write(line) }
	if seals, _, err := loadSeals(service.regPath, service.publicKey); err != nil {
		t.Fatal(err)
	} else if _, onDisk := seals["seal-unended"]; !onDisk {
		t.Fatal("the stand-in failure left no loadable record: the test tests nothing")
	}
	if _, err := service.acquire("seal-unended", "screening", vString("y"), nil); err == nil || !strings.Contains(err.Error(), "session is sealed") {
		t.Fatalf("an acquisition after a seal written whole but for its newline: %v", err)
	}
	// a write that fails before a byte is written is not a seal, and
	// leaves the session as it was
	if _, err := service.acquire("seal-unwritten", "screening", vString("x"), nil); err != nil {
		t.Fatal(err)
	}
	blocked := service.regPath + ".blocked"
	if err := os.Rename(service.regPath, blocked); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(service.regPath, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := service.sealSession("seal-unwritten"); err == nil {
		t.Fatal("a seal into a registry that cannot be opened succeeded")
	}
	os.Remove(service.regPath)
	os.Rename(blocked, service.regPath)
	if _, err := service.acquire("seal-unwritten", "screening", vString("y"), nil); err != nil {
		t.Fatalf("a session whose seal was never written was closed: %v", err)
	}
}

// A seal starts on a line of its own. A registry whose last line an earlier
// seal left unterminated -- written in part, or whole but for its newline --
// is ended before the next record: joined to that line, the record would make
// one line that is no seal, so a retried seal would answer sealed here and
// load as nothing after a restart, and a seal written whole would be lost
// with the next one.
func TestASealStartsOnALineOfItsOwn(t *testing.T) {
	service, _ := testService(t)
	loaded := func() map[string]seal {
		t.Helper()
		seals, _, err := loadSeals(service.regPath, service.publicKey)
		if err != nil {
			t.Fatal(err)
		}
		return seals
	}
	for _, session := range []string{"torn", "whole", "next"} {
		if _, err := service.acquire(session, "screening", vString("x"), nil); err != nil {
			t.Fatalf("acquire %s: %v", session, err)
		}
	}
	// an earlier seal of "torn" written in part: the start of its record
	handle, err := os.OpenFile(service.regPath, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := handle.WriteString(`{"finalCount":1,"keyId":"`); err != nil {
		t.Fatal(err)
	}
	handle.Close()
	if _, err := service.sealSession("torn"); err != nil {
		t.Fatalf("the retried seal: %v", err)
	}
	if got, ok := loaded()["torn"]; !ok || got.finalCount != 1 {
		t.Fatalf("the seal retried after a torn record does not load: %v", loaded())
	}
	// a seal of "whole" written whole but for its newline
	if _, err := service.sealSession("whole"); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(service.regPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(service.regPath, []byte(strings.TrimSuffix(string(data), "\n")), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, ok := loaded()["whole"]; !ok {
		t.Fatal("an unterminated whole seal does not load: the test tests nothing")
	}
	if _, err := service.sealSession("next"); err != nil {
		t.Fatal(err)
	}
	seals := loaded()
	for _, session := range []string{"torn", "whole", "next"} {
		if _, ok := seals[session]; !ok {
			t.Fatalf("the seal of %s does not load: %v", session, seals)
		}
	}
	// a write that fails once it has ended the earlier line, and before a
	// byte of the record, wrote no seal: the session stays open, and a
	// retry writes the record
	if _, err := service.acquire("ended", "screening", vString("x"), nil); err != nil {
		t.Fatal(err)
	}
	unterminated, err := os.OpenFile(service.regPath, os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := unterminated.WriteString(`{"finalCount":`); err != nil {
		t.Fatal(err)
	}
	unterminated.Close()
	service.registry.write = func(f *os.File, line []byte) (int, error) {
		if line[0] != '\n' {
			t.Fatal("no newline ended the unterminated line: the test tests nothing")
		}
		n, _ := f.Write(line[:1])
		return n, errors.New("the disk filled after one byte")
	}
	if _, err := service.sealSession("ended"); err == nil || !strings.Contains(err.Error(), "after one byte") {
		t.Fatalf("a seal whose record was never written: %v", err)
	}
	service.registry.write = func(f *os.File, line []byte) (int, error) { return f.Write(line) }
	if _, err := service.acquire("ended", "screening", vString("y"), nil); err != nil {
		t.Fatalf("a session whose record was never written was closed: %v", err)
	}
	if _, err := service.sealSession("ended"); err != nil {
		t.Fatalf("the retried seal: %v", err)
	}
	if got, ok := loaded()["ended"]; !ok || got.finalCount != 2 {
		t.Fatalf("the retried seal does not load at its count: %v", loaded())
	}
}

// A seal is final across a restart: a process started on the same store
// and registry refuses an acquisition into a session an earlier process
// sealed, before the source is started -- the registry is the one record of
// that seal, and the new process's session map does not hold it. An
// unsealed session from before the restart may still be continued by a
// read, as it always could; and a registry that cannot be read is a
// refusal, never taken for the absence of a seal.
func TestAcquireAfterRestartHonoursTheRegistrysSeal(t *testing.T) {
	service, _ := testService(t)
	if _, err := service.acquire("restart-sealed", "screening", vString("x"), nil); err != nil {
		t.Fatalf("first acquire: %v", err)
	}
	if _, err := service.sealSession("restart-sealed"); err != nil {
		t.Fatalf("seal: %v", err)
	}
	if _, err := service.acquire("restart-open", "screening", vString("x"), nil); err != nil {
		t.Fatalf("acquire into the unsealed session: %v", err)
	}
	restarted, err := newGatewayService(service.storeRoot, testSeed, "gateway:test", service.regPath, service.sources)
	if err != nil {
		t.Fatal(err)
	}
	// From here the source must never run for the sealed session. It
	// announces itself by creating this file.
	started := filepath.Join(t.TempDir(), "source-started")
	t.Setenv(envSourceReady, started)
	_, err = restarted.acquire("restart-sealed", "screening", vString("x"), nil)
	if err == nil || !strings.Contains(err.Error(), "sealed in the registry") || !errors.As(err, new(badRequest)) {
		t.Fatalf("an acquisition into a session sealed before the restart: %v", err)
	}
	if _, err := os.Stat(started); err == nil {
		t.Fatal("the source ran for a session sealed before the restart")
	}
	if restarted.started.Load() != 0 {
		t.Fatalf("%d sources started for a session sealed before the restart", restarted.started.Load())
	}
	restarted.mu.Lock()
	_, entered := restarted.sessions["restart-sealed"]
	restarted.mu.Unlock()
	if entered {
		t.Fatal("the refused session entered the new process's map")
	}
	// the unsealed session from before the restart: a read may continue it
	// as it always could -- the registry does not refuse it, its source runs,
	// and, its first receipt being on disk, the stamp is the append-only
	// collision it has always been (act_test holds the case where the first
	// receipt is gone and the read succeeds)
	startsBefore := restarted.started.Load()
	_, err = restarted.acquire("restart-open", "screening", vString("x"), nil)
	if err == nil || !strings.Contains(err.Error(), "receipt already exists (append-only)") {
		t.Fatalf("an unsealed session from before the restart: %v", err)
	}
	if restarted.started.Load() != startsBefore+1 {
		t.Fatal("the unsealed session's source did not run: the read was refused before it")
	}
	// a session new to both processes is admitted and minted
	if _, err := restarted.acquire("restart-new", "screening", vString("x"), nil); err != nil {
		t.Fatalf("a new session after the restart: %v", err)
	}
	// a registry that cannot be read refuses a session the process does not
	// hold, and does not start its source, while a held session is still
	// judged by its map: a directory where the file should be, on every
	// platform; a link that leads nowhere, wherever the platform will make
	// one; a file this process may not read, off Windows and not as root.
	// Each case sets the registry aside first and puts it back after,
	// whatever happens in between.
	aside := service.regPath + ".aside"
	unreadable := func(t *testing.T, stand func(t *testing.T)) {
		t.Helper()
		if err := os.Rename(service.regPath, aside); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if err := os.RemoveAll(service.regPath); err != nil {
				t.Error(err)
			}
			if err := os.Rename(aside, service.regPath); err != nil {
				t.Error(err)
			}
		})
		stand(t)
		os.Remove(started)
		before := restarted.started.Load()
		if _, err := restarted.acquire("restart-unknown", "screening", vString("x"), nil); err == nil || !strings.Contains(err.Error(), "registry could not be read") {
			t.Fatalf("an unknown session was not refused for the registry: %v", err)
		}
		if restarted.started.Load() != before {
			t.Fatal("a source started with the registry unreadable")
		}
		if _, err := restarted.acquire("restart-new", "screening", vString(t.Name()), nil); err != nil {
			t.Fatalf("a held session with the registry unreadable: %v", err)
		}
	}
	t.Run("a directory", func(t *testing.T) {
		unreadable(t, func(t *testing.T) {
			if err := os.Mkdir(service.regPath, 0o700); err != nil {
				t.Fatal(err)
			}
		})
	})
	t.Run("a link that leads nowhere", func(t *testing.T) {
		unreadable(t, func(t *testing.T) {
			linkOrSkip(t, filepath.Join(t.TempDir(), "nothing"), service.regPath)
		})
	})
	t.Run("a file this process may not read", func(t *testing.T) {
		if runtime.GOOS == "windows" || os.Geteuid() == 0 {
			t.Skip("permission bits do not bar this process here")
		}
		unreadable(t, func(t *testing.T) {
			data, err := os.ReadFile(aside)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(service.regPath, data, 0o000); err != nil {
				t.Fatal(err)
			}
		})
	})
}

// A seal counting below zero closes its session where the engine checks
// sealing, as it is loaded where the verifier reads the registry (SPEC.md §4
// step 2; §6 loads a seal for /acquire as §4 does). No gateway writes one,
// but a registry holding one, signed under the engine's key and naming its
// keyId, seals the session, at -1 as at the least integer §1.1 admits: an acquisition into it is refused before its
// source starts, an action is refused at the session step, and sealing it
// again is refused. A session the registry does not seal is the control.
func TestASealCountingBelowZeroClosesItsSession(t *testing.T) {
	service, _ := testService(t)
	registry, err := os.OpenFile(service.regPath, os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	priv := ed25519.NewKeyFromSeed(testSeed)
	if _, err := registry.WriteString(sealLine(t, priv, "below-zero", -1) + sealLine(t, priv, "least", minSafeInteger)); err != nil {
		registry.Close()
		t.Fatal(err)
	}
	if err := registry.Close(); err != nil {
		t.Fatal(err)
	}

	for _, check := range []struct {
		name string
		why  func(string) string
	}{
		{"an acquisition's registry check", service.sealedElsewhere},
		{"an action's session step", service.sessionOpen},
	} {
		if got := check.why("below-zero"); !strings.Contains(got, "sealed in the registry") {
			t.Fatalf("%s took a session sealed at -1 for open: %q", check.name, got)
		}
		if got := check.why("least"); !strings.Contains(got, "sealed in the registry") {
			t.Fatalf("%s took a session sealed at the least integer SPEC.md §1.1 admits for open: %q", check.name, got)
		}
		if got := check.why("unsealed"); got != "" {
			t.Fatalf("%s refused a session the registry does not seal: %q", check.name, got)
		}
	}

	started := filepath.Join(t.TempDir(), "source-started")
	t.Setenv(envSourceReady, started)
	if _, err := service.acquire("below-zero", "screening", vString("x"), nil); err == nil || !strings.Contains(err.Error(), "sealed in the registry") || !errors.As(err, new(badRequest)) {
		t.Fatalf("an acquisition into a session sealed at -1: %v", err)
	}
	if service.started.Load() != 0 {
		t.Fatal("a source started for a session sealed at -1")
	}
	if _, err := os.Stat(started); err == nil {
		t.Fatal("the source ran for a session sealed at -1")
	}
	// Unchanged behaviour, not the fix: the writer refuses a seal for a
	// session that any parseable line of the registry names, whatever that
	// line's count or signature, so it refused this one before the fix too.
	if _, err := service.registry.seal("below-zero", 0, nowStamp()); err == nil || !strings.Contains(err.Error(), "already sealed") {
		t.Fatalf("a second seal of a session sealed at -1: %v", err)
	}
	if _, err := service.acquire("unsealed", "screening", vString("x"), nil); err != nil {
		t.Fatalf("an acquisition into a session the registry does not seal: %v", err)
	}
}

func TestSealRefusesWhileAnAcquisitionIsInFlight(t *testing.T) {
	service, _ := testService(t)

	// One receipt first, so the session already EXISTS. Without this the test
	// passes against the unfixed gateway for the wrong reason: there, a session
	// is not created until its source completes, so the seal below fails with
	// "no such session" rather than because work is in flight. Found by
	// mutation-checking this test against the original code.
	if _, err := service.acquire("race-inflight", "screening", vString("x"), nil); err != nil {
		t.Fatalf("seed acquire: %v", err)
	}

	dir := t.TempDir()
	started, release := filepath.Join(dir, "started"), filepath.Join(dir, "release")
	t.Setenv(envSourceReady, started)
	t.Setenv(envSourceWait, release)

	done := make(chan error, 1)
	go func() { _, err := service.acquire("race-inflight", "screening", vString("x"), nil); done <- err }()
	waitForFile(t, started) // the source is now running and cannot finish

	before := registryLines(t, service.regPath)
	if _, err := service.sealSession("race-inflight"); err == nil {
		t.Fatal("seal must refuse while an admitted acquisition is in flight")
	}
	if after := registryLines(t, service.regPath); after != before {
		t.Fatalf("a refused seal wrote %d registry record(s)", after-before)
	}

	openBarrier(t, release)
	if err := <-done; err != nil {
		t.Fatalf("in-flight acquire: %v", err)
	}

	// Once the work it was waiting for has landed, the same seal succeeds and
	// counts that receipt -- the refusal is a retry, not a rejection.
	t.Setenv(envSourceWait, "")
	out, err := service.sealSession("race-inflight")
	if err != nil {
		t.Fatalf("seal after the acquisition finished: %v", err)
	}
	if count, ok := out["finalCount"].(float64); !ok || int(count) != 2 {
		t.Fatalf("finalCount = %v, want 2 (the seed receipt and the in-flight one)",
			out["finalCount"])
	}
}

// The hazard admitting early introduces: a session created for an acquisition
// whose source then FAILED would be left behind, and could be sealed as a real
// zero-receipt session that verifies.
//
// Recorded from a mutation check: this test also passes against the UNFIXED
// gateway, which never created the session in the first place. It does not
// demonstrate the fix -- it guards the new admission path against
// reintroducing the phantom, which is a regression this change could plausibly
// cause and nothing else would catch.
func TestFailedSourceLeavesNoSealablePhantomSession(t *testing.T) {
	service, _ := testService(t)
	t.Setenv(envSourceFail, "1")

	if _, err := service.acquire("race-phantom", "screening", vString("x"), nil); err == nil {
		t.Fatal("a failing source must fail the acquisition")
	}
	if _, err := service.sealSession("race-phantom"); err == nil {
		t.Fatal("a session whose only acquisition failed must not be sealable")
	}
	service.mu.Lock()
	_, present := service.sessions["race-phantom"]
	service.mu.Unlock()
	if present {
		t.Fatal("the failed acquisition left a session behind")
	}
	if lines := registryLines(t, service.regPath); lines != 0 {
		t.Fatalf("registry has %d record(s) after a failed source", lines)
	}
}

// Independent sessions must not serialize, and concurrent successes on one
// session must still receive contiguous indices in completion order.
func TestConcurrentAcquisitionsKeepContiguousIndices(t *testing.T) {
	service, _ := testService(t)
	const n = 6
	done := make(chan error, n)
	for i := 0; i < n; i++ {
		go func() { _, err := service.acquire("race-parallel", "screening", vString("x"), nil); done <- err }()
	}
	for i := 0; i < n; i++ {
		if err := <-done; err != nil {
			t.Fatalf("concurrent acquire: %v", err)
		}
	}
	service.mu.Lock()
	state := service.sessions["race-parallel"]
	index, inFlight := state.index, state.inFlight
	service.mu.Unlock()
	if index != n {
		t.Fatalf("index = %d, want %d", index, n)
	}
	if inFlight != 0 {
		t.Fatalf("inFlight = %d after every acquisition finished, want 0", inFlight)
	}
	for i := 0; i < n; i++ {
		if _, err := os.Stat(filepath.Join(service.storeRoot, "receipts", "race-parallel",
			fmt.Sprintf("%d.json", i))); err != nil {
			t.Fatalf("receipt %d missing: %v", i, err)
		}
	}

	// Contiguous indices are necessary but not sufficient: the prevSignature
	// chain has to be sound too, and only verification checks that. Interleaved
	// stamping would produce n well-named files whose chain forks. The session
	// is deliberately left unsealed, so unregistered-session is expected here
	// and a broken chain or sequence is not.
	_, counts := statuses(t, service.storeRoot, service.regPath)
	if counts["chain-broken"] != 0 || counts["sequence-broken"] != 0 {
		t.Fatalf("chain-broken=%d sequence-broken=%d, want 0 and 0",
			counts["chain-broken"], counts["sequence-broken"])
	}
	if counts["ok"] != n {
		t.Fatalf("%d receipts verify, want %d", counts["ok"], n)
	}
}

// The converse of the in-flight seal refusal: holding one session must not hold
// the gateway. The mutex is taken to admit and released before the source runs,
// so an unrelated session can acquire AND seal while another's source is stuck.
//
// The barrier is named in session A's arguments, not in the environment, because
// every helper subprocess inherits the same environment -- an environment-named
// barrier would hold B's source alongside A's and the test could not tell a
// serialized gateway from a working one.
//
// Recorded from a mutation check: this test passes against the pre-#36 gateway
// too, which also released the mutex around the subprocess. It does not
// demonstrate that change; it pins the property the change had to preserve, and
// it fails if the critical section is ever widened to span a source.
func TestBlockedSourceDoesNotBlockAnIndependentSession(t *testing.T) {
	service, _ := testService(t)

	dir := t.TempDir()
	done := make(chan error, 1)
	go func() { _, err := service.acquire("race-indep-a", "screening", barrierArg(dir), nil); done <- err }()
	waitForFile(t, filepath.Join(dir, startedFile)) // A's source is running and cannot finish

	if _, err := service.acquire("race-indep-b", "screening", vString("x"), nil); err != nil {
		t.Fatalf("session B could not acquire while session A's source was blocked: %v", err)
	}
	out, err := service.sealSession("race-indep-b")
	if err != nil {
		t.Fatalf("session B could not seal while session A's source was blocked: %v", err)
	}
	if count, ok := out["finalCount"].(float64); !ok || int(count) != 1 {
		t.Fatalf("session B finalCount = %v, want 1", out["finalCount"])
	}

	// A is untouched by B's traffic and still completes once released.
	openBarrier(t, filepath.Join(dir, releaseFile))
	if err := <-done; err != nil {
		t.Fatalf("session A acquire: %v", err)
	}
}

// --- request body bounds (issue #40) ---------------------------------------

// countingReader streams a VALID, enormous JSON object and reports how much of
// it the server consumed.
//
// Valid is load-bearing and was learned the hard way: an earlier version of
// this test streamed raw filler, which is not JSON at its first byte, so the
// decoder stopped immediately whether or not a limit existed. The test passed
// against the unbounded gateway — precisely the "rejects it, but only after
// reading all of it" trap this test exists to catch, reproduced inside the
// test itself. A body the decoder is willing to keep reading is the only kind
// that can distinguish the two.
type countingReader struct {
	prefix    []byte
	remaining int64
	suffix    []byte
	read      int64
}

func newCountingBody(total int64) *countingReader {
	prefix := []byte(`{"session":"`)
	suffix := []byte(`"}`)
	return &countingReader{
		prefix:    prefix,
		remaining: total - int64(len(prefix)) - int64(len(suffix)),
		suffix:    suffix,
	}
}

func (c *countingReader) Read(p []byte) (int, error) {
	take := func(src []byte) (int, []byte) {
		n := copy(p, src)
		c.read += int64(n)
		return n, src[n:]
	}
	if len(c.prefix) > 0 {
		n, rest := take(c.prefix)
		c.prefix = rest
		return n, nil
	}
	if c.remaining > 0 {
		n := int64(len(p))
		if n > c.remaining {
			n = c.remaining
		}
		for i := int64(0); i < n; i++ {
			p[i] = 'a'
		}
		c.remaining -= n
		c.read += n
		return int(n), nil
	}
	if len(c.suffix) > 0 {
		n, rest := take(c.suffix)
		c.suffix = rest
		return n, nil
	}
	return 0, io.EOF
}

func TestOversizedRequestBodyIsRefusedWithoutBufferingIt(t *testing.T) {
	service, _ := testService(t)
	handler := service.handler()

	for _, path := range []string{"/acquire", "/seal"} {
		t.Run(path, func(t *testing.T) {
			// Twenty times the limit, streamed rather than materialized, so the
			// test itself does not allocate what it is checking nobody reads.
			body := newCountingBody(20 * maxRequestBody)
			req := httptest.NewRequest(http.MethodPost, path, body)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
			}
			// Some slack for buffering inside net/http and the JSON decoder;
			// the assertion that matters is that it is bounded, not that it is
			// exact.
			if limit := int64(maxRequestBody) + 64*1024; body.read > limit {
				t.Fatalf("server read %d bytes of a %d-byte body; the limit is %d, so "+
					"it buffered past the bound instead of refusing at it",
					body.read, 20*maxRequestBody, maxRequestBody)
			}
		})
	}
}

// --max-request raises the /acquire bound and nothing else: a body past the
// default is admitted to /acquire and still refused by /seal and /act, and a
// body past the raised bound is refused without being buffered.
func TestMaxRequestRaisesTheAcquireBoundAlone(t *testing.T) {
	service, server := testService(t)
	service.maxRequest = 2 * maxRequestBody
	pad := strings.Repeat("x", maxRequestBody+maxRequestBody/2)
	payload := fmt.Sprintf(`{"session":"raised","source":"screening","arguments":{"pad":%q}}`, pad)
	resp, err := http.Post(server.URL+"/acquire", "application/json", strings.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("a body past the default under a raised bound: %d %s", resp.StatusCode, raw)
	}
	seal := fmt.Sprintf(`{"session":"raised","pad":%q}`, pad)
	if code, answer := post(t, server, "/seal", seal); code != http.StatusBadRequest || !strings.Contains(fmt.Sprint(answer["error"]), "request body too large") {
		t.Fatalf("/seal under a raised /acquire bound: %d %v", code, answer)
	}
	body := newCountingBody(20 * service.maxRequest)
	rec := httptest.NewRecorder()
	service.handler().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/acquire", body))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("past the raised bound: %d", rec.Code)
	}
	if limit := service.maxRequest + 64*1024; body.read > limit {
		t.Fatalf("server read %d bytes past a raised bound of %d", body.read, service.maxRequest)
	}
	// /act reads a body only for an authenticated requester, so the service
	// is given an identity for this last request.
	issuer := newIssuer(t)
	id := identityFor(t, issuer)
	service.identity = &id
	token := issuer.mint(t, "ec-1", nil, goodClaims(time.Now()))
	act := fmt.Sprintf(`{"session":"raised","platform":"tickets","tool":"update_ticket","arguments":{"pad":%q}}`, pad)
	if code, answer := authed(t, server, "/act", act, token); code != http.StatusBadRequest || !strings.Contains(fmt.Sprint(answer["error"]), "request body too large") {
		t.Fatalf("/act under a raised /acquire bound: %d %v", code, answer)
	}
}

// An /acquire body of exactly the configured bound is admitted, and one byte
// more is refused before any source runs.
func TestAcquireBodyAtTheBoundIsAdmittedAndOneBytePastIsNot(t *testing.T) {
	service, server := testService(t)
	service.maxRequest = maxRequestBody + 4096
	sized := func(size int64) string {
		frame := `{"session":"exact","source":"screening","arguments":{"pad":""}}`
		open, closing := frame[:len(frame)-3], frame[len(frame)-3:]
		body := open + strings.Repeat("x", int(size)-len(frame)) + closing
		if int64(len(body)) != size {
			t.Fatalf("built a %d-byte body, want %d", len(body), size)
		}
		return body
	}
	code, answer := post(t, server, "/acquire", sized(service.maxRequest))
	if code != http.StatusOK {
		t.Fatalf("a body of exactly the bound: %d %v", code, answer)
	}
	started := service.started.Load()
	code, answer = post(t, server, "/acquire", sized(service.maxRequest+1))
	if code != http.StatusBadRequest || !strings.Contains(fmt.Sprint(answer["error"]), "request body too large") {
		t.Fatalf("a body one byte past the bound: %d %v", code, answer)
	}
	if service.started.Load() != started {
		t.Fatal("a body past the bound started a source")
	}
}

// The value budget: every value the parser makes counts once, member names
// do not, and the value past the budget is refused. parseJSON itself has no
// budget -- a source's output, a stored receipt and a registry line are
// parsed as before.
func TestValueBudget(t *testing.T) {
	for _, tc := range []struct {
		text   string
		values int
	}{
		{`0`, 1},
		{`[0,"a"]`, 3},
		{`{"a":null,"b":[true,{}]}`, 5},
		{`[[],{},[[]]]`, 5},
		{`[false,-1]`, 3},
	} {
		if _, err := parseJSONWithin([]byte(tc.text), tc.values); err != nil {
			t.Fatalf("%s holds %d values and a budget of %d refused it: %v", tc.text, tc.values, tc.values, err)
		}
		_, err := parseJSONWithin([]byte(tc.text), tc.values-1)
		if tc.values == 1 {
			// a budget of zero is no budget
			if err != nil {
				t.Fatalf("%s under no budget: %v", tc.text, err)
			}
			continue
		}
		want := fmt.Sprintf("more JSON values than the budget of %d", tc.values-1)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("%s holds %d values under a budget of %d: %v", tc.text, tc.values, tc.values-1, err)
		}
	}
	// A byte that cannot begin a value is refused as that, not counted: [0,]
	// holds two values, and a budget of two says so.
	if _, err := parseJSONWithin([]byte(`[0,]`), 2); err == nil || !strings.Contains(err.Error(), "unexpected byte ']'") {
		t.Fatalf("[0,] under a budget of 2: %v", err)
	}
	past := []byte("[" + strings.Repeat("0,", maxArgumentValues) + "0]")
	if _, err := parseJSON(past); err != nil {
		t.Fatalf("parseJSON refused %d values: %v", maxArgumentValues+2, err)
	}
}

// The value budget is 524,288, the number README.md and SECURITY.md state, and
// a body of the default bound cannot reach it: a value takes a byte and all
// but one of them a separator or a bracket besides, so a one-mebibyte body --
// here the arguments member alone, an array of zeros and one space -- holds
// at most 524,281 values. That body is refused for its missing session, after
// its arguments were parsed, not for its values.
func TestAOneMebibyteBodyCannotReachTheValueBudget(t *testing.T) {
	if maxArgumentValues != 524288 {
		t.Fatalf("the value budget is %d; README.md and SECURITY.md state 524,288", maxArgumentValues)
	}
	service, server := testService(t)
	if service.maxRequest != maxRequestBody {
		t.Fatalf("the service's /acquire bound is %d, want the default %d", service.maxRequest, maxRequestBody)
	}
	const open, closing = `{"arguments": [`, `]}`
	elements := (maxRequestBody - len(open) - len(closing) + 1) / 2
	body := open + strings.TrimSuffix(strings.Repeat("0,", elements), ",") + closing
	if len(body) != maxRequestBody || elements+1 != 524281 {
		t.Fatalf("built a %d-byte body of %d values, want %d bytes of 524281", len(body), elements+1, maxRequestBody)
	}
	code, answer := post(t, server, "/acquire", body)
	if code != http.StatusBadRequest || !strings.Contains(fmt.Sprint(answer["error"]), "session id must match") {
		t.Fatalf("a one-mebibyte body of %d values: %d %v", elements+1, code, answer)
	}
}

// /acquire holds its arguments to the value budget: exactly the budget is
// admitted, one value more is refused before any source runs, and the
// refusal names the budget.
func TestAcquireArgumentsAreHeldToTheValueBudget(t *testing.T) {
	service, server := testService(t)
	service.maxRequest = 4 * maxRequestBody
	body := func(elements int) string {
		return `{"session":"values","source":"screening","arguments":[` +
			strings.TrimSuffix(strings.Repeat("0,", elements), ",") + `]}`
	}
	// the array is one value, so it holds maxArgumentValues-1 elements
	code, answer := post(t, server, "/acquire", body(maxArgumentValues-1))
	if code != http.StatusOK {
		t.Fatalf("arguments of exactly the budget: %d %v", code, answer)
	}
	started := service.started.Load()
	code, answer = post(t, server, "/acquire", body(maxArgumentValues))
	want := fmt.Sprintf("more JSON values than the budget of %d", maxArgumentValues)
	if code != http.StatusBadRequest || !strings.Contains(fmt.Sprint(answer["error"]), want) {
		t.Fatalf("arguments one value past the budget: %d %v", code, answer)
	}
	if service.started.Load() != started {
		t.Fatal("arguments past the budget started a source")
	}
}

// The value budget is for the arguments: a source may return more values
// than it, within its output bound.
func TestSourceOutputIsNotHeldToTheValueBudget(t *testing.T) {
	service, server := testService(t)
	service.maxSourceOutput = 4 * maxRequestBody
	t.Setenv(envSourceValues, strconv.Itoa(maxArgumentValues+1))
	code, answer := post(t, server, "/acquire", `{"session":"many","source":"screening","arguments":{}}`)
	if code != http.StatusOK {
		t.Fatalf("a result of more values than the argument budget: %d %v", code, answer["error"])
	}
	if result, ok := answer["result"].([]any); !ok || len(result) != maxArgumentValues+1 {
		t.Fatalf("the result did not come back whole")
	}
}

// A source's context is made for the timeout declared for that source, and
// for the default -- thirty seconds, the figure README.md and SECURITY.md
// state -- for a source that declared none. The figure is read from the seam
// that makes the context, exactly, rather than from a clock, so no scheduler
// decides what this test says; what the run reads of the deadline is then
// checked to be the context's own and not that figure worked out again.
func TestSourceDeadlineIsItsOwnTimeout(t *testing.T) {
	service, _ := testService(t)
	spec := service.sources["screening"]
	spec.timeout = 45 * time.Second
	service.sources["screening"] = spec
	other := spec
	other.timeout = 0
	service.sources["other"] = other
	// The source each request is for: these are made one after another, so
	// the seam below records the timeout it was handed against the source
	// that asked for it.
	var making string
	made := map[string]time.Duration{}
	// The context this makes carries a deadline further off than the timeout
	// it was handed, by a margin no scheduler accounts for, so a deadline
	// read from the context can be told from that figure worked out again.
	const further = 5 * time.Minute
	service.sourceContext = func(parent context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
		made[making] = timeout
		return context.WithDeadline(parent, time.Now().Add(timeout+further))
	}
	remaining := map[string]time.Duration{}
	service.sourceDeadline = func(source string, deadline time.Time) {
		remaining[source] = time.Until(deadline)
	}
	for _, source := range []string{"screening", "other"} {
		making = source
		if _, err := service.acquire("deadline-"+source, source, newObject(), nil); err != nil {
			t.Fatalf("%s: %v", source, err)
		}
	}
	// The default is written out rather than named, so a change to
	// defaultSourceTimeout is a change this test sees.
	for source, want := range map[string]time.Duration{"screening": 45 * time.Second, "other": 30 * time.Second} {
		got, seen := made[source]
		if !seen || got != want {
			t.Fatalf("%s's context was made for %v, want %v", source, got, want)
		}
		// and what the run reads is that context's own deadline, not the
		// timeout worked out again: the margin above tells the two apart.
		left, read := remaining[source]
		if !read || left <= want || left > want+further {
			t.Fatalf("%s's run read %v of deadline, want the context's own, between %v and %v", source, left, want, want+further)
		}
	}
}

// deadlineOnDemand is a source's context whose deadline the test ends. Until
// then it is a context whose deadline has not passed; ended, its Done closes
// and its Err is context.DeadlineExceeded, as a real deadline's are, so
// os/exec cancels the source as it does at a real one. The cancel runSource
// defers, an overflow's stop and the service's shutdown end it as cancelled.
type deadlineOnDemand struct {
	parent   context.Context
	deadline time.Time
	done     chan struct{}
	mu       sync.Mutex
	err      error
}

func (c *deadlineOnDemand) Deadline() (time.Time, bool) { return c.deadline, true }
func (c *deadlineOnDemand) Done() <-chan struct{}       { return c.done }
func (c *deadlineOnDemand) Value(key any) any           { return c.parent.Value(key) }

func (c *deadlineOnDemand) Err() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.err
}

// end ends the context with err, and reports whether it was this call that
// ended it.
func (c *deadlineOnDemand) end(err error) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.err != nil {
		return false
	}
	c.err = err
	close(c.done)
	return true
}

// deadlinesOnDemand makes the service's source contexts deadlineOnDemand
// ones, and returns what ends the deadline of the last one made: it reports
// whether that ended a context still running, and so is false when no source
// context was made through the seam.
func deadlinesOnDemand(service *gatewayService) (expire func() bool) {
	var mu sync.Mutex
	var last *deadlineOnDemand
	service.sourceContext = func(parent context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
		c := &deadlineOnDemand{parent: parent, deadline: time.Now().Add(timeout), done: make(chan struct{})}
		go func() {
			select {
			case <-parent.Done():
				c.end(parent.Err())
			case <-c.done:
			}
		}()
		mu.Lock()
		last = c
		mu.Unlock()
		return c, func() { c.end(context.Canceled) }
	}
	return func() bool {
		mu.Lock()
		c := last
		mu.Unlock()
		return c != nil && c.end(context.DeadlineExceeded)
	}
}

// answered is what a request made in the background came to.
type answered struct {
	code  int
	error string
	err   error
}

// postInBackground posts body to path and delivers the answer on the channel
// it returns.
func postInBackground(server *httptest.Server, path, body string) <-chan answered {
	done := make(chan answered, 1)
	go func() {
		resp, err := http.Post(server.URL+path, "application/json", strings.NewReader(body))
		if err != nil {
			done <- answered{err: err}
			return
		}
		defer resp.Body.Close()
		var answer map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&answer)
		done <- answered{code: resp.StatusCode, error: fmt.Sprint(answer["error"])}
	}()
	return done
}

// awaitAnswer is the background request's answer; the wait is a guard
// against a hang, not a bound anything is held to.
func awaitAnswer(t *testing.T, done <-chan answered, hang time.Duration) answered {
	t.Helper()
	select {
	case got := <-done:
		if got.err != nil {
			t.Fatal(got.err)
		}
		return got
	case <-time.After(hang):
		t.Fatalf("the request was not answered within %v", hang)
		return answered{}
	}
}

// awaitStartedOrAnswered waits until the source announces at ready that it
// started, or until the request is answered first, which fails the test with
// that answer rather than waiting for an announcement that will not come.
func awaitStartedOrAnswered(t *testing.T, ready string, done <-chan answered) {
	t.Helper()
	guard := time.After(60 * time.Second)
	for {
		if _, err := os.Stat(ready); err == nil {
			return
		}
		select {
		case got := <-done:
			t.Fatalf("the request was answered before its source started: %d %s %v", got.code, got.error, got.err)
		case <-guard:
			t.Fatalf("the source never announced that it started: %s", ready)
		case <-time.After(time.Millisecond):
		}
	}
}

// A source still running when its deadline passes is ended there, and the
// caller is told so, with the timeout's figure: for a source --source-timeout
// names, and for one under the default, which the test sets to a figure of its
// own. The test ends the deadline itself once the source has announced that it
// started, so neither how long the source takes to start nor the scheduler
// decides what is reported; TestSourceTimeoutAtARealDeadline is the same end at
// a real deadline.
func TestSourceTimeoutEndsTheSource(t *testing.T) {
	for _, tt := range []struct {
		name string
		want string
		set  func(*testing.T, *gatewayService)
	}{
		{"a source --source-timeout names", "did not finish within its 45-second timeout", func(_ *testing.T, service *gatewayService) {
			spec := service.sources["screening"]
			spec.timeout = 45 * time.Second
			service.sources["screening"] = spec
		}},
		{"a source under the default", "did not finish within its 17-second timeout", func(t *testing.T, service *gatewayService) {
			if spec := service.sources["screening"]; spec.timeout != 0 {
				t.Fatalf("the test source declares a timeout of %v", spec.timeout)
			}
			service.defaultTimeout = 17 * time.Second
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			service, server := testService(t)
			// Run before the server's close: a source a failed run left
			// waiting is killed rather than left holding the close.
			t.Cleanup(service.cancel)
			tt.set(t, service)
			expire := deadlinesOnDemand(service)
			dir := t.TempDir()
			ready := filepath.Join(dir, "started")
			t.Setenv(envSourceReady, ready)
			t.Setenv(envSourceWait, filepath.Join(dir, "never"))
			done := postInBackground(server, "/acquire", `{"session":"slow","source":"screening","arguments":{}}`)
			awaitStartedOrAnswered(t, ready, done)
			if !expire() {
				t.Fatal("the source's context was not the one the test ends")
			}
			got := awaitAnswer(t, done, 60*time.Second)
			if got.code != http.StatusBadRequest || !strings.Contains(got.error, tt.want) {
				t.Fatalf("a source past its deadline: %d %s", got.code, got.error)
			}
		})
	}
}

// The timeout at a real deadline: five seconds, long enough that a slow
// start does not reach it, ends the source and is reported with its figure.
// The wait for the answer guards against a hang only.
func TestSourceTimeoutAtARealDeadline(t *testing.T) {
	service, server := testService(t)
	t.Cleanup(service.cancel)
	spec := service.sources["screening"]
	spec.timeout = 5 * time.Second
	service.sources["screening"] = spec
	dir := t.TempDir()
	ready := filepath.Join(dir, "started")
	t.Setenv(envSourceReady, ready)
	t.Setenv(envSourceWait, filepath.Join(dir, "never"))
	done := postInBackground(server, "/acquire", `{"session":"slow","source":"screening","arguments":{}}`)
	got := awaitAnswer(t, done, 120*time.Second)
	if got.code != http.StatusBadRequest || !strings.Contains(got.error, "did not finish within its 5-second timeout") {
		t.Fatalf("a source past its timeout: %d %s", got.code, got.error)
	}
	if _, err := os.Stat(ready); err != nil {
		t.Fatalf("the source had not started, so its refusal says nothing of a running source's timeout: %v", err)
	}
}

// A source that ended on its own is reported as what it did, even when its
// deadline passes before the gateway has finished with it: the test ends the
// deadline once the source has been waited for, before its failure is
// attributed, and the source, which was not cancelled, is not said to have
// timed out.
func TestASourceOvertakenByItsDeadlineIsNotATimeout(t *testing.T) {
	for _, tc := range []struct {
		name     string
		fail     string
		wantCode int
		want     string
	}{
		{name: "failed", fail: "1", wantCode: http.StatusBadRequest, want: "source failed: source refused"},
		{name: "succeeded", wantCode: http.StatusOK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			service, server := testService(t)
			t.Setenv(envSourceFail, tc.fail)
			expire := deadlinesOnDemand(service)
			var expired atomic.Bool
			service.afterSourceWait = func() { expired.Store(expire()) }
			code, answer := post(t, server, "/acquire", `{"session":"overtaken","source":"screening","arguments":{}}`)
			if !expired.Load() {
				t.Fatal("the deadline was not ended between the source's wait and its attribution")
			}
			if code != tc.wantCode || (tc.want != "" && strings.TrimSpace(fmt.Sprint(answer["error"])) != tc.want) {
				t.Fatalf("a source that ended on its own, overtaken by its deadline: %d %v", code, answer)
			}
		})
	}
}

// The timeout is said of a source only when its cancellation succeeded, its
// context ended at its deadline, and it did not exit on its own -- judged on
// the wait errors real processes give: the helper exiting with status 7, and
// the helper killed. On Unix the status tells the exit from the kill; elsewhere
// it does not, and a cancellation that returns an error, as the kill of a
// process os/exec has collected does, is what leaves the flag unset.
func TestSourceTimeoutAttribution(t *testing.T) {
	helper := func(env ...string) *exec.Cmd {
		cmd := exec.Command(os.Args[0])
		cmd.Env = append([]string{envSourceHelper + "=1", "PATH=" + os.Getenv("PATH")}, env...)
		return cmd
	}
	exited := helper(envSourceExit + "=7").Run()
	var exit *exec.ExitError
	if !errors.As(exited, &exit) || exit.ExitCode() != 7 {
		t.Fatalf("the helper did not exit with status 7: %v", exited)
	}
	killedCmd := helper(envSourceWait + "=" + filepath.Join(t.TempDir(), "never"))
	if err := killedCmd.Start(); err != nil {
		t.Fatal(err)
	}
	if err := killedCmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	killed := killedCmd.Wait()
	if !errors.As(killed, &exit) {
		t.Fatalf("the killed helper's wait error is not an exit: %v", killed)
	}

	if got := exitedOnItsOwn(exited); got != exitStatusTellsAKill {
		t.Fatalf("an exit with status 7 exited on its own: %v, want %v", got, exitStatusTellsAKill)
	}
	if exitedOnItsOwn(killed) || exitedOnItsOwn(nil) || exitedOnItsOwn(context.DeadlineExceeded) {
		t.Fatal("a killed source, no error or a deadline's error was taken for an exit on its own")
	}
	if got := sourceTimedOut(true, context.DeadlineExceeded, exited); got == exitStatusTellsAKill {
		t.Fatalf("a cancelled source that exited with status 7 at its deadline timed out: %v", got)
	}
	if !sourceTimedOut(true, context.DeadlineExceeded, killed) {
		t.Fatal("a source cancelled and killed at its deadline did not time out")
	}
	for _, tc := range []struct {
		name      string
		cancelled bool
		ctxErr    error
	}{
		{"not cancelled", false, context.DeadlineExceeded},
		{"cancelled by shutdown or an overflow", true, context.Canceled},
		{"a context that has not ended", true, nil},
	} {
		if sourceTimedOut(tc.cancelled, tc.ctxErr, killed) {
			t.Fatalf("%s: a killed source timed out", tc.name)
		}
	}

	var cancelled atomic.Bool
	if err := recordCancellation(func() error { return os.ErrProcessDone }, &cancelled)(); !errors.Is(err, os.ErrProcessDone) || cancelled.Load() {
		t.Fatalf("a cancellation that failed: returned %v, recorded %v", err, cancelled.Load())
	}
	if err := recordCancellation(func() error { return nil }, &cancelled)(); err != nil || !cancelled.Load() {
		t.Fatalf("a cancellation that succeeded: returned %v, recorded %v", err, cancelled.Load())
	}
}

func TestBodyAtOrBelowTheLimitIsUnaffected(t *testing.T) {
	service, server := testService(t)
	_ = service

	// Padding the arguments object to just under the limit must still work, and
	// must still produce a receipt: the bound is a ceiling, not a new rejection
	// path for ordinary requests.
	pad := strings.Repeat("x", maxRequestBody-4096)
	payload := fmt.Sprintf(`{"session":"bounded","source":"screening","arguments":{"pad":%q}}`, pad)
	if len(payload) >= maxRequestBody {
		t.Fatalf("test payload %d bytes is not below the %d-byte limit", len(payload), maxRequestBody)
	}
	resp, err := http.Post(server.URL+"/acquire", "application/json", strings.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 200: %s", resp.StatusCode, raw)
	}

	// And trailing whitespace still parses, so #37's contract is untouched.
	resp2, err := http.Post(server.URL+"/seal", "application/json",
		strings.NewReader(`{"session":"bounded"}`+"\n\n  "))
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp2.Body)
		t.Fatalf("seal status = %d, want 200: %s", resp2.StatusCode, raw)
	}
}

func TestVerifyMissingReceiptsRoot(t *testing.T) {
	// the corpus materializer structurally creates the receipts and artifacts directories for every vector, so the frozen corpus cannot express a missing receipts root.

	t.Run("missing receipts root", func(t *testing.T) {
		st, reg, storeRoot, registryPath := testStore(t)
		stampSession(t, st, "sess-a", 2)
		if _, err := reg.seal("sess-a", 2, "t"); err != nil {
			t.Fatal(err)
		}
		if err := os.RemoveAll(filepath.Join(storeRoot, "receipts")); err != nil {
			t.Fatal(err)
		}
		ok, counts := statuses(t, storeRoot, registryPath)
		if ok || counts["sealed-session-missing"] != 1 {
			t.Fatalf("deleted receipts root not caught: ok=%v %v", ok, counts)
		}
	})

	t.Run("non-existent store root", func(t *testing.T) {
		_, _, storeRoot, registryPath := testStore(t)
		missingRoot := filepath.Join(storeRoot, "does-not-exist")
		ok, findings := statuses(t, missingRoot, registryPath)
		if !ok {
			t.Errorf("expected ok=true, got ok=%v", ok)
		}
		if len(findings) != 0 {
			t.Errorf("expected 0 findings, got %v", findings)
		}
	})

	t.Run("empty store", func(t *testing.T) {
		_, _, storeRoot, registryPath := testStore(t)
		ok, counts := statuses(t, storeRoot, registryPath)
		if !ok || len(counts) > 0 {
			t.Fatalf("empty store failed verification: ok=%v %v", ok, counts)
		}
	})
}

// --- /registry endpoint (issue #53) ----------------------------------------
func TestRegistryEndpointServesRawBytes(t *testing.T) {
	t.Run("empty before any seal", func(t *testing.T) {
		service, server := testService(t)

		resp, err := http.Get(server.URL + "/registry")
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
		}
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		if len(body) != 0 {
			t.Fatalf("body = %d bytes, want 0 (the empty registry the start made)", len(body))
		}

		// the start made the registry, empty; no seal has been written
		if info, err := os.Stat(service.regPath); err != nil || info.Size() != 0 {
			t.Fatalf("registry before any seal: %v %v, want an empty file", info, err)
		}
	})

	t.Run("byte-identical to file after seals", func(t *testing.T) {
		service, server := testService(t)

		// accquire 2 sessions
		if code, _ := post(t, server, "/acquire",
			`{"session":"reg-a","source":"screening","arguments":{}}`); code != http.StatusOK {
			t.Fatalf("acquire reg-a: %d", code)
		}
		if code, _ := post(t, server, "/acquire",
			`{"session":"reg-b","source":"screening","arguments":{}}`); code != http.StatusOK {
			t.Fatalf("acquire reg-b: %d", code)
		}

		// Seal both sessions.
		if code, _ := post(t, server, "/seal", `{"session":"reg-a"}`); code != http.StatusOK {
			t.Fatalf("seal reg-a: %d", code)
		}
		if code, _ := post(t, server, "/seal", `{"session":"reg-b"}`); code != http.StatusOK {
			t.Fatalf("seal reg-b: %d", code)
		}

		// Fetch /registry and read the file directly.
		resp, err := http.Get(server.URL + "/registry")
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
		}
		wire, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		disk, err := os.ReadFile(service.regPath)
		if err != nil {
			t.Fatal(err)
		}

		if !bytes.Equal(wire, disk) {
			t.Fatalf("/registry response is not byte-identical to the file on disk:\nwire: %s\ndisk: %s", wire, disk)
		}
	})

	t.Run("each line is canonical", func(t *testing.T) {
		service, server := testService(t)
		_ = service

		post(t, server, "/acquire", `{"session":"canon-a","source":"screening","arguments":{}}`)
		post(t, server, "/acquire", `{"session":"canon-b","source":"screening","arguments":{}}`)
		post(t, server, "/seal", `{"session":"canon-a"}`)
		post(t, server, "/seal", `{"session":"canon-b"}`)

		resp, err := http.Get(server.URL + "/registry")
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		wire, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}

		lines := bytes.Split(bytes.TrimSpace(wire), []byte("\n"))
		if len(lines) != 2 {
			t.Fatalf("expected 2 seal lines, got %d", len(lines))
		}
		for i, line := range lines {
			// Must parse.
			if _, err := parseJSON(line); err != nil {
				t.Fatalf("line %d: parse failed: %v", i, err)
			}
			// Must equal its own canonical form.
			reCanon, err := canonText(line)
			if err != nil {
				t.Fatalf("line %d: canonicalize failed: %v", i, err)
			}
			if !bytes.Equal(line, reCanon) {
				t.Fatalf("line %d is not canonical:\ngot:  %s\nwant: %s", i, line, reCanon)
			}
		}
	})

	t.Run("loadSeals loads both sessions", func(t *testing.T) {
		service, server := testService(t)
		_ = service

		// Seal two sessions.
		post(t, server, "/acquire", `{"session":"load-a","source":"screening","arguments":{}}`)
		post(t, server, "/acquire", `{"session":"load-b","source":"screening","arguments":{}}`)
		post(t, server, "/seal", `{"session":"load-a"}`)
		post(t, server, "/seal", `{"session":"load-b"}`)

		resp, err := http.Get(server.URL + "/registry")
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		wire, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}

		tmp := filepath.Join(t.TempDir(), "served-registry.jsonl")
		if err := os.WriteFile(tmp, wire, 0o600); err != nil {
			t.Fatal(err)
		}

		public := []byte(mustPublic(t))
		seals, _, err := loadSeals(tmp, public)
		if err != nil {
			t.Fatal(err)
		}

		// Both sessions must be present.
		if len(seals) != 2 {
			t.Fatalf("loadSeals loaded %d seal(s), want 2", len(seals))
		}
		for _, want := range []string{"load-a", "load-b"} {
			if _, ok := seals[want]; !ok {
				t.Fatalf("loadSeals missing session %q", want)
			}
		}
	})
}

func TestMethodContractForStateChangingRoutes(t *testing.T) {
	tests := []struct {
		method string
		route  string
		body   string
		name   string
	}{
		{http.MethodGet, "/acquire", "", "GET /acquire nil body"},
		{http.MethodPut, "/acquire", "", "PUT /acquire nil body"},
		{http.MethodDelete, "/acquire", "", "DELETE /acquire nil body"},
		{http.MethodGet, "/seal", "", "GET /seal nil body"},
		{http.MethodPut, "/seal", "", "PUT /seal nil body"},
		{http.MethodDelete, "/seal", "", "DELETE /seal nil body"},
		// The load-bearing rows that make the side-effect assertions active
		{http.MethodGet, "/acquire", `{"session":"test-session","source":"screening"}`, "GET /acquire valid body"},
		{http.MethodGet, "/seal", `{"session":"test-session"}`, "GET /seal valid body"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			svc, _ := testService(t)
			storeRoot := svc.storeRoot
			regPath := svc.regPath

			var reqBody io.Reader
			if tc.body != "" {
				reqBody = strings.NewReader(tc.body)
			}
			req := httptest.NewRequest(tc.method, tc.route, reqBody)
			rr := httptest.NewRecorder()

			svc.handler().ServeHTTP(rr, req)

			if rr.Code != http.StatusNotFound {
				t.Errorf("Code = %d, want %d", rr.Code, http.StatusNotFound)
			}

			body := strings.TrimSpace(rr.Body.String())
			if body != `{"error":"not found"}` {
				t.Errorf("Body = %q, want %q", body, `{"error":"not found"}`)
			}

			entries, err := os.ReadDir(filepath.Join(storeRoot, "receipts"))
			if err != nil {
				t.Errorf("ReadDir error = %v, want nil", err)
			}
			if len(entries) != 0 {
				t.Errorf("len(entries) = %d, want 0", len(entries))
			}

			// nothing sealed: the registry is as the start made it, empty
			if info, err := os.Stat(regPath); err != nil || info.Size() != 0 {
				t.Errorf("registry = %v %v, want the empty file the start made", info, err)
			}
		})
	}
}

// --receipt-version 2 keeps the version 2 form for a consumer not yet updated:
// the eleven members, the keyed arguments digest, and no salts.
func TestAcquireMintsVersion2WhenConfigured(t *testing.T) {
	service, server := testService(t)
	service.receiptVersion = receiptVersion
	code, first := post(t, server, "/acquire",
		`{"session":"v2-1","source":"screening","arguments":{"q":"acme"}}`)
	if code != http.StatusOK {
		t.Fatalf("acquire failed: %d %v", code, first)
	}
	receipt := first["receipt"].(map[string]any)
	for _, member := range []string{
		"receiptVersion", "sessionId", "callIndex", "prevSignature", "source",
		"argumentsDigest", "resultDigest", "servedAt", "authority", "keyId", "signature",
	} {
		if _, present := receipt[member]; !present {
			t.Fatalf("the version 2 receipt must carry %q; got %v", member, receipt)
		}
	}
	if len(receipt) != 11 || receipt["receiptVersion"] != "2" {
		t.Fatalf("the version 2 receipt carries its eleven members and nothing else: %v", receipt)
	}
	if _, present := first["salts"]; present {
		t.Fatal("a version 2 acquisition has no salts")
	}
	if code, body := post(t, server, "/seal", `{"session":"v2-1"}`); code != http.StatusOK {
		t.Fatalf("seal failed: %d %v", code, body)
	}
	report, err := verifyWithRegistry(service.storeRoot, service.regPath, "gateway:test", service.publicKey)
	if err != nil || !report.OK {
		t.Fatalf("a version 2 store minted on request must verify: %v %v", err, report)
	}
}
