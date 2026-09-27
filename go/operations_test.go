package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func awaitOperation(t *testing.T, g *gatewayService, req operationRequest, want string) operationStatus {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		g.operationsMu.Lock()
		status, e := g.operationStatus(req)
		g.operationsMu.Unlock()
		if e != nil {
			t.Fatal(e)
		}
		if status.State == want {
			return status
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("operation never reached", want)
	return operationStatus{}
}
func operationFixture(t *testing.T) (*gatewayService, operationRequest, string) {
	if !durableOperationsSupported {
		t.Skip("durable operations require Unix directory synchronization")
	}
	g, _ := testService(t)
	dir := t.TempDir()
	req := operationRequest{ID: strings.Repeat("a", 32), Source: "screening", Arguments: canon(barrierArg(dir)), Deadline: time.Now().Add(time.Minute).UTC().Format(time.RFC3339Nano)}
	t.Cleanup(func() {
		g.cancel()
		limit := time.Now().Add(5 * time.Second)
		for time.Now().Before(limit) {
			g.operationsMu.Lock()
			n := len(g.operations)
			g.operationsMu.Unlock()
			if n == 0 {
				return
			}
			time.Sleep(time.Millisecond)
		}
	})
	return g, req, dir
}
func TestDurableOperationDuplicateRetainedResponseAndRestart(t *testing.T) {
	g, req, barrier := operationFixture(t)
	status, code, e := g.startOperation(req)
	if e != nil || code != 202 || status.State != "running" {
		t.Fatal(status, code, e)
	}
	waitForFile(t, filepath.Join(barrier, startedFile))
	started, _ := os.ReadFile(filepath.Join(barrier, startedFile))
	for range 5 {
		if _, code, e = g.startOperation(req); e != nil || code != 202 {
			t.Fatal(code, e)
		}
	}
	changed := req
	changed.Arguments = []byte(`{}`)
	if _, code, e = g.startOperation(changed); e == nil || code != 409 {
		t.Fatal("changed payload reused identity")
	}
	changed = req
	changed.Subject = "another-user"
	if _, code, e = g.startOperation(changed); e == nil || code != 409 {
		t.Fatal("changed caller reused identity")
	}
	openBarrier(t, filepath.Join(barrier, releaseFile))
	done := awaitOperation(t, g, req, "completed")
	if len(done.Response) == 0 {
		t.Fatal("missing original response")
	}
	g2, e := newGatewayService(g.storeRoot, testSeed, "gateway:test", g.regPath, g.sources)
	if e != nil {
		t.Fatal(e)
	}
	defer g2.cancel()
	replay, code, e := g2.startOperation(req)
	if e != nil || code != 200 || !bytes.Equal(done.Response, replay.Response) {
		t.Fatal("lost retained proof across restart", code, e)
	}
	later, _ := os.ReadFile(filepath.Join(barrier, startedFile))
	if !bytes.Equal(started, later) {
		t.Fatal("source executed twice")
	}
	files, _ := filepath.Glob(filepath.Join(g.storeRoot, "receipts", "async."+req.ID, "*.json"))
	if len(files) != 1 {
		t.Fatal("duplicate signed receipts", files)
	}
	var response map[string]json.RawMessage
	if json.Unmarshal(replay.Response, &response) != nil || len(response["salts"]) == 0 {
		t.Fatal("lost commitment salt")
	}
}
func TestDurableOperationUncertainClaimNeverReplayed(t *testing.T) {
	g, req, barrier := operationFixture(t)
	dir := g.operationDir(req.ID)
	if e := os.MkdirAll(dir, 0700); e != nil {
		t.Fatal(e)
	}
	if e := g.store.write(filepath.Join(dir, "request.json"), operationJSON(req), true); e != nil {
		t.Fatal(e)
	}
	if e := g.store.write(filepath.Join(dir, "claim"), []byte("previous-process"), true); e != nil {
		t.Fatal(e)
	}
	status, _, e := g.startOperation(req)
	if e != nil || status.State != "needs-attention" {
		t.Fatal(status, e)
	}
	if _, e = os.Stat(filepath.Join(barrier, startedFile)); !os.IsNotExist(e) {
		t.Fatal("uncertain source replayed")
	}
}
func TestDurableOperationCancellationWinsLateCompletion(t *testing.T) {
	g, req, barrier := operationFixture(t)
	srv := httptest.NewServer(g.handler())
	defer srv.Close()
	if _, _, e := g.startOperation(req); e != nil {
		t.Fatal(e)
	}
	waitForFile(t, filepath.Join(barrier, startedFile))
	code, _ := post(t, srv, "/operations/"+req.ID+"/cancel", `{}`)
	if code != 200 {
		t.Fatal(code)
	}
	openBarrier(t, filepath.Join(barrier, releaseFile))
	status := awaitOperation(t, g, req, "cancelled")
	if len(status.Response) != 0 {
		t.Fatal("cancelled response exposed as evidence")
	}
	for range 3 {
		status, _, e := g.startOperation(req)
		if e != nil || status.State != "cancelled" {
			t.Fatal(status, e)
		}
	}
}
func TestDurableOperationQueuedIntentCanStartAfterRestart(t *testing.T) {
	g, req, barrier := operationFixture(t)
	dir := g.operationDir(req.ID)
	os.MkdirAll(dir, 0700)
	if e := g.store.write(filepath.Join(dir, "request.json"), operationJSON(req), true); e != nil {
		t.Fatal(e)
	}
	openBarrier(t, filepath.Join(barrier, releaseFile))
	if _, _, e := g.startOperation(req); e != nil {
		t.Fatal(e)
	}
	awaitOperation(t, g, req, "completed")
}

func TestDurableOperationUnsupportedPlatformRefusesBeforeAdmission(t *testing.T) {
	if durableOperationsSupported {
		t.Skip("this platform supports durable operations")
	}
	g, _ := testService(t)
	if _, code, e := g.startOperation(operationRequest{ID: strings.Repeat("f", 32)}); e == nil || code != 503 {
		t.Fatal(code, e)
	}
	if _, e := os.Stat(filepath.Join(g.storeRoot, "operations")); !os.IsNotExist(e) {
		t.Fatal("unsupported platform persisted intent")
	}
}

func TestDurableOperationInspectionRequiresOriginalPrincipal(t *testing.T) {
	g, req, _ := operationFixture(t)
	req.Issuer = "issuer"
	req.Subject = "owner"
	dir := g.operationDir(req.ID)
	if e := os.MkdirAll(dir, 0700); e != nil {
		t.Fatal(e)
	}
	if e := g.store.write(filepath.Join(dir, "request.json"), operationJSON(req), true); e != nil {
		t.Fatal(e)
	}
	// No identity configuration must not turn a previously private operation
	// into an anonymously readable/cancellable result after a restart.
	server := httptest.NewServer(g.handler())
	defer server.Close()
	res, e := http.Get(server.URL + "/operations/" + req.ID)
	if e != nil {
		t.Fatal(e)
	}
	res.Body.Close()
	if res.StatusCode != 404 {
		t.Fatal(res.StatusCode)
	}
	if code, _ := post(t, server, "/operations/"+req.ID+"/cancel", `{}`); code != 404 {
		t.Fatal(code)
	}
	if _, e = os.Stat(filepath.Join(dir, "cancelled")); !os.IsNotExist(e) {
		t.Fatal("another principal cancelled the operation")
	}
}
