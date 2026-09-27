package main

// Asynchronous control-plane state is not evidence. Only a completed ordinary
// acquisition response is consumable. Immutable claims are never reclaimed.
import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

var operationID = regexp.MustCompile(`^[a-f0-9]{32}$`)
var operationMembers = map[string]bool{"id": true, "source": true, "arguments": true, "deadline": true}

type operationRequest struct {
	ID          string          `json:"id"`
	Source      string          `json:"source"`
	Arguments   json.RawMessage `json:"arguments"`
	Deadline    string          `json:"deadline"`
	Issuer      string          `json:"issuer,omitempty"`
	Subject     string          `json:"subject,omitempty"`
	TokenDigest string          `json:"tokenDigest,omitempty"`
}
type operationStatus struct {
	ID       string          `json:"id"`
	State    string          `json:"state"`
	Deadline string          `json:"deadline"`
	Response json.RawMessage `json:"response,omitempty"`
	Reason   string          `json:"reason,omitempty"`
}

func operationJSON(v any) []byte { b, _ := json.Marshal(v); return b }
func (g *gatewayService) operationDir(id string) string {
	return filepath.Join(g.storeRoot, "operations", id)
}
func (g *gatewayService) operationRoutes(mux *http.ServeMux, auth func(http.ResponseWriter, *http.Request) (*caller, bool), write func(http.ResponseWriter, int, any), fail func(http.ResponseWriter, error)) {
	mux.HandleFunc("/operations", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			write(w, 404, map[string]string{"error": "not found"})
			return
		}
		who, ok := auth(w, r)
		if !ok {
			return
		}
		limitBodyTo(w, r, g.maxRequest)
		body, e := requestMembers(r.Body, operationMembers)
		if e != nil {
			fail(w, badRequest{e})
			return
		}
		var req operationRequest
		req.ID, e = memberText(body, "id")
		if e == nil {
			req.Source, e = memberText(body, "source")
		}
		if e == nil {
			req.Deadline, e = memberText(body, "deadline")
		}
		if e != nil {
			fail(w, badRequest{e})
			return
		}
		args := value(newObject())
		if len(body["arguments"]) > 0 {
			args, e = parseJSONWithin(body["arguments"], maxArgumentValues)
		}
		if e != nil {
			fail(w, badRequest{e})
			return
		}
		req.Arguments = canon(args)
		if who != nil {
			req.Issuer = who.issuer
			req.Subject = who.subject
			req.TokenDigest = who.tokenDigest
		}
		status, code, e := g.startOperation(req)
		if e != nil {
			write(w, code, map[string]string{"error": e.Error()})
			return
		}
		write(w, code, status)
	})
	mux.HandleFunc("/operations/", func(w http.ResponseWriter, r *http.Request) {
		who, ok := auth(w, r)
		if !ok {
			return
		}
		id := strings.TrimPrefix(r.URL.Path, "/operations/")
		cancel := strings.HasSuffix(id, "/cancel")
		id = strings.TrimSuffix(id, "/cancel")
		if !operationID.MatchString(id) || (!cancel && r.Method != http.MethodGet) || (cancel && r.Method != http.MethodPost) {
			write(w, 404, map[string]string{"error": "not found"})
			return
		}
		g.operationsMu.Lock()
		defer g.operationsMu.Unlock()
		raw, e := os.ReadFile(filepath.Join(g.operationDir(id), "request.json"))
		var req operationRequest
		if e != nil || json.Unmarshal(raw, &req) != nil {
			write(w, 404, map[string]string{"error": "operation not found"})
			return
		}
		issuer, subject := "", ""
		if who != nil {
			issuer, subject = who.issuer, who.subject
		}
		if req.Issuer != issuer || req.Subject != subject {
			write(w, 404, map[string]string{"error": "operation not found"})
			return
		}
		status, e := g.operationStatus(req)
		if e == nil && cancel && (status.State == "queued" || status.State == "running" || status.State == "needs-attention") {
			e = g.store.write(filepath.Join(g.operationDir(id), "cancelled"), []byte("Cancellation requested; remote completion may still occur.\n"), false)
			if e == nil {
				e = syncOperationDirectory(g.operationDir(id))
			}
			if stop := g.operations[id]; stop != nil {
				stop()
			}
			if e == nil {
				status, e = g.operationStatus(req)
			}
		}
		if e != nil {
			fail(w, e)
			return
		}
		write(w, 200, status)
	})
}
func (g *gatewayService) startOperation(req operationRequest) (operationStatus, int, error) {
	g.operationsMu.Lock()
	defer g.operationsMu.Unlock()
	if !durableOperationsSupported {
		return operationStatus{}, 503, errors.New("durable source operations are not supported on this platform")
	}
	if !operationID.MatchString(req.ID) {
		return operationStatus{}, 400, errors.New("invalid operation ID")
	}
	deadline, e := time.Parse(time.RFC3339Nano, req.Deadline)
	if e != nil {
		return operationStatus{}, 400, errors.New("invalid operation deadline")
	}
	dir := g.operationDir(req.ID)
	// Sync each newly linked directory before any claim can admit a provider
	// call. Refuse symlink/shared operation directories, including old entries.
	for _, path := range []string{filepath.Join(g.storeRoot, "operations"), dir} {
		if e = os.MkdirAll(path, 0700); e != nil {
			return operationStatus{}, 500, e
		}
		st, err := os.Lstat(path)
		if err != nil {
			return operationStatus{}, 500, err
		}
		if !st.IsDir() || st.Mode().Perm()&0077 != 0 {
			return operationStatus{}, 500, errors.New("operation state must be a private directory")
		}
		if e = syncOperationDirectory(filepath.Dir(path)); e != nil {
			return operationStatus{}, 500, e
		}
	}
	raw, e := os.ReadFile(filepath.Join(dir, "request.json"))
	if e == nil {
		var held operationRequest
		if json.Unmarshal(raw, &held) != nil {
			return operationStatus{}, 500, errors.New("operation record unreadable")
		}
		compare := req
		compare.TokenDigest = held.TokenDigest
		if !bytes.Equal(operationJSON(compare), operationJSON(held)) {
			return operationStatus{}, 409, errors.New("operation ID already names another request or caller")
		}
		req = held
	} else {
		if !os.IsNotExist(e) {
			return operationStatus{}, 500, e
		}
		if !time.Now().Before(deadline) || time.Until(deadline) > 7*24*time.Hour {
			return operationStatus{}, 400, errors.New("deadline must be within the next seven days")
		}
		if _, ok := g.sources[req.Source]; !ok || strings.HasSuffix(req.Source, "/write") {
			return operationStatus{}, 400, errors.New("unknown read source")
		}
		if e = os.MkdirAll(dir, 0700); e != nil {
			return operationStatus{}, 500, e
		}
		if e = g.store.write(filepath.Join(dir, "request.json"), operationJSON(req), true); e != nil {
			return operationStatus{}, 409, errors.New("operation admission raced; retry the same request")
		}
	}
	if g.operations == nil {
		g.operations = map[string]context.CancelFunc{}
		var b [16]byte
		if _, e = rand.Read(b[:]); e != nil {
			return operationStatus{}, 500, e
		}
		g.operationOwner = hex.EncodeToString(b[:])
	}
	status, e := g.operationStatus(req)
	if e != nil {
		return status, 500, e
	}
	if status.State == "queued" && len(g.operations) < 4 && g.ctx.Err() == nil {
		if e = g.store.write(filepath.Join(dir, "claim"), []byte(g.operationOwner), true); e == nil {
			if e = syncOperationDirectory(dir); e != nil {
				return operationStatus{}, 500, e
			}
			ctx, stop := context.WithDeadline(g.ctx, deadline)
			g.operations[req.ID] = stop
			go g.executeOperation(ctx, stop, req)
			status.State = "running"
		} else {
			status, e = g.operationStatus(req)
			if e != nil {
				return status, 500, e
			}
		}
	}
	code := 200
	if status.State == "queued" || status.State == "running" {
		code = 202
	}
	return status, code, nil
}
func (g *gatewayService) operationStatus(req operationRequest) (operationStatus, error) {
	dir := g.operationDir(req.ID)
	status := operationStatus{ID: req.ID, State: "queued", Deadline: req.Deadline}
	if _, e := os.Stat(filepath.Join(dir, "cancelled")); e == nil {
		status.State = "cancelled"
		status.Reason = "Cancelled locally; the provider may still finish."
		return status, nil
	} else if !os.IsNotExist(e) {
		return status, e
	}
	if raw, e := os.ReadFile(filepath.Join(dir, "result.json")); e == nil {
		e = json.Unmarshal(raw, &status)
		return status, e
	} else if !os.IsNotExist(e) {
		return status, e
	}
	if claim, e := os.ReadFile(filepath.Join(dir, "claim")); e == nil {
		status.State = "running"
		if string(claim) != g.operationOwner || g.operations[req.ID] == nil {
			status.State = "needs-attention"
			status.Reason = "The operation owner is unavailable. The source was not called again."
		}
	} else if !os.IsNotExist(e) {
		return status, e
	}
	deadline, e := time.Parse(time.RFC3339Nano, req.Deadline)
	if e != nil {
		return status, e
	}
	if !time.Now().Before(deadline) {
		status.State = "expired"
		status.Reason = "The source deadline elapsed; remote completion may still occur."
	}
	return status, nil
}
func (g *gatewayService) executeOperation(ctx context.Context, stop context.CancelFunc, req operationRequest) {
	defer stop()
	done := make(chan struct{})
	defer close(done)
	go func() {
		tick := time.NewTicker(time.Second)
		defer tick.Stop()
		for {
			select {
			case <-done:
				return
			case <-ctx.Done():
				return
			case <-tick.C:
				if _, e := os.Stat(filepath.Join(g.operationDir(req.ID), "cancelled")); e == nil {
					stop()
					return
				}
			}
		}
	}()
	var who *caller
	if req.Issuer != "" {
		who = &caller{issuer: req.Issuer, subject: req.Subject, tokenDigest: req.TokenDigest}
	}
	args, e := parseJSONWithin(req.Arguments, maxArgumentValues)
	var response map[string]any
	if e == nil {
		response, e = g.acquireContext(ctx, "async."+req.ID, req.Source, args, who)
	}
	status := operationStatus{ID: req.ID, State: "completed", Deadline: req.Deadline}
	if e != nil {
		status.State = "needs-attention"
		status.Reason = "Source acquisition did not complete verifiably. It was not repeated automatically."
	} else {
		status.Response = operationJSON(response)
	}
	_, _ = g.sealSession("async." + req.ID)
	g.operationsMu.Lock()
	defer g.operationsMu.Unlock()
	// An unpersisted completion leaves a claim requiring attention. A cancellation
	// tombstone takes precedence over a late result, even across processes.
	if e := g.store.write(filepath.Join(g.operationDir(req.ID), "result.json"), operationJSON(status), true); e == nil {
		_ = syncOperationDirectory(g.operationDir(req.ID))
	}
	delete(g.operations, req.ID)
}
