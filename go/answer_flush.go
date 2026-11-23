package main

// An answer flushed before the hand-off (ADR-0059 section 5, condition C10):
// a handler's answer is kept until it returns, then written with an explicit
// Content-Length, the length the server would have set itself, and flushed,
// and only then does the post-answer work begin, so none of it stands
// between the answer's bytes and the caller. The status, the header fields
// and the body are the bytes the handler wrote; only the order of the header
// lines on the wire can differ (RFC 9110, section 5.3). The refusal journal
// hands its record off here (sink_refusal_entries.go names its seam).

import (
	"bytes"
	"net/http"
	"strconv"
)

// heldAnswer is a handler's answer, kept.
type heldAnswer struct {
	header http.Header
	status int
	body   bytes.Buffer
}

func newHeldAnswer() *heldAnswer { return &heldAnswer{header: http.Header{}} }

func (a *heldAnswer) Header() http.Header { return a.header }

func (a *heldAnswer) WriteHeader(code int) {
	if a.status == 0 {
		a.status = code
	}
}

func (a *heldAnswer) Write(p []byte) (int, error) {
	if a.status == 0 {
		a.status = http.StatusOK
	}
	return a.body.Write(p)
}

// answerThenHandOff writes the answer kept to w, with its explicit
// Content-Length where a body is allowed, flushes it explicitly, and then
// runs handOff. A flush that fails is a connection that failed: the answer
// is what it is, and the hand-off still runs after it.
func (a *heldAnswer) answerThenHandOff(w http.ResponseWriter, handOff func()) {
	for name, values := range a.header {
		w.Header()[name] = values
	}
	status := a.status
	if status == 0 {
		status = http.StatusOK
	}
	if status >= 200 && status != http.StatusNoContent && status != http.StatusNotModified {
		w.Header().Set("Content-Length", strconv.Itoa(a.body.Len()))
	}
	w.WriteHeader(status)
	_, _ = w.Write(a.body.Bytes())
	_ = http.NewResponseController(w).Flush()
	if handOff != nil {
		handOff()
	}
}
