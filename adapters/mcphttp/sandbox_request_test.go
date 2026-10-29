package mcphttp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSandboxEscalationRequestIsRefusedByName(t *testing.T) {
	replies := make(chan string, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var message struct {
			ID    string `json:"id"`
			Error struct {
				Code    int    `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
		}
		if json.NewDecoder(r.Body).Decode(&message) != nil || message.ID != "escalation" || message.Error.Code != -32601 {
			t.Error("invalid escalation response")
		}
		replies <- message.Error.Message
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()
	c, err := Open(server.URL, Options{}, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	_, done, err := c.message(context.Background(), []byte(`{"jsonrpc":"2.0","id":"escalation","method":"sandbox/escalate","params":{"mode":"danger-full-access"}}`), 1)
	if err != nil || done {
		t.Fatalf("escalation request: %v %v", done, err)
	}
	if message := <-replies; !strings.HasPrefix(message, "sandbox-escalation-refused:") {
		t.Fatal(message)
	}
}
