package main

import (
	"bytes"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

// deadlineRecorder is a response writer that keeps each write deadline set
// on it, as http.ResponseController sets one on a connection.
type deadlineRecorder struct {
	*httptest.ResponseRecorder
	deadlines []time.Time
}

func (d *deadlineRecorder) SetWriteDeadline(at time.Time) error {
	d.deadlines = append(d.deadlines, at)
	return nil
}

func limitsService(t *testing.T) *gatewayService {
	t.Helper()
	root := t.TempDir()
	service, err := newGatewayService(filepath.Join(root, "store"), testSeed, "gateway:test",
		filepath.Join(root, "registry.jsonl"), nil)
	if err != nil {
		t.Fatal(err)
	}
	return service
}

// A loopback listener is served as it was before the limits for one other
// hosts can reach: the two read timeouts and nothing else, the mux itself
// as the handler, and no write deadline set on any answer.
func TestALoopbackListenerIsServedAsBefore(t *testing.T) {
	for _, addr := range []*net.TCPAddr{
		{IP: net.ParseIP("127.0.0.1"), Port: 8787}, {IP: net.IPv6loopback, Port: 8787}, {IP: net.ParseIP("127.0.0.2"), Port: 9000},
	} {
		t.Run(addr.String(), func(t *testing.T) {
			service := limitsService(t)
			server := service.httpServer(addr)
			if _, isMux := server.Handler.(*http.ServeMux); !isMux {
				t.Fatalf("a loopback listener's handler is %T, not the mux", server.Handler)
			}
			want := &http.Server{Handler: server.Handler, ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second}
			if !reflect.DeepEqual(server, want) {
				t.Fatalf("a loopback listener's server: %+v", server)
			}
			if service.listening != net.Addr(addr) {
				t.Fatalf("listening %v, want %v", service.listening, addr)
			}
			for _, path := range []string{"/registry", "/publickey", "/verify"} {
				rec := &deadlineRecorder{ResponseRecorder: httptest.NewRecorder()}
				server.Handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
				if rec.Code != http.StatusOK || len(rec.deadlines) != 0 {
					t.Fatalf("%s on loopback: %d, deadlines %v", path, rec.Code, rec.deadlines)
				}
			}
		})
	}
}

// A listener other hosts can reach is served under limits of its own: an
// idle connection closed after a minute, headers bounded at 64 KiB, and
// the answers of /registry and /publickey, which need no token, each given
// a write deadline 30 seconds out; every other answer has its deadline
// cleared, so none set for an open route holds over a later request on the
// connection. The server has no WriteTimeout, which would count an
// /acquire's or an /act's run against its answer. The answers' bytes are
// a loopback listener's.
func TestAListenerOtherHostsCanReachIsServedUnderLimits(t *testing.T) {
	for _, addr := range []*net.TCPAddr{
		{IP: net.IPv4zero, Port: 8787}, {IP: net.IPv6unspecified, Port: 8787}, {IP: net.ParseIP("192.0.2.10"), Port: 8787},
	} {
		t.Run(addr.String(), func(t *testing.T) {
			service := limitsService(t)
			loopback := service.httpServer(&net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8787}).Handler
			server := service.httpServer(addr)
			if server.ReadHeaderTimeout != 10*time.Second || server.ReadTimeout != 30*time.Second ||
				server.IdleTimeout != 60*time.Second || server.MaxHeaderBytes != 64<<10 || server.WriteTimeout != 0 {
				t.Fatalf("the limits: header %v, read %v, idle %v, header bytes %d, write %v",
					server.ReadHeaderTimeout, server.ReadTimeout, server.IdleTimeout, server.MaxHeaderBytes, server.WriteTimeout)
			}
			for _, tc := range []struct {
				path string
				open bool
			}{{"/registry", true}, {"/publickey", true}, {"/verify", false}, {"/registry/", false}, {"/nothing", false}} {
				before := time.Now()
				rec := &deadlineRecorder{ResponseRecorder: httptest.NewRecorder()}
				server.Handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, tc.path, nil))
				after := time.Now()
				if len(rec.deadlines) != 1 {
					t.Fatalf("%s: deadlines %v, want one", tc.path, rec.deadlines)
				}
				at := rec.deadlines[0]
				if tc.open && (at.Before(before.Add(30*time.Second)) || at.After(after.Add(30*time.Second))) {
					t.Fatalf("%s: write deadline %v, want 30s from %v", tc.path, at, before)
				}
				if !tc.open && !at.IsZero() {
					t.Fatalf("%s: write deadline %v, want it cleared", tc.path, at)
				}
				same := httptest.NewRecorder()
				loopback.ServeHTTP(same, httptest.NewRequest(http.MethodGet, tc.path, nil))
				if rec.Code != same.Code || !bytes.Equal(rec.Body.Bytes(), same.Body.Bytes()) || !reflect.DeepEqual(rec.Header(), same.Header()) {
					t.Fatalf("%s: %d %q %v, on loopback %d %q %v", tc.path, rec.Code, rec.Body, rec.Header(), same.Code, same.Body, same.Header())
				}
			}
		})
	}
}
