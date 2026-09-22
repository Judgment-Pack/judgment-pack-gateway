package connections

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

type Selection struct {
	FileID string `json:"fileId"`
	Grant  string `json:"grant"`
}
type Status struct {
	Version      int      `json:"version"`
	Provider     string   `json:"provider"`
	State        string   `json:"state"`
	Account      *account `json:"account,omitempty"`
	MaxFileBytes int      `json:"maxFileBytes"`
	MaxFiles     int      `json:"maxFiles"`
}
type FlowResult struct {
	ID         string      `json:"id"`
	State      string      `json:"state"`
	URL        string      `json:"url,omitempty"`
	Error      string      `json:"error,omitempty"`
	Selections []Selection `json:"selections,omitempty"`
}
type flow struct {
	FlowResult
	state, verifier, redirect string
	client                    Client
	connection, epoch         string
	pick                      bool
	until                     time.Time
	cancel                    context.CancelFunc
	listener                  net.Listener
	consumed                  bool
}
type Broker struct {
	mu       sync.Mutex
	store    *Store
	provider provider
	disabled bool
	active   *flow
}

func New(s *Store, disabled bool) *Broker {
	return &Broker{store: s, provider: google(), disabled: disabled}
}
func NewGmail(s *Store, disabled bool) *Broker {
	return &Broker{store: s, provider: googleMail(), disabled: disabled}
}
func NewNotion(s *Store, disabled bool) *Broker {
	return &Broker{store: s, provider: notion(), disabled: disabled}
}
func (b *Broker) Close() { b.mu.Lock(); defer b.mu.Unlock(); b.cancel() }
func (b *Broker) cancel() {
	if b.active != nil {
		b.active.cancel()
		b.active.listener.Close()
		b.active.State = "canceled"
		b.active.URL = ""
	}
}
func (b *Broker) Handle(ctx context.Context, method string, raw json.RawMessage) (any, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(raw) == 0 {
		raw = []byte("{}")
	}
	if err := b.store.locked(func(v *state) error {
		if v.Disabled != b.disabled {
			v.Disabled = b.disabled
			v.Epoch = randomID()
			return b.store.write("state.json", v)
		}
		return nil
	}); err != nil {
		return nil, err
	}
	if b.disabled {
		b.cancel()
		if method == "status" {
			return Status{1, b.provider.kind(), "blocked", nil, MaxFileBytes, 4}, nil
		}
		return nil, ErrPolicy
	}
	if b.provider.obsidian {
		return b.vaultOperation(ctx, method, raw)
	}
	switch method {
	case "status":
		var empty struct{}
		if decode(raw, &empty) != nil {
			return nil, ErrRequest
		}
		out := Status{1, b.provider.kind(), "setup-required", nil, MaxFileBytes, 4}
		err := b.store.locked(func(v *state) error {
			if v.Client.ID != "" || b.provider.notion {
				out.State = "not-connected"
			}
			if v.Connection != nil {
				out.State = "connected"
				out.Account = &v.Connection.Account
			}
			return nil
		})
		return out, err
	case "configure":
		if b.provider.notion {
			return nil, ErrRequest
		}
		var c Client
		if decode(raw, &c) != nil || !validClient(c) {
			return nil, ErrRequest
		}
		b.cancel()
		err := b.store.locked(func(v *state) error {
			if v.Connection != nil && (v.Client != c) {
				return Error("disconnect-first")
			}
			v.Client = c
			v.Epoch = randomID()
			return b.store.write("state.json", v)
		})
		return map[string]bool{"saved": err == nil}, err
	case "search", "select":
		if b.provider.notion {
			return b.notionOperation(ctx, method, raw)
		}
		if !b.provider.gmail {
			return nil, ErrRequest
		}
		return b.mailOperation(ctx, method, raw)
	case "connect", "pick":
		if method == "pick" && (b.provider.gmail || b.provider.notion) {
			return nil, ErrRequest
		}
		var empty struct{}
		if decode(raw, &empty) != nil {
			return nil, ErrRequest
		}
		if b.provider.notion {
			return b.startNotion(ctx)
		}
		return b.start(method == "pick")
	case "poll", "cancel":
		var q struct {
			ID string `json:"id"`
		}
		if decode(raw, &q) != nil || b.active == nil || b.active.ID != q.ID {
			return nil, ErrRequest
		}
		if method == "cancel" {
			b.cancel()
		}
		if time.Now().After(b.active.until) && b.active.State == "pending" {
			b.cancel()
			b.active.Error = "authorization-expired"
		}
		result := b.active.FlowResult
		result.URL = ""
		return result, nil
	case "disconnect":
		var empty struct{}
		if decode(raw, &empty) != nil {
			return nil, ErrRequest
		}
		b.cancel()
		var token string
		err := b.store.locked(func(v *state) error {
			if v.Connection != nil {
				token = v.Connection.Refresh
				if token == "" {
					token = v.Connection.Access
				}
			}
			v.Connection = nil
			v.Epoch = randomID()
			return b.store.write("state.json", v)
		})
		if err != nil {
			return nil, err
		}
		revoked := true
		if b.provider.notion {
			revoked = false
		}
		if token != "" && !b.provider.notion {
			values := url.Values{"token": {token}}
			_, _, err = b.provider.request(ctx, "POST", b.provider.revoke, "", values, 64<<10)
			revoked = err == nil
		}
		return map[string]bool{"disconnected": true, "revoked": revoked}, nil
	default:
		return nil, ErrRequest
	}
}
func (b *Broker) start(pick bool) (FlowResult, error) {
	if b.active != nil && b.active.State == "pending" && time.Now().Before(b.active.until) {
		return FlowResult{}, Error("authorization-in-progress")
	}
	b.cancel()
	var client Client
	var connection, epoch string
	var login string
	err := b.store.locked(func(v *state) error {
		if v.Epoch == "" {
			v.Epoch = randomID()
			if err := b.store.write("state.json", v); err != nil {
				return err
			}
		}
		epoch = v.Epoch
		client = v.Client
		if v.Connection != nil {
			connection = v.Connection.ID
			login = v.Connection.Account.Email
		}
		return nil
	})
	if err != nil {
		return FlowResult{}, err
	}
	if client.ID == "" {
		return FlowResult{}, ErrSetup
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return FlowResult{}, ErrProvider
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	f := &flow{FlowResult: FlowResult{ID: randomID(), State: "pending"}, state: randomID(), verifier: randomID(), client: client, connection: connection, epoch: epoch, pick: pick, until: time.Now().Add(5 * time.Minute), cancel: cancel, listener: listener}
	f.redirect = "http://" + listener.Addr().String() + "/oauth/callback"
	q := url.Values{"client_id": {client.ID}, "redirect_uri": {f.redirect}, "response_type": {"code"}, "scope": {b.provider.scope()}, "access_type": {"offline"}, "include_granted_scopes": {"false"}, "prompt": {"consent"}, "state": {f.state}, "code_challenge": {challenge(f.verifier)}, "code_challenge_method": {"S256"}}
	if login != "" {
		q.Set("login_hint", login)
	}
	if pick {
		q.Set("trigger_onepick", "true")
		q.Set("allow_multiple", "true")
		q.Set("mimetypes", "application/pdf,text/plain,text/markdown,text/csv,application/json,application/vnd.google-apps.document,application/vnd.google-apps.spreadsheet,application/vnd.google-apps.presentation")
	}
	f.URL = b.provider.auth + "?" + q.Encode()
	b.active = f
	server := &http.Server{ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 50 * time.Second, MaxHeaderBytes: 16 << 10, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { b.callback(ctx, f, w, r) })}
	go func() { _ = server.Serve(listener) }()
	go func() { <-ctx.Done(); _ = server.Close() }()
	return f.FlowResult, nil
}
func (b *Broker) callback(ctx context.Context, f *flow, w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	q, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil || len(r.URL.RawQuery) > 12<<10 || r.Host != f.listener.Addr().String() || r.Method != "GET" || r.URL.Path != "/oauth/callback" {
		http.Error(w, "Invalid callback.", 400)
		return
	}
	for _, v := range q {
		if len(v) != 1 {
			http.Error(w, "Invalid callback.", 400)
			return
		}
	}
	b.mu.Lock()
	if b.active != f || f.consumed || f.State != "pending" || time.Now().After(f.until) || subtle.ConstantTimeCompare([]byte(q.Get("state")), []byte(f.state)) != 1 {
		b.mu.Unlock()
		http.Error(w, "Authorization expired.", 400)
		return
	}
	f.consumed = true
	b.mu.Unlock()
	var ids []string
	resultErr := error(nil)
	if q.Get("error") != "" {
		resultErr = ErrCanceled
	} else if q.Get("code") == "" || len(q.Get("code")) > 4096 {
		resultErr = ErrRequest
	}
	if f.pick && resultErr == nil {
		ids = strings.Split(q.Get("picked_file_ids"), ",")
		if len(ids) > 4 {
			resultErr = Error("too-many-files")
		}
		seen := map[string]bool{}
		for _, id := range ids {
			if !identifier.MatchString(id) || seen[id] {
				resultErr = ErrRequest
			}
			seen[id] = true
		}
	}
	var t tokenReply
	var a account
	if resultErr == nil {
		t, resultErr = b.provider.exchange(ctx, f.client, url.Values{"grant_type": {"authorization_code"}, "code": {q.Get("code")}, "code_verifier": {f.verifier}, "redirect_uri": {f.redirect}})
	}
	if resultErr == nil {
		if b.provider.notion {
			if !identifier.MatchString(t.User) || !identifier.MatchString(t.Workspace) {
				resultErr = ErrProvider
			} else {
				a = account{ID: t.Workspace + ":" + t.User, Name: "Notion"}
			}
		} else {
			a, resultErr = b.provider.who(ctx, t.Access)
		}
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.active != f || f.State != "pending" || ctx.Err() != nil {
		http.Error(w, "Authorization canceled.", 400)
		return
	}
	if b.provider.notion && resultErr == Error("registration-expired") {
		// Only invalidate the registration used by this still-current flow.
		// A concurrent disconnect or reconfiguration must never be undone.
		if err := b.store.locked(func(v *state) error {
			if v.Disabled || v.Epoch != f.epoch || v.Client != f.client {
				return ErrCanceled
			}
			v.Client, v.Redirect, v.Connection, v.Epoch = Client{}, "", nil, randomID()
			return b.store.write("state.json", v)
		}); err != nil {
			resultErr = err
		}
	}
	if resultErr == nil {
		resultErr = b.store.locked(func(v *state) error {
			if v.Disabled {
				return ErrPolicy
			}
			if v.Client != f.client || v.Epoch != f.epoch {
				return ErrCanceled
			}
			previous := v.Connection
			if f.connection != "" {
				if previous == nil || previous.ID != f.connection {
					return ErrCanceled
				}
				if previous.Account.ID != a.ID {
					return Error("wrong-account")
				}
			} else if previous != nil {
				return ErrCanceled
			}
			c := &credential{ID: randomID(), Account: a, Access: t.Access, Refresh: t.Refresh, Expires: time.Now().Add(time.Duration(t.Expires) * time.Second).Unix()}
			if previous != nil {
				c.ID = previous.ID
				if c.Refresh == "" {
					c.Refresh = previous.Refresh
				}
			}
			if c.Refresh == "" {
				return ErrRevoked
			}
			v.Connection = c
			if err := b.store.write("state.json", v); err != nil {
				return err
			}
			var err error
			if f.pick {
				f.Selections, err = b.store.makeGrants(c.ID, ids)
			}
			return err
		})
	}
	f.URL = ""
	f.State = "complete"
	if resultErr != nil {
		f.State = "failed"
		f.Error = resultErr.Error()
		if resultErr == ErrCanceled {
			f.State = "canceled"
		}
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte("Return to Judgment Pack to continue. You can close this tab."))
	// Close the listener now; allow the current response to flush before timeout cleanup.
	f.listener.Close()
}
