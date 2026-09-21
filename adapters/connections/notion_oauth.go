package connections

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"adapters/mcphttp"
)

const notionResource = "https://mcp.notion.com"
const notionEndpoint = notionResource + "/mcp"

func notion() provider {
	return provider{auth: notionResource + "/authorize", token: notionResource + "/token", api: notionEndpoint, client: mcphttp.HTTPClient(), notion: true}
}
func OpenNotionStore(dir, principal string) (*Store, error) {
	root, err := OpenStore(dir, principal)
	if err != nil {
		return nil, err
	}
	root.Close()
	return OpenStore(filepath.Join(dir, "notion"), principal)
}

// Discovery is deliberately confined to the reviewed provider origin. A provider
// response cannot nominate a new host to receive credentials or local requests.
func (p provider) notionDiscovery(ctx context.Context) error {
	raw, _, err := p.request(ctx, "GET", notionResource+"/.well-known/oauth-protected-resource", "", nil, 64<<10)
	if err != nil {
		return err
	}
	var resource struct {
		Resource string   `json:"resource"`
		Servers  []string `json:"authorization_servers"`
	}
	if json.Unmarshal(raw, &resource) != nil || resource.Resource != notionResource || len(resource.Servers) != 1 || resource.Servers[0] != notionResource {
		return ErrProvider
	}
	raw, _, err = p.request(ctx, "GET", notionResource+"/.well-known/oauth-authorization-server", "", nil, 64<<10)
	if err != nil {
		return err
	}
	var metadata struct {
		Issuer      string   `json:"issuer"`
		Auth        string   `json:"authorization_endpoint"`
		Token       string   `json:"token_endpoint"`
		Register    string   `json:"registration_endpoint"`
		PKCE        []string `json:"code_challenge_methods_supported"`
		AuthMethods []string `json:"token_endpoint_auth_methods_supported"`
	}
	if json.Unmarshal(raw, &metadata) != nil || metadata.Issuer != notionResource || metadata.Auth != p.auth || metadata.Token != p.token || metadata.Register != notionResource+"/register" {
		return ErrProvider
	}
	has := func(v []string, s string) bool {
		for _, x := range v {
			if x == s {
				return true
			}
		}
		return false
	}
	if !has(metadata.PKCE, "S256") || !has(metadata.AuthMethods, "none") {
		return ErrProvider
	}
	return nil
}
func (p provider) registerNotion(ctx context.Context, redirect string) (Client, error) {
	raw, _ := json.Marshal(map[string]any{"client_name": "Judgment Pack Desk", "redirect_uris": []string{redirect}, "grant_types": []string{"authorization_code", "refresh_token"}, "response_types": []string{"code"}, "token_endpoint_auth_method": "none", "scope": "default"})
	req, err := http.NewRequestWithContext(ctx, "POST", notionResource+"/register", bytes.NewReader(raw))
	if err != nil {
		return Client{}, ErrProvider
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := p.client.Do(req)
	if err != nil {
		return Client{}, ErrProvider
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 && resp.StatusCode != 201 {
		return Client{}, ErrProvider
	}
	raw, err = io.ReadAll(io.LimitReader(resp.Body, 64<<10+1))
	if err != nil || len(raw) > 64<<10 {
		return Client{}, ErrProvider
	}
	var v struct {
		ID        string   `json:"client_id"`
		Secret    string   `json:"client_secret"`
		Method    string   `json:"token_endpoint_auth_method"`
		Redirects []string `json:"redirect_uris"`
	}
	if json.Unmarshal(raw, &v) != nil || len(v.ID) == 0 || len(v.ID) > 4096 || len(v.Secret) > 4096 || strings.ContainsAny(v.ID+v.Secret, "\x00\r\n") || v.Method != "none" || len(v.Redirects) != 1 || v.Redirects[0] != redirect {
		return Client{}, ErrProvider
	}
	return Client{ID: v.ID, Secret: v.Secret}, nil
}
func (b *Broker) startNotion(ctx context.Context) (FlowResult, error) {
	if b.active != nil && b.active.State == "pending" && time.Now().Before(b.active.until) {
		return FlowResult{}, Error("authorization-in-progress")
	}
	b.cancel()
	if err := b.provider.notionDiscovery(ctx); err != nil {
		return FlowResult{}, err
	}
	var client Client
	var redirect, epoch, connection string
	err := b.store.locked(func(v *state) error {
		if v.Disabled {
			return ErrPolicy
		}
		client, redirect, epoch = v.Client, v.Redirect, v.Epoch
		if v.Connection != nil {
			connection = v.Connection.ID
		}
		return nil
	})
	if err != nil {
		return FlowResult{}, err
	}
	address := "127.0.0.1:0"
	if client.ID != "" {
		u, e := url.Parse(redirect)
		if e != nil || u.Scheme != "http" || u.Hostname() != "127.0.0.1" || u.Port() == "" || u.User != nil || u.Path != "/oauth/callback" || u.RawQuery != "" || u.Fragment != "" {
			return FlowResult{}, ErrStorage
		}
		address = u.Host
	}
	listener, err := net.Listen("tcp4", address)
	if err != nil {
		return FlowResult{}, Error("callback-unavailable")
	}
	success := false
	defer func() {
		if !success {
			listener.Close()
		}
	}()
	if client.ID == "" {
		redirect = "http://" + listener.Addr().String() + "/oauth/callback"
		client, err = b.provider.registerNotion(ctx, redirect)
		if err != nil {
			return FlowResult{}, err
		}
		err = b.store.locked(func(v *state) error {
			if v.Disabled || v.Epoch != epoch || v.Client.ID != "" || v.Connection != nil {
				return ErrCanceled
			}
			v.Client = client
			v.Redirect = redirect
			v.Epoch = randomID()
			epoch = v.Epoch
			return b.store.write("state.json", v)
		})
		if err != nil {
			return FlowResult{}, err
		}
	}
	flowCtx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	f := &flow{FlowResult: FlowResult{ID: randomID(), State: "pending"}, state: randomID(), verifier: randomID(), redirect: redirect, client: client, connection: connection, epoch: epoch, until: time.Now().Add(5 * time.Minute), cancel: cancel, listener: listener}
	q := url.Values{"client_id": {client.ID}, "redirect_uri": {redirect}, "response_type": {"code"}, "scope": {"default"}, "state": {f.state}, "code_challenge": {challenge(f.verifier)}, "code_challenge_method": {"S256"}, "resource": {notionResource}}
	f.URL = b.provider.auth + "?" + q.Encode()
	b.active = f
	server := &http.Server{ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 50 * time.Second, MaxHeaderBytes: 16 << 10, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { b.callback(flowCtx, f, w, r) })}
	go func() { _ = server.Serve(listener) }()
	go func() { <-flowCtx.Done(); _ = server.Close() }()
	success = true
	return f.FlowResult, nil
}

// Serialize rotating refresh tokens across the broker and all adapter processes.
// Keep the state lock free during network I/O, so disconnect still takes effect.
func (p provider) notionAccess(ctx context.Context, s *Store, client Client, c credential, epoch string) (string, error) {
	f, err := s.root.OpenFile("refresh.lock", os.O_CREATE|os.O_RDWR|noFollow|nonBlock, 0600)
	if err != nil {
		return "", ErrStorage
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || private(st, false) != nil {
		return "", ErrStorage
	}
	for lock(f) != nil {
		select {
		case <-ctx.Done():
			return "", ErrCanceled
		case <-time.After(20 * time.Millisecond):
		}
	}
	defer unlock(f)
	err = s.locked(func(v *state) error {
		if v.Disabled {
			return ErrPolicy
		}
		if v.Epoch != epoch || v.Client != client || v.Connection == nil || v.Connection.ID != c.ID {
			return ErrCanceled
		}
		c = *v.Connection
		return nil
	})
	if err != nil {
		return "", err
	}
	if c.Expires > time.Now().Add(time.Minute).Unix() {
		return c.Access, nil
	}
	if c.Refresh == "" {
		return "", ErrRevoked
	}
	// Unlike the Google helper, distinguish a terminal invalid_grant from network
	// failures. Neither errors nor token endpoint response bodies reach the caller.
	values := url.Values{"grant_type": {"refresh_token"}, "client_id": {client.ID}, "refresh_token": {c.Refresh}, "resource": {notionResource}}
	if client.Secret != "" {
		values.Set("client_secret", client.Secret)
	}
	req, err := http.NewRequestWithContext(ctx, "POST", p.token, strings.NewReader(values.Encode()))
	if err != nil {
		return "", ErrProvider
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := p.client.Do(req)
	if err != nil {
		return "", ErrProvider
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10+1))
	if err != nil || len(raw) > 64<<10 {
		return "", ErrProvider
	}
	var t tokenReply
	var failure struct {
		Error string `json:"error"`
	}
	terminal := resp.StatusCode == 400 && json.Unmarshal(raw, &failure) == nil && (failure.Error == "invalid_grant" || failure.Error == "invalid_client")
	if !terminal && (resp.StatusCode != 200 || json.Unmarshal(raw, &t) != nil || len(t.Access) == 0 || len(t.Access) > 8192 || len(t.Refresh) == 0 || len(t.Refresh) > 8192 || t.Expires <= 0 || t.Expires > 86400 || !strings.EqualFold(t.Type, "Bearer") || (t.Scope != "" && t.Scope != "default") || strings.ContainsAny(t.Access+t.Refresh, "\x00\r\n")) {
		return "", ErrProvider
	}
	err = s.locked(func(v *state) error {
		if v.Disabled {
			return ErrPolicy
		}
		if v.Epoch != epoch || v.Client != client || v.Connection == nil || v.Connection.ID != c.ID || v.Connection.Refresh != c.Refresh {
			return ErrCanceled
		}
		if terminal {
			v.Connection = nil
			v.Epoch = randomID()
		} else {
			v.Connection.Access = t.Access
			v.Connection.Refresh = t.Refresh
			v.Connection.Expires = time.Now().Add(time.Duration(t.Expires) * time.Second).Unix()
		}
		return s.write("state.json", v)
	})
	if err != nil {
		return "", err
	}
	if terminal {
		return "", ErrRevoked
	}
	return t.Access, nil
}

func notionError(err error) error {
	if errors.Is(err, mcphttp.ErrUnauthorized) {
		return ErrRevoked
	}
	if errors.Is(err, mcphttp.ErrLimit) {
		return ErrLimit
	}
	return ErrProvider
}
