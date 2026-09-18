package connections

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const driveScope = "https://www.googleapis.com/auth/drive.file"
const MaxFileBytes = 4 << 20
const MaxOutputBytes = 16 << 20

// Endpoints are fixed in production. Tests supply an isolated TLS server.
type provider struct {
	auth, token, revoke, api string
	client                   *http.Client
}

func google() provider {
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.Proxy = nil
	t.MaxResponseHeaderBytes = 64 << 10
	t.ResponseHeaderTimeout = 15 * time.Second
	t.TLSHandshakeTimeout = 10 * time.Second
	t.DialContext = (&net.Dialer{Timeout: 10 * time.Second}).DialContext
	return provider{"https://accounts.google.com/o/oauth2/v2/auth", "https://oauth2.googleapis.com/token", "https://oauth2.googleapis.com/revoke", "https://www.googleapis.com/drive/v3", &http.Client{Transport: t, Timeout: 45 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
}
func (p provider) request(ctx context.Context, method, endpoint, token string, form url.Values, max int64) ([]byte, *http.Response, error) {
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint, body)
	if err != nil {
		return nil, nil, ErrProvider
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	response, err := p.client.Do(req)
	if err != nil {
		return nil, nil, ErrProvider
	}
	defer response.Body.Close()
	if response.StatusCode == 401 {
		return nil, nil, ErrRevoked
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, nil, ErrProvider
	}
	if response.ContentLength > max {
		return nil, nil, ErrLimit
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, max+1))
	if err != nil {
		return nil, nil, ErrProvider
	}
	if int64(len(raw)) > max {
		return nil, nil, ErrLimit
	}
	if token != "" && bytes.Contains(raw, []byte(token)) {
		return nil, nil, ErrProvider
	}
	return raw, response, nil
}

type tokenReply struct {
	Access  string `json:"access_token"`
	Refresh string `json:"refresh_token"`
	Expires int64  `json:"expires_in"`
	Scope   string `json:"scope"`
	Type    string `json:"token_type"`
}

func (p provider) exchange(ctx context.Context, client Client, values url.Values) (tokenReply, error) {
	values.Set("client_id", client.ID)
	if client.Secret != "" {
		values.Set("client_secret", client.Secret)
	}
	raw, _, err := p.request(ctx, "POST", p.token, "", values, 64<<10)
	if err != nil {
		return tokenReply{}, err
	}
	var t tokenReply
	if json.Unmarshal(raw, &t) != nil || len(t.Access) == 0 || len(t.Access) > 8192 || len(t.Refresh) > 8192 || t.Expires <= 0 || t.Expires > 86400 || !strings.EqualFold(t.Type, "Bearer") {
		return t, ErrProvider
	}
	if t.Scope != "" && t.Scope != driveScope {
		return t, ErrProvider
	}
	return t, nil
}

// Refresh uses a snapshot outside the custody lock. A concurrent disconnect or
// reconfiguration can revoke it while the provider is slow; commit rechecks that
// generation and never restores credentials that were removed in the meantime.
func (p provider) access(ctx context.Context, s *Store, client Client, c credential, epoch string) (string, error) {
	if c.Expires > time.Now().Add(time.Minute).Unix() {
		return c.Access, nil
	}
	if c.Refresh == "" {
		return "", ErrRevoked
	}
	t, err := p.exchange(ctx, client, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {c.Refresh}})
	if err != nil {
		return "", ErrRevoked
	}
	var access string
	err = s.locked(func(v *state) error {
		if v.Disabled {
			return ErrPolicy
		}
		if v.Epoch != epoch || v.Client != client || v.Connection == nil || v.Connection.ID != c.ID {
			return ErrCanceled
		}
		current := v.Connection
		// Do not overwrite a newer refresh or consent result for this connection.
		if current.Access != c.Access || current.Refresh != c.Refresh || current.Expires != c.Expires {
			if current.Expires <= time.Now().Add(time.Minute).Unix() {
				return ErrRevoked
			}
			access = current.Access
			return nil
		}
		current.Access = t.Access
		current.Expires = time.Now().Add(time.Duration(t.Expires) * time.Second).Unix()
		if t.Refresh != "" {
			current.Refresh = t.Refresh
		}
		if err := s.write("state.json", v); err != nil {
			return err
		}
		access = current.Access
		return nil
	})
	return access, err
}
func (p provider) who(ctx context.Context, access string) (account, error) {
	raw, _, err := p.request(ctx, "GET", p.api+"/about?fields=user(permissionId,emailAddress,displayName)", access, nil, 64<<10)
	if err != nil {
		return account{}, err
	}
	var r struct {
		User struct {
			ID    string `json:"permissionId"`
			Email string `json:"emailAddress"`
			Name  string `json:"displayName"`
		} `json:"user"`
	}
	if json.Unmarshal(raw, &r) != nil || !identifier.MatchString(r.User.ID) || len(r.User.Email) > 320 || len(r.User.Name) > 512 {
		return account{}, ErrProvider
	}
	return account{r.User.ID, r.User.Email, r.User.Name}, nil
}
func challenge(verifier string) string {
	s := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(s[:])
}
