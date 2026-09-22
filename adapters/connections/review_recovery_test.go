//go:build linux || darwin

package connections

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestRefreshCommitsAfterCallerCancellation(t *testing.T) {
	b, _ := notionFixture(t)
	connectNotion(t, b)
	expire(t, b)
	client, c, epoch, _ := b.connectedSnapshot()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p := &rotatingToken{valid: c.Refresh}
	p.hook = func(_ int, r *http.Request) error { cancel(); return r.Context().Err() }
	b.provider.client.Transport = p
	if _, err := b.provider.access(ctx, b.store, client, c, epoch); err != nil {
		t.Fatal(err)
	}
	ok, refresh := connected(b)
	if !ok || refresh != "rotated-refresh-1" {
		t.Fatal("rotated token was not committed")
	}
	if _, err := b.provider.access(context.Background(), b.store, client, c, epoch); err != nil {
		t.Fatal(err)
	}
	if p.n != 1 || p.refused != 0 {
		t.Fatal("cancellation lost the rotated token")
	}
}

func TestRefreshDoesNotStartWithoutCommitBudget(t *testing.T) {
	b, _ := notionFixture(t)
	connectNotion(t, b)
	expire(t, b)
	client, c, epoch, _ := b.connectedSnapshot()
	p := &rotatingToken{valid: c.Refresh}
	b.provider.client.Transport = p
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := b.provider.access(ctx, b.store, client, c, epoch); err != ErrCanceled {
		t.Fatal(err)
	}
	if p.n != 0 {
		t.Fatal("started rotation without time to commit")
	}
}

func TestRefreshCommitCannotOverwriteNewerCredentials(t *testing.T) {
	b, _ := notionFixture(t)
	connectNotion(t, b)
	expire(t, b)
	client, c, epoch, _ := b.connectedSnapshot()
	p := &rotatingToken{valid: c.Refresh}
	p.hook = func(_ int, _ *http.Request) error {
		return b.store.locked(func(v *state) error { v.Connection.Refresh = "newer-consent"; return b.store.write("state.json", v) })
	}
	b.provider.client.Transport = p
	if _, err := b.provider.access(context.Background(), b.store, client, c, epoch); err != ErrCanceled {
		t.Fatal(err)
	}
	_, refresh := connected(b)
	if refresh != "newer-consent" {
		t.Fatal("newer credentials overwritten")
	}
}

func TestDeadNotionRegistrationIsReplaced(t *testing.T) {
	for _, status := range []int{400, 401} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			b, _ := notionFixture(t)
			connectNotion(t, b)
			expire(t, b)
			client, c, epoch, _ := b.connectedSnapshot()
			base := b.provider.client.Transport
			b.provider.client.Transport = testTransportFunc(func(r *http.Request) (*http.Response, error) {
				if r.URL.Path == "/token" {
					return testReply(status, `{"error":"invalid_client"}`), nil
				}
				return base.RoundTrip(r)
			})
			if _, err := b.provider.access(context.Background(), b.store, client, c, epoch); err != ErrRevoked {
				t.Fatal(err)
			}
			registrations := 0
			b.provider.client.Transport = testTransportFunc(func(r *http.Request) (*http.Response, error) {
				if r.URL.Path == "/register" {
					registrations++
				}
				return base.RoundTrip(r)
			})
			connectNotion(t, b)
			if registrations != 1 {
				t.Fatal("dead client registration reused")
			}
		})
	}
}

func TestInvalidClientDuringConsentResetsRegistration(t *testing.T) {
	b, _ := notionFixture(t)
	base := b.provider.client.Transport
	b.provider.client.Transport = testTransportFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path == "/token" {
			return testReply(401, `{"error":"invalid_client"}`), nil
		}
		return base.RoundTrip(r)
	})
	v, err := b.Handle(context.Background(), "connect", []byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(v.(FlowResult).URL)
	q := u.Query()
	resp, err := http.Get(q.Get("redirect_uri") + "?" + url.Values{"state": {q.Get("state")}, "code": {"fixture-code"}}.Encode())
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if err := b.store.locked(func(v *state) error {
		if v.Client.ID != "" || v.Redirect != "" || v.Connection != nil {
			t.Error("dead registration retained")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	b.provider.client.Transport = base
	connectNotion(t, b)
}

func TestDisconnectedNotionRegistrationRecoversOccupiedPort(t *testing.T) {
	b, _ := notionFixture(t)
	connectNotion(t, b)
	var previous string
	b.store.locked(func(v *state) error { previous = v.Redirect; return nil })
	if _, err := b.Handle(context.Background(), "disconnect", []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(previous)
	ln, err := net.Listen("tcp4", u.Host)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	connectNotion(t, b)
	b.store.locked(func(v *state) error {
		if v.Redirect == previous {
			t.Error("occupied callback port reused")
		}
		return nil
	})
}

func TestNotionLongTokenLifetimeIsClamped(t *testing.T) {
	b, _ := notionFixture(t)
	connectNotion(t, b)
	expire(t, b)
	client, c, epoch, _ := b.connectedSnapshot()
	b.provider.client.Transport = testTransportFunc(func(r *http.Request) (*http.Response, error) {
		return testReply(200, `{"access_token":"new-access","refresh_token":"new-refresh","expires_in":9223372036854775807,"token_type":"Bearer"}`), nil
	})
	if _, err := b.provider.access(context.Background(), b.store, client, c, epoch); err != nil {
		t.Fatal(err)
	}
	b.store.locked(func(v *state) error {
		remaining := time.Until(time.Unix(v.Connection.Expires, 0))
		if remaining < 23*time.Hour || remaining > 24*time.Hour {
			t.Error("unsafe cache lifetime")
		}
		return nil
	})
}

func TestNestedNotionCredentialEchoIsRefused(t *testing.T) {
	for _, field := range []string{"text", "title", "url"} {
		t.Run(field, func(t *testing.T) {
			page := map[string]string{"text": "body", "title": "Policy", "url": "https://www.notion.so/" + strings.ReplaceAll(testPage, "-", "") + "?x=notion-private-access"}
			if field != "url" {
				delete(page, "url")
				page[field] = "notion-private-access"
			}
			raw, _ := json.Marshal(page)
			nested := strings.ReplaceAll(string(raw), "notion-private-access", `notion\u002dprivate\u002daccess`)
			if out, err := fetchWith(t, nested); err == nil || len(out) != 0 {
				t.Fatal("nested credential echo accepted")
			}
		})
	}
}

func TestNotionPartialSourceIsRefused(t *testing.T) {
	if out, err := fetchWith(t, `{"title":"Policy","text":"body","truncated":true}`); err != Error("source-incomplete") || len(out) != 0 {
		t.Fatal("partial upstream source presented as complete", err)
	}
	if _, err := fetchWith(t, `{"title":"Policy","text":"body","truncated":false}`); err != nil {
		t.Fatal(err)
	}
}

func TestObsidianLinksPercentEncodeSpaces(t *testing.T) {
	got := vaultURL("My + vault", "folder/my + note.md")
	if strings.Contains(got, "+") || !strings.Contains(got, "%20") || !strings.Contains(got, "%2B") {
		t.Fatal(got)
	}
	u, _ := url.Parse(got)
	if u.Query().Get("vault") != "My + vault" || u.Query().Get("file") != "folder/my + note" {
		t.Fatal(got)
	}
}
