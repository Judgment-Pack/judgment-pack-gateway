//go:build linux || darwin

package connections

import (
	"adapters/internal/fakemcp"
	"adapters/mcphttp"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

// The safeguards of the three merged providers -- the Databricks API and MCP
// profiles and the Azure DevOps API profile, each as its review rounds left
// it -- held on the MCP profile's path from the start, by tests that answer
// from the in-process Streamable HTTP fake.

// adoMCPNamespace is a store holding the MCP connection "board" under an
// access token, and beside it a second connection, "second", under a
// personal access token: every credential custody holds for the provider
// is held out of every request, answer and outgoing text.
func adoMCPNamespace(t *testing.T) (*Store, *Broker, AzureDevOpsConnection, string) {
	t.Helper()
	s, b, c, dir := adoMCPFixture(t, adoBearerFields(), adoMCPServers())
	second := adoTokenFields()
	second["id"] = "second"
	if err := adoConfigure(b, second); err != nil {
		t.Fatal(err)
	}
	return s, b, c, dir
}

// adoMCPCredentials is each credential custody holds in adoMCPNamespace.
var adoMCPCredentials = map[string]string{"the access token": adoBearer, "the other connection's token": adoPAT, "its basic value": adoBasic}

// adoMCPAbsent fails where text holds a credential or the session id, as
// written, in escapes, or nested.
func adoMCPAbsent(t *testing.T, name, text string) {
	t.Helper()
	for _, marker := range []string{adoBearer, adoPAT, adoBasic, adoMCPSession} {
		if strings.Contains(text, marker) || databricksSpells(text, []string{marker}) {
			t.Errorf("%s: %q holds a credential or the session id", name, text)
		}
	}
}

// Each credential custody holds -- the access token in use, and the other
// connection's token and its basic value -- in an answer, as written, in
// escapes, or nested past one decoding, in the result, the handshake or the
// listing, is refused before anything of the answer is read: nothing is
// kept, nothing more is asked, and no error repeats it. The client refuses
// its own token as written or escaped in its own words; the whole message's
// screen refuses the rest, at every stage, in the same words.
func TestAzureDevOpsMCPEveryCredentialInAnAnswerIsRefused(t *testing.T) {
	s, _, c, _ := adoMCPNamespace(t)
	byClient := "provider-unavailable: the MCP server remote: the server's answer repeats the credential"
	byScreen := "provider-unavailable: the MCP server remote: the server's answer repeats the credential or its session id, and is not kept"
	for name, secret := range adoMCPCredentials {
		for form, written := range map[string]string{"as written": secret, "escaped": adoEscaped(secret), "nested": adoNested(secret, 5)} {
			for place, k := range map[string]struct {
				change  func(*fakemcp.Script)
				methods string
			}{
				"the result": {func(script *fakemcp.Script) {
					script.Result = `{"content":[{"type":"text","text":"` + written + `"}]}`
				}, "initialize,notifications/initialized,tools/list,tools/call,DELETE"},
				"a member name of the result": {func(script *fakemcp.Script) {
					script.Result = `{"content":[{"type":"text","text":"1"}],"structuredContent":{"` + written + `":1}}`
				}, "initialize,notifications/initialized,tools/list,tools/call,DELETE"},
				"the server's name": {func(script *fakemcp.Script) {
					script.ServerInfo = `{"name":"` + written + `","version":"1"}`
				}, "initialize,DELETE"},
				"a tool's description": {func(script *fakemcp.Script) {
					script.Tools = strings.Replace(adoMCPTools, `"name":"other"`, `"name":"other","description":"`+written+`"`, 1)
				}, "initialize,notifications/initialized,tools/list,DELETE"},
			} {
				f := adoFakeMCP(t, k.change)
				out, err := azureDevOpsAcquire(context.Background(), s, adoMCPRead(c, "wit_work_item", `{"action":"get","id":12}`), adoMCPServe(nil, f))
				want := byScreen
				// The client knows its own token, and refuses an answer that
				// repeats it as written or escaped before the connection reads it.
				if secret == adoBearer && form != "nested" {
					want = byClient
				}
				if out != nil || err == nil || err.Error() != want {
					t.Errorf("%s %s in %s: %v", name, form, place, err)
				}
				if got := adoMethods(f); got != k.methods {
					t.Errorf("%s %s in %s: %s", name, form, place, got)
				}
				if err != nil {
					adoMCPAbsent(t, name+" "+form+" in "+place, err.Error())
				}
			}
		}
	}
}

// A server's text -- a refusal's message, a failed tool's text -- that spells
// a credential or the session id, as decoded, is not reported: the whole
// message is refused before its text is read (round 1 of #256). Where a
// text reaches the refusal's words unscreened, each whole credential is
// replaced before it is cut.
func TestAzureDevOpsMCPAServersTextThatSpellsASecretIsNotReported(t *testing.T) {
	s, _, c, _ := adoMCPNamespace(t)
	secrets := map[string]string{"the session id": adoMCPSession}
	for name, secret := range adoMCPCredentials {
		secrets[name] = secret
	}
	for name, secret := range secrets {
		nested := adoNested(secret, 3)
		f := adoFakeMCP(t, func(script *fakemcp.Script) {
			script.Result = `{"content":[{"type":"text","text":"denied for ` + nested + `"}],"isError":true}`
		})
		out, err := azureDevOpsAcquire(context.Background(), s, adoMCPRead(c, "wit_work_item", ""), adoMCPServe(nil, f))
		if out != nil || err == nil || err.Error() != "provider-unavailable: the MCP server remote: the server's answer repeats the credential or its session id, and is not kept" || !strings.Contains(adoMethods(f), "tools/call") {
			t.Errorf("%s in a failed tool's text: %v", name, err)
		}
		f = adoFakeMCP(t, func(script *fakemcp.Script) {
			script.Refuse = `{"code":-32000,"message":"denied for ` + nested + `"}`
		})
		out, err = azureDevOpsAcquire(context.Background(), s, adoMCPRead(c, "wit_work_item", ""), adoMCPServe(nil, f))
		if out != nil || err == nil || err.Error() != "provider-unavailable: the MCP server remote: the server's answer repeats the credential or its session id, and is not kept" {
			t.Errorf("%s in a refusal: %v", name, err)
		}
		if err != nil {
			adoMCPAbsent(t, name, err.Error())
		}
	}
	// A credential as written across the cut of a failed tool's text: the
	// message is refused whole; and the text, where it reaches the
	// refusal's words, has it replaced before it is cut.
	long := strings.Repeat("x", databricksMessageBytes-len("tool-error: ")-len(adoPAT)+1) + adoPAT
	result := `{"content":[{"type":"text","text":"` + long + `"}],"isError":true}`
	f := adoFakeMCP(t, func(script *fakemcp.Script) { script.Result = result })
	if _, err := azureDevOpsAcquire(context.Background(), s, adoMCPRead(c, "wit_work_item", ""), adoMCPServe(nil, f)); err == nil || err.Error() != "provider-unavailable: the MCP server remote: the server's answer repeats the credential or its session id, and is not kept" {
		t.Errorf("across the cut: %.80q", err)
	}
	if _, err := databricksToolAnswer([]byte(result), 1<<20, []string{adoPAT}); err == nil || err.Error() != databricksClip("tool-error: "+strings.Repeat("x", databricksMessageBytes-len("tool-error: ")-len(adoPAT)+1)+"[redacted]") {
		t.Errorf("the words across the cut: %.80q", err)
	}
}

// The session id the server issues is the client's alone: an answer that
// repeats it, in a result or an error, as written, escaped or nested, is
// refused, and no error says it.
func TestAzureDevOpsMCPTheSessionIdIsNeverCarried(t *testing.T) {
	s, b, c, _ := adoMCPNamespace(t)
	byClient := "provider-unavailable: the MCP server remote: the server's answer repeats its session id"
	for name, k := range map[string]struct {
		change func(*fakemcp.Script)
		want   string
	}{
		"in a result": {func(script *fakemcp.Script) {
			script.Result = `{"content":[{"type":"text","text":"` + adoMCPSession + `"}]}`
		}, byClient},
		"escaped in a result": {func(script *fakemcp.Script) {
			script.Result = `{"content":[{"type":"text","text":"` + adoEscaped(adoMCPSession) + `"}]}`
		}, byClient},
		"nested in a result": {func(script *fakemcp.Script) {
			script.Result = `{"content":[{"type":"text","text":"` + adoNested(adoMCPSession, 4) + `"}]}`
		}, "provider-unavailable: the MCP server remote: the server's answer repeats the credential or its session id, and is not kept"},
		"in a refusal": {func(script *fakemcp.Script) {
			script.Refuse = `{"code":-32000,"message":"no session ` + adoMCPSession + `"}`
		}, byClient},
		"nested in a refusal": {func(script *fakemcp.Script) {
			script.Refuse = `{"code":-32000,"message":"no session ` + adoNested(adoMCPSession, 4) + `"}`
		}, "provider-unavailable: the MCP server remote: the server's answer repeats the credential or its session id, and is not kept"},
		"in the server's name": {func(script *fakemcp.Script) { script.ServerInfo = `{"name":"` + adoMCPSession + `","version":"1"}` }, byClient},
	} {
		f := adoFakeMCP(t, k.change)
		out, err := azureDevOpsAcquire(context.Background(), s, adoMCPRead(c, "wit_work_item", ""), adoMCPServe(nil, f))
		if out != nil || err == nil || err.Error() != k.want {
			t.Errorf("%s: %v", name, err)
		}
		if err != nil {
			adoMCPAbsent(t, name, err.Error())
		}
		// A test reports neither the id nor anything of an answer that
		// repeats it.
		b.provider = adoMCPServe(newADOFake(t), f)
		answer, err := b.Handle(context.Background(), "test", []byte(`{"id":"board","revision":"`+c.Revision+`"}`))
		raw, _ := json.Marshal(answer)
		if err != nil {
			t.Errorf("%s: test %v", name, err)
		}
		adoMCPAbsent(t, name+": test", string(raw))
	}
}

// A read whose arguments, tool or server carry a credential custody holds --
// the access token, the other connection's token or its basic value; as
// written, escaped, as a member name, nested -- is refused before anything
// is sent, in words that name the rule and not the value.
func TestAzureDevOpsMCPArgumentsCarryingACredentialAreNotSent(t *testing.T) {
	s, _, c, _ := adoMCPNamespace(t)
	f := adoFakeMCP(t, nil)
	p := adoMCPServe(nil, f)
	for name, secret := range adoMCPCredentials {
		value, _ := json.Marshal(secret)
		for place, arguments := range map[string]string{
			"a value":          `{"action":"get","project":` + string(value) + `}`,
			"a value, escaped": `{"action":"get","project":"` + adoEscaped(secret) + `"}`,
			"a member name":    `{"` + adoEscaped(secret) + `":1}`,
			"nested":           `{"a":{"b":["x",` + string(value) + `]}}`,
			"nested escapes":   `{"query":"` + adoNested(secret, 6) + `"}`,
			"JSON in a string": `{"query":"{\"inner\":` + strings.ReplaceAll(string(value), `"`, `\"`) + `}"}`,
		} {
			out, err := azureDevOpsAcquire(context.Background(), s, adoMCPRead(c, "wit_work_item", arguments), p)
			if out != nil || err != azureDevOpsInRequest || strings.Contains(err.Error(), secret) {
				t.Errorf("%s in %s: %v", name, place, err)
			}
		}
	}
	if n := len(f.Requests()); n != 0 {
		t.Fatalf("%d requests were sent", n)
	}
}

// Configure refuses a connection whose MCP settings -- a tool on its list --
// spell a credential custody holds, its own or another connection's, as
// written or in escapes, and keeps nothing of it; status does not report a
// list written into custody by another hand that spells one.
func TestAzureDevOpsMCPConfiguredNamesNeverCarryASecret(t *testing.T) {
	s, b, _, dir := adoMCPNamespace(t)
	for name, tools := range map[string][]string{
		"its own access token":                  {"wit_work_item", adoBearer},
		"its own access token, escaped":         {adoEscaped(adoBearer)},
		"the other connection's token":          {adoPAT},
		"the other connection's token, escaped": {"x" + adoEscaped(adoPAT)},
	} {
		fields := adoBearerFields()
		fields["id"] = "other"
		if err := adoConfigureMCP(b, fields, []AzureDevOpsMCPServer{{Server: "remote", Tools: tools}}); err != azureDevOpsInConfiguration || bytes.Contains(adoState(t, dir), []byte(`"other"`)) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// A list written into custody by another hand.
	s.locked(func(v *state) error {
		v.AzureDevOps.Connections[0].MCP[0].Tools = []string{"wit_work_item", adoPAT}
		return s.write("state.json", v)
	})
	status, err := b.Handle(context.Background(), "status", []byte(`{}`))
	raw, _ := json.Marshal(status)
	if err != nil || bytes.Contains(raw, []byte(adoPAT)) || bytes.Contains(raw, []byte(`"mcp"`)) || !bytes.Contains(raw, []byte(`"ready":false`)) {
		t.Fatalf("status %s %v", raw, err)
	}
}

// Every answer of a session is screened before it is read, and is read by
// the exact names of the members it is decided by: a handshake, a listing or
// a result that also names one in another case is refused, and no tool is
// called for a handshake or a listing that is.
func TestAzureDevOpsMCPTheMembersDecidedByAreReadByExactName(t *testing.T) {
	s, _, c, _ := adoMCPFixture(t, adoBearerFields(), adoMCPServers())
	initialize := "provider-unavailable: the MCP server remote: initialize: the server's answer is not an initialize result of the protocol's form, or names a member it is read by in another case"
	listing := "provider-unavailable: the MCP server remote: tools/list: the server's answer is not a tool list of the protocol's form, or names a member it is read by in another case"
	result := "provider-unavailable: the MCP server's answer is not of the form this connection reads, or names a member it reads in another case"
	text := `[{"type":"text","text":"1 item"}]`
	for name, k := range map[string]struct {
		change func(*fakemcp.Script)
		want   string
		called bool
	}{
		"a server's name beside its alias": {func(script *fakemcp.Script) { script.ServerInfo = `{"name":"fake","Name":"other","version":"1"}` }, initialize, false},
		"a tool's name beside its alias": {func(script *fakemcp.Script) {
			script.Tools = `[{"name":"wit_work_item","Name":"other","inputSchema":{"type":"object"}}]`
		}, listing, false},
		"an output schema beside its alias": {func(script *fakemcp.Script) {
			script.Tools = `[{"name":"wit_work_item","outputSchema":{"type":"object"},"OutputSchema":{"type":"string"}}]`
		}, listing, false},
		"isError beside a capital that says otherwise": {func(script *fakemcp.Script) {
			script.Result = `{"content":` + text + `,"isError":false,"IsError":true}`
		}, result, true},
		"isError beside its long s": {func(script *fakemcp.Script) {
			script.Result = `{"content":` + text + `,"isError":false,"iſError":true}`
		}, result, true},
		"content beside its capital": {func(script *fakemcp.Script) {
			script.Result = `{"content":` + text + `,"Content":[{"type":"text","text":"other"}]}`
		}, result, true},
		"a text beside its capital": {func(script *fakemcp.Script) { script.Result = `{"content":[{"type":"text","text":"a","Text":"b"}]}` }, result, true},
	} {
		f := adoFakeMCP(t, k.change)
		out, err := azureDevOpsAcquire(context.Background(), s, adoMCPRead(c, "wit_work_item", ""), adoMCPServe(nil, f))
		if out != nil || err == nil || err.Error() != k.want || k.called != strings.Contains(adoMethods(f), "tools/call") {
			t.Errorf("%s: %v, %s", name, err, adoMethods(f))
		}
	}
}

// Compression is neither asked for nor undone: no request asks for an
// encoding, and an answer that names one -- compressed or not, at any stage
// of the session -- is refused, so the bound is on the bytes received.
func TestAzureDevOpsMCPACompressedAnswerIsRefused(t *testing.T) {
	s, _, c, _ := adoMCPFixture(t, adoBearerFields(), adoMCPServers())
	for _, stage := range []string{"initialize", "tools/list", "tools/call"} {
		for _, compressed := range []bool{true, false} {
			f := adoFakeMCP(t, func(script *fakemcp.Script) {
				script.Answer = func(w http.ResponseWriter, method string, id json.RawMessage) bool {
					if method != stage {
						return false
					}
					result := `{"protocolVersion":"2025-06-18","capabilities":{"tools":{}},"serverInfo":{"name":"fake","version":"1"}}`
					switch method {
					case "initialize":
						w.Header().Set("Mcp-Session-Id", adoMCPSession)
					case "tools/list":
						result = `{"tools":` + adoMCPTools + `}`
					case "tools/call":
						result = adoMCPResult
					}
					message := []byte(`{"jsonrpc":"2.0","id":` + string(id) + `,"result":` + result + `}`)
					w.Header().Set("Content-Type", "application/json")
					w.Header().Set("Content-Encoding", "gzip")
					if compressed {
						var b bytes.Buffer
						z := gzip.NewWriter(&b)
						z.Write(message)
						z.Close()
						message = b.Bytes()
					}
					w.Write(message)
					return true
				}
			})
			out, err := azureDevOpsAcquire(context.Background(), s, adoMCPRead(c, "wit_work_item", ""), adoMCPServe(nil, f))
			if out != nil || err != azureDevOpsMCPEncoded {
				t.Errorf("%s, compressed %v: %v", stage, compressed, err)
			}
			for _, r := range f.Requests() {
				if r.Header.Get("Accept-Encoding") != "" {
					t.Errorf("%s: a request asked for %q", stage, r.Header.Get("Accept-Encoding"))
				}
			}
			if stage != "tools/call" && strings.Contains(adoMethods(f), "tools/call") {
				t.Errorf("%s: a tool was called after an encoded answer", stage)
			}
		}
	}
}

// The access token is held to its expiry immediately before every request
// of a session: one configured to expire within the minute is refused
// before anything is sent, and a session whose next request would go within
// the minute ends there, with nothing kept, and no further request -- not
// even the session's end -- is sent under it.
func TestAzureDevOpsMCPTheBearerIsCheckedBeforeEverySend(t *testing.T) {
	fields := adoBearerFields()
	fields["expires-at"] = time.Now().Add(30 * time.Second).UTC().Format(time.RFC3339)
	s, b, c, _ := adoMCPFixture(t, fields, adoMCPServers())
	f := adoFakeMCP(t, nil)
	b.provider = adoMCPServe(newADOFake(t), f)
	if out, err := azureDevOpsAcquire(context.Background(), s, adoMCPRead(c, "wit_work_item", ""), adoMCPServe(nil, f)); out != nil || err != azureDevOpsExpired || len(f.Requests()) != 0 {
		t.Fatalf("expired on arrival: %v, %d requests", err, len(f.Requests()))
	}
	answer, err := b.Handle(context.Background(), "test", []byte(`{"id":"board","revision":"`+c.Revision+`"}`))
	raw, _ := json.Marshal(answer)
	if err != nil || !bytes.Contains(raw, []byte(`"error":"credentials-expired: `)) || !bytes.Contains(raw, []byte(`"api":{"error":"credentials-expired: `)) || len(f.Requests()) != 0 {
		t.Fatalf("a test expired on arrival: %s %v, %d requests", raw, err, len(f.Requests()))
	}
	fields = adoBearerFields()
	fields["expires-at"] = time.Now().Add(62 * time.Second).UTC().Format(time.RFC3339)
	s, _, c, _ = adoMCPFixture(t, fields, adoMCPServers())
	slow := adoFakeMCP(t, func(script *fakemcp.Script) {
		script.Answer = func(w http.ResponseWriter, method string, _ json.RawMessage) bool {
			if method == "initialize" {
				time.Sleep(2500 * time.Millisecond)
			}
			return false
		}
	})
	out, err := azureDevOpsAcquire(context.Background(), s, adoMCPRead(c, "wit_work_item", ""), adoMCPServe(nil, slow))
	if out != nil || err != azureDevOpsExpired || adoMethods(slow) != "initialize" {
		t.Fatalf("expiring in a session: %v, %s", err, adoMethods(slow))
	}
}

// Every outgoing text is screened once more: a test's report whose list
// names the session id has it replaced, and a status, a refusal and a test
// answer hold no credential custody holds, whatever the server sends back.
func TestAzureDevOpsMCPEveryOutgoingTextIsScreened(t *testing.T) {
	// The session id as a tool on the list the server does not offer.
	s, _, c, _ := adoMCPFixture(t, adoBearerFields(), []AzureDevOpsMCPServer{{Server: "remote", Tools: []string{adoMCPSession, "wit_work_item"}}})
	f := adoFakeMCP(t, nil)
	reports, _, err := adoMCPServe(nil, f).azureDevOpsMCPTest(context.Background(), s, c.ID, c.Revision)
	raw, _ := json.Marshal(reports)
	if err != nil || !bytes.Contains(raw, []byte(`"notOffered":["[redacted]"]`)) || strings.Contains(adoMethods(f), "tools/call") {
		t.Fatalf("test %s %v", raw, err)
	}
	adoMCPAbsent(t, "test", string(raw))
	out, err := azureDevOpsAcquire(context.Background(), s, adoMCPRead(c, adoMCPSession, ""), adoMCPServe(nil, adoFakeMCP(t, nil)))
	if out != nil || err == nil || err.Error() != "tool-not-offered: the MCP server remote does not offer the tool the read names; nothing was called" {
		t.Fatal(err)
	}
	// A server echoing whatever it is sent, in every place it can.
	var seen []string
	ns, nb, nc, _ := adoMCPNamespace(t)
	for _, stage := range []string{"initialize", "tools/list", "tools/call"} {
		echoing := adoFakeMCP(t, func(script *fakemcp.Script) {
			script.Answer = func(w http.ResponseWriter, method string, _ json.RawMessage) bool {
				if method != stage {
					return false
				}
				w.WriteHeader(403)
				fmt.Fprintf(w, `{"message":%q}`, adoPAT+" "+adoBasic)
				return true
			}
		})
		_, err := azureDevOpsAcquire(context.Background(), ns, adoMCPRead(nc, "wit_work_item", ""), adoMCPServe(nil, echoing))
		if err == nil {
			t.Fatal(stage, "kept")
		}
		seen = append(seen, err.Error())
		nb.provider = adoMCPServe(newADOFake(t), echoing)
		answer, err := nb.Handle(context.Background(), "test", []byte(`{"id":"board","revision":"`+nc.Revision+`"}`))
		raw, _ := json.Marshal(answer)
		seen = append(seen, string(raw), fmt.Sprint(err))
	}
	status, _ := nb.Handle(context.Background(), "status", []byte(`{}`))
	raw, _ = json.Marshal(status)
	seen = append(seen, string(raw))
	for i, text := range seen {
		adoMCPAbsent(t, fmt.Sprint("output ", i), text)
	}
}

// The cross-vendor round's probes (round 1, at a8fdd3d), adopted as
// regressions: each asserted a defect or a hold, and now asserts the fix or
// the hold.

// adoMCPWire is the remote server and the organization's API answering in
// process, as a probe scripts it: initialize with a session id, a listing of
// two pages, the call and the session's end, each answer under a peer
// certificate named by its method. mutate changes an answer before it is
// written, and fail fails a request before it is answered. It records the
// methods it was sent; a request elsewhere, or under another bearer or
// header, fails the test.
type adoMCPWire struct {
	t               *testing.T
	methods         []string
	page            int
	session, header string
	mutate          func(method string, envelope map[string]any, response *http.Response)
	fail            func(method string) error
}

func adoMCPWireDefault(t *testing.T) *adoMCPWire {
	return &adoMCPWire{t: t, session: adoMCPSession, header: "true"}
}

func (w *adoMCPWire) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.URL.Scheme != "https" || r.URL.Host != adoMCPHost && r.URL.Host != "dev.azure.com" {
		w.t.Fatalf("a request to %s", r.URL)
	}
	if r.Header.Get("Authorization") != "Bearer "+adoBearer {
		w.t.Fatal("another bearer")
	}
	if r.URL.Host == "dev.azure.com" {
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(adoWIQL)), Request: r}, nil
	}
	if r.URL.Path != "/example" {
		w.t.Fatalf("another path: %s", r.URL.Path)
	}
	// As the page writes it: the header's name is as sent, not as Go
	// would write it.
	if got := strings.Join(r.Header[azureDevOpsReadOnlyHeader], ","); got != w.header {
		w.t.Fatalf("the read-only header %q, not %q", got, w.header)
	}
	var request map[string]json.RawMessage
	method := r.Method
	if r.Body != nil {
		json.NewDecoder(r.Body).Decode(&request)
		json.Unmarshal(request["method"], &method)
	}
	w.methods = append(w.methods, method)
	if w.fail != nil {
		if err := w.fail(method); err != nil {
			return nil, err
		}
	}
	var result any
	switch method {
	case "initialize":
		result = json.RawMessage(`{"protocolVersion":"2025-06-18","capabilities":{"tools":{}},"serverInfo":{"name":"fixture","version":"1"}}`)
	case "tools/list":
		w.page++
		result = json.RawMessage(`{"tools":[],"nextCursor":"page2"}`)
		if w.page > 1 {
			result = json.RawMessage(`{"tools":` + adoMCPTools + `}`)
		}
	case "tools/call":
		result = json.RawMessage(adoMCPResult)
	}
	response := &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"application/json"}}, Request: r,
		TLS: &tls.ConnectionState{PeerCertificates: []*x509.Certificate{{Raw: []byte(method)}}}}
	if method == "initialize" {
		response.Header.Set("Mcp-Session-Id", w.session)
	}
	envelope := map[string]any{"jsonrpc": "2.0", "id": request["id"], "result": result}
	if method == "notifications/initialized" || method == "DELETE" {
		response.StatusCode, envelope = 202, map[string]any{}
	}
	if w.mutate != nil {
		w.mutate(method, envelope, response)
	}
	raw, _ := json.Marshal(envelope)
	response.Body = io.NopCloser(bytes.NewReader(raw))
	return response, nil
}

// at reports whether method is the stage a probe names: a method, or the
// first or the second page of the listing.
func (w *adoMCPWire) at(stage, method string) bool {
	return method == stage || method == "tools/list" && (stage == "list1" && w.page == 1 || stage == "list2" && w.page == 2)
}

// adoMCPThrough is the connection's own provider with the wire as its
// transport.
func adoMCPThrough(w *adoMCPWire) provider {
	p := azureDevOpsProvider()
	p.client = &http.Client{Transport: w, CheckRedirect: p.client.CheckRedirect, Timeout: p.client.Timeout}
	return p
}

// adoMCPKeptNothing fails where an output or an error spells a credential
// or the session id.
func adoMCPKeptNothing(t *testing.T, name string, out []byte, err error) {
	t.Helper()
	secrets := []string{adoBearer, adoPAT, adoBasic, adoMCPSession}
	if databricksCarries(out, secrets) || err != nil && databricksSpells(err.Error(), secrets) {
		t.Errorf("%s: a credential or the session id in %q, %v", name, out, err)
	}
}

// adoMCPExtra adds a member beside a result's own, holding text.
func adoMCPExtra(envelope map[string]any, text string) {
	raw, _ := json.Marshal(envelope["result"])
	envelope["result"] = json.RawMessage(string(raw[:len(raw)-1]) + `,"extra":"` + text + `"}`)
}

// Every credential custody holds and the session id, as written, escaped or
// nested seven levels, beside a result's members at every stage -- the
// handshake, either page of the listing, the call -- or in a JSON-RPC
// error, is refused with nothing kept; in the arguments, nothing is sent; in
// a transport's error, nothing is kept. A test and a status hold none, and
// configure refuses a name that spells one.
func TestAzureDevOpsMCPEverySecretAtEveryStageIsRefused(t *testing.T) {
	s, b, c, _ := adoMCPNamespace(t)
	for name, secret := range map[string]string{"the access token": adoBearer, "the other token": adoPAT, "its basic value": adoBasic, "the session id": adoMCPSession} {
		for form, written := range map[string]string{"as written": secret, "escaped": adoEscaped(secret), "nested": adoNested(secret, 7)} {
			for _, stage := range []string{"initialize", "list1", "list2", "tools/call", "a JSON-RPC error"} {
				w := adoMCPWireDefault(t)
				w.mutate = func(method string, envelope map[string]any, _ *http.Response) {
					switch {
					case stage == "a JSON-RPC error" && method == "tools/call":
						delete(envelope, "result")
						envelope["error"] = json.RawMessage(`{"code":-1,"message":"` + written + `"}`)
					case w.at(stage, method):
						adoMCPExtra(envelope, written)
					}
				}
				out, err := azureDevOpsAcquire(context.Background(), s, adoMCPRead(c, "wit_work_item", ""), adoMCPThrough(w))
				if out != nil || err == nil {
					t.Errorf("%s %s at %s: kept", name, form, stage)
				}
				adoMCPKeptNothing(t, name+" "+form+" at "+stage, out, err)
			}
			if name != "the session id" {
				w := adoMCPWireDefault(t)
				out, err := azureDevOpsAcquire(context.Background(), s, adoMCPRead(c, "wit_work_item", `{"x":"`+written+`"}`), adoMCPThrough(w))
				if out != nil || err == nil || len(w.methods) != 0 {
					t.Errorf("%s %s in the arguments: sent", name, form)
				}
				adoMCPKeptNothing(t, name+" in the arguments", out, err)
			}
		}
	}
	for _, stage := range []string{"initialize", "tools/list", "tools/call"} {
		w := adoMCPWireDefault(t)
		w.fail = func(method string) error {
			if method == stage {
				return errors.New("unreachable " + adoNested(adoPAT, 4))
			}
			return nil
		}
		out, err := azureDevOpsAcquire(context.Background(), s, adoMCPRead(c, "wit_work_item", ""), adoMCPThrough(w))
		if out != nil || err == nil {
			t.Errorf("a transport's error at %s: kept", stage)
		}
		adoMCPKeptNothing(t, "a transport's error at "+stage, out, err)
	}
	w := adoMCPWireDefault(t)
	b.provider = adoMCPThrough(w)
	answer, err := b.Handle(context.Background(), "test", []byte(`{"id":"board","revision":"`+c.Revision+`"}`))
	raw, _ := json.Marshal(answer)
	if err != nil || strings.Contains(strings.Join(w.methods, ","), "tools/call") || !bytes.Contains(raw, []byte(`"api":{"ok":true}`)) {
		t.Fatalf("test %s %v", raw, err)
	}
	adoMCPKeptNothing(t, "test", raw, err)
	answer, err = b.Handle(context.Background(), "status", []byte(`{}`))
	raw, _ = json.Marshal(answer)
	adoMCPKeptNothing(t, "status", raw, err)
	for _, secret := range []string{adoBearer, adoPAT, adoBasic} {
		fields := adoBearerFields()
		fields["id"], fields["name"] = "new", secret
		if err := adoConfigureMCP(b, fields, adoMCPServers()); err == nil {
			t.Error("a name spelling a credential was configured")
		}
	}
}

// What a read reaches and records holds: the endpoint and the header (sent
// or off), distinct statements for distinct calls, the result's peer and
// snapshot, the schema where one is declared; a tool off the list or a
// server named by a URL reaches nothing; a redirect makes one request; and
// the organization URL maps to the endpoint, other forms refused.
func TestAzureDevOpsMCPReachRecordAndHeaderHold(t *testing.T) {
	for _, off := range []bool{false, true} {
		servers := adoMCPServers()
		if off {
			servers[0].ReadOnlyHeader = "off"
		}
		s, b, c, _ := adoMCPFixture(t, adoBearerFields(), servers)
		statements := map[string]bool{}
		for _, q := range []AzureDevOpsRequest{adoMCPRead(c, "wit_work_item", `{"id":1}`), adoMCPRead(c, "wit_work_item", `{"id":2}`), adoMCPRead(c, "repo_repository", `{"id":1}`)} {
			w := adoMCPWireDefault(t)
			if off {
				w.header = ""
			}
			out, err := azureDevOpsAcquire(context.Background(), s, q, adoMCPThrough(w))
			if err != nil {
				t.Fatal(err)
			}
			adoMCPKeptNothing(t, q.Tool, out, err)
			var e struct {
				Acquisition struct {
					Statement, PeerIdentity, Snapshot string
					Schema                            any
				}
			}
			json.Unmarshal(out, &e)
			if statements[e.Acquisition.Statement] {
				t.Fatal("two calls, one commitment")
			}
			statements[e.Acquisition.Statement] = true
			if e.Acquisition.PeerIdentity != "tls:"+digest([]byte("tools/call")) || e.Acquisition.Snapshot != digest([]byte(adoMCPResult)) || (e.Acquisition.Schema == nil) != (q.Tool == "repo_repository") {
				t.Fatalf("%s: %+v", q.Tool, e.Acquisition)
			}
			if got := strings.Join(w.methods, ","); got != "initialize,notifications/initialized,tools/list,tools/list,tools/call,DELETE" {
				t.Fatal(got)
			}
		}
		setting := "send"
		if off {
			setting = "off"
		}
		answer, err := b.Handle(context.Background(), "status", []byte(`{}`))
		raw, _ := json.Marshal(answer)
		if err != nil || !bytes.Contains(raw, []byte(`"readOnlyHeader":"`+setting+`"`)) {
			t.Fatalf("status %s %v", raw, err)
		}
		for _, q := range []AzureDevOpsRequest{adoMCPRead(c, "wit_work_item_write", ""), {Connection: c.ID, Revision: c.Revision, Read: "mcp", Server: "https://elsewhere.example", Tool: "wit_work_item"}} {
			w := adoMCPWireDefault(t)
			if out, err := azureDevOpsAcquire(context.Background(), s, q, adoMCPThrough(w)); out != nil || err == nil || len(w.methods) != 0 {
				t.Fatalf("%s %s reached the server", q.Server, q.Tool)
			}
		}
		w := adoMCPWireDefault(t)
		if off {
			w.header = ""
		}
		w.mutate = func(_ string, _ map[string]any, r *http.Response) {
			r.StatusCode = 302
			r.Header.Set("Location", "https://elsewhere.example/"+adoBearer)
		}
		out, err := azureDevOpsAcquire(context.Background(), s, adoMCPRead(c, "wit_work_item", ""), adoMCPThrough(w))
		if out != nil || err == nil || len(w.methods) != 1 {
			t.Fatalf("a redirect: %v, %v", err, w.methods)
		}
		adoMCPKeptNothing(t, "a redirect", out, err)
	}
	for _, bad := range []string{"https://dev.azure.com/example/p", "https://dev.azure.com:443/example", "https://x@dev.azure.com/example", "https://dev.azure.com.elsewhere/example", "https://dev.azure.com./example", "https://example.visualstudio.com./", "https://example.visualstudio.com:443", "http://dev.azure.com/example"} {
		if _, ok := AzureDevOpsOrganization(bad); ok {
			t.Errorf("%s accepted", bad)
		}
	}
	for _, good := range []string{"https://dev.azure.com/example/", "https://example.visualstudio.com/"} {
		if organization, ok := AzureDevOpsOrganization(good); !ok || (AzureDevOpsConnection{Organization: organization}).mcpEndpoint() != "https://mcp.dev.azure.com/example" {
			t.Errorf("%s: %s", good, organization)
		}
	}
	_, b, _, _ := adoMCPFixture(t, adoTokenFields(), nil)
	fields := adoTokenFields()
	fields["id"] = "new"
	if err := adoConfigureMCP(b, fields, adoMCPServers()); err != azureDevOpsMCPBearer {
		t.Fatal(err)
	}
}

// The whole of every message is screened before any member of it is read
// or acted on -- not only the result a read takes -- for every credential
// custody holds and the session id, to the decoding fixed point: a member
// beside the envelope's own carrying the other connection's token, or the
// access token or the session id nested past one decoding, at the
// handshake, the listing or the call, as JSON or as an event stream, or a
// notification in the stream before the response, is refused, and nothing
// of the read is kept (round 1, finding 2: the round's nine reproductions,
// each kept a record).
func TestAzureDevOpsMCPTheWholeMessageIsScreenedBeforeItIsRead(t *testing.T) {
	s, _, c, _ := adoMCPNamespace(t)
	want := "provider-unavailable: the MCP server remote: the server's answer repeats the credential or its session id, and is not kept"
	for name, secret := range map[string]string{"the other token": adoPAT, "the access token nested": adoNested(adoBearer, 5), "the session id nested": adoNested(adoMCPSession, 5)} {
		for _, stage := range []string{"initialize", "tools/list", "tools/call"} {
			w := adoMCPWireDefault(t)
			w.mutate = func(method string, envelope map[string]any, _ *http.Response) {
				if method == stage {
					envelope["extra"] = json.RawMessage(`"` + secret + `"`)
				}
			}
			out, err := azureDevOpsAcquire(context.Background(), s, adoMCPRead(c, "wit_work_item", ""), adoMCPThrough(w))
			if out != nil || err == nil || err.Error() != want {
				t.Errorf("%s beside the envelope at %s: %v", name, stage, err)
			}
			if stage != "tools/call" && strings.Contains(strings.Join(w.methods, ","), "tools/call") {
				t.Errorf("%s at %s: a tool was called", name, stage)
			}
			adoMCPKeptNothing(t, name+" at "+stage, out, err)
		}
	}
	// As an event stream: beside the response, and in a notification the
	// stream carries before it.
	for name, event := range map[string]func(id string) string{
		"beside the response": func(id string) string {
			return `data: {"jsonrpc":"2.0","id":` + id + `,"result":` + adoMCPResult + `,"extra":"` + adoPAT + `"}` + "\n\n"
		},
		"in a notification before it": func(id string) string {
			return `data: {"jsonrpc":"2.0","method":"notifications/message","params":{"data":"` + adoEscaped(adoBasic) + `"}}` + "\n\n" +
				`data: {"jsonrpc":"2.0","id":` + id + `,"result":` + adoMCPResult + `}` + "\n\n"
		},
	} {
		f := adoFakeMCP(t, func(script *fakemcp.Script) {
			script.Answer = func(w http.ResponseWriter, method string, id json.RawMessage) bool {
				if method != "tools/call" {
					return false
				}
				w.Header().Set("Content-Type", "text/event-stream")
				io.WriteString(w, event(string(id)))
				return true
			}
		})
		out, err := azureDevOpsAcquire(context.Background(), s, adoMCPRead(c, "wit_work_item", ""), adoMCPServe(nil, f))
		if out != nil || err == nil || err.Error() != want {
			t.Errorf("an event stream, %s: %v", name, err)
		}
		adoMCPKeptNothing(t, "an event stream, "+name, out, err)
	}
}

// Content-Encoding at its boundary, the MCP profile's and the API
// profile's alike: no header, or identity -- which names no encoding -- in
// any case and given once or twice, is read; any other coding, an empty
// value, identity beside another coding in one header or in two, or an
// answer the transport undid, is refused (round 1, finding 4: identity is
// the documented exception).
func TestAzureDevOpsMCPContentEncodingAtItsBoundary(t *testing.T) {
	s, _, c, _ := adoMCPNamespace(t)
	as, _, ac, _ := adoFixture(t, adoTokenFields())
	for _, k := range []struct {
		values       []string
		uncompressed bool
		read         bool
	}{
		{nil, false, true}, {[]string{"identity"}, false, true}, {[]string{"Identity"}, false, true}, {[]string{"IDENTITY"}, false, true},
		{[]string{"identity, identity"}, false, true}, {[]string{"identity", "identity"}, false, true},
		{[]string{"gzip"}, false, false}, {[]string{"br"}, false, false}, {[]string{"x-identity"}, false, false}, {[]string{""}, false, false},
		{[]string{"identity, gzip"}, false, false}, {[]string{"identity", "gzip"}, false, false}, {nil, true, false},
	} {
		set := func(r *http.Response) {
			for _, value := range k.values {
				r.Header.Add("Content-Encoding", value)
			}
			r.Uncompressed = k.uncompressed
		}
		w := adoMCPWireDefault(t)
		w.mutate = func(_ string, _ map[string]any, r *http.Response) { set(r) }
		out, err := azureDevOpsAcquire(context.Background(), s, adoMCPRead(c, "wit_work_item", ""), adoMCPThrough(w))
		if k.read != (err == nil && out != nil) || !k.read && err != azureDevOpsMCPEncoded {
			t.Errorf("the MCP profile, %q (undone %v): %v", k.values, k.uncompressed, err)
		}
		p := adoThrough(func(r *http.Request) (*http.Response, error) {
			a := adoAnswer(r, 200, adoRepos, "peer")
			set(a)
			return a, nil
		})
		out, err = azureDevOpsAcquire(context.Background(), as, AzureDevOpsRequest{Connection: ac.ID, Revision: ac.Revision, Read: "repos.list"}, p)
		if k.read != (err == nil && out != nil) {
			t.Errorf("the API profile, %q (undone %v): %v", k.values, k.uncompressed, err)
		}
	}
}

// The access token is held to its expiry before every request of a
// session, the session's end included: whichever request would go within
// the minute is not sent, and the read keeps nothing (round 1, finding 3:
// a call answered just before the minute, its end refused, kept a record).
func TestAzureDevOpsMCPExpiryAtEveryRequestOfTheSession(t *testing.T) {
	before := map[string]string{"notifications/initialized": "initialize", "tools/list": "notifications/initialized", "list2": "tools/list", "tools/call": "tools/list", "DELETE": "tools/call"}
	for _, stage := range []string{"initialize", "notifications/initialized", "tools/list", "list2", "tools/call", "DELETE"} {
		fields := adoBearerFields()
		fields["expires-at"] = time.Now().Add(62 * time.Second).UTC().Format(time.RFC3339)
		s, _, c, _ := adoMCPFixture(t, fields, adoMCPServers())
		w := adoMCPWireDefault(t)
		waited := false
		// The answer before the stage is slow, so the stage's request would
		// go within the minute.
		w.mutate = func(method string, _ map[string]any, _ *http.Response) {
			if method == before[stage] && !waited && (stage != "tools/call" || w.page == 2) {
				waited = true
				time.Sleep(2200 * time.Millisecond)
			}
		}
		if stage == "initialize" {
			time.Sleep(2200 * time.Millisecond)
		}
		out, err := azureDevOpsAcquire(context.Background(), s, adoMCPRead(c, "wit_work_item", ""), adoMCPThrough(w))
		if out != nil || err != azureDevOpsExpired {
			t.Errorf("%s: %v, %d bytes", stage, err, len(out))
		}
		for _, method := range w.methods {
			if method == stage {
				t.Errorf("%s: sent after the expiry", stage)
			}
		}
		if stage == "list2" && w.page != 1 {
			t.Errorf("the second page was asked for")
		}
	}
	// A test whose session's end the guard refuses reports the server as
	// not read.
	fields := adoBearerFields()
	fields["expires-at"] = time.Now().Add(62 * time.Second).UTC().Format(time.RFC3339)
	s, _, c, _ := adoMCPFixture(t, fields, adoMCPServers())
	w := adoMCPWireDefault(t)
	w.mutate = func(method string, _ map[string]any, _ *http.Response) {
		if method == "tools/list" && w.page == 2 {
			time.Sleep(2200 * time.Millisecond)
		}
	}
	reports, _, err := adoMCPThrough(w).azureDevOpsMCPTest(context.Background(), s, c.ID, c.Revision)
	if err != nil || len(reports) != 1 || reports[0].OK || !strings.HasPrefix(reports[0].Error, "credentials-expired: ") || strings.Contains(strings.Join(w.methods, ","), "DELETE") {
		t.Fatalf("%+v %v %v", reports, err, w.methods)
	}
}

// A test's whole answer is held to the session id the server issued, which
// the broker's final screen does not know: an API refusal naming it --
// written before the session existed -- has it replaced, and an answer that
// would spell it where nothing can be replaced, as a member's name, is not
// written; a refusal of fixed words is (round 1, finding 1).
func TestAzureDevOpsMCPATestAnswerNeverCarriesTheSessionID(t *testing.T) {
	_, b, c, _ := adoMCPNamespace(t)
	session := "SessionMarkerReview247c3e"
	w := adoMCPWireDefault(t)
	w.session = session
	p := adoMCPThrough(w)
	p.client.Transport = testTransportFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Host == "dev.azure.com" {
			return &http.Response{StatusCode: 403, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(`{"typeKey":"` + session + `"}`)), Request: r}, nil
		}
		return w.RoundTrip(r)
	})
	b.provider = p
	answer, err := b.Handle(context.Background(), "test", []byte(`{"id":"board","revision":"`+c.Revision+`"}`))
	raw, _ := json.Marshal(answer)
	if err != nil || bytes.Contains(raw, []byte(session)) || !bytes.Contains(raw, []byte(`"api":{"error":"permission-denied: the organization answered 403 ([redacted])","ok":false}`)) {
		t.Fatalf("an API refusal naming the session id: %s %v", raw, err)
	}
	for _, fixed := range []string{"offered", "notOffered", "server", "api"} {
		w := adoMCPWireDefault(t)
		w.session = fixed
		b.provider = adoMCPThrough(w)
		answer, err := b.Handle(context.Background(), "test", []byte(`{"id":"board","revision":"`+c.Revision+`"}`))
		raw, _ := json.Marshal(answer)
		if answer != nil || err != unwritten || databricksSpells(err.Error(), []string{fixed}) {
			t.Errorf("the session id %q, a member's name: %s %v", fixed, raw, err)
		}
	}
}

// The guards hold at every stage: a member named in another case, an
// encoded answer, a length announced past the bound, a credential nested
// forty levels deep, each refused with nothing kept.
func TestAzureDevOpsMCPGuardsHoldAtEveryStage(t *testing.T) {
	s, _, c, _ := adoMCPNamespace(t)
	for _, stage := range []string{"initialize", "list1", "list2", "tools/call"} {
		for _, mode := range []string{"an alias", "an encoding", "a length", "forty levels"} {
			w := adoMCPWireDefault(t)
			w.mutate = func(method string, envelope map[string]any, r *http.Response) {
				if !w.at(stage, method) {
					return
				}
				switch mode {
				case "an encoding":
					r.Header.Set("Content-Encoding", "gzip")
				case "a length":
					r.ContentLength = 100 << 20
				case "forty levels":
					adoMCPExtra(envelope, adoNested(adoPAT, 40))
				case "an alias":
					raw, _ := json.Marshal(envelope["result"])
					alias := `"ProtocolVersion":"2025-06-18"`
					if method == "tools/list" {
						alias = `"Tools":[]`
					}
					if method == "tools/call" {
						alias = `"IsError":true`
					}
					envelope["result"] = json.RawMessage(string(raw[:len(raw)-1]) + `,` + alias + `}`)
				}
			}
			out, err := azureDevOpsAcquire(context.Background(), s, adoMCPRead(c, "wit_work_item", ""), adoMCPThrough(w))
			if out != nil || err == nil {
				t.Errorf("%s at %s: kept", mode, stage)
			}
			adoMCPKeptNothing(t, mode+" at "+stage, out, err)
		}
	}
}

// A test reports a handshake or a listing that carries a secret as not
// read, and holds none; status holds a fixed word a token happens to spell.
func TestAzureDevOpsMCPControlAnswersAreScreened(t *testing.T) {
	_, b, c, _ := adoMCPNamespace(t)
	for _, secret := range []string{adoBearer, adoPAT, adoBasic, adoMCPSession} {
		for _, stage := range []string{"initialize", "tools/list"} {
			w := adoMCPWireDefault(t)
			w.mutate = func(method string, envelope map[string]any, _ *http.Response) {
				if method == stage {
					adoMCPExtra(envelope, adoNested(secret, 5))
				}
			}
			b.provider = adoMCPThrough(w)
			answer, err := b.Handle(context.Background(), "test", []byte(`{"id":"board","revision":"`+c.Revision+`"}`))
			raw, _ := json.Marshal(answer)
			if err != nil || !bytes.Contains(raw, []byte(`"ok":false`)) {
				t.Errorf("at %s: %s %v", stage, raw, err)
			}
			adoMCPKeptNothing(t, "test at "+stage, raw, err)
		}
	}
	for _, marker := range []string{"defaultResultBytes", "permission-denied"} {
		fields := adoBearerFields()
		fields["access-token"] = marker
		_, fb, _, _ := adoMCPFixture(t, fields, adoMCPServers())
		answer, err := fb.Handle(context.Background(), "status", []byte(`{}`))
		raw, _ := json.Marshal(answer)
		if databricksCarries(raw, []string{fields["access-token"]}) || err != nil && databricksSpells(err.Error(), []string{fields["access-token"]}) {
			t.Errorf("status: %s %v", raw, err)
		}
	}
}

// The forms hold: a header setting out of its form is refused; arguments
// naming the header, a URL or another project are the tool's and change
// nothing of the request; and a server written into custody under a
// personal access token reaches nothing.
func TestAzureDevOpsMCPFormsHoldInMemory(t *testing.T) {
	s, b, c, _ := adoMCPNamespace(t)
	for _, value := range []any{"OFF", "false", "true", false, 0, "off ", "send\r\n"} {
		fields := adoBearerFields()
		fields["id"] = "new"
		if err := adoConfigureMCP(b, fields, []map[string]any{{"server": "remote", "tools": []string{"wit_work_item"}, "readOnlyHeader": value}}); err == nil {
			t.Errorf("%q: configured", value)
		}
	}
	w := adoMCPWireDefault(t)
	if out, err := azureDevOpsAcquire(context.Background(), s, adoMCPRead(c, "wit_work_item", `{"readOnlyHeader":"off","X-MCP-Readonly":"false","url":"https://elsewhere.example/","project":"another-project"}`), adoMCPThrough(w)); err != nil || len(out) == 0 {
		t.Fatal(err)
	}
	ps, _, pc, _ := adoFixture(t, adoTokenFields())
	ps.locked(func(v *state) error {
		v.AzureDevOps.Connections[0].MCP = []AzureDevOpsMCPServer{{Server: "remote", Tools: []string{"wit_work_item"}, ReadOnlyHeader: "send"}}
		return ps.write("state.json", v)
	})
	w = adoMCPWireDefault(t)
	if out, err := azureDevOpsAcquire(context.Background(), ps, adoMCPRead(pc, "wit_work_item", ""), adoMCPThrough(w)); out != nil || err == nil || len(w.methods) != 0 {
		t.Fatal("a server under a personal access token was reached")
	}
}

// Beneath the whole message's screen, the read's own screens still hold:
// the handshake, a listing page and a tool's result that spell a secret,
// nested past one decoding, are refused by the connection where a client
// screens nothing of its own (one opened without a screen).
func TestAzureDevOpsMCPTheReadsOwnScreensHoldBeneathTheMessages(t *testing.T) {
	secrets := []string{adoBearer, adoPAT, adoBasic}
	nested := adoNested(adoPAT, 5)
	for _, stage := range []string{"initialize", "list1"} {
		w := adoMCPWireDefault(t)
		w.header = ""
		w.mutate = func(method string, envelope map[string]any, _ *http.Response) {
			if w.at(stage, method) {
				adoMCPExtra(envelope, nested)
			}
		}
		client, err := mcphttp.Open("https://mcp.dev.azure.com/example", mcphttp.Options{Token: adoBearer}, &http.Client{Transport: w})
		if err != nil {
			t.Fatal(err)
		}
		held, err := databricksMCPInitialize(context.Background(), client, secrets)
		if err == nil {
			err = databricksMCPList(context.Background(), client, held, func(string, json.RawMessage) (bool, error) { return false, nil })
		}
		if err != databricksMCPRepeats {
			t.Errorf("%s: %v", stage, err)
		}
	}
	result := `{"content":[{"type":"text","text":"1"}],"structuredContent":{"note":"` + nested + `"}}`
	if out, err := databricksToolAnswer([]byte(result), 1<<20, secrets); out != nil || err == nil || err.Error() != "provider-unavailable: the MCP server's answer repeats the credential or its session id, and is not kept" {
		t.Errorf("a result: %v", err)
	}
}
