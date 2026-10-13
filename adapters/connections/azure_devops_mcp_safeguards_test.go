//go:build linux || darwin

package connections

import (
	"adapters/internal/fakemcp"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
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
// kept, nothing more is asked, and no error repeats it.
func TestAzureDevOpsMCPEveryCredentialInAnAnswerIsRefused(t *testing.T) {
	s, _, c, _ := adoMCPNamespace(t)
	byClient := "provider-unavailable: the MCP server remote: the server's answer repeats the credential"
	byResult := "provider-unavailable: the MCP server's answer repeats the credential or its session id, and is not kept"
	bySession := "provider-unavailable: the MCP server remote: the server's answer repeats the credential or its session id, and is not kept"
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
				want := byResult
				if place != "the result" && place != "a member name of the result" {
					want = bySession
				}
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
// a credential or the session id is not reported where it still spells one
// once its own escapes are decoded; where it spells one only as written, each
// whole one is replaced before the text is cut.
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
		if out != nil || err == nil || err.Error() != "tool-error: the tool reported an error whose text repeats the credential or its session id; the text is not reported" {
			t.Errorf("%s in a failed tool's text: %v", name, err)
		}
		f = adoFakeMCP(t, func(script *fakemcp.Script) {
			script.Refuse = `{"code":-32000,"message":"denied for ` + nested + `"}`
		})
		out, err = azureDevOpsAcquire(context.Background(), s, adoMCPRead(c, "wit_work_item", ""), adoMCPServe(nil, f))
		if out != nil || err == nil || err.Error() != "provider-unavailable: the MCP server remote: the server's text repeats the credential or its session id, and is not reported" {
			t.Errorf("%s in a refusal: %v", name, err)
		}
		if err != nil {
			adoMCPAbsent(t, name, err.Error())
		}
	}
	// A credential as written in a failed tool's text, the client not
	// knowing it, is replaced before the text is cut, across the cut.
	long := strings.Repeat("x", databricksMessageBytes-len("tool-error: ")-len(adoPAT)+1) + adoPAT
	f := adoFakeMCP(t, func(script *fakemcp.Script) {
		script.Result = `{"content":[{"type":"text","text":"` + long + `"}],"isError":true}`
	})
	_, err := azureDevOpsAcquire(context.Background(), s, adoMCPRead(c, "wit_work_item", ""), adoMCPServe(nil, f))
	if want := databricksClip("tool-error: " + strings.Repeat("x", databricksMessageBytes-len("tool-error: ")-len(adoPAT)+1) + "[redacted]"); err == nil || err.Error() != want {
		t.Errorf("across the cut: %.80q", err)
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
		}, "provider-unavailable: the MCP server's answer repeats the credential or its session id, and is not kept"},
		"in a refusal": {func(script *fakemcp.Script) {
			script.Refuse = `{"code":-32000,"message":"no session ` + adoMCPSession + `"}`
		}, byClient},
		"nested in a refusal": {func(script *fakemcp.Script) {
			script.Refuse = `{"code":-32000,"message":"no session ` + adoNested(adoMCPSession, 4) + `"}`
		}, "provider-unavailable: the MCP server remote: the server's text repeats the credential or its session id, and is not reported"},
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
	reports, err := adoMCPServe(nil, f).azureDevOpsMCPTest(context.Background(), s, c.ID, c.Revision)
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
