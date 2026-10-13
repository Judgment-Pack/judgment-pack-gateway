package connections

// The MCP profile of an Azure DevOps connection: the organization's remote
// MCP server, which Azure DevOps hosts at https://mcp.dev.azure.com/
// {organization} and serves over Streamable HTTP under a Microsoft Entra
// access token. The operator enables it as the server "remote" with the
// tools a read may call on it. A read is one tool call through mcphttp, as
// the Databricks MCP profile makes one: initialize, the tool's descriptor
// from tools/list, the call, and the end of the session, each request under
// the connection's access token, checked against its expiry immediately
// before it is sent, and by default with the server's read-only header. What
// a tool does is the organization's: the header is the server's promise, and
// the allowlist and the credential's permissions are the only guard here.
import (
	"adapters/document"
	"adapters/internal/canon"
	"adapters/mcphttp"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

const (
	// AzureDevOpsMCPHost is where the remote MCP server is hosted; the
	// organization's name follows it.
	AzureDevOpsMCPHost = "https://mcp.dev.azure.com/"
	// azureDevOpsMCPServer is the one server a connection may enable: the
	// remote server of its own organization.
	azureDevOpsMCPServer = "remote"
	// azureDevOpsMCPTools bounds the tools a read may call.
	azureDevOpsMCPTools = 32
	// azureDevOpsMCPSeconds bounds a read, within the source's 55 seconds;
	// azureDevOpsMCPTestSeconds the server's part of a test, which follows
	// the API profile's 25-second request within the companion's 50.
	azureDevOpsMCPSeconds     = 50
	azureDevOpsMCPTestSeconds = 15
	// The read-only header the server documents, and the value it holds to.
	azureDevOpsReadOnlyHeader = "X-MCP-Readonly"
	azureDevOpsReadOnlyValue  = "true"
	// A server's readOnlyHeader: sent (the default), or turned off.
	azureDevOpsReadOnlySend = "send"
	azureDevOpsReadOnlyOff  = "off"
)

// AzureDevOpsMCPServer is the remote MCP server a connection enables, by its
// name, the tools a read may call on it (none, when the list is empty), and
// whether the read-only header is sent with every request: "send", the
// default, or "off", which the operator sets knowingly.
type AzureDevOpsMCPServer struct {
	Server         string   `json:"server"`
	Tools          []string `json:"tools"`
	ReadOnlyHeader string   `json:"readOnlyHeader,omitempty"`
}

const (
	// azureDevOpsMCPBearer refuses the MCP profile under a personal access
	// token, which the remote server does not take.
	azureDevOpsMCPBearer = Error("bearer-required: the remote MCP server takes a Microsoft Entra access token (auth \"bearer\"), and personal access tokens aren't supported for it; the connection was not saved")
	// azureDevOpsMCPEncoded is an answer that names a content encoding: none
	// was asked for, and the bound is on the bytes received.
	azureDevOpsMCPEncoded = Error("provider-unavailable: the MCP server's answer is encoded, and this connection reads only what it asked for, which is not")
)

// azureDevOpsMCPValid holds the servers a connection enables to their form:
// at most one, "remote", with at most 32 tools, each of a tool name's form
// and listed once, and a read-only header sent or turned off.
func azureDevOpsMCPValid(servers []AzureDevOpsMCPServer) bool {
	if len(servers) > 1 {
		return false
	}
	for _, server := range servers {
		if server.Server != azureDevOpsMCPServer || server.Tools == nil || len(server.Tools) > azureDevOpsMCPTools ||
			server.ReadOnlyHeader != azureDevOpsReadOnlySend && server.ReadOnlyHeader != azureDevOpsReadOnlyOff {
			return false
		}
		seen := map[string]bool{}
		for _, tool := range server.Tools {
			if !databricksTool.MatchString(tool) || seen[tool] {
				return false
			}
			seen[tool] = true
		}
	}
	return true
}

// mcpTexts are the connection's MCP settings as text: each server's name,
// its tools and its header setting.
func (c AzureDevOpsConnection) mcpTexts() []string {
	texts := []string{}
	for _, server := range c.MCP {
		texts = append(texts, server.Server, server.ReadOnlyHeader)
		texts = append(texts, server.Tools...)
	}
	return texts
}

// mcpEndpoint is the remote MCP server's endpoint for the connection's
// organization, https://mcp.dev.azure.com/{organization}: the organization's
// name taken from its configured URL, of either form, never from a request.
func (c AzureDevOpsConnection) mcpEndpoint() string {
	name, ok := strings.CutPrefix(c.Organization, "https://dev.azure.com/")
	if !ok {
		name = strings.TrimSuffix(strings.TrimPrefix(c.Organization, "https://"), ".visualstudio.com")
	}
	return AzureDevOpsMCPHost + name
}

// mcpServer is the server of that name the connection enables.
func (c AzureDevOpsConnection) mcpServer(name string) (AzureDevOpsMCPServer, bool) {
	for _, server := range c.MCP {
		if server.Server == name {
			return server, true
		}
	}
	return AzureDevOpsMCPServer{}, false
}

// checkMCP holds an mcp read to the connection: a server it enables, and a
// tool on that server's list.
func (q AzureDevOpsRequest) checkMCP(c AzureDevOpsConnection) error {
	server, ok := c.mcpServer(q.Server)
	if !ok {
		return databricksNotEnabled
	}
	for _, tool := range server.Tools {
		if tool == q.Tool {
			return nil
		}
	}
	return databricksNotAllowed
}

// azureDevOpsMCPGuard is the transport each request of an MCP session goes
// through: the access token is held to its expiry immediately before every
// request, and an answer that names a content encoding is refused, since
// none was asked for and the bound is on the bytes received. What it
// refused is kept for the refusal's words.
type azureDevOpsMCPGuard struct {
	next    http.RoundTripper
	c       AzureDevOpsConnection
	refused error
}

func (g *azureDevOpsMCPGuard) RoundTrip(r *http.Request) (*http.Response, error) {
	if g.c.expired() {
		g.refused = azureDevOpsExpired
		return nil, azureDevOpsExpired
	}
	response, err := g.next.RoundTrip(r)
	if err != nil {
		return nil, err
	}
	if encoding := response.Header.Get("Content-Encoding"); response.Uncompressed || encoding != "" && !strings.EqualFold(encoding, "identity") {
		response.Body.Close()
		g.refused = azureDevOpsMCPEncoded
		return nil, azureDevOpsMCPEncoded
	}
	return response, nil
}

// refusal is what a failure of the session is reported as: the guard's own
// refusal where it refused, and otherwise the client's, in the words the
// Databricks MCP profile uses, every secret replaced before it is cut.
func (g *azureDevOpsMCPGuard) refusal(err error, secrets []string) error {
	if g.refused != nil {
		return g.refused
	}
	return databricksMCPRefusal(azureDevOpsMCPServer, err, secrets)
}

// azureDevOpsMCPOpen is the client the remote server is reached through: its
// endpoint for the connection's organization, the access token as the
// bearer, the read-only header unless the operator turned it off, the
// server's list as the only tools a call may name, each answer read no
// further than the result bound and the room a message takes around it, or
// the client's own bound where that is larger; every request through the
// guard.
func (p provider) azureDevOpsMCPOpen(c AzureDevOpsConnection, server AzureDevOpsMCPServer) (*mcphttp.Client, *azureDevOpsMCPGuard, error) {
	guard := &azureDevOpsMCPGuard{next: p.client.Transport, c: c}
	headers := http.Header{}
	if server.ReadOnlyHeader != azureDevOpsReadOnlyOff {
		// Written as the server's page writes it.
		headers[azureDevOpsReadOnlyHeader] = []string{azureDevOpsReadOnlyValue}
	}
	limit := max(int64(c.resultBound())+azureDevOpsErrorBytes, mcphttp.MaxResponse)
	client, err := mcphttp.Open(c.mcpEndpoint(), mcphttp.Options{Token: c.AccessToken, Headers: headers, MaxResponse: limit, Tools: append([]string{}, server.Tools...)}, &http.Client{Transport: guard, Timeout: p.client.Timeout})
	return client, guard, err
}

// azureDevOpsMCPAcquire is one mcp read: one session with the remote server,
// under the connection's access token. The arguments, the tool and the
// server's name are screened for every credential custody holds for the
// provider before anything is sent, and every answer -- initialize, each
// tools/list page, the call -- for every one of them and the session id
// before it is read. The envelope's result is the tool's result in
// canonical form; its acquisition names the server's endpoint, the read as
// the statement the gateway commits to, the digest of the result as
// received, the TLS peer it came from, and the tool's declared output
// schema. The session id is in none of it, nor in any error.
func (p provider) azureDevOpsMCPAcquire(ctx context.Context, s *Store, c AzureDevOpsConnection, q AzureDevOpsRequest, secrets []string) (out []byte, err error) {
	defer func() {
		if err != nil {
			out, err = nil, databricksMCPOutward(err, secrets)
		}
	}()
	server, _ := c.mcpServer(q.Server)
	endpoint := c.mcpEndpoint()
	arguments, err := canon.Canonicalize(q.Arguments, canon.RefuseNumbers)
	if err != nil {
		return nil, ErrRequest
	}
	if databricksCarries(arguments, secrets) || databricksSpells(q.Tool, secrets) || databricksSpells(q.Server, secrets) {
		return nil, azureDevOpsInRequest
	}
	client, guard, err := p.azureDevOpsMCPOpen(c, server)
	if err != nil {
		return nil, guard.refusal(err, secrets)
	}
	rctx, cancel := context.WithTimeout(ctx, azureDevOpsMCPSeconds*time.Second)
	defer cancel()
	defer databricksMCPClose(ctx, client)
	secrets, err = databricksMCPInitialize(rctx, client, secrets)
	if err != nil {
		return nil, guard.refusal(err, secrets)
	}
	var descriptor json.RawMessage
	err = databricksMCPList(rctx, client, secrets, func(name string, tool json.RawMessage) (bool, error) {
		if name == q.Tool {
			descriptor = tool
		}
		return descriptor != nil, nil
	})
	if err != nil {
		return nil, guard.refusal(err, secrets)
	}
	if descriptor == nil {
		return nil, Error("tool-not-offered: the MCP server " + server.Server + " does not offer the tool the read names; nothing was called")
	}
	schema, err := databricksMCPSchema(descriptor)
	if err != nil {
		return nil, err
	}
	raw, err := client.CallTool(rctx, q.Tool, json.RawMessage(arguments))
	if err != nil {
		return nil, guard.refusal(err, secrets)
	}
	observed := time.Now().UTC().Format("2006-01-02T15:04:05Z")
	var peerIdentity any
	if identity := client.PeerIdentity(); identity != "" {
		peerIdentity = identity
	}
	result, err := databricksToolAnswer(raw, c.resultBound(), secrets)
	if err != nil {
		return nil, err
	}
	if err = azureDevOpsCurrent(s, c); err != nil {
		return nil, err
	}
	identity, err := document.OwnIdentity()
	if err != nil {
		return nil, ErrProvider
	}
	identity.Name = "adapter-sources"
	record := map[string]any{"connection": c.ID, "revision": c.Revision, "provider": "azure-devops", "project": c.Project, "read": "mcp", "server": server.Server, "endpoint": endpoint, "tool": q.Tool, "arguments": json.RawMessage(arguments)}
	encoded, err := canon.EncodeJSON(record)
	if err != nil {
		return nil, ErrRequest
	}
	statement, err := canon.Canonicalize(encoded, canon.RefuseNumbers)
	if err != nil {
		return nil, ErrRequest
	}
	acquisition := map[string]any{"adapter": identity, "endpoint": endpoint, "statement": string(statement), "snapshot": digest(raw), "peerIdentity": peerIdentity, "schema": schema, "upstreamToken": nil, "observedAt": observed}
	out, err = canon.EncodeJSON(map[string]any{"acquisition": acquisition, "result": json.RawMessage(result)})
	if err != nil {
		return nil, ErrProvider
	}
	if len(out) > MaxOutputBytes {
		return nil, Error(fmt.Sprintf("result-too-large: the envelope is larger than the source's output bound of %d bytes", MaxOutputBytes))
	}
	if databricksCarries(out, secrets) {
		return nil, Error("provider-unavailable: the record would carry the credential, and is not written")
	}
	return out, nil
}

// azureDevOpsMCPTest reaches the server the connection enables: initialize
// and its tools, and nothing called. It is nil for a connection that enables
// none, or whose connection could not be read, with the reason.
func (p provider) azureDevOpsMCPTest(ctx context.Context, s *Store, id, revision string) ([]databricksMCPReport, error) {
	c, secrets, err := azureDevOpsSnapshot(s, id, revision)
	if err != nil || len(c.MCP) == 0 {
		return nil, err
	}
	reports := []databricksMCPReport{}
	for _, server := range c.MCP {
		report, held := p.azureDevOpsMCPProbe(ctx, c, server, secrets)
		reports = append(reports, report.screened(held))
	}
	return reports, nil
}

// azureDevOpsMCPProbe is the server's part of a test, and the secrets its
// report is held against: the tools it offers, the names on the
// connection's list it does not, or why it could not be read.
func (p provider) azureDevOpsMCPProbe(ctx context.Context, c AzureDevOpsConnection, server AzureDevOpsMCPServer, secrets []string) (databricksMCPReport, []string) {
	report := databricksMCPReport{Server: server.Server, Offered: []string{}, NotOffered: []string{}}
	client, guard, err := p.azureDevOpsMCPOpen(c, server)
	if err != nil {
		report.Error = guard.refusal(err, secrets).Error()
		return report, secrets
	}
	rctx, cancel := context.WithTimeout(ctx, azureDevOpsMCPTestSeconds*time.Second)
	defer cancel()
	defer databricksMCPClose(ctx, client)
	secrets, err = databricksMCPInitialize(rctx, client, secrets)
	var names []string
	if err == nil {
		err = databricksMCPList(rctx, client, secrets, func(name string, _ json.RawMessage) (bool, error) {
			if len(names) == databricksMCPOffered {
				return true, fmt.Errorf("the server offers more than %d tools", databricksMCPOffered)
			}
			names = append(names, name)
			return false, nil
		})
	}
	if err != nil {
		report.Error = guard.refusal(err, secrets).Error()
		return report, secrets
	}
	offered := map[string]bool{}
	for _, name := range names {
		offered[name] = true
		if len(name) > databricksMCPName {
			name = clipSearchText(name, databricksMCPName) + "…"
		}
		report.Offered = append(report.Offered, name)
	}
	for _, tool := range server.Tools {
		if !offered[tool] {
			report.NotOffered = append(report.NotOffered, tool)
		}
	}
	report.OK = true
	return report, secrets
}
