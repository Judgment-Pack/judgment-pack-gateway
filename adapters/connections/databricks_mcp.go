package connections

// The MCP profile of a Databricks connection: the workspace's managed MCP
// servers, each an endpoint under the workspace that the operator enables
// with the tools a read may call on it, reached over Streamable HTTP through
// mcphttp under the API profile's credential. A read is one tool call:
// initialize, the tool's descriptor from tools/list, the call, and the end
// of the session. Its result is the tool's result as adapter-mcp's remote
// form reads a source's. What a tool does is the workspace's: the
// identity's grants and the allowlist are what keep this profile to reads.
import (
	"adapters/document"
	"adapters/internal/canon"
	"adapters/mcp"
	"adapters/mcphttp"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	// databricksMCPServers bounds the servers a connection enables, and
	// databricksMCPTools the tools each may call.
	databricksMCPServers = 16
	databricksMCPTools   = 32
	// databricksMCPSeconds bounds a read, within the source's 55 seconds;
	// databricksMCPTestSeconds each server's part of a test, within the
	// companion's 50.
	databricksMCPSeconds     = 50
	databricksMCPTestSeconds = 15
	// databricksMCPOffered bounds the tool names a test reports of a server.
	databricksMCPOffered = 1024
	databricksMCPName    = 128
)

// DatabricksMCPServer is one managed MCP server a connection enables, by
// its name, and the tools a read may call on it: none, when the list is
// empty.
type DatabricksMCPServer struct {
	Server string   `json:"server"`
	Tools  []string `json:"tools"`
}

// databricksSpace is a Genie space's id as Databricks writes it: 32
// lowercase hexadecimal characters.
var databricksSpace = regexp.MustCompile(`^[0-9a-f]{32}$`)

// databricksTool is a tool name of the form the MCP specification says a
// name should take: 1 to 128 ASCII letters, digits, underscores, hyphens
// and dots.
var databricksTool = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,128}$`)

var databricksStatus = regexp.MustCompile(`^the server answered ([1-5][0-9][0-9]) `)

// databricksMCPPath is the path under the workspace the server's name
// stands for, or "" for a name not of a server's form: "sql"; "genie:"
// and a space id; "functions:" and a function's catalog.schema.name; or
// "ai-search:" and an index's catalog.schema.name. Each Unity Catalog name
// is held to the API profile's name form and written into the path as a
// path segment.
func databricksMCPPath(name string) string {
	kind, key, keyed := strings.Cut(name, ":")
	switch kind {
	case "sql":
		if !keyed {
			return "/api/2.0/mcp/sql"
		}
	case "genie":
		if databricksSpace.MatchString(key) {
			return "/api/2.0/mcp/genie/" + key
		}
	case "functions", "ai-search":
		parts := strings.Split(key, ".")
		if len(parts) != 3 {
			return ""
		}
		path := "/api/2.0/mcp/" + kind
		for _, part := range parts {
			if !databricksName(part) {
				return ""
			}
			path += "/" + url.PathEscape(part)
		}
		return path
	}
	return ""
}

func databricksMCPValid(servers []DatabricksMCPServer) bool {
	if len(servers) > databricksMCPServers {
		return false
	}
	seen := map[string]bool{}
	for _, server := range servers {
		if databricksMCPPath(server.Server) == "" || seen[server.Server] || len(server.Tools) > databricksMCPTools {
			return false
		}
		seen[server.Server] = true
		tools := map[string]bool{}
		for _, tool := range server.Tools {
			if !databricksTool.MatchString(tool) || tools[tool] {
				return false
			}
			tools[tool] = true
		}
	}
	return true
}

// mcpServer is the server of that name the connection enables.
func (c DatabricksConnection) mcpServer(name string) (DatabricksMCPServer, bool) {
	for _, server := range c.MCP {
		if server.Server == name {
			return server, true
		}
	}
	return DatabricksMCPServer{}, false
}

const (
	databricksNotEnabled = Error("server-not-enabled: the connection does not enable the MCP server the read names; nothing was sent")
	databricksNotAllowed = Error("tool-not-allowed: the tool is not on the connection's list for that MCP server; nothing was sent")
)

// checkMCP holds an mcp read to its form: a server the connection enables,
// a tool on that server's list, and arguments that are an object ({} when
// left out); nothing of the API profile's reads.
func (q DatabricksRequest) checkMCP(c DatabricksConnection) (DatabricksRequest, error) {
	if q.Statement != "" || q.Parameters != nil || q.List != "" || q.Catalog != "" || q.Schema != "" || q.PageToken != "" || q.MaxResults != 0 || !databricksTool.MatchString(q.Tool) {
		return q, ErrRequest
	}
	if len(q.Arguments) == 0 || string(q.Arguments) == "null" {
		q.Arguments = json.RawMessage(`{}`)
	}
	if !canon.IsObject(q.Arguments) {
		return q, ErrRequest
	}
	server, ok := c.mcpServer(q.Server)
	if !ok {
		return q, databricksNotEnabled
	}
	for _, tool := range server.Tools {
		if tool == q.Tool {
			return q, nil
		}
	}
	return q, databricksNotAllowed
}

// databricksMCPSecrets is secrets with the session id the server issued
// among them, once it has issued one: an answer that repeats it is not
// kept, and no error or report carries it.
func databricksMCPSecrets(secrets []string, client *mcphttp.Client) []string {
	out := append([]string{}, secrets...)
	if session := client.SessionID(); session != "" {
		out = append(out, session)
	}
	sort.Slice(out, func(i, j int) bool { return len(out[i]) > len(out[j]) })
	return out
}

// databricksClip cuts a text the server wrote to the message bound, after
// every secret in it has been replaced.
func databricksClip(text string) string {
	if len(text) > databricksMessageBytes {
		return clipSearchText(text, databricksMessageBytes) + "…"
	}
	return text
}

// databricksMCPRefusal is what a failure of the client is reported as: the
// API profile's word for the status a server answered, where it answered
// one, and the client's own words, with every secret replaced before the
// text is cut to its bound. Nothing is retried.
func databricksMCPRefusal(server string, err error, secrets []string) error {
	detail := err.Error()
	var failure *mcphttp.Error
	if errors.As(err, &failure) {
		detail = failure.Detail
	} else if errors.Is(err, mcphttp.ErrProtocol) {
		detail = "the server's answer is not of the form the protocol states"
	}
	word, after := "provider-unavailable", ""
	if errors.Is(err, mcphttp.ErrLimit) {
		word = "result-too-large"
	}
	if match := databricksStatus.FindStringSubmatch(detail); match != nil {
		status, _ := strconv.Atoi(match[1])
		switch {
		case status == 401:
			word = "credentials-required"
		case status == 403:
			word = "permission-denied"
		case status == 429:
			word, after = "rate-limited", "; it was not retried"
		case status >= 400 && status < 500:
			word = "request-refused"
		}
	}
	return Error(databricksClip(databricksRedact(word+": the MCP server "+server+": "+detail+after, secrets)))
}

// databricksMCPClose ends the session, waiting a few seconds at most for a
// server that does not answer the end of it.
func databricksMCPClose(ctx context.Context, client *mcphttp.Client) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	client.Close(ctx)
}

// databricksMCPOpen is the client a server is reached through: its
// endpoint under the workspace, the credential as the bearer, the server's
// list as the only tools a call may name, and each answer read no further
// than the result bound and the room a message takes around it, or the
// client's own bound where that is larger.
func (p provider) databricksMCPOpen(c DatabricksConnection, server DatabricksMCPServer, bearer string) (*mcphttp.Client, error) {
	limit := max(int64(c.resultBound())+databricksErrorBytes, mcphttp.MaxResponse)
	return mcphttp.Open(c.Workspace+databricksMCPPath(server.Server), mcphttp.Options{Token: bearer, MaxResponse: limit, Tools: append([]string{}, server.Tools...)}, p.client)
}

// databricksMCPSchema is the tool's declared output schema, digested as
// adapter-mcp's remote form records it, or nil where it declares none;
// the descriptor's name and output schema are read by their exact names.
func databricksMCPSchema(descriptor json.RawMessage) (any, error) {
	if _, ok := databricksMembers(descriptor, "name", "outputSchema"); !ok {
		return nil, Error("provider-unavailable: the MCP server's tool descriptor names a member it is read by in another case")
	}
	schema, err := mcp.OutputSchema(descriptor)
	if err != nil {
		return nil, Error("provider-unavailable: the MCP server's tool descriptor is not one a schema is read from")
	}
	if schema == nil {
		return nil, nil
	}
	sum := sha256.Sum256(schema)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

// databricksToolAnswer reads a tool's result as received: held to the
// connection's bound; its deciding members (content, structuredContent,
// isError, and each content item's type and text) read by their exact
// names; parsed as adapter-mcp's remote form parses a source's result. A
// result that reports an error is refused with its text, every secret in
// it replaced before it is cut to its bound; a result that would be kept
// and repeats a secret or the session id, as written or in escapes, is not
// kept.
func databricksToolAnswer(raw []byte, bound int, secrets []string) ([]byte, error) {
	if len(raw) > bound {
		return nil, Error(fmt.Sprintf("result-too-large: the MCP server's result is larger than the connection's bound of %d bytes", bound))
	}
	malformed := Error("provider-unavailable: the MCP server's answer is not of the form this connection reads, or names a member it reads in another case")
	if _, err := canon.Canonicalize(raw, canon.CarryNumbersAsText); err != nil {
		return nil, malformed
	}
	top, ok := databricksMembers(raw, "content", "structuredContent", "isError")
	if !ok {
		return nil, malformed
	}
	var items []json.RawMessage
	if json.Unmarshal(top["content"], &items) == nil {
		for _, item := range items {
			if _, ok := databricksMembers(item, "type", "text"); !ok {
				return nil, malformed
			}
		}
	}
	result, err := mcp.ToolResult(raw)
	var failed *mcp.ToolError
	if errors.As(err, &failed) {
		return nil, Error(databricksClip("tool-error: " + databricksRedact(failed.Text, secrets)))
	}
	if err != nil {
		return nil, Error(databricksClip("provider-unavailable: the MCP server's answer is not a tool result: " + databricksRedact(err.Error(), secrets)))
	}
	if databricksCarries(raw, secrets) {
		return nil, Error("provider-unavailable: the MCP server's answer repeats the credential or its session id, and is not kept")
	}
	return result, nil
}

// databricksMCPAcquire is one mcp read: one session with the server the
// request names, under the connection's credential, after a token request
// where a service principal holds no token it may use. The arguments, the
// tool and the server's name are screened for every credential before
// anything is sent. The envelope's result is the tool's result in
// canonical form; its acquisition names the server's endpoint as
// configured, the read as the statement the gateway commits to, the digest
// of the result as received, the TLS peer it came from, and the tool's
// declared output schema. The session id is in none of it.
func (p provider) databricksMCPAcquire(ctx context.Context, s *Store, c DatabricksConnection, q DatabricksRequest) ([]byte, error) {
	server, _ := c.mcpServer(q.Server)
	endpoint := c.Workspace + databricksMCPPath(server.Server)
	arguments, err := canon.Canonicalize(q.Arguments, canon.RefuseNumbers)
	if err != nil {
		return nil, ErrRequest
	}
	carries := func(secrets []string) bool {
		return databricksCarries(arguments, secrets) || databricksLeaks([]byte(q.Tool), secrets) || databricksLeaks([]byte(q.Server), secrets)
	}
	if carries(c.secrets(databricksHeld(s, c))) {
		return nil, databricksInRequest
	}
	bearer, err := p.databricksBearer(ctx, s, c)
	if err != nil {
		return nil, err
	}
	secrets := c.secrets(bearer)
	if carries(secrets) {
		return nil, databricksInRequest
	}
	client, err := p.databricksMCPOpen(c, server, bearer)
	if err != nil {
		return nil, databricksMCPRefusal(server.Server, err, secrets)
	}
	rctx, cancel := context.WithTimeout(ctx, databricksMCPSeconds*time.Second)
	defer cancel()
	defer databricksMCPClose(ctx, client)
	err = client.Initialize(rctx)
	secrets = databricksMCPSecrets(secrets, client)
	if err != nil {
		return nil, databricksMCPRefusal(server.Server, err, secrets)
	}
	descriptor, err := mcp.OfferedTool(rctx, client, q.Tool)
	if errors.Is(err, mcp.ErrNotOffered) {
		return nil, Error("tool-not-offered: the MCP server " + server.Server + " does not offer the tool the read names; nothing was called")
	}
	if err != nil {
		return nil, databricksMCPRefusal(server.Server, err, secrets)
	}
	schema, err := databricksMCPSchema(descriptor)
	if err != nil {
		return nil, err
	}
	raw, err := client.CallTool(rctx, q.Tool, json.RawMessage(arguments))
	if err != nil {
		return nil, databricksMCPRefusal(server.Server, err, secrets)
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
	if err = databricksCurrent(s, c); err != nil {
		return nil, err
	}
	identity, err := document.OwnIdentity()
	if err != nil {
		return nil, ErrProvider
	}
	identity.Name = "adapter-sources"
	record := map[string]any{"connection": c.ID, "revision": c.Revision, "provider": "databricks", "read": "mcp", "server": server.Server, "endpoint": endpoint, "tool": q.Tool, "arguments": json.RawMessage(arguments)}
	encoded, err := canon.EncodeJSON(record)
	if err != nil {
		return nil, ErrRequest
	}
	statement, err := canon.Canonicalize(encoded, canon.RefuseNumbers)
	if err != nil {
		return nil, ErrRequest
	}
	acquisition := map[string]any{"adapter": identity, "endpoint": endpoint, "statement": string(statement), "snapshot": digest(raw), "peerIdentity": peerIdentity, "schema": schema, "upstreamToken": nil, "observedAt": observed}
	out, err := canon.EncodeJSON(map[string]any{"acquisition": acquisition, "result": json.RawMessage(result)})
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

// databricksMCPReport is what a test says of one server: the tools it
// offers, and the names on the connection's list for it that it does not;
// or why it could not be read.
type databricksMCPReport struct {
	Server     string   `json:"server"`
	OK         bool     `json:"ok"`
	Offered    []string `json:"offered"`
	NotOffered []string `json:"notOffered"`
	Error      string   `json:"error,omitempty"`
}

// databricksMCPTest reaches each server the connection enables: initialize
// and its tools, and nothing called. It is nil for a connection that
// enables none.
func (p provider) databricksMCPTest(ctx context.Context, s *Store, id, revision string) ([]databricksMCPReport, error) {
	c, err := databricksSnapshot(s, id, revision)
	if err != nil || len(c.MCP) == 0 {
		return nil, err
	}
	bearer, err := p.databricksBearer(ctx, s, c)
	if err != nil {
		return nil, err
	}
	reports := []databricksMCPReport{}
	for _, server := range c.MCP {
		reports = append(reports, p.databricksMCPProbe(ctx, c, server, bearer))
	}
	return reports, nil
}

func (p provider) databricksMCPProbe(ctx context.Context, c DatabricksConnection, server DatabricksMCPServer, bearer string) databricksMCPReport {
	report := databricksMCPReport{Server: server.Server, Offered: []string{}, NotOffered: []string{}}
	secrets := c.secrets(bearer)
	client, err := p.databricksMCPOpen(c, server, bearer)
	if err != nil {
		report.Error = databricksMCPRefusal(server.Server, err, secrets).Error()
		return report
	}
	rctx, cancel := context.WithTimeout(ctx, databricksMCPTestSeconds*time.Second)
	defer cancel()
	defer databricksMCPClose(ctx, client)
	err = client.Initialize(rctx)
	secrets = databricksMCPSecrets(secrets, client)
	var names []string
	if err == nil {
		names, err = mcp.OfferedTools(rctx, client)
	}
	if err != nil {
		report.Error = databricksMCPRefusal(server.Server, err, secrets).Error()
		return report
	}
	if len(names) > databricksMCPOffered {
		report.Error = fmt.Sprintf("provider-unavailable: the MCP server %s offers more than %d tools", server.Server, databricksMCPOffered)
		return report
	}
	offered := map[string]bool{}
	for _, name := range names {
		offered[name] = true
		name = databricksRedact(name, secrets)
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
	return report
}
