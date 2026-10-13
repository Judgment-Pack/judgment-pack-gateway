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
	"bytes"
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
	"unicode"
	"unicode/utf16"
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
	// databricksMCPPages bounds a tools/list, as adapter-mcp bounds one.
	databricksMCPPages = 32
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

// databricksUnescape decodes each JSON escape in text once -- \uXXXX, a
// surrogate pair as one character, and \" \\ \/ \b \f \n \r \t -- and leaves
// any other backslash as written.
func databricksUnescape(text string) string {
	if !strings.Contains(text, `\`) {
		return text
	}
	hex4 := func(at int) (rune, bool) {
		if at+4 > len(text) {
			return 0, false
		}
		n, err := strconv.ParseUint(text[at:at+4], 16, 16)
		return rune(n), err == nil
	}
	var b strings.Builder
	for i := 0; i < len(text); i++ {
		if text[i] != '\\' || i+1 == len(text) {
			b.WriteByte(text[i])
			continue
		}
		switch e := text[i+1]; e {
		case '"', '\\', '/':
			b.WriteByte(e)
		case 'b':
			b.WriteByte('\b')
		case 'f':
			b.WriteByte('\f')
		case 'n':
			b.WriteByte('\n')
		case 'r':
			b.WriteByte('\r')
		case 't':
			b.WriteByte('\t')
		case 'u':
			r, ok := hex4(i + 2)
			if !ok {
				b.WriteByte('\\')
				continue
			}
			i += 4
			if utf16.IsSurrogate(r) && i+7 < len(text) && text[i+2] == '\\' && text[i+3] == 'u' {
				if low, ok := hex4(i + 4); ok {
					if pair := utf16.DecodeRune(r, low); pair != unicode.ReplacementChar {
						r = pair
						i += 6
					}
				}
			}
			b.WriteRune(r)
		default:
			b.WriteByte('\\')
			continue
		}
		i++
	}
	return b.String()
}

// databricksSpells reports whether text spells a secret: as written, or
// once its JSON escapes are decoded, as many times over as they nest (four
// at most) -- a server's text may hold JSON of its own, whose escapes a
// reader decodes.
func databricksSpells(text string, secrets []string) bool {
	for round := 0; ; round++ {
		if databricksLeaks([]byte(text), secrets) {
			return true
		}
		next := databricksUnescape(text)
		if next == text || round == 4 {
			return false
		}
		text = next
	}
}

// databricksScreened is text the connection writes out -- an error, a field
// of a test's or a status's answer -- with every whole secret replaced; ok
// is false where it still spells one, whose text is then not written.
func databricksScreened(text string, secrets []string) (string, bool) {
	text = databricksRedact(text, secrets)
	return text, !databricksSpells(text, secrets)
}

// mcpSpells reports whether a server's name or a tool on its list spells
// the connection's configured credential, or one of others.
func (c DatabricksConnection) mcpSpells(others []string) bool {
	secrets := append([]string{c.Token, c.ClientSecret}, others...)
	for _, server := range c.MCP {
		if databricksSpells(server.Server, secrets) {
			return true
		}
		for _, tool := range server.Tools {
			if databricksSpells(tool, secrets) {
				return true
			}
		}
	}
	return false
}

// databricksTokensOf is every token held for the connection.
func databricksTokensOf(tokens []databricksToken, id string) []string {
	out := []string{}
	for _, t := range tokens {
		if t.Connection == id {
			out = append(out, t.Access)
		}
	}
	return out
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
	// The client's words may hold the server's (a JSON-RPC error's message),
	// which may hold JSON of its own: a detail that spells a secret once
	// its escapes are decoded is not repeated at all.
	if redacted, ok := databricksScreened(detail, secrets); ok {
		detail = redacted
	} else {
		detail = "the server's text repeats the credential or its session id, and is not reported"
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
		text, ok := databricksScreened(failed.Text, secrets)
		if !ok {
			return nil, Error("tool-error: the tool reported an error whose text repeats the credential or its session id; the text is not reported")
		}
		return nil, Error(databricksClip("tool-error: " + text))
	}
	if err != nil {
		return nil, Error(databricksClip("provider-unavailable: the MCP server's answer is not a tool result: " + databricksRedact(err.Error(), secrets)))
	}
	if databricksCarries(raw, secrets) {
		return nil, Error("provider-unavailable: the MCP server's answer repeats the credential or its session id, and is not kept")
	}
	return result, nil
}

// databricksMCPRepeats is an answer that spells a secret or the session id.
var databricksMCPRepeats = errors.New("the server's answer repeats the credential or its session id, and is not kept")

// databricksMCPVersions are the protocol versions the client speaks, as
// mcphttp's own initialize accepts them.
var databricksMCPVersions = map[string]bool{"2025-11-25": true, "2025-06-18": true, "2025-03-26": true}

// databricksMCPInitialize is the session's handshake, read here rather than
// by mcphttp's Initialize, whose decoder folds case: the answer is screened
// for every secret and the session id the server issued with it, raw and
// decoded, before anything of it is read; then held to an initialize
// result's shape by the exact names of its members -- a protocolVersion this
// client speaks, capabilities with tools, serverInfo with a name and a
// version -- an answer that also names one of them in another case refused.
// It returns secrets with the session id among them.
func databricksMCPInitialize(ctx context.Context, client *mcphttp.Client, secrets []string) ([]string, error) {
	raw, err := client.Request(ctx, "initialize", map[string]any{"protocolVersion": "2025-11-25", "capabilities": map[string]any{}, "clientInfo": map[string]string{"name": "judgment-pack-gateway", "version": "1"}})
	secrets = databricksMCPSecrets(secrets, client)
	if err != nil {
		return secrets, err
	}
	if databricksCarries(raw, secrets) {
		return secrets, databricksMCPRepeats
	}
	malformed := errors.New("initialize: the server's answer is not an initialize result of the protocol's form, or names a member it is read by in another case")
	if _, err := canon.Canonicalize(raw, canon.CarryNumbersAsText); err != nil {
		return secrets, malformed
	}
	top, ok := databricksMembers(raw, "protocolVersion", "capabilities", "serverInfo")
	if !ok || !canon.IsObject(top["capabilities"]) || !canon.IsObject(top["serverInfo"]) {
		return secrets, malformed
	}
	capabilities, ok1 := databricksMembers(top["capabilities"], "tools")
	info, ok2 := databricksMembers(top["serverInfo"], "name", "version")
	var version, name, serverVersion string
	hasVersion, ok3 := databricksField(top, "protocolVersion", &version)
	hasName, ok4 := databricksField(info, "name", &name)
	hasServerVersion, ok5 := databricksField(info, "version", &serverVersion)
	if !ok1 || !ok2 || !ok3 || !ok4 || !ok5 || !hasVersion || !hasName || name == "" || !hasServerVersion || !canon.IsObject(capabilities["tools"]) {
		return secrets, malformed
	}
	if !databricksMCPVersions[version] {
		return secrets, errors.New("initialize: the server speaks a protocol version this client does not")
	}
	return secrets, client.Negotiated(ctx, version)
}

// databricksMCPList pages the server's tools/list: each page screened for
// every secret and the session id, raw and decoded, before anything of it
// is read, and read by the exact names of the members it is decided by --
// tools, nextCursor, each tool's name -- a page that also names one in
// another case refused. visit is handed each tool's name and descriptor in
// order, and ends the listing by returning true. At most 32 pages; a
// cursor given twice is refused.
func databricksMCPList(ctx context.Context, client *mcphttp.Client, secrets []string, visit func(name string, descriptor json.RawMessage) (bool, error)) error {
	malformed := errors.New("tools/list: the server's answer is not a tool list of the protocol's form, or names a member it is read by in another case")
	params := map[string]any{}
	cursors := map[string]bool{}
	for page := 0; page < databricksMCPPages; page++ {
		raw, err := client.Request(ctx, "tools/list", params)
		if err != nil {
			return err
		}
		if databricksCarries(raw, secrets) {
			return databricksMCPRepeats
		}
		if _, err := canon.Canonicalize(raw, canon.CarryNumbersAsText); err != nil {
			return malformed
		}
		members, ok := databricksMembers(raw, "tools", "nextCursor")
		var tools []json.RawMessage
		var next string
		_, okNext := databricksField(members, "nextCursor", &next)
		if !ok || !okNext || !bytes.HasPrefix(bytes.TrimSpace(members["tools"]), []byte("[")) || json.Unmarshal(members["tools"], &tools) != nil {
			return malformed
		}
		for _, tool := range tools {
			head, ok := databricksMembers(tool, "name", "outputSchema")
			var name string
			present, okName := databricksField(head, "name", &name)
			if !ok || !canon.IsObject(tool) || !okName || !present || name == "" {
				return malformed
			}
			if done, err := visit(name, tool); done || err != nil {
				return err
			}
		}
		if next == "" {
			return nil
		}
		if cursors[digest([]byte(next))] {
			return errors.New("tools/list: the server gave a cursor it had given before")
		}
		cursors[digest([]byte(next))] = true
		params = map[string]any{"cursor": next}
	}
	return fmt.Errorf("tools/list did not end within %d pages", databricksMCPPages)
}

// databricksMCPOutward is an error the connection reports, held once more
// against every secret it knows of -- the configured credential, the token
// in use, and the session id once issued -- as a whole sentence, since a
// server's name is the operator's text and the session id the server's:
// each whole secret replaced, and a sentence that would still spell one not
// reported.
func databricksMCPOutward(err error, secrets []string) error {
	text, ok := databricksScreened(err.Error(), secrets)
	switch {
	case !ok:
		return Error("provider-unavailable: the MCP server's refusal would repeat the credential or its session id, and is not reported")
	case text != err.Error():
		return Error(databricksClip(text))
	}
	return err
}

// databricksMCPAcquire is one mcp read: one session with the server the
// request names, under the connection's credential, after a token request
// where a service principal holds no token it may use. The arguments, the
// tool and the server's name are screened for every credential before
// anything is sent, and every answer -- initialize, each tools/list page,
// the call -- for every credential and the session id before it is read.
// The envelope's result is the tool's result in canonical form; its
// acquisition names the server's endpoint as configured, the read as the
// statement the gateway commits to, the digest of the result as received,
// the TLS peer it came from, and the tool's declared output schema. The
// session id is in none of it, nor in any error.
func (p provider) databricksMCPAcquire(ctx context.Context, s *Store, c DatabricksConnection, q DatabricksRequest) (out []byte, err error) {
	secrets := c.secrets(databricksHeld(s, c))
	defer func() {
		if err != nil {
			out, err = nil, databricksMCPOutward(err, secrets)
		}
	}()
	server, _ := c.mcpServer(q.Server)
	endpoint := c.Workspace + databricksMCPPath(server.Server)
	arguments, err := canon.Canonicalize(q.Arguments, canon.RefuseNumbers)
	if err != nil {
		return nil, ErrRequest
	}
	carries := func(secrets []string) bool {
		return databricksCarries(arguments, secrets) || databricksLeaks([]byte(q.Tool), secrets) || databricksLeaks([]byte(q.Server), secrets)
	}
	if carries(secrets) {
		return nil, databricksInRequest
	}
	bearer, err := p.databricksBearer(ctx, s, c)
	if err != nil {
		return nil, err
	}
	secrets = c.secrets(bearer)
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
	secrets, err = databricksMCPInitialize(rctx, client, secrets)
	if err != nil {
		return nil, databricksMCPRefusal(server.Server, err, secrets)
	}
	var descriptor json.RawMessage
	err = databricksMCPList(rctx, client, secrets, func(name string, tool json.RawMessage) (bool, error) {
		if name == q.Tool {
			descriptor = tool
		}
		return descriptor != nil, nil
	})
	if err != nil {
		return nil, databricksMCPRefusal(server.Server, err, secrets)
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

// screened is the report held against every secret, the session id
// included, field by field: each whole secret replaced, and a field that
// would still spell one written as [redacted], an error as a sentence that
// names none.
func (r databricksMCPReport) screened(secrets []string) databricksMCPReport {
	field := func(text string) string {
		if out, ok := databricksScreened(text, secrets); ok {
			return out
		}
		return "[redacted]"
	}
	out := databricksMCPReport{Server: field(r.Server), OK: r.OK, Offered: []string{}, NotOffered: []string{}}
	for _, name := range r.Offered {
		out.Offered = append(out.Offered, field(name))
	}
	for _, name := range r.NotOffered {
		out.NotOffered = append(out.NotOffered, field(name))
	}
	if r.Error != "" {
		out.Error = databricksMCPOutward(Error(r.Error), secrets).Error()
	}
	return out
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
		report, secrets := p.databricksMCPProbe(ctx, c, server, bearer)
		reports = append(reports, report.screened(secrets))
	}
	return reports, nil
}

// databricksMCPProbe is one server's part of a test, and the secrets its
// report is held against.
func (p provider) databricksMCPProbe(ctx context.Context, c DatabricksConnection, server DatabricksMCPServer, bearer string) (databricksMCPReport, []string) {
	report := databricksMCPReport{Server: server.Server, Offered: []string{}, NotOffered: []string{}}
	secrets := c.secrets(bearer)
	client, err := p.databricksMCPOpen(c, server, bearer)
	if err != nil {
		report.Error = databricksMCPRefusal(server.Server, err, secrets).Error()
		return report, secrets
	}
	rctx, cancel := context.WithTimeout(ctx, databricksMCPTestSeconds*time.Second)
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
		report.Error = databricksMCPRefusal(server.Server, err, secrets).Error()
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
