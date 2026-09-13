// Package fakemcp stands in for an MCP server under test, and for the
// container runtime that would run one. A test binary that calls Run from
// its TestMain when EnvActivate is set speaks JSON-RPC over stdio as a
// server would -- answering initialize, tools/list and tools/call from what
// the test scripted, and misbehaving as told -- and, started as a runtime
// with `run`, records what it was asked and then acts as the server; `kill`
// and `inspect` answer as a runtime would for a container that is gone.
package fakemcp

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	// EnvActivate makes the test binary act as the server or the runtime.
	EnvActivate = "MCP_FAKE"
	// EnvTrace is a file every message received, and every run, is
	// appended to as one JSON line.
	EnvTrace = "MCP_FAKE_TRACE"
	// EnvKills is a file every kill appends the container name to.
	EnvKills = "MCP_FAKE_KILLS"
	// EnvTools names a file holding the tools/list "tools" array.
	EnvTools = "MCP_FAKE_TOOLS"
	// EnvResult names a file holding the tools/call result object.
	EnvResult = "MCP_FAKE_RESULT"
	// EnvEnvKeys lists, comma-separated, the environment variables whose
	// values the server records in its trace.
	EnvEnvKeys = "MCP_FAKE_ENV_KEYS"
	// EnvHang makes the server never answer tools/call.
	EnvHang = "MCP_FAKE_HANG"
	// EnvExitBeforeCall makes the server exit 1 instead of answering
	// tools/call, after writing EnvStderr.
	EnvExitBeforeCall = "MCP_FAKE_EXIT_BEFORE_CALL"
	// EnvStderr is written to stderr when the server starts.
	EnvStderr = "MCP_FAKE_STDERR"
	// EnvServerRequest makes the server ask the client for its roots
	// before answering tools/call, and record the client's answer.
	EnvServerRequest = "MCP_FAKE_SERVER_REQUEST"
	// EnvNotify makes the server send a notification before every answer.
	EnvNotify = "MCP_FAKE_NOTIFY"
	// EnvJunk makes the server write a line that is not a message before
	// answering tools/call.
	EnvJunk = "MCP_FAKE_JUNK"
	// EnvPagedTools makes tools/list answer one tool per page.
	EnvPagedTools = "MCP_FAKE_PAGED_TOOLS"
	// EnvInitError makes initialize answer with an error.
	EnvInitError = "MCP_FAKE_INIT_ERROR"
	// EnvStuck makes kill fail and inspect answer present.
	EnvStuck = "MCP_FAKE_STUCK"
)

// Invocation is what one runtime run was asked, and the env file it found
// mounted.
type Invocation struct {
	Argv    []string `json:"argv"`
	EnvFile string   `json:"envFile"`
}

// Run acts as the runtime when args name a runtime verb, else as the server.
func Run(args []string) int {
	if len(args) > 0 {
		switch args[0] {
		case "kill":
			if len(args) > 1 {
				appendLine(os.Getenv(EnvKills), args[1])
			}
			if os.Getenv(EnvStuck) == "1" {
				return 1
			}
			return 0
		case "inspect":
			if os.Getenv(EnvStuck) == "1" {
				return 0
			}
			if len(args) > 1 {
				os.Stderr.WriteString("Error: No such object: " + args[1] + "\n")
			}
			return 1
		case "run":
			inv := Invocation{Argv: args}
			for i, a := range args {
				if a == "--env-file" && i+1 < len(args) {
					data, _ := os.ReadFile(args[i+1])
					inv.EnvFile = string(data)
				}
			}
			line, _ := json.Marshal(map[string]any{"run": inv})
			appendLine(os.Getenv(EnvTrace), string(line))
			return serve()
		}
	}
	return serve()
}

func serve() int {
	if text := os.Getenv(EnvStderr); text != "" {
		os.Stderr.WriteString(text)
	}
	env := map[string]string{}
	for _, key := range strings.Split(os.Getenv(EnvEnvKeys), ",") {
		if key != "" {
			env[key] = os.Getenv(key)
		}
	}
	line, _ := json.Marshal(map[string]any{"env": env})
	appendLine(os.Getenv(EnvTrace), string(line))
	tools := json.RawMessage(`[{"name":"query","description":"Run a read-only query","inputSchema":{"type":"object","properties":{"sql":{"type":"string"}},"required":["sql"]}}]`)
	if path := os.Getenv(EnvTools); path != "" {
		tools, _ = os.ReadFile(path)
	}
	var toolList []json.RawMessage
	json.Unmarshal(tools, &toolList)
	result := json.RawMessage(`{"content":[{"type":"text","text":"1 row"}],"structuredContent":{"rows":[{"id":101,"amount":12.5}]}}`)
	if path := os.Getenv(EnvResult); path != "" {
		result, _ = os.ReadFile(path)
	}
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 1<<20), 64<<20)
	out := bufio.NewWriter(os.Stdout)
	emit := func(v any) {
		b, _ := json.Marshal(v)
		out.Write(append(b, '\n'))
		out.Flush()
	}
	for scanner.Scan() {
		raw := scanner.Bytes()
		appendLine(os.Getenv(EnvTrace), string(raw))
		var m struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
			Params struct {
				Name   string `json:"name"`
				Cursor string `json:"cursor"`
			} `json:"params"`
		}
		if json.Unmarshal(raw, &m) != nil {
			continue
		}
		if os.Getenv(EnvNotify) == "1" && m.Method != "" {
			emit(map[string]any{"jsonrpc": "2.0", "method": "notifications/message", "params": map[string]any{"level": "info", "data": "hello"}})
		}
		switch m.Method {
		case "initialize":
			if os.Getenv(EnvInitError) == "1" {
				emit(map[string]any{"jsonrpc": "2.0", "id": m.ID, "error": map[string]any{"code": -32602, "message": "unsupported protocol version"}})
				continue
			}
			emit(map[string]any{"jsonrpc": "2.0", "id": m.ID, "result": map[string]any{
				"protocolVersion": "2025-06-18", "capabilities": map[string]any{"tools": map[string]any{}},
				"serverInfo": map[string]any{"name": "fake-mcp", "version": "1.0"}}})
		case "notifications/initialized":
		case "tools/list":
			if os.Getenv(EnvPagedTools) == "1" && len(toolList) > 1 {
				page := 0
				if m.Params.Cursor != "" {
					page = int(m.Params.Cursor[0] - '0')
				}
				res := map[string]any{"tools": []json.RawMessage{toolList[page]}}
				if page+1 < len(toolList) {
					res["nextCursor"] = string(rune('0' + page + 1))
				}
				emit(map[string]any{"jsonrpc": "2.0", "id": m.ID, "result": res})
				continue
			}
			emit(map[string]any{"jsonrpc": "2.0", "id": m.ID, "result": map[string]any{"tools": toolList}})
		case "tools/call":
			if os.Getenv(EnvExitBeforeCall) == "1" {
				return 1
			}
			if os.Getenv(EnvHang) == "1" {
				time.Sleep(60 * time.Second)
				return 0
			}
			if os.Getenv(EnvJunk) == "1" {
				out.WriteString("Connected to database\n")
				out.Flush()
			}
			if os.Getenv(EnvServerRequest) == "1" {
				emit(map[string]any{"jsonrpc": "2.0", "id": "srv-1", "method": "roots/list", "params": map[string]any{}})
				if scanner.Scan() {
					appendLine(os.Getenv(EnvTrace), string(scanner.Bytes()))
				}
			}
			emit(map[string]any{"jsonrpc": "2.0", "id": m.ID, "result": result})
		default:
			if len(m.ID) > 0 {
				emit(map[string]any{"jsonrpc": "2.0", "id": m.ID, "error": map[string]any{"code": -32601, "message": "method not found"}})
			}
		}
	}
	return 0
}

func appendLine(path, line string) {
	if path == "" {
		return
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	defer f.Close()
	f.WriteString(line + "\n")
}

// MountDir is the host directory of the mount in a run's argv, for a test
// that wants to look at what was mounted.
func MountDir(argv []string) string {
	for i, a := range argv {
		if a == "-v" && i+1 < len(argv) {
			return filepath.Clean(strings.TrimSuffix(argv[i+1], ":/secrets:ro"))
		}
	}
	return ""
}
