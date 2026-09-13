// Package fakeruntime stands in for a container runtime under test. A test
// binary that calls Run from its TestMain when EnvActivate is set behaves,
// when the adapter starts it as its runtime, like `docker run`, `docker
// kill` and `docker inspect` would: it records what it was asked and the
// files the adapter mounted, plays back the connector output the test
// scripted -- filtered by the state the adapter handed back, as a connector
// resuming from a cursor would -- and answers kill and inspect as told. No
// container runtime is needed to test the adapter, and none is used in CI.
package fakeruntime

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	// EnvActivate makes the test binary act as the runtime.
	EnvActivate = "AIRBYTE_FAKE_RUNTIME"
	// EnvTrace is a file every run appends one JSON line to: an Invocation.
	EnvTrace = "AIRBYTE_FAKE_TRACE"
	// EnvKills is a file every kill appends the container name to.
	EnvKills = "AIRBYTE_FAKE_KILLS"
	// EnvDiscover and EnvRead name files whose contents are the connector's
	// stdout for those verbs. A read with a state file plays back only the
	// records and states past the state's cursor (an "updated_at" string).
	EnvDiscover = "AIRBYTE_FAKE_DISCOVER"
	EnvRead     = "AIRBYTE_FAKE_READ"
	// EnvCheck names a file whose contents are the connector's stdout for
	// check.
	EnvCheck = "AIRBYTE_FAKE_CHECK"
	// EnvStderr is written to stderr by every run.
	EnvStderr = "AIRBYTE_FAKE_STDERR"
	// EnvExit is the exit status of every run, 0 when unset.
	EnvExit = "AIRBYTE_FAKE_EXIT"
	// EnvHang makes a read sleep after its output until it is killed.
	EnvHang = "AIRBYTE_FAKE_HANG"
	// EnvHold makes a read leave a descendant holding stdout and exit;
	// EnvHoldStderr makes it hold stderr instead.
	EnvHold       = "AIRBYTE_FAKE_HOLD"
	EnvHoldStderr = "AIRBYTE_FAKE_HOLD_STDERR"
	// EnvHolderPid is the file the descendant's pid is written to.
	EnvHolderPid = "AIRBYTE_FAKE_HOLDER_PID"
	// EnvKillExit is the exit status of a kill, 0 when unset.
	EnvKillExit = "AIRBYTE_FAKE_KILL_EXIT"
	// EnvKillDelay is the seconds a kill sleeps before answering.
	EnvKillDelay = "AIRBYTE_FAKE_KILL_DELAY"
	// EnvInspectExit is the exit status of an inspect: 1 with "No such
	// object" on stderr (absent) when unset or 1, 0 for a container the
	// runtime still knows, any other value for a runtime that cannot say.
	EnvInspectExit = "AIRBYTE_FAKE_INSPECT_EXIT"
	// EnvStuckOnRead makes the container run for a read refuse its kill and
	// answer inspect as present, while discover's stops normally.
	EnvStuckOnRead = "AIRBYTE_FAKE_STUCK_ON_READ"
	// EnvInspectStderr, when set, is what an inspect writes on stderr
	// instead of the default, with {name} replaced by the container name.
	EnvInspectStderr = "AIRBYTE_FAKE_INSPECT_STDERR"
	// EnvHoldInspect makes an inspect leave a descendant holding its
	// output and exit.
	EnvHoldInspect = "AIRBYTE_FAKE_HOLD_INSPECT"

	envSleep = "AIRBYTE_FAKE_SLEEP"
)

// Invocation is what one run was asked, what it found mounted, and the
// modes of the mount directory ("dir") and its files.
type Invocation struct {
	Argv  []string          `json:"argv"`
	Verb  string            `json:"verb"`
	Image string            `json:"image"`
	Files map[string]string `json:"files"`
	Modes map[string]string `json:"modes"`
}

// Run acts on the runtime's arguments and returns the exit status.
func Run(args []string) int {
	if os.Getenv(envSleep) == "1" {
		time.Sleep(60 * time.Second)
		return 0
	}
	if len(args) == 0 {
		return 2
	}
	switch args[0] {
	case "kill":
		if len(args) > 1 {
			appendLine(os.Getenv(EnvKills), args[1])
		}
		if d, _ := strconv.Atoi(os.Getenv(EnvKillDelay)); d > 0 {
			time.Sleep(time.Duration(d) * time.Second)
		}
		if len(args) > 1 && stuck(args[1]) {
			return 1
		}
		code, _ := strconv.Atoi(os.Getenv(EnvKillExit))
		return code
	case "inspect":
		if len(args) > 1 && stuck(args[1]) {
			return 0
		}
		code := 1
		if v := os.Getenv(EnvInspectExit); v != "" {
			code, _ = strconv.Atoi(v)
		}
		name := ""
		if len(args) > 1 {
			name = args[1]
		}
		switch {
		case os.Getenv(EnvInspectStderr) != "":
			os.Stderr.WriteString(strings.ReplaceAll(os.Getenv(EnvInspectStderr), "{name}", name) + "\n")
		case code == 0:
		case code == 1:
			os.Stderr.WriteString("Error: No such object: " + name + "\n")
		default:
			os.Stderr.WriteString("Cannot connect to the Docker daemon\n")
		}
		if os.Getenv(EnvHoldInspect) == "1" {
			child := exec.Command(os.Args[0])
			child.Env = append(os.Environ(), envSleep+"=1")
			child.Stdout = os.Stdout
			child.Stderr = os.Stderr
			if err := child.Start(); err == nil {
				appendLine(os.Getenv(EnvHolderPid), strconv.Itoa(child.Process.Pid))
			}
		}
		return code
	case "run":
		inv := Invocation{Argv: args, Files: map[string]string{}, Modes: map[string]string{}}
		dir := ""
		for i, a := range args {
			if a == "-v" && i+1 < len(args) {
				dir = strings.TrimSuffix(args[i+1], ":/secrets:ro")
				j := i + 2
				if j < len(args) && args[j] == "--" {
					j++
				}
				if j+1 < len(args) {
					inv.Image = args[j]
					inv.Verb = args[j+1]
				}
			}
		}
		if dir != "" {
			if info, err := os.Stat(dir); err == nil {
				inv.Modes["dir"] = fmt.Sprintf("%04o", info.Mode().Perm())
			}
			if info, err := os.Stat(filepath.Dir(dir)); err == nil {
				inv.Modes["parent"] = fmt.Sprintf("%04o", info.Mode().Perm())
			}
			entries, _ := os.ReadDir(dir)
			for _, e := range entries {
				data, _ := os.ReadFile(filepath.Join(dir, e.Name()))
				inv.Files[e.Name()] = string(data)
				if info, err := e.Info(); err == nil {
					inv.Modes[e.Name()] = fmt.Sprintf("%04o", info.Mode().Perm())
				}
			}
		}
		line, _ := json.Marshal(inv)
		appendLine(os.Getenv(EnvTrace), string(line))
		var out []byte
		switch inv.Verb {
		case "check":
			out, _ = os.ReadFile(os.Getenv(EnvCheck))
		case "discover":
			out, _ = os.ReadFile(os.Getenv(EnvDiscover))
		case "read":
			out, _ = os.ReadFile(os.Getenv(EnvRead))
			if state, ok := inv.Files["state.json"]; ok {
				out = resumeFrom(out, state)
			}
		}
		os.Stdout.Write(out)
		if text := os.Getenv(EnvStderr); text != "" {
			os.Stderr.WriteString(text)
		}
		if inv.Verb == "read" && (os.Getenv(EnvHold) == "1" || os.Getenv(EnvHoldStderr) == "1") {
			child := exec.Command(os.Args[0])
			child.Env = append(os.Environ(), envSleep+"=1")
			if os.Getenv(EnvHold) == "1" {
				child.Stdout = os.Stdout
			} else {
				child.Stderr = os.Stderr
			}
			if err := child.Start(); err == nil {
				appendLine(os.Getenv(EnvHolderPid), strconv.Itoa(child.Process.Pid))
			}
			return 0
		}
		if inv.Verb == "read" && os.Getenv(EnvHang) == "1" {
			time.Sleep(60 * time.Second)
		}
		code, _ := strconv.Atoi(os.Getenv(EnvExit))
		return code
	}
	return 2
}

// resumeFrom plays back only what follows the state's cursor, as a
// connector resuming would: records whose data "updated_at" and states
// whose "updated_at" are past it. A state without a cursor filters nothing.
func resumeFrom(out []byte, stateFile string) []byte {
	cursor := cursorOf(stateFile)
	if cursor == "" {
		return out
	}
	var kept []string
	for _, line := range strings.Split(string(out), "\n") {
		var m struct {
			Type   string `json:"type"`
			Record struct {
				Data struct {
					UpdatedAt string `json:"updated_at"`
				} `json:"data"`
			} `json:"record"`
			State struct {
				Stream struct {
					State struct {
						UpdatedAt string `json:"updated_at"`
					} `json:"stream_state"`
				} `json:"stream"`
			} `json:"state"`
		}
		if json.Unmarshal([]byte(line), &m) == nil {
			if m.Type == "RECORD" && m.Record.Data.UpdatedAt != "" && m.Record.Data.UpdatedAt <= cursor {
				continue
			}
			if m.Type == "STATE" && m.State.Stream.State.UpdatedAt != "" && m.State.Stream.State.UpdatedAt <= cursor {
				continue
			}
		}
		kept = append(kept, line)
	}
	return []byte(strings.Join(kept, "\n"))
}

func cursorOf(stateFile string) string {
	var states []struct {
		Stream struct {
			State struct {
				UpdatedAt string `json:"updated_at"`
			} `json:"stream_state"`
		} `json:"stream"`
	}
	if json.Unmarshal([]byte(stateFile), &states) == nil && len(states) > 0 {
		return states[0].Stream.State.UpdatedAt
	}
	var legacy struct {
		UpdatedAt string `json:"updated_at"`
	}
	if json.Unmarshal([]byte(stateFile), &legacy) == nil {
		return legacy.UpdatedAt
	}
	return ""
}

// stuck reports whether the named container is the one a read ran, when
// EnvStuckOnRead is set: the trace says which verb each name was run for.
func stuck(name string) bool {
	if os.Getenv(EnvStuckOnRead) != "1" {
		return false
	}
	data, err := os.ReadFile(os.Getenv(EnvTrace))
	if err != nil {
		return false
	}
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		var inv Invocation
		if json.Unmarshal([]byte(line), &inv) == nil && inv.Verb == "read" && len(inv.Argv) > 3 && inv.Argv[3] == name {
			return true
		}
	}
	return false
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
