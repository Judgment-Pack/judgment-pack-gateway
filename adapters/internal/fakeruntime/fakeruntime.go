// Package fakeruntime stands in for a container runtime under test. A test
// binary that calls Run from its TestMain when EnvActivate is set behaves,
// when the adapter starts it as its runtime, like `docker run` and `docker
// kill` would: it records what it was asked, reads the files the adapter
// mounted, and plays back the connector output the test scripted. No
// container runtime is needed to test the adapter, and none is used in CI.
package fakeruntime

import (
	"encoding/json"
	"os"
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
	// stdout for those verbs.
	EnvDiscover = "AIRBYTE_FAKE_DISCOVER"
	EnvRead     = "AIRBYTE_FAKE_READ"
	// EnvStderr is written to stderr by every run.
	EnvStderr = "AIRBYTE_FAKE_STDERR"
	// EnvExit is the exit status of every run, 0 when unset.
	EnvExit = "AIRBYTE_FAKE_EXIT"
	// EnvHang makes a read sleep after its output until it is killed.
	EnvHang = "AIRBYTE_FAKE_HANG"
)

// Invocation is what one run was asked, and what it found mounted.
type Invocation struct {
	Argv  []string          `json:"argv"`
	Verb  string            `json:"verb"`
	Image string            `json:"image"`
	Files map[string]string `json:"files"`
}

// Run acts on the runtime's arguments and returns the exit status.
func Run(args []string) int {
	if len(args) == 0 {
		return 2
	}
	switch args[0] {
	case "kill":
		if len(args) > 1 {
			appendLine(os.Getenv(EnvKills), args[1])
		}
		return 0
	case "run":
		inv := Invocation{Argv: args, Files: map[string]string{}}
		dir := ""
		for i, a := range args {
			if a == "-v" && i+3 < len(args) {
				dir = strings.TrimSuffix(args[i+1], ":/secrets:ro")
				inv.Image = args[i+2]
				inv.Verb = args[i+3]
			}
		}
		if dir != "" {
			entries, _ := os.ReadDir(dir)
			for _, e := range entries {
				data, _ := os.ReadFile(filepath.Join(dir, e.Name()))
				inv.Files[e.Name()] = string(data)
			}
		}
		line, _ := json.Marshal(inv)
		appendLine(os.Getenv(EnvTrace), string(line))
		var out []byte
		switch inv.Verb {
		case "discover":
			out, _ = os.ReadFile(os.Getenv(EnvDiscover))
		case "read":
			out, _ = os.ReadFile(os.Getenv(EnvRead))
		}
		os.Stdout.Write(out)
		if text := os.Getenv(EnvStderr); text != "" {
			os.Stderr.WriteString(text)
		}
		if inv.Verb == "read" && os.Getenv(EnvHang) == "1" {
			time.Sleep(60 * time.Second)
		}
		code, _ := strconv.Atoi(os.Getenv(EnvExit))
		return code
	}
	return 2
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
