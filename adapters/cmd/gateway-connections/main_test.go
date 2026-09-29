package main

import (
	"adapters/connections"
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestFailedResponseDoesNotExposePartialResult(t *testing.T) {
	data, err := json.Marshal(response("request", map[string]string{"subject": "private subject", "grant": "private grant"}, errors.New("canceled")))
	if err != nil || strings.Contains(string(data), "private") || strings.Contains(string(data), "result") {
		t.Fatalf("failed response exposed data: %s %v", data, err)
	}
	if string(data) != `{"error":"canceled","id":"request"}` {
		t.Fatalf("wrong envelope: %s", data)
	}
}

func TestControlReplyRefusesOversizeWithoutLeakingPartialResult(t *testing.T) {
	var output bytes.Buffer
	if err := writeResponse(&output, response("request", map[string]string{"private": strings.Repeat("x", connections.ControlLineBytes)}, nil), "request"); err != nil {
		t.Fatal(err)
	}
	if output.Len() > connections.ControlLineBytes || strings.Contains(output.String(), "private") || output.String() != `{"error":"response-too-large","id":"request"}`+"\n" {
		t.Fatal("oversize response leaked", output.Len())
	}
	output.Reset()
	if err := writeResponse(&output, response("request", map[string]bool{"disconnected": true, "revoked": false}, nil), "request"); err != nil || !strings.Contains(output.String(), `"revoked":false`) {
		t.Fatal("valid response lost", err)
	}
}

func TestStorageMetadataPageAllowsEscapedLongKeysOnlyForList(t *testing.T) {
	items := make([]connections.StorageFile, 24)
	for i := range items {
		items[i] = connections.StorageFile{ID: strings.Repeat("&", 1024), Name: strings.Repeat("&", 1024), Kind: "file"}
	}
	result := response("request", connections.StoragePage{Items: items}, nil)
	var output bytes.Buffer
	if err := writeResponseLimit(&output, result, "request", "files-list"); err != nil {
		t.Fatal(err)
	}
	if output.Len() <= connections.ControlLineBytes || output.Len() > connections.StorageMetadataBytes || strings.Contains(output.String(), "response-too-large") {
		t.Fatal("legal metadata page refused", output.Len())
	}
	output.Reset()
	if err := writeResponseLimit(&output, result, "request", "files-status"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "response-too-large") {
		t.Fatal("ordinary bound relaxed")
	}
}

func TestOnlyARequestThatCarriesAFileHasTheLargerBound(t *testing.T) {
	for method, want := range map[string]int{
		"files-prepare":                  connections.StorageLineBytes,
		"files-prepare-google-document":  connections.StorageLineBytes,
		"files-commit":                   connections.ControlLineBytes,
		"files-status":                   connections.ControlLineBytes,
		"files-read":                     connections.ControlLineBytes,
		"files-list":                     connections.ControlLineBytes,
		"files-prepare-google-documents": connections.ControlLineBytes,
		"status":                         connections.ControlLineBytes,
		"":                               connections.ControlLineBytes,
	} {
		if got := requestBound(method); got != want {
			t.Fatalf("%q: a line of %d bytes", method, got)
		}
	}
	if connections.StorageConvertMethod != "files-prepare-google-document" {
		t.Fatal("the conversion's method has another name")
	}
}

func TestPipeHelper(t *testing.T) {
	if os.Getenv("GATEWAY_PIPE_HELPER") != "1" {
		return
	}
	publisherRegistration = []byte(`{}`)
	os.Args = append([]string{"gateway-connections"}, os.Args[3:]...)
	os.Exit(run())
}

// line is a request of a method whose JSON is of a length, to the byte.
func line(t *testing.T, id, method string, length int) []byte {
	t.Helper()
	request := func(content string) []byte {
		raw, err := json.Marshal(map[string]any{"id": id, "method": method, "params": map[string]string{"contentBase64": content}})
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	short := len(request(""))
	if length < short {
		t.Fatalf("a request of %s is %d bytes at the least", method, short)
	}
	raw := request(strings.Repeat("A", length-short))
	if len(raw) != length {
		t.Fatalf("the line is %d bytes and not %d", len(raw), length)
	}
	return raw
}

// pipe runs the program as a host runs it, over a store that has no
// connection, and gives what it answered, by the request's ID.
func pipe(t *testing.T, input []byte) (map[string]string, error) {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestPipeHelper$", "--", "--state-dir", dir, "--principal", "owner")
	cmd.Env = append(os.Environ(), "GATEWAY_PIPE_HELPER=1")
	cmd.Stdin = bytes.NewReader(input)
	raw, err := cmd.Output()
	answers := map[string]string{}
	lines := bufio.NewScanner(bytes.NewReader(raw))
	for lines.Scan() {
		var answer struct {
			ID    string `json:"id"`
			Error string `json:"error"`
		}
		if json.Unmarshal(lines.Bytes(), &answer) != nil || answer.ID == "" || answer.Error == "" || answers[answer.ID] != "" {
			t.Fatalf("an answer was %s", lines.Bytes())
		}
		answers[answer.ID] = answer.Error
	}
	return answers, err
}

// No store of this test has a connection, so every request is refused: by its
// length where its line is too long for its method, and otherwise by the
// broker, in the broker's word. A line's length is that of its JSON, without
// the line's ending.
func TestTheLineOfARequestThatCarriesAFileMayBeAsLongAsAFile(t *testing.T) {
	methods := map[string]int{
		"files-prepare":                 connections.StorageLineBytes,
		"files-prepare-google-document": connections.StorageLineBytes,
		"files-commit":                  connections.ControlLineBytes,
		"files-read":                    connections.ControlLineBytes,
		"files-list":                    connections.ControlLineBytes,
		"files-status":                  connections.ControlLineBytes,
	}
	var input bytes.Buffer
	for method, bound := range methods {
		for id, request := range map[string][]byte{
			"short":      line(t, method+" short", method, 200),
			"at":         line(t, method+" at", method, bound),
			"at, CRLF":   append(line(t, method+" at, CRLF", method, bound), '\r'),
			"over":       line(t, method+" over", method, bound+1),
			"over, CRLF": append(line(t, method+" over, CRLF", method, bound+1), '\r'),
		} {
			_ = id
			input.Write(request)
			input.WriteByte('\n')
		}
	}
	answers, err := pipe(t, input.Bytes())
	if err != nil || len(answers) != 5*len(methods) {
		t.Fatalf("%d answers to %d requests: %v", len(answers), 5*len(methods), err)
	}
	for method := range methods {
		short := answers[method+" short"]
		if short == "invalid-request" {
			t.Fatalf("%s: a short request is refused in the word of a long one, so the row tells nothing", method)
		}
		for _, row := range []string{" at", " at, CRLF"} {
			if answers[method+row] != short {
				t.Errorf("%s%s: answered %q, and a short one %q", method, row, answers[method+row], short)
			}
		}
		for _, row := range []string{" over", " over, CRLF"} {
			if answers[method+row] != "invalid-request" {
				t.Errorf("%s%s: answered %q", method, row, answers[method+row])
			}
		}
	}

	// A line that is longer than 6 MiB and three bytes with its ending is
	// not read to its end. The pipe ends, and the requests before that line
	// were answered. One byte shorter, the line is refused by name and the
	// pipe goes on.
	for _, method := range []string{"files-prepare", "files-status"} {
		input.Reset()
		input.Write(line(t, "before", method, 200))
		input.WriteByte('\n')
		input.Write(line(t, "long", method, connections.StorageLineBytes+2))
		input.WriteByte('\n')
		input.Write(line(t, "too long", method, connections.StorageLineBytes+3))
		input.WriteByte('\n')
		input.Write(line(t, "after", method, 200))
		input.WriteByte('\n')
		answers, err = pipe(t, input.Bytes())
		var exit *exec.ExitError
		if !errors.As(err, &exit) || exit.ExitCode() != 1 || len(answers) != 2 || answers["before"] == "" || answers["long"] != "invalid-request" {
			t.Fatalf("%s: the pipe ended with %v after the answers %v", method, err, answers)
		}
	}

	// A last line may have no ending. The pipe reads 6 MiB and two bytes of
	// it, which is one fewer than of a line with its ending.
	for method, bound := range methods {
		short, err := pipe(t, line(t, "last", method, 200))
		if err != nil || short["last"] == "" || short["last"] == "invalid-request" {
			t.Fatalf("%s: a short last line: %v, %v", method, short, err)
		}
		at, err := pipe(t, line(t, "last", method, bound))
		if err != nil || at["last"] != short["last"] {
			t.Errorf("%s: a last line at its bound: %v, %v", method, at, err)
		}
		over, err := pipe(t, line(t, "last", method, bound+1))
		if err != nil || over["last"] != "invalid-request" {
			t.Errorf("%s: a last line a byte past its bound: %v, %v", method, over, err)
		}
		most, err := pipe(t, line(t, "last", method, connections.StorageLineBytes+2))
		if err != nil || most["last"] != "invalid-request" {
			t.Errorf("%s: the longest last line the pipe reads: %v, %v", method, most, err)
		}
		none, err := pipe(t, line(t, "last", method, connections.StorageLineBytes+3))
		var exit *exec.ExitError
		if !errors.As(err, &exit) || exit.ExitCode() != 1 || len(none) != 0 {
			t.Errorf("%s: a last line longer than the pipe reads: %v, %v", method, none, err)
		}
	}

	// A line that is no request ends the pipe before its length is looked
	// at, and the pipe says so by another exit.
	for name, request := range map[string]string{
		"no JSON":           "files-status",
		"an ID too long":    `{"id":"` + strings.Repeat("i", 65) + `","method":"files-status","params":{}}`,
		"no JSON, and long": strings.Repeat("x", connections.ControlLineBytes+1),
	} {
		answers, err := pipe(t, []byte(request+"\n"))
		var exit *exec.ExitError
		if !errors.As(err, &exit) || exit.ExitCode() != 2 || len(answers) != 0 {
			t.Errorf("%s: the pipe ended with %v after the answers %v", name, err, answers)
		}
	}
}
