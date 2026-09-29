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

// The pipe is run as a host runs it, over a store that has no connection, so
// every request is refused: by its length where the line is too long for its
// method, and otherwise by the broker, in the broker's word.
func TestTheLineOfARequestThatCarriesAFileMayBeAsLongAsAFile(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	content := map[bool]string{false: "AAAA", true: strings.Repeat("A", connections.ControlLineBytes)}
	methods := []string{"files-prepare", "files-prepare-google-document", "files-commit", "files-read", "files-list", "files-status"}
	var input strings.Builder
	for _, method := range methods {
		for _, long := range []bool{false, true} {
			line, err := json.Marshal(map[string]any{"id": method, "method": method, "params": map[string]string{"contentBase64": content[long]}})
			if err != nil || long != (len(line) > connections.ControlLineBytes) {
				t.Fatal("the line is not the length the row is of", err)
			}
			input.Write(line)
			input.WriteByte('\n')
		}
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestPipeHelper$", "--", "--state-dir", dir, "--principal", "owner")
	cmd.Env = append(os.Environ(), "GATEWAY_PIPE_HELPER=1")
	cmd.Stdin = strings.NewReader(input.String())
	raw, err := cmd.Output()
	if err != nil {
		t.Fatalf("the pipe ended with %v", err)
	}
	var answers []string
	lines := bufio.NewScanner(bytes.NewReader(raw))
	for lines.Scan() {
		var answer struct {
			ID    string `json:"id"`
			Error string `json:"error"`
		}
		if json.Unmarshal(lines.Bytes(), &answer) != nil || answer.ID != methods[len(answers)/2] || answer.Error == "" {
			t.Fatalf("answer %d was %s", len(answers), lines.Bytes())
		}
		answers = append(answers, answer.Error)
	}
	if len(answers) != 2*len(methods) {
		t.Fatalf("%d answers to %d requests", len(answers), 2*len(methods))
	}
	for i, method := range methods {
		short, long := answers[2*i], answers[2*i+1]
		if short == "invalid-request" {
			t.Fatalf("%s: a short request is refused in the word of a long one, so the row tells nothing", method)
		}
		if carries := connections.StorageUpload(method); carries && long != short || !carries && long != "invalid-request" {
			t.Fatalf("%s: a short line was answered %q and a long one %q", method, short, long)
		}
	}
}
