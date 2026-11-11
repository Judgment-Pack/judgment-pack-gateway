package main

// What verification says of a session no seal closes (gateway #381): it
// stays unregistered-session, and a whole one is observed session-open.

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// verdictLines is a report's findings, one line each, sorted, and its
// session-open observations, in the order given.
func verdictLines(t *testing.T, rep *report) (findings, open []string) {
	t.Helper()
	for _, f := range rep.Findings {
		at := f["callIndex"]
		if file, named := f["file"]; named {
			at = file
		}
		findings = append(findings, fmt.Sprintf("%v/%v/%v", f["sessionId"], at, f["status"]))
	}
	sort.Strings(findings)
	for _, o := range rep.Observations {
		if o["observation"] == "session-open" {
			open = append(open, fmt.Sprintf("%v/%v/%v", o["sessionId"], o["callIndex"], o["observation"]))
		}
	}
	return findings, open
}

// The verification rows shared with the TypeScript reader
// (testdata/session-open/cases.json): a corpus vector, edited as the row
// says, and the session-open observations its verdict carries. A session
// is observed open when no seal closes it and it holds receipts that are
// every one whole, in sequence and chained; whatever else is found of it,
// and any seal, leaves it unobserved. Only those observations are read.
func TestSessionOpenObservationsSharedRows(t *testing.T) {
	publicKey := mustHex(t, strings.TrimSpace(readFile(t, corpusPath("TEST-PUBLIC-KEY"))))
	var rows []struct {
		Name         string   `json:"name"`
		Vector       string   `json:"vector"`
		Registry     *string  `json:"registry"`
		Remove       []string `json:"remove"`
		Tear         []string `json:"tear"`
		Observations []string `json:"observations"`
	}
	readJSON(t, filepath.Join("..", "testdata", "session-open", "cases.json"), &rows)
	if len(rows) == 0 {
		t.Fatal("no rows")
	}
	for _, row := range rows {
		var vec storeVector
		readJSON(t, corpusPath(filepath.FromSlash(row.Vector)), &vec)
		if row.Registry != nil {
			vec.Registry = *row.Registry
		}
		for _, file := range row.Remove {
			if _, there := vec.Files[file]; !there {
				t.Fatalf("%s: the vector holds no %s", row.Name, file)
			}
			delete(vec.Files, file)
		}
		for _, file := range row.Tear {
			text, there := vec.Files[file]
			if !there {
				t.Fatalf("%s: the vector holds no %s", row.Name, file)
			}
			vec.Files[file] = text[:len(text)/2]
		}
		tmp, root, registryPath, decisionRecords, err := materializeVector(vec)
		if err != nil {
			t.Fatal(err)
		}
		rep, err := verifyWithRegistryAndRecords(root, registryPath, vec.Authority, decisionRecords, publicKey)
		os.RemoveAll(tmp)
		if err != nil {
			t.Fatalf("%s: no verdict: %v", row.Name, err)
		}
		_, open := verdictLines(t, rep)
		if strings.Join(open, " ") != strings.Join(row.Observations, " ") {
			t.Fatalf("%s: observed %v, want %v", row.Name, open, row.Observations)
		}
		if len(open) > 0 && rep.OK {
			t.Fatalf("%s: an open session's store verified ok", row.Name)
		}
	}
}
