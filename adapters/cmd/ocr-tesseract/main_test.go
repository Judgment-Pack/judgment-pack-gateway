//go:build linux || darwin

package main

import (
	"adapters/internal/ocrrender"
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The renderer and recognizer are shell stand-ins: no installed OCR program
// is run by these tests.
func standIns(t *testing.T, render, recognize string) string {
	t.Helper()
	dir := t.TempDir()
	write := func(name, body string) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body), 0700); err != nil {
			t.Fatal(err)
		}
		return path
	}
	r, e := write("render", render), write("recognize", recognize)
	saved := tools
	t.Cleanup(func() { tools = saved })
	tools = func() (ocrrender.Tool, ocrrender.Tool, error) {
		return ocrrender.Tool{Path: r}, ocrrender.Tool{Path: e}, nil
	}
	return dir
}

type refusingReader struct{ t *testing.T }

func (r refusingReader) Read([]byte) (int, error) {
	r.t.Error("the document was read before the pages were checked")
	return 0, errors.New("read")
}

func TestPagesAreCheckedBeforeAnythingRuns(t *testing.T) {
	dir := standIns(t, "touch ran\nexit 1\n", "touch ran\nexit 1\n")
	t.Chdir(dir)
	many := make([]string, maxPages+1)
	for i := range many {
		many[i] = "1"
	}
	for _, args := range [][]string{nil, {"0"}, {"501"}, {"-1"}, {"01"}, {"+1"}, {"1", "1"}, {"one"}, {"1", "x"}, many} {
		var out bytes.Buffer
		if run(args, refusingReader{t}, &out) == nil || out.Len() != 0 {
			t.Fatal("pages accepted", args)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "ran")); err == nil {
		t.Fatal("a program ran for refused pages")
	}
}

func TestInputIsBounded(t *testing.T) {
	standIns(t, "/bin/cat >/dev/null\nprintf '\\211PNG'\n", "/bin/cat >/dev/null\nprintf text\n")
	for _, input := range [][]byte{nil, make([]byte, maxInput+1)} {
		var out bytes.Buffer
		if run([]string{"1"}, bytes.NewReader(input), &out) == nil || out.Len() != 0 {
			t.Fatal("input outside its bounds accepted", len(input))
		}
	}
}

func TestAnswerHoldsTheAskedPagesInOrder(t *testing.T) {
	standIns(t, "/bin/cat >/dev/null\nprintf 'image %s' \"$2\"\n", "/bin/cat\n")
	var out bytes.Buffer
	if err := run([]string{"3", "1"}, strings.NewReader("%PDF"), &out); err != nil {
		t.Fatal(err)
	}
	var answer struct {
		Pages []struct {
			Number int    `json:"number"`
			Text   string `json:"text"`
		} `json:"pages"`
	}
	if json.Unmarshal(out.Bytes(), &answer) != nil || len(answer.Pages) != 2 || answer.Pages[0].Number != 3 || answer.Pages[0].Text != "image 3" || answer.Pages[1].Number != 1 {
		t.Fatalf("%s", out.Bytes())
	}
}

func TestOutputBoundsEndTheRun(t *testing.T) {
	flood := "/bin/cat >/dev/null\nwhile :; do printf 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'; done\n"
	standIns(t, flood, "/bin/cat\n")
	var out bytes.Buffer
	if run([]string{"1"}, strings.NewReader("%PDF"), &out) == nil || out.Len() != 0 {
		t.Fatal("a page image past its bound was read")
	}
	standIns(t, "/bin/cat >/dev/null\nprintf image\n", flood)
	if run([]string{"1"}, strings.NewReader("%PDF"), &out) == nil || out.Len() != 0 {
		t.Fatal("page text past its bound was read")
	}
	big := filepath.Join(t.TempDir(), "page-text")
	if err := os.WriteFile(big, bytes.Repeat([]byte("a"), 1500000), 0600); err != nil {
		t.Fatal(err)
	}
	standIns(t, "/bin/cat >/dev/null\nprintf image\n", "/bin/cat >/dev/null\n/bin/cat "+big+"\n")
	pages := []string{}
	for i := 1; i <= 6; i++ {
		pages = append(pages, string(rune('0'+i)))
	}
	if run(pages, strings.NewReader("%PDF"), &out) == nil || out.Len() != 0 {
		t.Fatal("text past the document's bound was answered")
	}
}

func TestCheckNeedsEnglishData(t *testing.T) {
	standIns(t, "exit 0\n", "printf 'List of available languages (2):\\neng\\nosd\\n'\n")
	if run([]string{"--check"}, strings.NewReader(""), &bytes.Buffer{}) != nil {
		t.Fatal("check failed with English data")
	}
	standIns(t, "exit 0\n", "printf 'List of available languages (1):\\nosd\\n'\n")
	if run([]string{"--check"}, strings.NewReader(""), &bytes.Buffer{}) == nil {
		t.Fatal("check passed without English data")
	}
	standIns(t, "exit 1\n", "printf 'eng\\n'\n")
	if run([]string{"--check"}, strings.NewReader(""), &bytes.Buffer{}) == nil {
		t.Fatal("check passed without a renderer")
	}
}
