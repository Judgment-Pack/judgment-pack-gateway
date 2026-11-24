package main

// An answer kept until its handler returns is written with an explicit
// Content-Length and flushed before the hand-off begins (ADR-0059 section 5,
// condition C10): the caller holds every byte of it while the hand-off waits,
// and the bytes are those of the answer written directly.

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
)

func TestAnAnswerIsFlushedBeforeItsHandOff(t *testing.T) {
	const body = `{"error":"refused","code":"example"}`
	write := func(w http.ResponseWriter) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = io.WriteString(w, body)
	}
	received := make(chan struct{})
	handedOff := make(chan bool, 1)
	kept := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		answer := newHeldAnswer()
		write(answer)
		answer.answerThenHandOff(w, func() {
			select {
			case <-received:
				handedOff <- true
			case <-time.After(3 * time.Second):
				handedOff <- false
			}
		})
	}))
	defer kept.Close()
	direct := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { write(w) }))
	defer direct.Close()

	read := func(url string) (*http.Response, string) {
		response, err := http.Get(url)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		data, err := io.ReadAll(response.Body)
		if err != nil {
			t.Fatal(err)
		}
		return response, string(data)
	}
	got, gotBody := read(kept.URL)
	close(received)
	if !<-handedOff {
		t.Fatal("the hand-off began before the answer reached the caller")
	}
	want, wantBody := read(direct.URL)
	if got.StatusCode != want.StatusCode || gotBody != wantBody || gotBody != body ||
		got.Header.Get("Content-Type") != want.Header.Get("Content-Type") ||
		got.Header.Get("Content-Length") != want.Header.Get("Content-Length") ||
		got.Header.Get("Content-Length") != strconv.Itoa(len(body)) || len(got.TransferEncoding) != 0 {
		t.Fatalf("the answer kept is not the answer written directly: %d %q %v %v; want %d %q %v",
			got.StatusCode, gotBody, got.Header, got.TransferEncoding, want.StatusCode, wantBody, want.Header)
	}
}
