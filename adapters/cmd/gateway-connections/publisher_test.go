package main

import (
	"adapters/connections"
	"testing"
)

func TestPublisherRegistrationIsExplicitAndOptional(t *testing.T) {
	client, err := publisherClient([]byte("{}\n"))
	if err != nil || client != (connections.Client{}) {
		t.Fatal("source-only build should have no fake registration")
	}
	client, err = publisherClient([]byte(`{"installed":{"client_id":"publisher.apps.googleusercontent.com"}}`))
	if err != nil || client.ID != "publisher.apps.googleusercontent.com" {
		t.Fatal("publisher registration unavailable")
	}
	for _, raw := range []string{"", "null", "[]", `{"web":{}}`, `{"installed":{"client_id":"invalid","client_secret":"private"}}`} {
		if c, e := publisherClient([]byte(raw)); e == nil || c != (connections.Client{}) {
			t.Fatal("bad publisher registration silently accepted")
		}
	}
}
