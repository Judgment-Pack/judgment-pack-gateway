package connections

import (
	"strings"
	"testing"
)

func TestParseGoogleDesktopRegistration(t *testing.T) {
	client, err := ParseGoogleDesktopClient([]byte(`{"installed":{"client_id":"publisher.apps.googleusercontent.com","client_secret":"desktop-secret","project_id":"desk","auth_uri":"https://untrusted.example/auth","token_uri":"https://untrusted.example/token","redirect_uris":["https://untrusted.example/callback"]}}`))
	if err != nil || client != (Client{"publisher.apps.googleusercontent.com", "desktop-secret"}) {
		t.Fatal("valid Desktop registration was refused or its client changed")
	}
	if _, err := ParseGoogleDesktopClient([]byte(`{"installed":{"client_id":"publisher.apps.googleusercontent.com"}}`)); err != nil {
		t.Fatal("Desktop registration without a secret was refused")
	}
	for _, raw := range []string{
		`{}`, `null`, `[]`, `{"installed":null}`,
		`{"web":{"client_id":"publisher.apps.googleusercontent.com"}}`,
		`{"type":"service_account","private_key":"do-not-echo"}`,
		`{"installed":{"client_id":"publisher.apps.googleusercontent.com"},"web":{}}`,
		`{"installed":{"client_id":"publisher.apps.googleusercontent.com"},"type":"service_account"}`,
		`{"installed":{"client_id":"publisher.apps.googleusercontent.com","client_id":"other.apps.googleusercontent.com"}}`,
		`{"installed":{"client_id":"wrong.example","client_secret":"do-not-echo"}}`,
		`{"installed":{"client_id":"publisher.apps.googleusercontent.com","client_secret":42}}`,
		`{"installed":{"client_id":"publisher.apps.googleusercontent.com","client_secret":"line\nbreak"}}`,
		`{"installed":{"client_id":"publisher.apps.googleusercontent.com","client_secret":"` + strings.Repeat("a", 4097) + `"}}`,
		`{"installed":{"client_id":"publisher.apps.googleusercontent.com"},"extra":"` + strings.Repeat("a", 16<<10) + `"}`,
	} {
		if got, err := ParseGoogleDesktopClient([]byte(raw)); err != ErrRequest || got != (Client{}) {
			t.Fatal("invalid registration was accepted or leaked registration data")
		}
	}
}
