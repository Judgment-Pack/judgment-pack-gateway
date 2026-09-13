package redact

import (
	"strings"
	"testing"
)

// A connection string's user name and password are secrets in their own
// right, since a diagnostic quotes them alone.
func TestSecretsOfURLUserInfo(t *testing.T) {
	secrets := SecretsOf([]byte(`{"DATABASE_URL":"postgresql://app:hunter2@warehouse.internal:5432/decisions","MODE":"require"}`))
	joined := " " + strings.Join(secrets, " ") + " "
	for _, want := range []string{" hunter2 ", " app ", " require ", " postgresql://app:hunter2@warehouse.internal:5432/decisions "} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing %q in %v", want, secrets)
		}
	}
	if got := Redact("auth failed for hunter2 (user app) at warehouse.internal", secrets); got != "auth failed for [redacted] (user [redacted]) at warehouse.internal" {
		t.Fatalf("redaction: %q", got)
	}
}

// A percent-encoded password is a secret as written and as decoded; a
// query value is a secret; a value that is itself JSON is walked.
func TestSecretsOfEncodedQueryAndNestedJSON(t *testing.T) {
	secrets := SecretsOf([]byte(`{"URL":"postgresql://app:p%40ss@h/db?sslpassword=qsecret&x=1","NESTED":"{\"token\":\"tsecret\",\"n\":[\"deep\"]}"}`))
	got := Redact("p%40ss p@ss qsecret tsecret deep app", secrets)
	if got != "[redacted] [redacted] [redacted] [redacted] [redacted] [redacted]" {
		t.Fatalf("redaction: %q from %v", got, secrets)
	}
}
