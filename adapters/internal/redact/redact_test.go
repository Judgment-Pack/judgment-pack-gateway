package redact

import (
	"runtime"
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

// Query values are secrets with or without user-info, as written and as
// decoded; nested JSON is walked past leading whitespace with its numbers.
func TestSecretsOfQueryWithoutUserInfoAndNestedNumbers(t *testing.T) {
	secrets := SecretsOf([]byte(`{"URL":"https://host/?token=qsecret&k=q%20s","NESTED":"  {\"pin\":739201}"}`))
	got := Redact("qsecret q%20s q s 739201", secrets)
	if got != "[redacted] [redacted] [redacted] [redacted]" {
		t.Fatalf("redaction: %q from %v", got, secrets)
	}
}

func TestTrimPartialSecret(t *testing.T) {
	secrets := []string{"hunter2", "abcabd", "k"}
	for text, want := range map[string]string{
		"refused: hunt":    "refused: ",
		"refused: hunter2": "refused: hunter2", // whole, not partial: Redact's job
		"refused: hunter":  "refused: ",
		"no trace here":    "no trace here",
		"x abcab":          "x ",
		"x abcabcab":       "x abc",
		"ends with h":      "ends with ",
		"":                 "",
		"ab":               "",
	} {
		if got := TrimPartialSecret(text, secrets); got != want {
			t.Errorf("%q: got %q, want %q", text, got, want)
		}
	}
	if got := TrimPartialSecret("anything", nil); got != "anything" {
		t.Errorf("no secrets: %q", got)
	}
}

func TestDiagnosticReplacesWholeSecretsBeforeTrimming(t *testing.T) {
	// A secret whose end repeats its start, held whole in a buffer that
	// overflowed after it: whole first, so nothing of it is taken for a
	// prefix.
	secret := "TOPSECRET" + strings.Repeat("x", 100) + "TOPSECRET"
	got := Diagnostic("refused: "+secret, true, []string{secret})
	if got != "refused: [redacted]" {
		t.Fatalf("got %q", got)
	}
	if got := Diagnostic("refused: TOPSEC", true, []string{secret}); got != "refused: " {
		t.Fatalf("a partial start is still cut: %q", got)
	}
	if got := Diagnostic("refused: TOPSEC", false, []string{secret}); got != "refused: TOPSEC" {
		t.Fatalf("nothing is cut when nothing overflowed: %q", got)
	}
	// The length bound comes last, so a prefix past it is still cut.
	long := strings.Repeat("k", 70000)
	if got := Diagnostic("refused: "+long[:65527], true, []string{long}); got != "refused: " {
		t.Fatalf("a prefix longer than the bound is cut: %.60q", got)
	}
}

func TestSecretsOfWalksTokens(t *testing.T) {
	secrets := SecretsOf([]byte(`{"password":"first-secret","blob":"{\"token\":\"t-one\",\"token\":\"t-two\",\"n\":[7,{\"k\":\"deep\"}]}","port":5432}`))
	has := func(s string) bool {
		for _, x := range secrets {
			if x == s {
				return true
			}
		}
		return false
	}
	for _, want := range []string{"first-secret", "t-one", "t-two", "deep", "7", "5432"} {
		if !has(want) {
			t.Errorf("%q is a secret: %v", want, secrets)
		}
	}
	for _, not := range []string{"password", "blob", "token", "n", "k", "port"} {
		if has(not) {
			t.Errorf("%q is a member name, not a secret: %v", not, secrets)
		}
	}
}

func TestDiagnosticHoldsOverlappingSecretsTogether(t *testing.T) {
	// A short secret that begins a long one: a buffer that overflowed
	// inside the long one holds the short one whole at its start, and
	// replacing the short one first would leave the rest of the long
	// one's start unrecognizable as a prefix.
	long := "abc" + strings.Repeat("y", 75000)
	secrets := []string{long, "abc"}
	if got := Diagnostic("refused: "+long[:65527], true, secrets); got != "refused: " {
		t.Fatalf("got %.40q", got)
	}
	// A whole secret in the middle keeps its replacement; the start of
	// another after it is cut.
	if got := Diagnostic("a hunter2 b zz-lo", true, []string{"zz-long-secret", "hunter2"}); got != "a [redacted] b " {
		t.Fatalf("got %q", got)
	}
	// A whole secret ending the text, another secret's start inside it:
	// the whole one wins.
	if got := Diagnostic("x tail-secret", true, []string{"tail-secret", "secretive"}); got != "x [redacted]" {
		t.Fatalf("got %q", got)
	}
}

func TestRedactIsBuiltBounded(t *testing.T) {
	big := strings.Repeat("e", 32<<20)
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	got := Redact(big, []string{"e"})
	runtime.ReadMemStats(&after)
	if len(got) > MaxDiagnostic+len("…") || !strings.HasPrefix(got, "[redacted][redacted]") {
		t.Fatalf("bounded: %d bytes", len(got))
	}
	if allocated := after.TotalAlloc - before.TotalAlloc; allocated > 1<<20 {
		t.Fatalf("a diagnostic of a 32 MiB text allocated %d bytes; it is built bounded, never whole and then cut", allocated)
	}
}

func TestOverlappingSecretsAreCoveredTogether(t *testing.T) {
	for text, want := range map[string]string{
		"alice-super-secret":         "[redacted]",
		"user alice-super-secret ok": "user [redacted] ok",
		"aaa":                        "[redacted]",
		"alice":                      "[redacted]",
		"ice-super-secret alice":     "[redacted] [redacted]",
		"nothing here":               "nothing here",
	} {
		secrets := []string{"ice-super-secret", "alice", "aa"}
		if got := Redact(text, secrets); got != want {
			t.Errorf("Redact %q: got %q, want %q", text, got, want)
		}
		if got := Diagnostic(text, false, secrets); got != want {
			t.Errorf("Diagnostic %q: got %q, want %q", text, got, want)
		}
	}
	// A merged run the cut falls inside keeps its replacement.
	if got := Diagnostic("x alice-super-secret", true, []string{"ice-super-secret", "alice"}); got != "x [redacted]" {
		t.Fatalf("got %q", got)
	}
}
