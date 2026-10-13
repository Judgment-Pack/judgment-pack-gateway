package connections

import (
	"fmt"
	"strings"
	"testing"
)

// screenNested hides each character of s under levels of escapes, each
// level five bytes: \u005c spelling the backslash of the next.
func screenNested(s string, levels int) string {
	var b strings.Builder
	for _, r := range s {
		b.WriteString(`\`)
		b.WriteString(strings.Repeat("u005c", levels))
		fmt.Fprintf(&b, "u%04x", r)
	}
	return b.String()
}

// The decode runs to the point where it changes nothing, within its bound
// on passes: a secret under any nesting a text can hold is found, and a text
// still changing at the last pass is held to spell one, whatever it hides.
// A text longer than the size bound is held to spell one too.
func TestTheDecodeRunsToAFixedPointWithinItsBound(t *testing.T) {
	secret := "marker-secret-0123456789"
	for levels := range databricksSpellPasses + 8 {
		if !databricksSpells("near "+screenNested(secret, levels), []string{secret}) {
			t.Errorf("a secret under %d levels was not found", levels)
		}
	}
	harmless := "nothing-here"
	for levels, want := range map[int]bool{0: false, 4: false, 5: false, databricksSpellPasses - 1: false, databricksSpellPasses: true, databricksSpellPasses + 8: true} {
		if got := databricksSpells(screenNested(harmless, levels), []string{secret}); got != want {
			t.Errorf("harmless text under %d levels: %v", levels, got)
		}
	}
	if !databricksSpells(strings.Repeat("x", databricksSpellBytes+1), []string{secret}) || databricksSpells(strings.Repeat("x", 1024), []string{secret}) {
		t.Error("the size bound")
	}
	// Ordinary text with backslashes settles at once.
	for _, text := range []string{`C:\path\to\file`, `\\server\share`, `folder\`, `\`, `a\"b`} {
		if databricksSpells(text, []string{secret}) {
			t.Errorf("%q held to spell a secret", text)
		}
	}
	if databricksSpells(screenNested(secret, 3), nil) {
		t.Error("a text held to spell a secret where there is none")
	}
}

// What a provider writes out is held against every active secret, as it is,
// redacted, as the fallback, or not at all.
func TestOutwardTextIsWrittenOnlyWhereItSpellsNoSecret(t *testing.T) {
	secrets := []string{"marker-secret-0123456789"}
	fallback := Error("provider-unavailable: not reported")
	for _, k := range []struct {
		in, want string
		fallback Error
	}{
		{"request-refused: nothing", "request-refused: nothing", fallback},
		{"request-refused: near marker-secret-0123456789", "request-refused: near [redacted]", fallback},
		{"request-refused: near " + screenNested(secrets[0], 2), string(fallback), fallback},
		{"request-refused: near " + screenNested(secrets[0], 2), "", Error("not reported: marker-secret-0123456789")},
	} {
		if got := outward(Error(k.in), secrets, k.fallback); got.Error() != k.want {
			t.Errorf("%.60q: %q", k.in, got)
		}
	}
	if out, err := outwardAnswer(map[string]string{"name": screenNested(secrets[0], 6)}, nil, secrets); out != nil || err != unwritten {
		t.Error("an answer spelling a secret was written", out, err)
	}
	if out, err := outwardAnswer(map[string]bool{"ok": true}, nil, secrets); err != nil || out == nil {
		t.Error("a clean answer was not written", err)
	}
	if got := joinSecrets([]string{"bb", "", "a"}, []string{"ccc", "a"}); strings.Join(got, ",") != "ccc,bb,a" {
		t.Error(got)
	}
}
