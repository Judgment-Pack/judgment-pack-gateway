// Package redact keeps a connector's configuration out of the diagnostics
// that cross the source boundary, where the gateway returns them to whoever
// called /acquire.
package redact

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"sort"
	"strings"
)

// SecretsOf collects every scalar of the connector's configuration, at any
// depth -- every non-empty string and every number, as written, each once;
// the user name, the password and every query value inside a string that
// is a URL, encoded and decoded; and the scalars of a string that is itself
// JSON -- so that a diagnostic repeating one is redacted before it crosses the
// source boundary, where the gateway returns it to whoever called
// /acquire. The list is sorted longest first so a value that contains
// another is replaced whole. It is as good as the connector's habit of
// quoting its configuration verbatim: a secret it encodes or splits is not
// caught, a token inside a format this does not parse (a bare "key=value"
// line, a header) is not caught, and a one-letter value redacts every
// letter like it.
func SecretsOf(config []byte) []string {
	seen := map[string]bool{}
	var out []string
	add := func(s string) {
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	var scalar func(s string)
	scalar = func(x string) {
		add(x)
		// A connection string carries its password inside a longer
		// value, and a diagnostic quotes the password alone: the
		// user-info parts of a value that parses as a URL are secrets
		// in their own right, as written (percent-encoded) and as
		// decoded, and so is every query value. A value that is itself
		// JSON is walked.
		if u, err := url.Parse(x); err == nil {
			if u.User != nil {
				add(u.User.Username())
				if password, ok := u.User.Password(); ok {
					add(password)
				}
				if raw := rawUserInfo(x); raw != "" {
					user, password, _ := strings.Cut(raw, ":")
					add(user)
					add(password)
				}
			}
			// Query values whether or not the URL has user-info, as
			// written and as decoded.
			for _, pair := range strings.Split(u.RawQuery, "&") {
				if _, raw, ok := strings.Cut(pair, "="); ok {
					add(raw)
					if decoded, err := url.QueryUnescape(raw); err == nil {
						add(decoded)
					}
				}
			}
		}
		trimmed := strings.TrimSpace(x)
		if len(trimmed) > 1 && (trimmed[0] == '{' || trimmed[0] == '[') {
			walkTokens([]byte(trimmed), scalar)
		}
	}
	walkTokens(config, scalar)
	sort.SliceStable(out, func(i, j int) bool { return len(out[i]) > len(out[j]) })
	return out
}

// walkTokens hands every scalar value of a JSON text to scalar, as tokens,
// so that a value under a duplicate member name is seen as well as the
// last one -- a map decode would keep only the last -- and an object's
// member names are not taken for values. A text that is not JSON is walked
// as far as it parses.
func walkTokens(text []byte, scalar func(string)) {
	dec := json.NewDecoder(bytes.NewReader(text))
	dec.UseNumber()
	type frame struct{ object, key bool }
	var stack []frame
	for {
		tok, err := dec.Token()
		if err != nil {
			return
		}
		if delim, ok := tok.(json.Delim); ok {
			switch delim {
			case '{':
				stack = append(stack, frame{object: true, key: true})
			case '[':
				stack = append(stack, frame{})
			case '}', ']':
				if len(stack) > 0 {
					stack = stack[:len(stack)-1]
				}
				if len(stack) > 0 && stack[len(stack)-1].object {
					stack[len(stack)-1].key = true
				}
			}
			continue
		}
		top := len(stack) - 1
		isKey := top >= 0 && stack[top].object && stack[top].key
		if top >= 0 && stack[top].object {
			stack[top].key = !stack[top].key
		}
		if isKey {
			continue
		}
		switch v := tok.(type) {
		case string:
			scalar(v)
		case json.Number:
			scalar(v.String())
		}
	}
}

// rawUserInfo is the user-info segment of a URL as written, between the
// scheme's "//" and the "@" before the host.
func rawUserInfo(raw string) string {
	_, rest, ok := strings.Cut(raw, "//")
	if !ok {
		return ""
	}
	end := strings.IndexAny(rest, "/?#")
	authority := rest
	if end >= 0 {
		authority = rest[:end]
	}
	at := strings.LastIndex(authority, "@")
	if at < 0 {
		return ""
	}
	return authority[:at]
}

const MaxDiagnostic = 512

// Redact rewrites a diagnostic in one pass over the original text: at each
// position the longest configured value that starts there is replaced, and
// what was written is never scanned again, so a replacement can neither
// grow the text past its bound nor be re-matched. The output is bounded as
// it is built.
func Redact(text string, secrets []string) string {
	return bound(replace(text, secrets))
}

// replace is Redact without the length bound: every secret replaced, in
// one pass, longest first where they overlap.
func replace(text string, secrets []string) string {
	var out strings.Builder
	for i := 0; i < len(text); {
		matched := false
		for _, s := range secrets {
			if strings.HasPrefix(text[i:], s) {
				out.WriteString("[redacted]")
				i += len(s)
				matched = true
				break
			}
		}
		if !matched {
			out.WriteByte(text[i])
			i++
		}
	}
	return out.String()
}

// bound cuts a diagnostic to MaxDiagnostic, marked.
func bound(text string) string {
	if len(text) > MaxDiagnostic {
		return text[:MaxDiagnostic] + "…"
	}
	return text
}

// MaxCredentialBytes bounds a credentials file: a diagnostic buffer holds
// less than this, and a value that could not fit one whole is not let in.
const MaxCredentialBytes = 1 << 20

// ReadCredentials reads a credentials file of at most MaxCredentialBytes.
func ReadCredentials(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("credentials could not be read: %w", err)
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, MaxCredentialBytes+1))
	if err != nil {
		return nil, fmt.Errorf("credentials could not be read: %w", err)
	}
	if len(data) > MaxCredentialBytes {
		return nil, errors.New("credentials file exceeds 1 MiB")
	}
	return data, nil
}

// TrimPartialSecret cuts from the end of a text that was truncated any
// suffix that is a proper prefix of a secret: what was cut off may have
// been the rest of it, and the start of a credential is a leak of it.
// Applied after Redact, so a whole secret is replaced before its end is
// taken for a prefix of another (Diagnostic).
func TrimPartialSecret(text string, secrets []string) string {
	cut := 0
	for _, s := range secrets {
		if k := longestPrefixAtEnd(text, s); k > cut {
			cut = k
		}
	}
	return text[:len(text)-cut]
}

// longestPrefixAtEnd is the length of the longest proper prefix of s that
// text ends with, found by running s's prefix automaton over the tail of
// text: linear in the two lengths.
func longestPrefixAtEnd(text, s string) int {
	if len(s) < 2 {
		return 0
	}
	pattern := s[:len(s)-1]
	// The failure table: fail[i] is the length of the longest proper
	// prefix of pattern[:i+1] that is also its suffix.
	fail := make([]int, len(pattern))
	for i, k := 1, 0; i < len(pattern); i++ {
		for k > 0 && pattern[i] != pattern[k] {
			k = fail[k-1]
		}
		if pattern[i] == pattern[k] {
			k++
		}
		fail[i] = k
	}
	tail := text
	if len(tail) > len(pattern) {
		tail = tail[len(tail)-len(pattern):]
	}
	k := 0
	for i := 0; i < len(tail); i++ {
		for k > 0 && tail[i] != pattern[k] {
			k = fail[k-1]
		}
		if tail[i] == pattern[k] {
			k++
		}
		if k == len(pattern) {
			// The whole proper prefix matched somewhere in the tail;
			// only a match ending at the end counts, so keep scanning.
			k = fail[k-1]
			if i == len(tail)-1 {
				return len(pattern)
			}
		}
	}
	return k
}

// MalformedCredentials says a credentials file is not JSON, or has a
// member name twice, and echoes nothing of the file: a syntax error's
// detail quotes what it found, and a member's name may be another
// member's value.
func MalformedCredentials(err error) error {
	if strings.Contains(err.Error(), "duplicate member name") {
		return errors.New("credentials file has a member name twice")
	}
	return errors.New("credentials file is not JSON")
}

// Diagnostic is what may cross the source boundary of a text a server, a
// connector or a runtime wrote: every secret in it replaced, then, when
// the buffer it was read from overflowed, whatever ends it that is the
// start of a secret cut off -- whole before prefix, since a secret whose
// end repeats its start would otherwise lose its end -- and the length
// bound last, so a prefix past the bound is still cut.
func Diagnostic(text string, truncated bool, secrets []string) string {
	out := replace(text, secrets)
	if truncated {
		out = TrimPartialSecret(out, secrets)
	}
	return bound(out)
}
