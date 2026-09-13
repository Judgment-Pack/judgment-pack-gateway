// Package redact keeps a connector's configuration out of the diagnostics
// that cross the source boundary, where the gateway returns them to whoever
// called /acquire.
package redact

import (
	"bytes"
	"encoding/json"
	"net/url"
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
	dec := json.NewDecoder(bytes.NewReader(config))
	dec.UseNumber()
	var value any
	if dec.Decode(&value) != nil {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	add := func(s string) {
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	var walk func(v any)
	walk = func(v any) {
		switch x := v.(type) {
		case string:
			add(x)
			// A connection string carries its password inside a longer
			// value, and a diagnostic quotes the password alone: the
			// user-info parts of a value that parses as a URL are
			// secrets in their own right, as written (percent-encoded)
			// and as decoded, and so is every query value. A value that
			// is itself JSON is walked.
			if u, err := url.Parse(x); err == nil && u.User != nil {
				add(u.User.Username())
				if password, ok := u.User.Password(); ok {
					add(password)
				}
				if raw := rawUserInfo(x); raw != "" {
					user, password, _ := strings.Cut(raw, ":")
					add(user)
					add(password)
				}
				for _, values := range u.Query() {
					for _, v := range values {
						add(v)
					}
				}
			}
			var nested any
			if len(x) > 1 && (x[0] == '{' || x[0] == '[') && json.Unmarshal([]byte(x), &nested) == nil {
				walk(nested)
			}
		case json.Number:
			add(x.String())
		case map[string]any:
			for _, e := range x {
				walk(e)
			}
		case []any:
			for _, e := range x {
				walk(e)
			}
		}
	}
	walk(value)
	sort.SliceStable(out, func(i, j int) bool { return len(out[i]) > len(out[j]) })
	return out
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
	var out strings.Builder
	for i := 0; i < len(text); {
		if out.Len() > MaxDiagnostic {
			break
		}
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
	if out.Len() > MaxDiagnostic {
		return out.String()[:MaxDiagnostic] + "…"
	}
	return out.String()
}
