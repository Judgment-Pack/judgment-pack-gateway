package connections

import (
	"encoding/json"
	"sort"
)

// The screens a provider holding credentials applies to what it writes out:
// an error, and a control answer. Each is held against every credential the
// provider's custody holds for the principal -- every connection's, not only
// the one a request names -- whole, its fixed words included.

// withheld is the refusal written where no text is safe to write: an error
// with nothing in it.
const withheld = Error("")

// unwritten is a control answer that would repeat a credential.
const unwritten = Error("provider-unavailable: the answer would repeat a credential held for this provider, and is not written")

// joinSecrets is the secrets of every list given, each once, none empty,
// longest first, so that a replacement takes the whole of each.
func joinSecrets(lists ...[]string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, list := range lists {
		for _, s := range list {
			if s != "" && !seen[s] {
				seen[s] = true
				out = append(out, s)
			}
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return len(out[i]) > len(out[j]) })
	return out
}

// outward is an error as it is written out: as it is where it spells no
// secret, as written or in escapes; else with every whole secret replaced,
// where that spells none; else the fallback, where that spells none; else
// withheld.
func outward(err error, secrets []string, fallback Error) error {
	if err == nil {
		return nil
	}
	text := err.Error()
	if !databricksSpells(text, secrets) {
		return err
	}
	if redacted := databricksRedact(text, secrets); !databricksSpells(redacted, secrets) {
		return Error(redacted)
	}
	if !databricksSpells(string(fallback), secrets) {
		return fallback
	}
	return withheld
}

// outwardAnswer is a control answer as it is written out: its error screened
// by outward, and an answer that would repeat a secret anywhere in it, as
// written or in escapes, not written at all but refused, by unwritten or,
// where that would spell one, withheld.
func outwardAnswer(out any, err error, secrets []string) (any, error) {
	if err != nil {
		return out, outward(err, secrets, unwritten)
	}
	raw, e := json.Marshal(out)
	if e != nil || databricksCarries(raw, secrets) {
		return nil, outward(unwritten, secrets, withheld)
	}
	return out, nil
}
