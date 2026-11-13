package httpsource

// A throttled answer (gateway #425, SPEC.md §6, "Adapter sources"): an
// endpoint the acquisition reached -- the source's endpoint, or the token
// step's -- answered 429 or 503. The command exits with ThrottledStatus and
// writes Report on stdout beside it: the class and the wait the endpoint
// asked for, read here into whole seconds and bounded, and nothing else of
// the answer. Its stderr diagnostic is the one it wrote for that answer
// before the status existed, so a gateway that does not read the status
// reports the failure as it always did.

import (
	"net/http"
	"strings"
	"time"

	"adapters/internal/canon"
)

// ThrottledStatus is the exit status a throttled answer is reported by.
const ThrottledStatus = 7

// MaxRetryAfter is the longest wait, in seconds, a report carries; a longer
// one the endpoint asked for is carried as this.
const MaxRetryAfter = 3600

// Throttled is an answer of 429 or 503. RetryAfter is the wait in whole
// seconds, 0 to MaxRetryAfter, or nil when the answer gave none in a form
// taken (RetryAfter).
type Throttled struct {
	Status     int
	RetryAfter *int
	text       string
}

func (t *Throttled) Error() string { return t.text }

// Report is what the command writes on stdout beside ThrottledStatus:
// {"throttled": {"retryAfter": N | null, "status": 429 | 503}}.
func (t *Throttled) Report() []byte {
	out, _ := canon.EncodeJSON(map[string]any{"throttled": map[string]any{"status": t.Status, "retryAfter": t.RetryAfter}})
	return out
}

// throttles is whether a status is one a throttled answer is reported for.
func throttles(status int) bool {
	return status == http.StatusTooManyRequests || status == http.StatusServiceUnavailable
}

// throttled is the failure of an answer of status, 429 or 503, whose
// Retry-After lines are values, with text as its diagnostic.
func throttled(status int, values []string, now time.Time, text string) *Throttled {
	return &Throttled{Status: status, RetryAfter: RetryAfter(values, now), text: text}
}

// RetryAfter reads an answer's Retry-After lines (RFC 9110 §10.2.3) into
// whole seconds from now: exactly one line, either delta-seconds (one or
// more ASCII digits) or an HTTP-date of any of the three forms RFC 9110
// §5.6.7 has a recipient accept. A delay past MaxRetryAfter is
// MaxRetryAfter; a date is counted up to the next whole second, and one at
// or before now is no wait. No line, more than one, a value of neither form
// -- a sign, a fraction, a list -- and a date not after now are nil: no
// wait is passed on, rather than a wait the endpoint did not state.
func RetryAfter(values []string, now time.Time) *int {
	if len(values) != 1 {
		return nil
	}
	value := strings.TrimSpace(values[0])
	if value == "" {
		return nil
	}
	if strings.Trim(value, "0123456789") == "" {
		seconds := 0
		for _, digit := range value {
			seconds = seconds*10 + int(digit-'0')
			if seconds > MaxRetryAfter {
				seconds = MaxRetryAfter
				break
			}
		}
		return &seconds
	}
	date, err := http.ParseTime(value)
	if err != nil {
		return nil
	}
	wait := date.Sub(now)
	if wait <= 0 {
		return nil
	}
	seconds := MaxRetryAfter
	if wait < MaxRetryAfter*time.Second {
		seconds = int((wait + time.Second - 1) / time.Second)
	}
	return &seconds
}
