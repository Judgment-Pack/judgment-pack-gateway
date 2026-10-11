package connections

import (
	"encoding/json"
	"errors"
	"reflect"
	"testing"
)

// The operator's list: absent or empty is none; a supported name is that
// policy; anything else refuses the list whole.
func TestWebRedirectPolicyConfiguration(t *testing.T) {
	for _, value := range []string{"", GoogleGroundingPolicy} {
		got, err := ParseWebRedirectPolicies(value)
		want := []string{}
		if value != "" {
			want = []string{value}
		}
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Errorf("%q: %v %v", value, got, err)
		}
	}
	for _, value := range []string{"any-origin", "google-grounding,any-origin", "google-grounding,google-grounding", "google-grounding,", ",google-grounding", " google-grounding", "Google-Grounding", "google-grounding\n", "*"} {
		if got, err := ParseWebRedirectPolicies(value); !errors.Is(err, ErrWebRedirectPolicy) || got != nil {
			t.Errorf("%q admitted: %v", value, got)
		}
	}
	if len(WebRedirectPolicyRefusal) > 160 || WebRedirectPolicyRefusal[:len(ErrWebRedirectPolicy.Error())] != ErrWebRedirectPolicy.Error() {
		t.Error("the refusal is not one bounded line under its code")
	}
}

// With no policy the plan is the plan; with one, the web source alone is
// launched with the flag, and nothing else moves.
func TestTheLocalPlanCarriesTheOperatorsRedirectPolicies(t *testing.T) {
	plain := ConnectionLocalPlanFor(true, true)
	before, _ := json.Marshal(plain)
	for _, none := range [][]string{nil, {}} {
		got, _ := json.Marshal(plain.WithWebRedirectPolicies(none))
		if string(got) != string(before) {
			t.Fatalf("no policy changed the plan: %s", got)
		}
	}
	served := plain.WithWebRedirectPolicies([]string{GoogleGroundingPolicy})
	if after, _ := json.Marshal(plain); string(after) != string(before) {
		t.Fatal("the plan it was given was changed")
	}
	if len(served.Sources) != len(plain.Sources) {
		t.Fatal("sources changed")
	}
	for i, source := range served.Sources {
		want := plain.Sources[i]
		if source.ID == "web" {
			want.Args = append(append([]string{}, want.Args...), "--redirect-policies=google-grounding")
		}
		if !reflect.DeepEqual(source, want) {
			t.Errorf("%s: %+v", source.ID, source)
		}
	}
}

// The report names what this distribution supports and what the
// configuration it was given enables.
func TestTheSourceCapabilitiesReport(t *testing.T) {
	for _, c := range []struct {
		enabled []string
		want    string
	}{
		{[]string{}, `{"version":1,"sources":[{"id":"web","redirectPolicies":{"supported":["google-grounding"],"enabled":[]}}]}`},
		{nil, `{"version":1,"sources":[{"id":"web","redirectPolicies":{"supported":["google-grounding"],"enabled":[]}}]}`},
		{[]string{GoogleGroundingPolicy}, `{"version":1,"sources":[{"id":"web","redirectPolicies":{"supported":["google-grounding"],"enabled":["google-grounding"]}}]}`},
	} {
		raw, err := json.Marshal(ConnectionSourceCapabilities(c.enabled))
		if err != nil || string(raw) != c.want {
			t.Errorf("%s", raw)
		}
	}
}
