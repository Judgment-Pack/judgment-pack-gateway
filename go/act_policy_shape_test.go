package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"strconv"
	"strings"
	"testing"
)

// A decision policy that holds a container's shape
// (docs/adr/0018-a-policy-holds-a-containers-shape.md): shape holds the value
// at a pointer to an array or an object, an array to at most so many
// elements, at policy-bind after fix and before closed, before anything is
// sent; a version-10 member of the engine's configuration, in the policy's
// digest; and closed treats a shaped pointer as reaching its container and
// nothing under it.

// The configuration member: each form accepted, and refused case by case.
func TestShapeConfiguration(t *testing.T) {
	catalog := catalogWith(t, map[string]string{"postgres": postgresBinding})
	ref := "postgres@" + digestOf(postgresBinding)
	config := func(version, policy string) string {
		extra := `,"write":true`
		if policy != "" {
			extra += `,"decisionPolicy":{"execute":` + policy + `}`
		}
		text := engineJSON(t, catalog, ``, platformJSONFor(t, "warehouse", ref, "engine-warehouse", extra, "history", "live", "write"))
		return strings.Replace(text, `"engineVersion":"1"`, `"engineVersion":"`+version+`"`, 1)
	}
	good := `{"outcomes":["approve"],"fix":[{"argument":"/updates/1","value":{"op":"replace"}}],` +
		`"shape":[{"pointer":"/updates","type":"array","maxLength":2},{"type":"object","pointer":"/meta"}],"closed":true}`
	cfg, sources, err := load(t, config("10", good))
	if err != nil {
		t.Fatal(err)
	}
	policy := sources["warehouse/write"].policies["execute"]
	if cfg.version != "10" || policy == nil || len(policy.shape) != 2 ||
		policy.shape[0] != (heldShape{pointer: "/updates", array: true, maxLength: 2}) ||
		policy.shape[1] != (heldShape{pointer: "/meta"}) {
		t.Fatalf("version %s, policy %+v", cfg.version, policy)
	}
	// Each form alone: none at all, the whole arguments, an array of none
	// and of the most, a shaped pointer that is also bound, and a fixed
	// pointer under a shaped one.
	for _, alone := range []string{
		`{"outcomes":["approve"],"shape":[]}`,
		`{"outcomes":["approve"],"shape":[{"pointer":"","type":"object"}]}`,
		`{"outcomes":["approve"],"shape":[{"pointer":"/l","type":"array","maxLength":0}]}`,
		`{"outcomes":["approve"],"shape":[{"pointer":"/l","type":"array","maxLength":` + strconv.Itoa(maxShapeLength) + `}]}`,
		`{"outcomes":["approve"],"bind":[{"argument":"/l","fact":"/l"}],"shape":[{"pointer":"/l","type":"array","maxLength":3}]}`,
		`{"outcomes":["approve"],"fix":[{"argument":"/l/0","value":1}],"shape":[{"pointer":"/l","type":"array","maxLength":1}]}`,
	} {
		if _, _, err := load(t, config("10", alone)); err != nil {
			t.Fatalf("%s: %v", alone, err)
		}
	}
	// A policy without the member means in a version-10 file what it means in
	// a version-9 one: no shape held, and the same digest.
	before := `{"outcomes":["approve"],"bind":[{"argument":"/id","fact":"/id"}],"fix":[{"argument":"/action","value":"update"}],"closed":true}`
	digests := map[string]bool{}
	for _, version := range []string{"9", "10"} {
		cfg, sources, err := load(t, config(version, before))
		if err != nil || cfg.version != version {
			t.Fatalf("version %s without shape: %v", version, err)
		}
		p := sources["warehouse/write"].policies["execute"]
		if p.shape != nil {
			t.Fatalf("version %s: a policy without the member holds no shape: %+v", version, p)
		}
		digests[p.digest] = true
	}
	if len(digests) != 1 {
		t.Fatalf("one policy, two digests by the file's version: %v", digests)
	}
	with := func(entries string) string {
		return config("10", `{"outcomes":["approve"],"shape":`+entries+`}`)
	}
	bound := "an integer from 0 to " + strconv.Itoa(maxShapeLength)
	for _, tc := range []struct{ name, text, want string }{
		{"shape in a version-9 file", config("9", `{"outcomes":["approve"],"shape":[{"pointer":"/updates","type":"array","maxLength":2}]}`), "shape is a version-10 member; engineVersion 9 has no shape"},
		{"an empty shape in a version-9 file", config("9", `{"outcomes":["approve"],"shape":[]}`), "shape is a version-10 member; engineVersion 9 has no shape"},
		{"shape in a version-4 file", config("4", `{"outcomes":["approve"],"shape":[{"pointer":"/meta","type":"object"}]}`), "shape is a version-10 member; engineVersion 4 has no shape"},
		{"shape not an array", with(`{"pointer":"/meta","type":"object"}`), "shape, when present, is an array of {pointer, type}"},
		{"an entry that is not an object", with(`["/meta"]`), "shape[0] must be an object of pointer and type"},
		{"an entry without its pointer", with(`[{"type":"object"}]`), `shape[0]: missing member "pointer"`},
		{"an entry without its type", with(`[{"pointer":"/meta"}]`), `shape[0]: missing member "type"`},
		{"an entry with a member beyond its form", with(`[{"pointer":"/l","type":"array","maxLength":2,"minLength":1}]`), `shape[0]: unknown member "minLength"`},
		{"a pointer without its slash", with(`[{"pointer":"meta","type":"object"}]`), "shape[0]: pointer must be a JSON pointer"},
		{"a pointer with a bad escape", with(`[{"pointer":"/a~2b","type":"object"}]`), "shape[0]: pointer must be a JSON pointer"},
		{"a pointer that is not a string", with(`[{"pointer":1,"type":"object"}]`), "shape[0]: pointer must be a JSON pointer"},
		{"a type that is no container", with(`[{"pointer":"/meta","type":"string"}]`), `shape[0]: type must be "array" or "object"`},
		{"a type spelled another way", with(`[{"pointer":"/l","type":"Array","maxLength":2}]`), `shape[0]: type must be "array" or "object"`},
		{"a type that is not a string", with(`[{"pointer":"/l","type":["array"],"maxLength":2}]`), `shape[0]: type must be "array" or "object"`},
		{"an array without its bound", with(`[{"pointer":"/l","type":"array"}]`), "shape[0]: an array's shape carries maxLength, " + bound},
		{"a negative bound", with(`[{"pointer":"/l","type":"array","maxLength":-1}]`), "shape[0]: maxLength must be " + bound},
		{"a bound one past the most", with(`[{"pointer":"/l","type":"array","maxLength":` + strconv.Itoa(maxShapeLength+1) + `}]`), "shape[0]: maxLength must be " + bound},
		{"a bound that is a string", with(`[{"pointer":"/l","type":"array","maxLength":"2"}]`), "shape[0]: maxLength must be " + bound},
		{"a bound that is null", with(`[{"pointer":"/l","type":"array","maxLength":null}]`), "shape[0]: maxLength must be " + bound},
		{"a bound that is a fraction", with(`[{"pointer":"/l","type":"array","maxLength":2.5}]`), "engine configuration"},
		{"an object with a bound", with(`[{"pointer":"/meta","type":"object","maxLength":2}]`), "shape[0]: maxLength is an array's; an object's shape is exactly {pointer, type}"},
		{"a pointer shaped twice to one shape", with(`[{"pointer":"/l","type":"array","maxLength":2},{"maxLength":2,"type":"array","pointer":"/l"}]`), `shape names the pointer "/l" twice`},
		{"a pointer shaped twice to two", with(`[{"pointer":"/l","type":"array","maxLength":2},{"pointer":"/l","type":"object"}]`), `shape names the pointer "/l" twice`},
		{"a pointer both fixed and shaped", config("10", `{"outcomes":["approve"],"fix":[{"argument":"/l","value":[]}],"shape":[{"pointer":"/l","type":"array","maxLength":0}]}`), `shape[0]: the argument "/l" is both fixed and shaped`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := parseEngineConfig([]byte(tc.text)); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want a refusal saying %q, got %v", tc.want, err)
			}
		})
	}
}

// connect keeps a version-10 policy as written, and the version: a pin
// captured beside it raises nothing and lowers nothing.
func TestConnectKeepsAShapedPolicyAndTheVersion(t *testing.T) {
	policy := `{"execute":{"outcomes":["approve"],"fix":[{"argument":"/updates/0","value":"x"}],"shape":[{"pointer":"/updates","type":"array","maxLength":1}],"closed":true}}`
	f := newConnectFixture(t, postgresBinding, ``)
	entry := `"warehouse":{"binding":"postgres@` + digestOf(postgresBinding) + `","credentials":{"history":{"file":"` + escapePath(f.credentials) + `"},"live":{"file":"` + escapePath(f.credentials) + `"},"write":{"file":"` + escapePath(f.credentials) + `"}},"user":"engine-warehouse","write":true,"decisionPolicy":` + policy + `}`
	text := strings.Replace(strings.Replace(f.fileText(t), `"engineVersion":"1"`, `"engineVersion":"10"`, 1), `"platforms":{}`, `"platforms":{`+entry+`}`, 1)
	if err := os.WriteFile(f.config, []byte(text), 0o640); err != nil {
		t.Fatal(err)
	}
	before, _, err := loadEngineConfig(f.config, stubAccounts(stubUsers))
	if err != nil {
		t.Fatal(err)
	}
	digest := before.platforms[0].policies["execute"].digest
	req := f.request()
	req.replace = true
	req.write = true
	req.credentials = map[string]string{"history": f.credentials, "live": f.credentials, "write": f.credentials}
	f.captured = `{"query":{"description":"Run a query","inputSchemaText":"{\"type\":\"object\"}"}}`
	if _, err := connect(context.Background(), req, f.host, f.check); err != nil {
		t.Fatal(err)
	}
	after, _, err := loadEngineConfig(f.config, stubAccounts(stubUsers))
	if err != nil {
		t.Fatal(err)
	}
	kept := after.platforms[0].policies["execute"]
	if after.version != "10" || after.platforms[0].descriptors == "" || kept == nil || kept.digest != digest || len(kept.shape) != 1 {
		t.Fatalf("version %s, pin %q, policy %+v: the policy kept as written, the version neither raised nor lowered", after.version, after.platforms[0].descriptors, kept)
	}
}

// The digest names the policy as configured, shape with the rest: a policy
// that differs from another only in its shape has another digest, and the
// same policy spelled in another order has the same.
func TestShapeIsInThePolicysDigest(t *testing.T) {
	base := `{"outcomes":["approve"],"shape":[{"pointer":"/updates","type":"array","maxLength":2},{"pointer":"/meta","type":"object"}],"closed":true}`
	// The canonical form, written by hand: members by code point, at every
	// depth; arrays in their order; the bound an integer.
	canonical := `{"closed":true,"outcomes":["approve"],"shape":[{"maxLength":2,"pointer":"/updates","type":"array"},{"pointer":"/meta","type":"object"}]}`
	sum := sha256.Sum256([]byte(canonical))
	want := "sha256:" + hex.EncodeToString(sum[:])
	respelled := "{ \"closed\": true,\n \"shape\": [ {\"maxLength\": 2, \"type\": \"arr\\u0061y\", \"pointer\": \"/updates\"},\n" +
		` {"type": "object", "pointer": "/meta"} ], "outcomes": ["approve"] }`
	for _, text := range []string{base, respelled} {
		if got := mustPolicy(t, text).digest; got != want {
			t.Fatalf("%s: digest %s, want %s", text, got, want)
		}
	}
	entries := `[{"pointer":"/updates","type":"array","maxLength":2},{"pointer":"/meta","type":"object"}]`
	seen := map[string]string{want: base}
	for _, other := range []string{
		strings.Replace(base, `"maxLength":2`, `"maxLength":3`, 1),
		strings.Replace(base, `"pointer":"/updates"`, `"pointer":"/update"`, 1),
		strings.Replace(base, `{"pointer":"/updates","type":"array","maxLength":2}`, `{"pointer":"/updates","type":"object"}`, 1),
		strings.Replace(base, `,{"pointer":"/meta","type":"object"}`, ``, 1),
		// the same entries in another order: the same checks, another digest
		strings.Replace(base, entries, `[{"pointer":"/meta","type":"object"},{"pointer":"/updates","type":"array","maxLength":2}]`, 1),
		strings.Replace(base, entries, `[]`, 1),
		strings.Replace(base, `"shape":`+entries+`,`, ``, 1),
	} {
		d := mustPolicy(t, other).digest
		if prior, ok := seen[d]; ok {
			t.Fatalf("two policies, one digest:\n%s\n%s", prior, other)
		}
		seen[d] = other
	}
}

// What a closed policy reaches with a shape (ADR-0018): a shaped pointer
// reaches its container, which is not refused, and covers nothing under it;
// each member or element there is reached only as a pointer of bind or fix
// reaches it. The containers on the way to a shaped pointer are walked.
func TestAClosedPolicyReachesAShapedContainerAndNothingUnderIt(t *testing.T) {
	for _, tc := range []struct {
		named, shaped []string
		arguments     string
		want          string // the first pointer refused; "" when every one is reached
	}{
		{nil, []string{"/l"}, `{"l":[]}`, ""},
		{nil, []string{"/l"}, `{"l":[1]}`, "/l/0"},
		{nil, []string{"/l"}, `{"l":[[]]}`, "/l/0"},
		{nil, []string{"/o"}, `{"o":{}}`, ""},
		{nil, []string{"/o"}, `{"o":{"a":1}}`, "/o/a"},
		{nil, []string{"/l"}, `{"l":[],"x":1}`, "/x"},
		// an absent container leaves nothing to walk: the shape's own check
		// refuses the absence
		{nil, []string{"/l"}, `{}`, ""},
		// nor does the walk judge the type: the shape's check did
		{nil, []string{"/l"}, `{"l":{}}`, ""},
		// a value at a shaped pointer that is no container is refused, as on
		// the way to any pointer; the shape's check refuses it first
		{nil, []string{"/l"}, `{"l":5}`, "/l"},
		// the way to a shaped pointer is walked, member by member
		{nil, []string{"/a/l"}, `{"a":{"l":[]}}`, ""},
		{nil, []string{"/a/l"}, `{"a":{"l":[],"m":1}}`, "/a/m"},
		{nil, []string{"/a/l"}, `{"a":{"l":["x"]}}`, "/a/l/0"},
		// members under a shaped container are reached by bind and fix
		{[]string{"/l/0"}, []string{"/l"}, `{"l":[1]}`, ""},
		{[]string{"/l/0"}, []string{"/l"}, `{"l":[1,2]}`, "/l/1"},
		{[]string{"/l/0/op"}, []string{"/l", "/l/0"}, `{"l":[{"op":"test"}]}`, ""},
		{[]string{"/l/0/op"}, []string{"/l", "/l/0"}, `{"l":[{"op":"test","from":"/x"}]}`, "/l/0/from"},
		// a pointer covering the container covers what the shape does not
		{[]string{"/l"}, []string{"/l"}, `{"l":[1,[2]]}`, ""},
		// a shape of the whole arguments covers nothing
		{nil, []string{""}, `{}`, ""},
		{nil, []string{""}, `{"x":1}`, "/x"},
	} {
		v, err := parseJSON([]byte(tc.arguments))
		if err != nil {
			t.Fatal(err)
		}
		got, found := unreachedArgument(v, tc.named, tc.shaped)
		if found != (tc.want != "") || got != tc.want {
			t.Fatalf("%q, shaped %q, over %s: got %q (%v), want %q", tc.named, tc.shaped, tc.arguments, got, found, tc.want)
		}
	}
}

// The check, through /act at policy-bind, over the in-process stand-in that
// counts every request: a refused write sends nothing at all, an admitted
// one is one call of exactly the arguments asked.
func TestActHoldsArgumentsToAShape(t *testing.T) {
	bin, _ := buildMCPStandIns(t, t.TempDir())

	t.Run("an array to its bound", func(t *testing.T) {
		h := newHeldTicketAt(t, bin, "10", `{"outcomes":["approve"],"bind":[{"argument":"/id","fact":"/ticket/id"}],`+
			`"shape":[{"pointer":"/tags","type":"array","maxLength":2}]}`)
		// at the bound, under it, and empty; a policy that is not closed
		// admits the elements, and a member it does not name
		h.sent(t, `{"id":"T-7","tags":["refund","billing"]}`)
		h.sent(t, `{"id":"T-7","tags":["refund"],"note":"by hand"}`)
		h.sent(t, `{"id":"T-7","tags":[]}`)
		// one over
		h.refused(t, `{"id":"T-7","tags":["refund","billing","more"]}`, `argument "/tags" holds more elements than the policy's shape allows`)
		// absent is not the container, as it is not a fixed value
		h.refused(t, `{"id":"T-7"}`, `argument "/tags" is not of the shape the policy holds it to`)
		// another container, or none, in its place
		h.refused(t, `{"id":"T-7","tags":{"0":"refund","1":"billing"}}`, `argument "/tags" is not of the shape the policy holds it to`)
		h.refused(t, `{"id":"T-7","tags":{}}`, `argument "/tags" is not of the shape the policy holds it to`)
		h.refused(t, `{"id":"T-7","tags":"refund"}`, `argument "/tags" is not of the shape the policy holds it to`)
		h.refused(t, `{"id":"T-7","tags":null}`, `argument "/tags" is not of the shape the policy holds it to`)
		// bind still holds first, and its sentence is its own
		h.refused(t, `{"id":"T-8","tags":{}}`, `the argument at "/id" does not equal the fact at "/ticket/id"`)
	})

	t.Run("an array of none", func(t *testing.T) {
		h := newHeldTicketAt(t, bin, "10", `{"outcomes":["approve"],"shape":[{"pointer":"/tags","type":"array","maxLength":0}]}`)
		h.sent(t, `{"tags":[]}`)
		h.refused(t, `{"tags":[null]}`, `argument "/tags" holds more elements than the policy's shape allows`)
	})

	t.Run("an object", func(t *testing.T) {
		h := newHeldTicketAt(t, bin, "10", `{"outcomes":["approve"],"shape":[{"pointer":"/labels","type":"object"}]}`)
		h.sent(t, `{"labels":{}}`)
		h.sent(t, `{"labels":{"0":"refund","team":"billing"}}`)
		// a shape of object on an array, of any length
		h.refused(t, `{"labels":["refund"]}`, `argument "/labels" is not of the shape the policy holds it to`)
		h.refused(t, `{"labels":[]}`, `argument "/labels" is not of the shape the policy holds it to`)
		h.refused(t, `{"labels":"team"}`, `argument "/labels" is not of the shape the policy holds it to`)
	})

	t.Run("closed with a shape and nothing under it", func(t *testing.T) {
		h := newHeldTicketAt(t, bin, "10", `{"outcomes":["approve"],"shape":[{"pointer":"/updates","type":"array","maxLength":2}],"closed":true}`)
		// what closed admits: the container the shape reaches, empty, and
		// nothing beside it
		h.sent(t, `{"updates":[]}`)
		h.refused(t, `{"updates":[{"op":"test"}]}`, `argument "/updates/0" is reached by no binding`)
		h.refused(t, `{"updates":[],"note":"x"}`, `argument "/note" is reached by no binding`)
		// and not the empty arguments, nor none, which a closed policy with
		// neither bind nor fix nor shape admits: the shape holds the
		// container there
		h.refused(t, `{}`, `argument "/updates" is not of the shape the policy holds it to`)
		h.refused(t, `{"updates":{}}`, `argument "/updates" is not of the shape the policy holds it to`)
	})

	t.Run("the order: fix, then shape, then closed", func(t *testing.T) {
		policy := `{"outcomes":["approve"],"bind":[{"argument":"/id","fact":"/ticket/id"},{"argument":"/updates/0/value","fact":"/ticket/revision"}],` +
			`"fix":[{"argument":"/action","value":"update"},{"argument":"/updates/0/op","value":"test"},{"argument":"/updates/0/path","value":"/rev"},` +
			`{"argument":"/updates/1","value":{"op":"replace","path":"/fields/System.State","value":"Approved"}}],` +
			`"shape":[{"pointer":"/updates","type":"array","maxLength":2}],"closed":true}`
		h := newHeldTicketAt(t, bin, "10", policy)
		array := `[{"op":"test","path":"/rev","value":4},{"op":"replace","path":"/fields/System.State","value":"Approved"}]`
		object := `{"0":{"op":"test","path":"/rev","value":4},"1":{"op":"replace","path":"/fields/System.State","value":"Approved"}}`
		h.sent(t, `{"action":"update","id":"T-7","updates":`+array+`}`)
		h.refused(t, `{"action":"update","id":"T-7","updates":`+object+`}`, `argument "/updates" is not of the shape the policy holds it to`)
		// a value fixed otherwise is refused by fix before the shape is held
		h.refused(t, `{"action":"update_batch","id":"T-7","updates":`+object+`}`, `argument "/action" is not the fixed value`)
		// the shape is held before the closed set is walked
		h.refused(t, `{"action":"update","id":"T-7","project":"another","updates":`+object+`}`, `argument "/updates" is not of the shape the policy holds it to`)
		h.refused(t, `{"action":"update","id":"T-7","project":"another","updates":`+array+`}`, `argument "/project" is reached by no binding`)
	})

	t.Run("a policy without a shape, in a version-10 file", func(t *testing.T) {
		// ADR-0016's policy means in a version-10 file what it meant: it
		// admits the object in place of the array, as it always did.
		policy := `{"outcomes":["approve"],"bind":[{"argument":"/id","fact":"/ticket/id"},{"argument":"/updates/0/value","fact":"/ticket/revision"}],` +
			`"fix":[{"argument":"/updates/0/op","value":"test"},{"argument":"/updates/1","value":{"op":"replace"}}],"closed":true}`
		h := newHeldTicketAt(t, bin, "10", policy)
		h.sent(t, `{"id":"T-7","updates":[{"op":"test","value":4},{"op":"replace"}]}`)
		h.sent(t, `{"id":"T-7","updates":{"0":{"op":"test","value":4},"1":{"op":"replace"}}}`)
	})
}
