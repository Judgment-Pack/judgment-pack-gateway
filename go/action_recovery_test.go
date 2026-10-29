package main

import (
	"strings"
	"testing"
)

const recoveryDeclaration = `{"query":{"idempotencyArgument":"request_id","readBack":{"tool":"query","arguments":{"key":{"actionKey":true},"ticket":{"argument":"/ticket"},"literal":{"literal":7}},"keyPointer":"/key","outcomePointer":"/state","committedValue":"done"}},"sibling":null}`

func TestActionRecoveryPinnedContract(t *testing.T) {
	base := strings.Replace(customerBinding("https://example.test/read", "https://example.test/write"), `"bindingVersion":"2"`, `"bindingVersion":"3"`, 1)
	base = strings.TrimSuffix(base, "}") + `,"actionRecovery":` + recoveryDeclaration + `}`
	b, err := parseBinding([]byte(base))
	if err != nil {
		t.Fatal(err)
	}
	contract := b.actionRecovery["query"]
	key := strings.Repeat("a", 64)
	args := newObject()
	args.set("ticket", vString("T-1"))
	if err := contract.applyKey(args, key); err != nil {
		t.Fatal(err)
	}
	if err := contract.applyKey(args, strings.Repeat("b", 64)); err == nil {
		t.Fatal("conflicting idempotency argument accepted")
	}
	request, err := contract.readBack.request(key, args)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(canon(request)); got != `{"arguments":{"key":"`+key+`","literal":7,"ticket":"T-1"},"tool":"query"}` {
		t.Fatal(got)
	}
	for _, tc := range []struct{ raw, want string }{
		{`{"key":"` + key + `","state":"done"}`, "committed"},
		{`{"key":"other","state":"done"}`, "unknown"},
		{`{"key":"` + key + `","state":"absent"}`, "unknown"},
		{`{}`, "unknown"},
	} {
		v, _ := parseJSON([]byte(tc.raw))
		if got := contract.readBack.outcome(key, v); got != tc.want {
			t.Fatalf("%s: %s", tc.raw, got)
		}
	}
	if _, err = contract.readBack.request(key, newObject()); err == nil {
		t.Fatal("missing original argument accepted")
	}
	for name, broken := range map[string]string{
		"old version":         strings.Replace(base, `"bindingVersion":"3"`, `"bindingVersion":"2"`, 1),
		"missing declaration": strings.Replace(base, `,"actionRecovery":`+recoveryDeclaration, "", 1),
		"missing tool":        strings.Replace(base, `,"sibling":null`, "", 1),
		"extra tool":          strings.Replace(base, `"sibling":null`, `"sibling":null,"other":null`, 1),
		"empty support":       strings.Replace(base, `"sibling":null`, `"sibling":{}`, 1),
		"unknown support":     strings.Replace(base, `"sibling":null`, `"sibling":{"retry":true}`, 1),
		"write readback":      strings.Replace(base, `"operation":"read"`, `"operation":"act"`, 1),
		"bad pointer":         strings.Replace(base, `"/key"`, `"/key~2"`, 1),
		"false key":           strings.Replace(base, `"actionKey":true`, `"actionKey":false`, 1),
		"ambiguous map":       strings.Replace(base, `"actionKey":true`, `"actionKey":true,"literal":"x"`, 1),
		"unallowed read tool": strings.Replace(base, `"tool":"query"`, `"tool":"other"`, 1),
		"null argument name":  strings.Replace(base, `"idempotencyArgument":"request_id"`, `"idempotencyArgument":null`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := parseBinding([]byte(broken)); err == nil {
				t.Fatal("accepted malformed recovery")
			}
		})
	}
}
