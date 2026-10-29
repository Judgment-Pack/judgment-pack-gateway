package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// Recovery is an owner claim pinned by the binding, never inferred from a tool
// annotation or provider. A nil entry explicitly declares unsupported recovery.
type actionRecovery struct {
	declaration         *vObject
	idempotencyArgument string
	readBack            *actionReadBack
}
type actionReadBack struct {
	tool                                       string
	arguments                                  *vObject
	keyPointer, outcomePointer, committedValue string
}

func parseActionRecovery(raw value, b binding) (map[string]*actionRecovery, error) {
	obj, err := requireObject(raw, "actionRecovery")
	if err != nil {
		return nil, err
	}
	if b.write == nil || len(obj.names) != len(b.write.tools) {
		return nil, errors.New("actionRecovery must cover exactly every write tool")
	}
	out := map[string]*actionRecovery{}
	for _, name := range obj.names {
		if !contains(b.write.tools, name) {
			return nil, errors.New("actionRecovery names an undeclared write tool")
		}
		v, _ := obj.get(name)
		if _, unsupported := v.(vNull); unsupported {
			out[name] = nil
			continue
		}
		declaration, err := requireObject(v, "actionRecovery tool")
		if err != nil {
			return nil, err
		}
		if err = exactlyMembers(declaration, map[string]bool{"idempotencyArgument": false, "readBack": false}, "actionRecovery tool"); err != nil {
			return nil, err
		}
		if len(declaration.names) == 0 {
			return nil, errors.New("actionRecovery tool must declare support or null")
		}
		contract := &actionRecovery{declaration: declaration}
		if _, present := declaration.get("idempotencyArgument"); present {
			contract.idempotencyArgument, err = requireString(declaration, "idempotencyArgument")
			if err != nil || !actionArgumentName(contract.idempotencyArgument) {
				return nil, errors.New("idempotencyArgument must be a nonempty bounded argument name")
			}
		}
		if rb, present := declaration.get("readBack"); present {
			r, err := requireObject(rb, "readBack")
			if err != nil {
				return nil, err
			}
			if err = exactlyMembers(r, map[string]bool{"tool": true, "arguments": true, "keyPointer": true, "outcomePointer": true, "committedValue": true}, "readBack"); err != nil {
				return nil, err
			}
			read := &actionReadBack{}
			read.tool, err = requireString(r, "tool")
			if err != nil || b.live == nil || !contains(b.live.tools, read.tool) {
				return nil, errors.New("readBack tool must be an allowed live tool")
			}
			owner := b.live.taxonomies[read.tool]
			if owner.Operation != "read" || (owner.Effect != "read" && owner.Effect != "read-external") {
				return nil, errors.New("readBack tool requires a read owner declaration")
			}
			for name, dest := range map[string]*string{"keyPointer": &read.keyPointer, "outcomePointer": &read.outcomePointer, "committedValue": &read.committedValue} {
				*dest, err = requireString(r, name)
				if err != nil || len(*dest) > 4096 {
					return nil, fmt.Errorf("readBack %s must be a bounded string", name)
				}
			}
			if !validPointer(read.keyPointer) || !validPointer(read.outcomePointer) || read.committedValue == "" {
				return nil, errors.New("readBack requires valid result pointers and a nonempty committedValue")
			}
			av, _ := r.get("arguments")
			read.arguments, err = requireObject(av, "readBack.arguments")
			if err != nil || len(read.arguments.names) > 128 {
				return nil, errors.New("readBack.arguments must be a bounded object")
			}
			for _, arg := range read.arguments.names {
				if !actionArgumentName(arg) {
					return nil, errors.New("readBack argument name is invalid")
				}
				raw, _ := read.arguments.get(arg)
				mapping, err := requireObject(raw, "readBack argument mapping")
				if err != nil || len(mapping.names) != 1 {
					return nil, errors.New("readBack argument requires exactly one mapping")
				}
				v, _ := mapping.get(mapping.names[0])
				switch mapping.names[0] {
				case "actionKey":
					if flag, ok := v.(vBool); !ok || !bool(flag) {
						return nil, errors.New("actionKey mapping must be true")
					}
				case "argument":
					if p, ok := v.(vString); !ok || len(p) > 4096 || !validPointer(string(p)) {
						return nil, errors.New("argument mapping requires a valid bounded JSON pointer")
					}
				case "literal": // Already parsed with the binding's canonical JSON bounds.
				default:
					return nil, errors.New("unknown readBack argument mapping")
				}
			}
			contract.readBack = read
		}
		out[name] = contract
	}
	return out, nil
}
func actionArgumentName(s string) bool {
	return s != "" && len(s) <= 256 && !strings.ContainsAny(s, "\x00\r\n")
}
func (r *actionRecovery) digest() string {
	var v value = vNull{}
	if r != nil {
		v = r.declaration
	}
	sum := sha256.Sum256(append([]byte("judgment-pack-gateway/action-recovery/1:"), canon(v)...))
	return "sha256:" + hex.EncodeToString(sum[:])
}
func (r *actionRecovery) applyKey(arguments *vObject, key string) error {
	if r == nil || r.idempotencyArgument == "" {
		return nil
	}
	if old, present := arguments.get(r.idempotencyArgument); present && old != vString(key) {
		return errors.New("action-key-conflict: idempotency argument differs from actionKey")
	}
	arguments.set(r.idempotencyArgument, vString(key))
	return nil
}
func (r *actionReadBack) request(key string, arguments value) (*vObject, error) {
	mapped := newObject()
	for _, name := range r.arguments.names {
		raw, _ := r.arguments.get(name)
		mapping := raw.(*vObject)
		kind := mapping.names[0]
		v, _ := mapping.get(kind)
		switch kind {
		case "actionKey":
			v = vString(key)
		case "argument":
			var found bool
			v, found = resolvePointer(arguments, string(v.(vString)))
			if !found {
				return nil, errors.New("action-reconciliation-unavailable: original argument mapping does not resolve")
			}
		}
		mapped.set(name, v)
	}
	request := newObject()
	request.set("tool", vString(r.tool))
	request.set("arguments", mapped)
	return request, nil
}
func (r *actionReadBack) outcome(key string, result value) string {
	observed, ok := resolvePointer(result, r.keyPointer)
	if !ok || observed != vString(key) {
		return "unknown"
	}
	state, ok := resolvePointer(result, r.outcomePointer)
	if !ok || state != vString(r.committedValue) {
		return "unknown"
	}
	return "committed"
}
