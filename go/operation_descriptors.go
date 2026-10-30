package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
)

func enabledMCPOperations(p platformConfig, b binding) map[string]*operation {
	ops := map[string]*operation{}
	if b.live != nil {
		ops["live"] = b.live
	}
	if p.write && b.write != nil {
		ops["write"] = b.write
	}
	return ops
}

func operationPinsMatch(p platformConfig, b binding) error {
	if !b.hasOwnerDeclarations() {
		if p.operationDescriptors != nil {
			return errors.New("operationDescriptors requires an owner-declared bindingVersion2")
		}
		return nil
	}
	ops := enabledMCPOperations(p, b)
	if p.descriptors != "" || p.operationDescriptors == nil || len(p.operationDescriptors) != len(ops) {
		return fmt.Errorf("platform %s: V2 requires exactly the enabled operationDescriptors, without legacy descriptors", p.name)
	}
	for name := range ops {
		if !isDigest(p.operationDescriptors[name]) {
			return fmt.Errorf("platform %s: missing %s descriptor approval", p.name, name)
		}
	}
	return nil
}

func renderOperationPlatformEntry(data []byte, req connectRequest, ref string, pins map[string]string, parameters map[string]string) ([]byte, error) {
	rendered, err := renderPlatformEntry(data, req, ref, "", parameters)
	if err != nil {
		return nil, err
	}
	raw, err := parseJSON(rendered)
	if err != nil {
		return nil, err
	}
	obj := raw.(*vObject)
	if version, _ := memberString(obj, "engineVersion"); !versionAtLeast(version, "11") {
		obj.set("engineVersion", vString("11"))
	}
	platforms, _ := obj.get("platforms")
	entry, _ := platforms.(*vObject).get(req.platform)
	values := newObject()
	for name, pin := range pins {
		values.set(name, vString(pin))
	}
	entry.(*vObject).set("operationDescriptors", values)
	var text strings.Builder
	formatValue(&text, obj, "")
	text.WriteByte('\n')
	if text.Len() > maxEngineConfigBytes {
		return nil, errors.New("configuration with operation approvals exceeds bound")
	}
	return []byte(text.String()), nil
}

// All independent captures succeed before any config write. All immutable files precede its rename.
func connectTaxonomyOperations(ctx context.Context, req connectRequest, file *configFile, data []byte, cfg engineConfig, bindings map[string]binding, b binding, entry, written platformConfig, previous *platformConfig, sources map[string]sourceSpec, check func(context.Context, sourceSpec) ([]byte, error), out connectOutcome) (connectOutcome, error) {
	if req.noDescriptors {
		return out, errors.New("V2 registration requires all enabled operation snapshots")
	}
	ops := enabledMCPOperations(entry, b)
	pins := map[string]string{}
	for name := range ops {
		pins[name] = "sha256:" + strings.Repeat("0", 64)
	}
	placeholder, err := renderOperationPlatformEntry(data, req, entry.binding, pins, entry.parameters)
	if err != nil {
		return out, err
	}
	if _, err = renderDescriptorStatements(placeholder, req.platform, pins); err != nil {
		return out, err
	}
	// Size-check every declaration before any publication or target is reached.
	declarations := map[string][]byte{}
	for name, op := range ops {
		raw, err := ownerFileDeclaration(entry, op)
		if err != nil {
			return out, err
		}
		declarations[name] = raw
	}
	var held []*os.Root
	defer func() {
		for _, root := range held {
			root.Close()
		}
	}()
	declarationNames := []string{}
	for name := range declarations {
		declarationNames = append(declarationNames, name)
	}
	sort.Strings(declarationNames)
	for _, name := range declarationNames {
		_, root, err := file.publishSnapshot(declarations[name])
		if err != nil {
			return out, err
		}
		held = append(held, root)
	}
	var names []string
	for name := range sources {
		if strings.HasPrefix(name, req.platform+"/") {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	captures := map[string]liveCapture{}
	for _, name := range names {
		kind := strings.TrimPrefix(name, req.platform+"/")
		spec := sources[name]
		if ops[kind] != nil {
			spec.check = append(append([]string(nil), spec.check...), "--descriptors-platform="+req.platform, "--descriptors-binding="+entry.binding, "--descriptors-operation="+kind)
		}
		report, err := check(ctx, spec)
		if err != nil {
			return out, fmt.Errorf("%s: %w", name, err)
		}
		answer, err := describeCheck(spec.shape, report, remoteURL(spec.argv))
		if err != nil {
			return out, fmt.Errorf("%s: %w", name, err)
		}
		out.answers = append(out.answers, name+": "+answer)
		if op := ops[kind]; op != nil {
			captured, err := readCapture(report, req.platform, entry.binding, op)
			if err != nil {
				return out, err
			}
			captures[kind] = captured
			out.answers = append(out.answers, name+": approved owner taxonomy and operation "+kind)
			for _, line := range captureLines(captured, op) {
				out.answers = append(out.answers, name+": "+line)
			}
		}
	}
	keys := []string{}
	for name := range ops {
		keys = append(keys, name)
	}
	sort.Strings(keys)
	statementPins := map[string]string{}
	for _, name := range keys {
		captured, ok := captures[name]
		if !ok || captured.data == nil {
			return out, errors.New("missing complete operation capture")
		}
		if previous != nil && previous.operationDescriptors[name] != "" {
			prior, err := file.readPinnedSnapshot(previous.operationDescriptors[name])
			if err != nil {
				out.answers = append(out.answers, req.platform+"/"+name+": descriptors: the previous snapshot does not verify against its pin, so nothing is compared: "+err.Error())
			} else {
				var allowedBefore map[string]bool
				if before, err := loadBinding(cfg.catalog, previous.binding); err == nil {
					if before, err = resolveParameters(before, previous.parameters, previous.binding); err == nil {
						if op := enabledMCPOperations(*previous, before)[name]; op != nil {
							allowedBefore = map[string]bool{}
							for _, tool := range op.tools {
								allowedBefore[tool] = true
							}
						}
					}
				}
				for _, line := range compareLines(&prior, allowedBefore, captured, ops[name]) {
					out.answers = append(out.answers, req.platform+"/"+name+": "+line)
				}
			}
		}
		pin, root, err := file.publishSnapshot(captured.data)
		if err != nil {
			return out, err
		}
		held = append(held, root)
		pins[name] = pin
		provenance, err := retainConnectedCapture(cfg, captured.data, name)
		if err != nil {
			return out, err
		}
		statementPins[name] = provenance.statement
		if previous != nil {
			old := previous.operationDescriptors[name]
			if old != pin {
				out.answers = append(out.answers, req.platform+"/"+name+": descriptor approval changed; explicit replacement recorded")
			}
		}
	}
	text, err := renderOperationPlatformEntry(data, req, entry.binding, pins, entry.parameters)
	if err != nil {
		return out, err
	}
	text, err = renderDescriptorStatements(text, req.platform, statementPins)
	if err != nil {
		return out, err
	}
	if _, err = parseEngineConfig(text); err != nil {
		return out, err
	}
	if beforeCommit != nil {
		beforeCommit()
	}
	file.beforeRename = func() error {
		for _, root := range held {
			if err := file.stillHeld(root); err != nil {
				return err
			}
		}
		return nil
	}
	if err = file.replace(data, text); err != nil {
		var late errNotDurable
		if errors.As(err, &late) {
			out.written = req.config
		}
		return out, err
	}
	out.written = req.config
	if req.afterWrite != nil {
		if err := req.afterWrite(file); err != nil {
			return out, err
		}
	}
	written.operationDescriptors = pins
	if previous != nil {
		out.after = restartLines(*previous, written)
	}
	return out, nil
}

func (d *servedDirectory) readOperation(p platformConfig, b binding, name string) (*servedPlatform, error) {
	if !b.hasOwnerDeclarations() {
		return d.read(p, b)
	}
	if err := operationPinsMatch(p, b); err != nil {
		return nil, err
	}
	op := enabledMCPOperations(p, b)[name]
	if op == nil {
		return nil, errors.New("operation is not enabled")
	}
	selected := binding{version: b.version, platform: b.platform}
	if name == "live" {
		selected.live = op
	} else {
		selected.write = op
	}
	p.descriptors = p.operationDescriptors[name]
	return readServedPlatform(d.dir, d.name, d.owner, p, selected)
}
