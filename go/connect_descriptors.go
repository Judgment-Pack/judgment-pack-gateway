package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"
)

// What connect does with the descriptors a platform's live check captured
// (docs/design/tool-descriptors.md): it reads them from the report
// strictly, says of each allowed tool what was captured or why it fell
// back, compares them with the snapshot the entry pinned before, and says
// which processes must restart for the change to be served.

// liveCapture is what a live check reported of its capture.
type liveCapture struct {
	data      []byte // the snapshot as connect writes it; nil when there is none
	snap      snapshot
	fallbacks []reportedFallback
	unlisted  int
	dropped   string
}

type reportedFallback struct {
	Tool   string `json:"tool"`
	Part   string `json:"part"`
	Reason string `json:"reason"`
}

// readCapture reads what the live check captured. The whole report is
// held to the strict parser -- no member twice at any depth, UTF-8 without
// a lone surrogate, nothing after it -- and the snapshot member then to
// the snapshot's shape, to the platform and binding it was captured for,
// and to the tools the live operation allows. The fallbacks are words for
// the operator, read as the rest of the report is.
func readCapture(report []byte, platform, ref string, live *operation) (liveCapture, error) {
	var c liveCapture
	v, err := parseJSON(report)
	if err != nil {
		return c, fmt.Errorf("descriptors: the report is not strict JSON: %v", err)
	}
	top, ok := v.(*vObject)
	if !ok {
		return c, errors.New("descriptors: the report is not an object")
	}
	checkValue, _ := top.get("check")
	check, ok := checkValue.(*vObject)
	if !ok {
		return c, errors.New("descriptors: the report carries no check")
	}
	var lenient struct {
		Check struct {
			Fallbacks          []reportedFallback `json:"fallbacks"`
			FallbacksUnlisted  int                `json:"fallbacksUnlisted"`
			DescriptorsDropped string             `json:"descriptorsDropped"`
		} `json:"check"`
	}
	if err := json.Unmarshal(report, &lenient); err != nil {
		return c, fmt.Errorf("descriptors: the report's fallbacks cannot be read: %v", err)
	}
	c.fallbacks, c.unlisted, c.dropped = lenient.Check.Fallbacks, lenient.Check.FallbacksUnlisted, lenient.Check.DescriptorsDropped
	value, present := check.get("descriptors")
	if !present {
		if c.dropped == "" {
			return c, errors.New("descriptors: the report carries no snapshot, and says of none why")
		}
		return c, nil
	}
	c.data = canon(value)
	if c.snap, err = parseSnapshot(c.data); err != nil {
		return c, fmt.Errorf("descriptors: %v", err)
	}
	if c.snap.platform != platform || c.snap.binding != ref {
		return c, errors.New("descriptors: the snapshot is not of this platform and binding")
	}
	allowed := map[string]bool{}
	for _, tool := range live.tools {
		allowed[tool] = true
	}
	for _, name := range c.snap.names {
		if !allowed[name] {
			return c, errors.New("descriptors: the snapshot holds a tool the live operation does not allow")
		}
	}
	return c, nil
}

// captureLines says, for the operator, what was captured of the server and
// of each tool the live operation allows, in the binding's order, or why
// it fell back.
func captureLines(c liveCapture, live *operation) []string {
	reasons := map[string][]string{}
	var lines []string
	for _, f := range c.fallbacks {
		if f.Part == "server" {
			lines = append(lines, "descriptors: the server's identity fell back: "+f.Reason)
			continue
		}
		part := map[string]string{"description": "description", "inputSchema": "input schema", "tool": "tool"}[f.Part]
		if part == "" {
			part = f.Part
		}
		reasons[f.Tool] = append(reasons[f.Tool], part+": "+f.Reason)
	}
	if c.data == nil {
		lines = append(lines, "descriptors: none captured: "+c.dropped)
	} else if c.snap.server != nil {
		lines = append(lines, "descriptors: server "+strings.TrimSpace(c.snap.server.name+" "+c.snap.server.version))
	}
	for _, name := range live.tools {
		t, captured := c.snap.tools[name]
		var parts []string
		if t.description != nil {
			parts = append(parts, fmt.Sprintf("description %d bytes", len(*t.description)))
		}
		if t.inputSchemaText != nil {
			parts = append(parts, fmt.Sprintf("input schema %d bytes", len(*t.inputSchemaText)))
		}
		line := "descriptors: " + name
		switch {
		case captured:
			line += " captured (" + strings.Join(parts, ", ") + ")"
			if len(reasons[name]) > 0 {
				line += "; fell back: " + strings.Join(reasons[name], "; ")
			}
		case len(reasons[name]) > 0:
			line += " fell back: " + strings.Join(reasons[name], "; ")
		case c.unlisted > 0:
			line += " fell back; the reason is past what the report lists"
		default:
			line += " fell back"
		}
		lines = append(lines, line)
	}
	return lines
}

// compareLines says how the snapshot captured now differs from the one
// the entry pinned before, over every tool either binding allows or either
// snapshot holds: a tool the binding allows now and did not is added, one
// it no longer allows is removed, one captured in both whose candidates
// differ is changed, and one captured in only one of them is now, or no
// longer, fallen back. The server's identity is compared the same way. The
// capture time never counts. previous is nil when there is no previous
// snapshot to compare with; allowedBefore is nil when the previous binding
// cannot be read, and then the previous snapshot stands for it.
func compareLines(previous *snapshot, allowedBefore map[string]bool, now liveCapture, live *operation) []string {
	if previous == nil {
		return nil
	}
	allowedNow := map[string]bool{}
	for _, tool := range live.tools {
		allowedNow[tool] = true
	}
	before := allowedBefore
	if before == nil {
		before = map[string]bool{}
		for _, name := range previous.names {
			before[name] = true
		}
	}
	var formerly []string
	for tool := range before {
		formerly = append(formerly, tool)
	}
	sort.Strings(formerly)
	var names []string
	seen := map[string]bool{}
	for _, name := range append(append(append([]string{}, live.tools...), previous.names...), formerly...) {
		if !seen[name] {
			seen[name] = true
			names = append(names, name)
		}
	}
	var changes []string
	switch was, is := previous.server, now.snap.server; {
	case was != nil && is != nil && *was != *is:
		changes = append(changes, "the server's identity changed")
	case was != nil && is == nil:
		changes = append(changes, "the server's identity now fallen back")
	case was == nil && is != nil:
		changes = append(changes, "the server's identity no longer fallen back")
	}
	for _, name := range names {
		was, inBefore := previous.tools[name]
		is, inAfter := now.snap.tools[name]
		switch {
		case !allowedNow[name]:
			changes = append(changes, name+" removed")
		case !before[name]:
			changes = append(changes, name+" added")
		case inBefore && inAfter && !reflect.DeepEqual(was, is):
			changes = append(changes, name+" changed")
		case inBefore && !inAfter:
			changes = append(changes, name+" now fallen back")
		case !inBefore && inAfter:
			changes = append(changes, name+" no longer fallen back")
		}
	}
	if len(changes) == 0 {
		return []string{"descriptors: against the previous snapshot, nothing changed"}
	}
	return []string{"descriptors: against the previous snapshot: " + strings.Join(changes, ", ")}
}

// readPinnedSnapshot reads the snapshot a pin names from the snapshots'
// directory, opened as the entry it is, judged by what was opened -- a regular
// file of the snapshot's mode and an owner the frontend accepts -- and
// digested before it is parsed. It is how connect finds the previous
// snapshot to compare with.
func (f *configFile) readPinnedSnapshot(pin string) (snapshot, error) {
	hexSum, ok := strings.CutPrefix(pin, "sha256:")
	if !ok || !isDigest(pin) {
		return snapshot{}, errors.New("not a pin")
	}
	name := f.snapshotDir() + "/" + hexSum + ".json"
	file, info, err := openEntry(f.dir, name)
	if err != nil {
		return snapshot{}, fmt.Errorf("%s %v", name, err)
	}
	defer file.Close()
	if err := snapshotHeld(info, f.owner, false); err != nil {
		return snapshot{}, fmt.Errorf("%s %v", name, err)
	}
	data, err := readBoundedFrom(file, name, maxSnapshotBytes)
	if err != nil {
		return snapshot{}, err
	}
	sum := sha256.Sum256(data)
	if hex.EncodeToString(sum[:]) != hexSum {
		return snapshot{}, fmt.Errorf("%s does not digest to its pin", name)
	}
	return parseSnapshot(data)
}

// environmentOf is an environment as the file holds it, a variable to its
// value, whatever order it was given in.
func environmentOf(pairs []string) map[string]string {
	env := map[string]string{}
	for _, pair := range pairs {
		key, value, _ := strings.Cut(pair, "=")
		env[key] = value
	}
	return env
}

// restartLines says which processes must restart for what a --replace
// wrote to be served, comparing the entry as the file held it with the
// entry as it is written: when nothing the signer reads changed -- the
// binding's pin, a credentials path, the user, the endpoint, the
// environment, the write flag -- and only the descriptors' pin did, the
// frontend alone; otherwise both.
func restartLines(previous, next platformConfig) []string {
	var signer []string
	if previous.binding != next.binding {
		signer = append(signer, "the binding")
	}
	if !reflect.DeepEqual(previous.credentials, next.credentials) {
		signer = append(signer, "a credentials path")
	}
	if previous.user != next.user {
		signer = append(signer, "the user")
	}
	if previous.endpoint != next.endpoint {
		signer = append(signer, "the endpoint")
	}
	if !reflect.DeepEqual(environmentOf(previous.environment), environmentOf(next.environment)) {
		signer = append(signer, "the environment")
	}
	if previous.write != next.write {
		signer = append(signer, "the write flag")
	}
	switch {
	case len(signer) > 0:
		return []string{"restart: what the signer reads changed (" + strings.Join(signer, ", ") + "); restart both processes"}
	case previous.descriptors != next.descriptors:
		return []string{"restart: only the descriptors' pin changed; restarting the frontend alone serves it"}
	}
	return []string{"restart: nothing either process reads changed"}
}
