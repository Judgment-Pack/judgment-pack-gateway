package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// The frontend reads each pinned snapshot at start, and only then
// (docs/design/tool-descriptors.md, "What the frontend reads, once"): in
// its own constructor, given the configuration's path, apart from the
// configuration loading the signer shares. Nothing reads a snapshot again,
// so a rewrite after start changes nothing until the next start, which
// then verifies what it reads.

// maxListingBytes bounds the whole tools/list answer, serialized;
// listingBound is it, unless a test lowers it.
const maxListingBytes = 8 << 20

var listingBound = maxListingBytes

// readServedPlatforms reads the snapshot every platform pins, each by the
// note's five checks in order -- the directory, the file, the digest, the
// strict decoding and the snapshot's own, then every candidate judged
// again -- and refuses the start on any failure: a pinned snapshot is never
// a fallback.
func readServedPlatforms(configPath string, cfg engineConfig, bindings map[string]binding) (map[string]*servedPlatform, error) {
	served := map[string]*servedPlatform{}
	var pinned []platformConfig
	for _, p := range cfg.platforms {
		if p.descriptors != "" {
			pinned = append(pinned, p)
		}
	}
	if len(pinned) == 0 {
		return served, nil
	}
	if configPath == "" {
		return nil, errors.New("descriptors: a snapshot is read beside the configuration, and the MCP server was not given its path")
	}
	parent, err := os.OpenRoot(filepath.Dir(configPath))
	if err != nil {
		return nil, fmt.Errorf("descriptors: %v", err)
	}
	defer parent.Close()
	configInfo, err := parent.Lstat(filepath.Base(configPath))
	if err != nil {
		return nil, fmt.Errorf("descriptors: %v", err)
	}
	owner := ownerIDsOf(configInfo)
	// 1. The directory, opened relative to the configuration's own,
	// following no link, judged by what was opened.
	name := filepath.Base(configPath) + ".descriptors"
	entry, err := parent.Lstat(name)
	if err != nil {
		return nil, fmt.Errorf("descriptors: %s: %w", name, err)
	}
	if entry.Mode()&os.ModeSymlink != 0 || !entry.IsDir() {
		return nil, fmt.Errorf("descriptors: %s is not a directory", name)
	}
	if entryJudged != nil {
		entryJudged(name)
	}
	dir, err := parent.OpenRoot(name)
	if err != nil {
		return nil, fmt.Errorf("descriptors: %v", err)
	}
	defer dir.Close()
	opened, err := dir.Stat(".")
	if err != nil {
		return nil, fmt.Errorf("descriptors: %v", err)
	}
	// Judged before the open and again after it, each time as what was
	// opened: the held directory follows a link inside it, and a link put
	// in the entry's place is found by the second look.
	after, err := parent.Lstat(name)
	if err != nil || after.Mode()&os.ModeSymlink != 0 || !os.SameFile(entry, opened) || !os.SameFile(after, opened) {
		return nil, fmt.Errorf("descriptors: %s is not the directory its name held a moment ago", name)
	}
	if err := servedInvariant(opened, owner); err != nil {
		return nil, fmt.Errorf("descriptors: %s %v", name, err)
	}
	for _, p := range pinned {
		platform, err := readServedPlatform(dir, name, owner, p, bindings[p.name])
		if err != nil {
			return nil, fmt.Errorf("platform %s: descriptors: %w", p.name, err)
		}
		served[p.name] = platform
	}
	return served, nil
}

// readServedPlatform reads one pinned snapshot from the open directory.
func readServedPlatform(dir *os.Root, dirName string, owner fileOwnerIDs, p platformConfig, b binding) (*servedPlatform, error) {
	if b.live == nil {
		return nil, errors.New("the binding has no live operation to describe")
	}
	name := strings.TrimPrefix(p.descriptors, "sha256:") + ".json"
	// 2. The file, opened relative to the directory, following no link,
	// judged by what was opened.
	entry, err := dir.Lstat(name)
	if err != nil {
		return nil, fmt.Errorf("%s/%s: %w", dirName, name, err)
	}
	if entry.Mode()&os.ModeSymlink != 0 || !entry.Mode().IsRegular() {
		return nil, fmt.Errorf("%s/%s is not a regular file", dirName, name)
	}
	if entryJudged != nil {
		entryJudged(name)
	}
	file, err := openServedSnapshot(dir, name)
	if err != nil {
		return nil, fmt.Errorf("%s/%s: %v", dirName, name, err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	after, err := dir.Lstat(name)
	if err != nil || after.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || !os.SameFile(entry, info) || !os.SameFile(after, info) {
		return nil, fmt.Errorf("%s/%s is not the file its name held a moment ago", dirName, name)
	}
	if err := servedInvariant(info, owner); err != nil {
		return nil, fmt.Errorf("%s/%s %v", dirName, name, err)
	}
	if info.Size() > maxSnapshotBytes {
		return nil, fmt.Errorf("%s/%s is %d bytes, over %d", dirName, name, info.Size(), maxSnapshotBytes)
	}
	// 3. At most the bound and a byte, digested before anything parses it.
	data, err := io.ReadAll(io.LimitReader(file, maxSnapshotBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxSnapshotBytes {
		return nil, fmt.Errorf("%s/%s is over %d bytes", dirName, name, maxSnapshotBytes)
	}
	sum := sha256.Sum256(data)
	if "sha256:"+hex.EncodeToString(sum[:]) != p.descriptors {
		return nil, fmt.Errorf("%s/%s does not digest to its pin", dirName, name)
	}
	// 4. Strictly decoded, and the snapshot of this entry: its platform,
	// its binding, a policy this engine implements, and tools its live
	// operation allows.
	snap, err := parseSnapshot(data)
	if err != nil {
		return nil, err
	}
	if snap.platform != p.name || snap.binding != p.binding {
		return nil, errors.New("the snapshot is not of this platform and binding")
	}
	allowed := map[string]bool{}
	for _, tool := range b.live.tools {
		allowed[tool] = true
	}
	// 5. Every candidate passes the display policy, the grammar and the
	// limits again. The frontend holds no credentials, so it cannot
	// screen for them; the adapter that captured did.
	served := &servedPlatform{capturedAt: snap.capturedAt, tools: map[string]servedTool{}}
	if snap.server != nil {
		if r := judgeText(snap.server.name, identityBound, "the server's name"); r != nil {
			return nil, r
		}
		if r := judgeText(snap.server.version, identityBound, "the server's version"); r != nil {
			return nil, r
		}
		served.server = snap.server
	}
	together := 0
	for _, tool := range snap.names {
		if !allowed[tool] {
			return nil, errors.New("the snapshot holds a tool the live operation does not allow")
		}
		candidates := snap.tools[tool]
		var t servedTool
		if d := candidates.description; d != nil {
			if r := judgeText(*d, descriptionBound, "a description"); r != nil {
				return nil, r
			}
			t.description = d
		}
		if text := candidates.inputSchemaText; text != nil {
			if r := judgeSchemaText(*text); r != nil {
				return nil, fmt.Errorf("an input schema: %v", r)
			}
			root, err := decodeWritten([]byte(*text))
			if err != nil {
				return nil, err
			}
			t.schema = root
			together += len(*text)
		}
		if t.description != nil {
			together += len(*t.description)
		}
		served.tools[tool] = t
	}
	// Each within its own limit, and together within theirs.
	if together > maxCandidateTextBytes {
		return nil, fmt.Errorf("its descriptions and schemas are %d bytes together, over %d", together, maxCandidateTextBytes)
	}
	return served, nil
}

// buildListing is the whole tools/list answer's tools, each platform
// served from its snapshot while the answer, serialized, stays within
// listingBound: past that, platforms' snapshots are dropped whole, in
// reverse table order, until it fits, and dropped says which, in the
// order dropped. Should it pass the bound with every snapshot dropped,
// the start is refused.
//
// Nothing past the bound is built. Each tool's entry is serialized as it
// is sent, and the answer's size counted from the entries: first each
// without a snapshot, then platform by platform in table order each with
// its snapshot, its description built only as far as the room left. The
// entries counted are the entries sent. A tool described
// from a snapshot is never shorter than described without one (the
// provenance sentence and the fence outweigh the sentence they replace,
// and a projection holds at least the open schema), so the answer only
// grows as platforms are kept: the platforms kept are the longest run from
// the table's start that fits, which is what dropping from its end until
// it fits leaves.
func buildListing(order []string, tools map[string]mcpTool, platforms []platformConfig, served map[string]*servedPlatform) ([]json.RawMessage, []string, error) {
	total, err := listingSize(nil)
	if err != nil {
		return nil, nil, err
	}
	entries := make(map[string]json.RawMessage, len(order))
	for i, name := range order {
		entry, err := listingEntry(tools[name], nil, -1)
		if err != nil {
			return nil, nil, err
		}
		entries[name] = entry
		total += len(entry)
		if i > 0 {
			total++
		}
	}
	if total > listingBound {
		return nil, nil, fmt.Errorf("the tool listing is %d bytes with every snapshot dropped, over %d", total, listingBound)
	}
	byPlatform := map[string][]string{}
	for _, name := range order {
		if t := tools[name]; !t.seal {
			byPlatform[t.platform] = append(byPlatform[t.platform], name)
		}
	}
	var dropped []string
	full := false
	for _, p := range platforms {
		sp := served[p.name]
		if sp == nil {
			continue
		}
		if !full {
			grown, described := 0, map[string]json.RawMessage{}
			for _, name := range byPlatform[p.name] {
				room := listingBound - total - grown + len(entries[name])
				entry, err := listingEntry(tools[name], sp, room)
				if err != nil {
					return nil, nil, err
				}
				if entry == nil {
					full = true
					break
				}
				described[name] = entry
				grown += len(entry) - len(entries[name])
			}
			if !full {
				for name, entry := range described {
					entries[name] = entry
				}
				total += grown
				continue
			}
		}
		dropped = append([]string{p.name}, dropped...)
	}
	list := make([]json.RawMessage, len(order))
	for i, name := range order {
		list[i] = entries[name]
	}
	return list, dropped, nil
}

// listingEntry is a tool's entry in the listing, serialized as it is sent,
// or nil should it pass limit bytes (a negative limit is none): its
// description is built no further than limit.
func listingEntry(t mcpTool, p *servedPlatform, limit int) (json.RawMessage, error) {
	var entry map[string]any
	if t.seal {
		entry = map[string]any{
			"name":        t.name,
			"description": "Seal a receipt session at its final count, so it can be verified. Takes the session name; answers the seal record. A session with an acquisition still in flight is refused by the engine.",
			"inputSchema": map[string]any{"type": "object", "properties": map[string]any{"session": map[string]any{"type": "string"}}, "required": []string{"session"}, "additionalProperties": false},
		}
	} else {
		description, ok := describePlatformToolWithin(t, p, limit)
		if !ok {
			return nil, nil
		}
		entry = map[string]any{"name": t.name, "description": description, "inputSchema": servedSchema(t, p)}
	}
	out, err := json.Marshal(entry)
	if err != nil || (limit >= 0 && len(out) > limit) {
		return nil, err
	}
	return out, nil
}

// listingIDBytes is the most an id may take in an answer: written in at
// most mcpMaxIDBytes, and written back with HTML escaping, which turns a
// byte into as many as six (<, > and & become \u003c, \u003e, \u0026).
const listingIDBytes = 6 * mcpMaxIDBytes

// listingSize is the tools/list answer as it is sent, with an id as long
// as an answer can carry one.
func listingSize(list []json.RawMessage) (int, error) {
	if list == nil {
		list = []json.RawMessage{}
	}
	out, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": json.RawMessage(strings.Repeat("9", listingIDBytes)), "result": map[string]any{"tools": list}})
	return len(out), err
}
