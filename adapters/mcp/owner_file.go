package mcp

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"

	"adapters/internal/canon"
)

// Read once through a held directory/file. No later reopen can change accepted bytes.
func readImmutableEvidence(path string, bound int) ([]byte, error) {
	parent := filepath.Dir(path)
	before, err := os.Lstat(parent)
	if err != nil {
		return nil, err
	}
	if !before.IsDir() || before.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("evidence parent is not a direct directory")
	}
	root, err := os.OpenRoot(parent)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	opened, err := root.Stat(".")
	if err != nil {
		return nil, err
	}
	after, err := os.Lstat(parent)
	if err != nil || !os.SameFile(before, opened) || !os.SameFile(after, opened) || after.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("evidence directory changed")
	}
	name := filepath.Base(path)
	entry, err := root.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !entry.Mode().IsRegular() || entry.Mode()&os.ModeSymlink != 0 || entry.Mode().Perm()&0o022 != 0 {
		return nil, errors.New("evidence is not an immutable regular file")
	}
	file, err := root.Open(name)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	again, err := root.Lstat(name)
	if err != nil || !os.SameFile(entry, info) || !os.SameFile(again, info) || again.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("evidence file changed")
	}
	raw, err := io.ReadAll(io.LimitReader(file, int64(bound)+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > bound {
		return nil, errors.New("evidence exceeds snapshot bound")
	}
	return raw, nil
}

func (cfg Config) withOwnerDeclaration() (Config, error) {
	if cfg.OwnerDeclarationFile == "" || cfg.ownerDeclarationLoaded {
		return cfg, nil
	}
	if err := cfg.ownerRefusal(); err != nil {
		return cfg, err
	}
	expected := DescriptorTarget{Platform: cfg.ApprovedPlatform, Binding: cfg.ApprovedBinding, Operation: cfg.ApprovedOperation}
	if cfg.Descriptors != nil {
		expected = *cfg.Descriptors
	}
	if expected.refusal() != nil || (expected.Operation != "live" && expected.Operation != "write") {
		return cfg, errors.New("owner declaration requires a trusted exact source context")
	}
	raw, err := readImmutableEvidence(cfg.OwnerDeclarationFile, MaxOwnerDeclarationBytes)
	if err != nil {
		return cfg, err
	}
	sum := sha256.Sum256(raw)
	if "sha256:"+hex.EncodeToString(sum[:]) != cfg.OwnerDeclarationPin {
		return cfg, errors.New("owner declaration digest changed")
	}
	canonical, err := canon.Canonicalize(raw, canon.RefuseNumbers)
	if err != nil || !bytes.Equal(raw, canonical) {
		return cfg, errors.New("owner declaration is not canonical")
	}
	members, err := exactMembers(raw)
	if err != nil || len(members) != 5 {
		return cfg, errors.New("unsupported owner declaration shape")
	}
	for key, want := range map[string]string{"declarationVersion": "1", "platform": expected.Platform, "binding": expected.Binding, "operation": expected.Operation} {
		var got string
		if len(members[key]) == 0 || members[key][0] != '"' || json.Unmarshal(members[key], &got) != nil || got != want {
			return cfg, errors.New("owner declaration identity differs")
		}
	}
	entries, err := exactMembers(members["tools"])
	if err != nil || len(entries) == 0 {
		return cfg, errors.New("missing owner declarations")
	}
	cfg.ToolTaxonomies = map[string]ToolTaxonomy{}
	for name, raw := range entries {
		owner, err := decodeTaxonomy(raw)
		if err != nil || !owner.External() {
			return cfg, errors.New("invalid external owner declaration")
		}
		cfg.ToolTaxonomies[name] = owner
	}
	cfg.ownerDeclarationLoaded = true
	return cfg, cfg.ownerRefusal()
}
