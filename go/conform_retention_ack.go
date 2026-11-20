package main

// The acknowledgment-line vectors (ADR-0053 §11), corpus/retention-ack/*.json:
// each an acknowledgedBy list, one line, and the answer gateway retain gives
// that line under it. No verifier reads an acknowledgment line, so they are
// run in process, with no process-contract command.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type retentionAckVector struct {
	Name string `json:"name"`
	Note string `json:"note"`
	// AcknowledgedBy is retention.acknowledgedBy, read as a version-40
	// configuration reads it (p256SignerVersion).
	AcknowledgedBy json.RawMessage `json:"acknowledgedBy"`
	Line           string          `json:"line"`
	// Expected is {"accepted": true} or {"refused": <why>}, why the
	// sentence retain gives after "acknowledgment line <n> ".
	Expected struct {
		Accepted bool   `json:"accepted"`
		Refused  string `json:"refused"`
	} `json:"expected"`
}

func retentionAckVectorPaths(corpusDir string) ([]string, error) {
	found, err := filepath.Glob(filepath.Join(corpusDir, "retention-ack", "*.json"))
	if err != nil {
		return nil, err
	}
	sort.Strings(found)
	return found, nil
}

// readRetentionAckVector reads one vector strictly: no member it does not
// name, none given twice, and exactly one of the two answers.
func readRetentionAckVector(path string) (retentionAckVector, error) {
	var vector retentionAckVector
	raw, err := os.ReadFile(path)
	if err != nil {
		return vector, err
	}
	if err := noMemberTwice(raw); err != nil {
		return vector, fmt.Errorf("%s: %v", path, err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&vector); err != nil {
		return vector, fmt.Errorf("%s: %v", path, err)
	}
	if dec.More() {
		return vector, fmt.Errorf("%s: more than one JSON value", path)
	}
	if vector.Name != strings.TrimSuffix(filepath.Base(path), ".json") {
		return vector, fmt.Errorf("%s: named %q", path, vector.Name)
	}
	if vector.Expected.Accepted == (vector.Expected.Refused != "") {
		return vector, fmt.Errorf("%s: expected is exactly one of accepted and refused", path)
	}
	return vector, nil
}

// runRetentionAckVectors holds gateway retain's reading of a line to every
// acknowledgment-line vector, and answers the disagreements and how many
// vectors it read.
func runRetentionAckVectors(corpusDir string) ([]string, int, error) {
	paths, err := retentionAckVectorPaths(corpusDir)
	if err != nil {
		return nil, 0, err
	}
	var failures []string
	for _, path := range paths {
		vector, err := readRetentionAckVector(path)
		if err != nil {
			return nil, 0, err
		}
		retention, err := parseJSON([]byte(`{"window":30,"acknowledgedBy":` + string(vector.AcknowledgedBy) + `}`))
		if err != nil {
			return nil, 0, fmt.Errorf("%s: acknowledgedBy: %v", path, err)
		}
		cfg, err := parseRetentionConfig(retention, p256SignerVersion)
		if err != nil {
			return nil, 0, fmt.Errorf("%s: %v", path, err)
		}
		_, why := retentionAckOf([]byte(vector.Line), cfg)
		switch {
		case vector.Expected.Accepted && why != "":
			failures = append(failures, fmt.Sprintf("retention-ack %s: expected accepted, refused: %s", vector.Name, why))
		case !vector.Expected.Accepted && why == "":
			failures = append(failures, fmt.Sprintf("retention-ack %s: expected refused %q, accepted", vector.Name, vector.Expected.Refused))
		case !vector.Expected.Accepted && why != vector.Expected.Refused:
			failures = append(failures, fmt.Sprintf("retention-ack %s: expected refused %q, refused: %s", vector.Name, vector.Expected.Refused, why))
		}
	}
	return failures, len(paths), nil
}
