package main

// The engine configuration's `witness` member (docs/adr/0013-checkpoint-
// witness.md §4, "Configuration"; docs/design/engine-config.md): where a
// witness keeps its log and its marks, how a trail is registered, who may
// submit, and the bounds on each submitter. A configuration that carries it
// makes the signer a witness, and its endpoints the signer's.

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"unicode/utf8"
)

// witnessSpec is the `witness` member as written.
type witnessSpec struct {
	paths witnessPaths
	// firstSubmission is registration "first-submission"; false is
	// "operator", the default.
	firstSubmission bool
	// submitters are the pairs allowed to submit at all, when the member
	// was given (submittersGiven), even empty; absent, any subject the
	// configured issuer's tokens name may submit.
	submitters           []submitterKey
	submittersGiven      bool
	trailsPerSubmitter   int
	submissionsPerMinute int
}

var witnessMembers = map[string]bool{
	"log": true, "marks": true, "registration": false, "submitters": false,
	"trailsPerSubmitter": false, "submissionsPerMinute": false,
}

// witnessBounds are the two bounds' defaults and ranges (ADR-0013 §4), on
// the precedent of the MCP server's.
var witnessBounds = []struct {
	name          string
	def, min, max int
	into          func(*witnessSpec) *int
}{
	{"trailsPerSubmitter", 100, 1, 100000, func(w *witnessSpec) *int { return &w.trailsPerSubmitter }},
	{"submissionsPerMinute", 60, 1, 6000, func(w *witnessSpec) *int { return &w.submissionsPerMinute }},
}

// parseWitnessConfig holds the `witness` member to its shape: a closed
// object; the log and the marks absolute, clean paths, the marks neither the
// log nor a file kept beside it; registration "operator" or
// "first-submission"; each submitter a closed {issuer, subject} of the
// configured issuer, none given twice; and the bounds within their ranges.
func parseWitnessConfig(v value, issuer string) (*witnessSpec, error) {
	obj, err := requireObject(v, "witness")
	if err != nil {
		return nil, err
	}
	if err := exactlyMembers(obj, witnessMembers, "witness"); err != nil {
		return nil, err
	}
	w := &witnessSpec{}
	if w.paths.log, err = requireAbsolutePath(obj, "log"); err != nil {
		return nil, fmt.Errorf("witness.%v", err)
	}
	if w.paths.marks, err = requireAbsolutePath(obj, "marks"); err != nil {
		return nil, fmt.Errorf("witness.%v", err)
	}
	if err := w.paths.check(); err != nil {
		return nil, err
	}
	if _, present := obj.get("registration"); present {
		mode, err := requireString(obj, "registration")
		switch {
		case err != nil:
			return nil, errors.New(`witness.registration must be "operator" or "first-submission"`)
		case mode == "first-submission":
			w.firstSubmission = true
		case mode != "operator":
			return nil, fmt.Errorf(`witness.registration %q is not "operator" or "first-submission"`, requestText(mode))
		}
	}
	if submittersValue, present := obj.get("submitters"); present {
		list, ok := submittersValue.(vArray)
		if !ok {
			return nil, errors.New("witness.submitters must be an array of {issuer, subject}")
		}
		// present and empty is a statement: no subject may submit, and the
		// witness only serves what it holds
		w.submittersGiven = true
		seen := map[submitterKey]bool{}
		for i, item := range list {
			pair, ok := item.(*vObject)
			if !ok {
				return nil, fmt.Errorf("witness.submitters[%d] must be an object {issuer, subject}", i)
			}
			if err := exactlyMembers(pair, map[string]bool{"issuer": true, "subject": true}, fmt.Sprintf("witness.submitters[%d]", i)); err != nil {
				return nil, err
			}
			var key submitterKey
			if key.issuer, err = requireString(pair, "issuer"); err != nil || key.issuer == "" {
				return nil, fmt.Errorf("witness.submitters[%d].issuer must be a non-empty string", i)
			}
			if key.subject, err = requireString(pair, "subject"); err != nil || key.subject == "" || !utf8.ValidString(key.subject) {
				return nil, fmt.Errorf("witness.submitters[%d].subject must be a non-empty string", i)
			}
			// A pair of another issuer is one no token this engine
			// accepts can name: an allowance that allows nobody.
			if key.issuer != issuer {
				return nil, fmt.Errorf("witness.submitters[%d] names issuer %q, which is not identity.issuer; this engine accepts tokens of that issuer alone", i, requestText(key.issuer))
			}
			if seen[key] {
				return nil, fmt.Errorf("witness.submitters[%d] names subject %q again", i, requestText(key.subject))
			}
			seen[key] = true
			w.submitters = append(w.submitters, key)
		}
	}
	for _, b := range witnessBounds {
		*b.into(w) = b.def
		n, present, err := integerMember(obj, b.name)
		if err != nil {
			return nil, fmt.Errorf("witness.%s must be an integer", b.name)
		}
		if !present {
			continue
		}
		if n < int64(b.min) || n > int64(b.max) {
			return nil, fmt.Errorf("witness.%s %d is outside %d to %d", b.name, n, b.min, b.max)
		}
		*b.into(w) = int(n)
	}
	return w, nil
}

// files are the witness's files by what they are, in the order a refusal
// names them: the log, the registrations and the set-aside file beside it,
// and the marks.
func (w *witnessSpec) files() [][2]string {
	return [][2]string{
		{"witness.log", w.paths.log},
		{"the witness's registrations", w.paths.log + registrationsSuffix},
		{"the witness's set-aside file", w.paths.log + setAsideSuffix},
		{"witness.marks", w.paths.marks},
	}
}

// apart is why a witness's files would be another file of the engine's, or
// nil: none is the seed or the registry, and none is in the store or the
// decision-record directory, which are written and read as other things.
func (w *witnessSpec) apart(cfg engineConfig) error {
	for _, file := range w.files() {
		for _, other := range [][2]string{{"seed", cfg.seed}, {"registry", cfg.registry}} {
			if file[1] == other[1] {
				return fmt.Errorf("%s %s is the %s", file[0], file[1], other[0])
			}
		}
		for _, dir := range [][2]string{{"store", cfg.store}, {"decisionRecords", cfg.decisionRecords}} {
			if file[1] == dir[1] || strings.HasPrefix(file[1], dir[1]+string(filepath.Separator)) {
				return fmt.Errorf("%s %s is in the %s %s; a witness keeps its files apart from the engine's other files", file[0], file[1], dir[0], dir[1])
			}
		}
	}
	return nil
}

// witnessRefusals are the conditions under which an engine with a witness
// does not start, beside its own: a platform where a witness keeps no
// files; and marks on the log's own device, which the ADR keeps on storage
// apart from the log's -- another device or volume -- so that a log
// restored from a backup is judged against marks no backup of the log's
// storage restored. A device apart is not proof of storage apart: two
// devices may share a disk, and a backup may take both; the check refuses
// only what is plainly one storage.
func witnessRefusals(w *witnessSpec, host engineHost) error {
	if !witnessFilesKept {
		return errWitnessFilesNotKept
	}
	if host.device == nil {
		return nil
	}
	logDir, marksDir := filepath.Dir(w.paths.log), filepath.Dir(w.paths.marks)
	logDevice, err := host.device(logDir)
	if err != nil {
		return fmt.Errorf("witness.log: its directory %s: %v", logDir, err)
	}
	marksDevice, err := host.device(marksDir)
	if err != nil {
		return fmt.Errorf("witness.marks: its directory %s: %v", marksDir, err)
	}
	if logDevice == marksDevice {
		return fmt.Errorf("witness.marks: its directory %s is on the device of the log's directory %s; the marks are kept on storage apart from the log's, another device or volume, so that a restored log is judged against marks no backup of the log's storage restored", marksDir, logDir)
	}
	return nil
}
