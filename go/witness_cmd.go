package main

// `gateway witness`: a witness's log checked offline, by anyone holding a
// copy of it and the witness's public key (`verify`); and the witness's
// operator's three acts on its files, each under the engine configuration
// that makes the signer a witness (`register`, `retire`, `repair`;
// docs/adr/0013-checkpoint-witness.md §4, "Registration", "What the witness
// stores" and "Start-up, and repair").
//
// The three acts take the files as the witness takes them: each locked by
// what it is, through its own descriptor, before a byte of it is read, with
// exactly one name (witnessFiles.hold). A witness running holds them for as
// long as it runs, so an act on a running witness refuses, says so, and
// changes nothing; the witness is stopped for it and started again after.

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

const witnessUsage = `usage:
  gateway witness verify --log <file> --public-key <file> [--marks <file>]
  gateway witness register --config <engine.json> --trail <id> --issuer <issuer> --subject <subject>
  gateway witness retire --config <engine.json> --trail <id>
  gateway witness repair --config <engine.json>`

// witnessCommands are the flags each subcommand takes, and whether each is
// required.
var witnessCommands = map[string]map[string]bool{
	"verify":   {"--log": true, "--public-key": true, "--marks": false},
	"register": {"--config": true, "--trail": true, "--issuer": true, "--subject": true},
	"retire":   {"--config": true, "--trail": true},
	"repair":   {"--config": true},
}

func cmdWitness(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || witnessCommands[args[0]] == nil {
		fmt.Fprintln(stderr, witnessUsage)
		return 2
	}
	allowed := witnessCommands[args[0]]
	flags := map[string]string{}
	for rest := args[1:]; len(rest) > 0; rest = rest[2:] {
		name := rest[0]
		if _, known := allowed[name]; !known || len(rest) < 2 || rest[1] == "" {
			fmt.Fprintln(stderr, witnessUsage)
			return 2
		}
		if _, given := flags[name]; given {
			fmt.Fprintf(stderr, "%s is given twice\n%s\n", name, witnessUsage)
			return 2
		}
		flags[name] = rest[1]
	}
	for name, required := range allowed {
		if required && flags[name] == "" {
			fmt.Fprintln(stderr, witnessUsage)
			return 2
		}
	}
	if trail, given := flags["--trail"]; given && !isLowerHexOfLen(trail, 32) {
		fmt.Fprintf(stderr, "a trail is 32 lowercase hexadecimal characters\n%s\n", witnessUsage)
		return 2
	}
	switch args[0] {
	case "register":
		return witnessRegister(flags, stdout, stderr)
	case "retire":
		return witnessRetire(flags, stdout, stderr)
	case "repair":
		return witnessRepair(flags, stdout, stderr)
	}
	out, err := witnessVerify(flags["--log"], flags["--public-key"], flags["--marks"])
	if err != nil {
		// no verdict could be reached
		fmt.Fprintln(stderr, "witness verify:", err)
		return 1
	}
	stdout.Write(append(out, '\n'))
	return 0
}

// witnessVerifyReport is the verdict, as `gateway verify` gives its own in
// its JSON (SPEC.md §5a.2): ok exactly when the checks found nothing. With
// the marks, outcome is what the witness's start-up would do with these two
// files; without them, null.
type witnessVerifyReport struct {
	OK         bool             `json:"ok"`
	Findings   []witnessFinding `json:"findings"`
	Outcome    *string          `json:"outcome"`
	Statements int64            `json:"statements"`
}

// witnessVerify applies the witness's start-up checks to a copy of its log,
// all but the registrations: every complete line a statement in the bytes
// the witness writes, verifying under the key given; each trail's chain
// from index 0, contiguous and linked, by the chain rule; and the log
// ending cleanly. Given the marks, also that the log reaches every mark and
// that no statement but the log's last is unmarked, with the outcome the
// three rules of recovery give. A key the key rule refuses is answered as a
// reader answers it, {"refused": <reason>}, before the log is read.
//
// That shows a copy is internally consistent. It does not authenticate
// registrations, show that every trail or statement was kept, or show that
// the copy is the log the witness serves now.
func witnessVerify(logPath, keyPath, marksPath string) ([]byte, error) {
	key, err := readWitnessKeyFile(keyPath)
	if err != nil {
		return nil, err
	}
	if refusal := witnessKeyRefusal(key); refusal != "" {
		return json.Marshal(map[string]string{"refused": refusal})
	}
	log, err := openRegular(logPath)
	if err != nil {
		return nil, err
	}
	defer log.Close()
	in := witnessInput{log: log}
	if marksPath != "" {
		marks, err := openRegular(marksPath)
		if err != nil {
			return nil, err
		}
		defer marks.Close()
		in.marks, in.marksChecked = marks, true
	}
	j, err := judgeWitness(in, key)
	if err != nil {
		return nil, err
	}
	report := witnessVerifyReport{OK: len(j.findings) == 0, Findings: j.findings.list(), Statements: j.statements}
	if marksPath != "" {
		report.Outcome = &j.outcome
	}
	return json.Marshal(report)
}

// --- the operator's acts ------------------------------------------------------

// witnessEngineConfig reads the engine configuration an act names, held to
// the shape serve holds it to, and requires a witness in it. Nothing else
// in the file is resolved: no user is looked up and no binding read.
func witnessEngineConfig(path string) (engineConfig, error) {
	data, err := readBounded(path, maxEngineConfigBytes)
	if err != nil {
		return engineConfig{}, fmt.Errorf("engine configuration: %v", err)
	}
	cfg, err := parseEngineConfig(data)
	if err != nil {
		return engineConfig{}, err
	}
	if cfg.witness == nil {
		return engineConfig{}, fmt.Errorf("engine configuration %s has no witness member; a witness's files are named there", path)
	}
	return cfg, nil
}

// witnessConfigOf is how a witness under a configuration's member is opened,
// under the gateway's own seed (ADR-0013, question 6).
func witnessConfigOf(spec *witnessSpec, seed []byte) witnessConfig {
	public, sign := witnessSeedSigner(seed)
	return witnessConfig{paths: spec.paths, firstSubmission: spec.firstSubmission, publicKey: public, sign: sign, trailsPerSubmitter: spec.trailsPerSubmitter}
}

// openEngineWitness opens the witness a configuration's member names, as
// serve opens it: its start-up checks applied, nothing repaired.
func openEngineWitness(spec *witnessSpec, seed []byte) (*witnessLog, error) {
	return openWitnessLog(witnessConfigOf(spec, seed))
}

// witnessStartLine is what a witness says, once, when it starts.
func witnessStartLine(log *witnessLog, spec *witnessSpec) string {
	trails, statements := log.held()
	mode := "operator"
	if spec.firstSubmission {
		mode = "first-submission"
	}
	return fmt.Sprintf("witness: %d statements of %d trails under key %s; registration %s; its reads are open to anyone who names a trail", statements, trails, log.keyID, mode)
}

// witnessHeldSentence is what an act says when a running witness, or
// another act, holds the files.
const witnessHeldSentence = "a running witness, or another act on it, holds the witness's files: stop the witness and run this again; nothing was changed"

// witnessActFailed says why an act did nothing, or failed, on stderr.
func witnessActFailed(stderr io.Writer, act string, err error) int {
	if errors.Is(err, errWitnessHeld) {
		fmt.Fprintf(stderr, "witness %s: %s (%v)\n", act, witnessHeldSentence, err)
		return 1
	}
	fmt.Fprintf(stderr, "witness %s: %v\n", act, err)
	return 1
}

// witnessRegister registers a trail to the one issuer and subject that may
// submit for it, or changes its registration: the witness's operator's act,
// appended to the registrations and synced, recorded and never served. The
// issuer is the configured one, and the subject, when the configuration
// names the submitters, one of them: a registration no token could match
// is refused rather than kept.
func witnessRegister(flags map[string]string, stdout, stderr io.Writer) int {
	cfg, err := witnessEngineConfig(flags["--config"])
	if err != nil {
		return witnessActFailed(stderr, "register", err)
	}
	r := witnessRegistration{trail: flags["--trail"], issuer: flags["--issuer"], subject: flags["--subject"]}
	if r.issuer != cfg.identity.issuer {
		return witnessActFailed(stderr, "register", fmt.Errorf("the registration names issuer %q, and this engine takes tokens of identity.issuer %q alone, so no submission could match it; nothing was changed", requestText(r.issuer), requestText(cfg.identity.issuer)))
	}
	if cfg.witness.submittersGiven && !containsSubmitter(cfg.witness.submitters, submitterKey{r.issuer, r.subject}) {
		return witnessActFailed(stderr, "register", fmt.Errorf("subject %q is not among witness.submitters, so no submission of it is taken; nothing was changed", requestText(r.subject)))
	}
	if err := registerWitnessTrail(cfg.witness.paths, r, witnessIO{}); err != nil {
		return witnessActFailed(stderr, "register", err)
	}
	fmt.Fprintf(stdout, "registered trail %s to subject %q of issuer %q\n", r.trail, requestText(r.subject), requestText(r.issuer))
	return 0
}

func containsSubmitter(list []submitterKey, key submitterKey) bool {
	for _, k := range list {
		if k == key {
			return true
		}
	}
	return false
}

// witnessRetire signs a trail's retirement, the last statement of its
// chain, with the witness stopped: the files are held and checked as a
// start checks them, the retirement is signed, made durable and marked, and
// printed as its line. A trail retired already is answered with its
// retirement, and nothing is signed.
func witnessRetire(flags map[string]string, stdout, stderr io.Writer) int {
	cfg, err := witnessEngineConfig(flags["--config"])
	if err != nil {
		return witnessActFailed(stderr, "retire", err)
	}
	seed, err := loadSeed(cfg.seed)
	if err != nil {
		return witnessActFailed(stderr, "retire", fmt.Errorf("seed: %v", err))
	}
	log, err := openEngineWitness(cfg.witness, seed)
	if err != nil {
		return witnessActFailed(stderr, "retire", err)
	}
	defer log.close()
	answer, err := log.retire(flags["--trail"])
	if err != nil {
		return witnessActFailed(stderr, "retire", err)
	}
	if answer.kind == "retired" {
		fmt.Fprintln(stderr, "witness retire: the trail was retired already; nothing was signed")
	}
	stdout.Write(append(append([]byte(nil), answer.statements[0]...), '\n'))
	return 0
}

// witnessRepairReport is what a repair did: the outcome of the start-up
// checks it acted on, their findings, whether it wrote, and whether the
// witness starts now.
type witnessRepairReport struct {
	Outcome  string           `json:"outcome"`
	Findings []witnessFinding `json:"findings"`
	Repaired bool             `json:"repaired"`
	Starts   bool             `json:"starts"`
}

// witnessRepair does what the three rules of recovery allow and nothing
// else (repairWitnessLog), with the witness stopped, and says what it did
// in its JSON: exit 0 when the witness starts now, 1 when it does not --
// a log copy that passes the checks against the marks, or a new key, is
// then the operator's to put in place, and the explanation is on stderr.
func witnessRepair(flags map[string]string, stdout, stderr io.Writer) int {
	cfg, err := witnessEngineConfig(flags["--config"])
	if err != nil {
		return witnessActFailed(stderr, "repair", err)
	}
	seed, err := loadSeed(cfg.seed)
	if err != nil {
		return witnessActFailed(stderr, "repair", fmt.Errorf("seed: %v", err))
	}
	j, err := repairWitnessLog(witnessConfigOf(cfg.witness, seed))
	if err != nil {
		return witnessActFailed(stderr, "repair", err)
	}
	report := witnessRepairReport{Outcome: j.outcome, Findings: j.findings.list()}
	switch j.outcome {
	case outcomeStart:
		report.Starts = true
	case outcomeRefused, outcomeNewKey:
		fmt.Fprintln(stderr, "witness repair:", strings.TrimPrefix(witnessNotStarted{j}.Error(), "witness: "))
	default:
		report.Repaired, report.Starts = true, true
	}
	out, err := json.Marshal(report)
	if err != nil {
		return witnessActFailed(stderr, "repair", err)
	}
	stdout.Write(append(out, '\n'))
	if !report.Starts {
		return 1
	}
	return 0
}
