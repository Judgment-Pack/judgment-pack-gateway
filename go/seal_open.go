package main

// `gateway seal-open` (gateway #395; SPEC.md §3c): a session an earlier
// process left open, sealed after the interruption, the gateway stopped. The
// gateway that minted a session holds its count and its chain in memory and
// seals from them; one that stopped by a signal or a crash leaves the session
// with receipts and no seal (open_sessions.go). A seal of §3's form says the
// count is the minting process's own, so it is never made from the store. A
// seal made after an interruption says the count is the store's: it names
// the receipts found and the signature of the last of them, signed by the key
// in force, and only seals -- a session so sealed is never continued, and is
// sealed in the registry to /acquire, /seal and /act alike.
//
// What may be sealed is what gateway verify observes session-open: a session
// no seal closes, holding receipts every one of which passes the ladder, in
// sequence and chained, under the keys the registry's walk reaches. A session
// that is not so -- a receipt torn, missing, misfiled or out of its chain --
// is refused with what verification finds of it, and left as it is. A receipt
// is staged to a file of its own and linked into place whole (store_fs.go),
// so an interrupted write leaves a staging file, never a torn receipt: the
// staging file is no receipt, is not counted, and is left where it is.
// Nothing is deleted.
//
// The registry is held as a gateway holds it while it serves
// (holdEngineRegistry), so a running gateway refuses the command, as it
// refuses gateway rotate-key; a rotation under way beside the seed, and a
// registry whose walk ends at another key, are refused under the lock; and
// the store and the registry are read, and the seals appended, under it.
// The same sealing is what the start does with the switch on
// (sealOpenAtStart, --seal-open-at-start), under the lock the gateway holds,
// before it serves.

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const sealOpenUsage = `usage: gateway seal-open (--config <engine.json> | --store <dir> --seed <file> --registry <file> --authority <authority>) (--session <id> | --all)
Seals, the gateway stopped, a session an earlier process left open: one no
seal closes whose receipts gateway verify finds every one whole, in sequence
and chained. The seal says it was made after an interruption, over the
receipts the store holds (SPEC.md §3c); such a session is never continued.
--all seals each such session in the store, and names each one that is not
whole, which stays as it is. Prints each seal appended, as its registry line.
Nothing is deleted.`

// sealOpenTarget is a session found whole and unsealed: its count and the
// signature of its last receipt.
type sealOpenTarget struct {
	sessionID string
	count     int64
	head      string
}

// sealOpenRead is a session that could not be read: no answer, so nothing is
// sealed.
type sealOpenRead struct {
	sessionID string
	err       error
}

func (e sealOpenRead) Error() string {
	return fmt.Sprintf("session %s could not be read, and nothing was sealed: %v", e.sessionID, e.err)
}

// sealOpenJudge is what may be done with one session: a target to seal, a
// refusal, or neither (a session --all passes over: sealed, or holding no
// receipt); an error is a session that could not be read.
func sealOpenJudge(storeRoot, authority string, walk *registryWalk, sessionID string, named bool) (*sealOpenTarget, string, error) {
	// a directory --all meets that no session id names is no session of
	// a gateway's (SPEC.md §3a)
	if requireSession(sessionID) != nil {
		return nil, fmt.Sprintf("the store's directory %q is not named as a session is (SPEC.md §3a); it is not sealed", sessionID), nil
	}
	if _, sealed := walk.seals[sessionID]; sealed {
		if named {
			return nil, fmt.Sprintf("session %s is sealed in the registry; it is not sealed again", sessionID), nil
		}
		return nil, "", nil
	}
	info, err := os.Lstat(filepath.Join(storeRoot, "receipts", sessionID))
	switch {
	case err != nil && absent(err):
		return nil, fmt.Sprintf("session %s is not in the store", sessionID), nil
	case err != nil:
		return nil, "", sealOpenRead{sessionID, err}
	case !info.IsDir():
		return nil, fmt.Sprintf("session %s is in the store as something other than a session directory; nothing is sealed there", sessionID), nil
	}
	result, err := verifySessionUnder(storeRoot, sessionID, authority, walk.keys)
	if err != nil {
		return nil, "", sealOpenRead{sessionID, err}
	}
	if result.count == 0 {
		if named {
			return nil, fmt.Sprintf("session %s holds no receipt; there is nothing to seal", sessionID), nil
		}
		return nil, "", nil
	}
	if !result.whole {
		var found []string
		for _, f := range result.findings {
			switch file, ci := f["file"], f["callIndex"]; {
			case f["status"] == "ok":
			case file != nil:
				found = append(found, fmt.Sprintf("file %v %v", file, f["status"]))
			case ci != nil:
				found = append(found, fmt.Sprintf("receipt %v %v", ci, f["status"]))
			default:
				found = append(found, fmt.Sprint(f["status"]))
			}
		}
		return nil, fmt.Sprintf("session %s is not whole, so it is not sealed: %s; gateway verify reports what it finds of it, and nothing is changed or deleted", sessionID, strings.Join(found, ", ")), nil
	}
	// a receipt the ladder passes holds its signature as 128 lowercase
	// hexadecimal characters, which is what the seal names
	head := result.signatures[strconv.FormatInt(result.count-1, 10)]
	return &sealOpenTarget{sessionID: sessionID, count: result.count, head: head}, "", nil
}

// sealOpenUnder seals what may be sealed -- the session named, or with ""
// every session in the store -- with the registry locked and data read under
// the lock. Every session is judged before a seal is appended, and a session
// that could not be read stops it all with nothing appended. It answers the
// seals appended, in order, and the refusals; a seal whose append fails ends
// it, the seals before it standing.
func sealOpenUnder(storeRoot, authority string, writer *registryWriter, data []byte, session, via string, stamp func() string) ([]*vObject, []string, error) {
	walk, err := engineWalk(data, writer.priv.Public().(ed25519.PublicKey))
	if err != nil {
		return nil, nil, err
	}
	names := []string{session}
	if session == "" {
		if names, err = listSessions(storeRoot); err != nil {
			return nil, nil, fmt.Errorf("the store's sessions could not be read, and nothing was sealed: %v", err)
		}
	} else if err := requireSession(session); err != nil {
		return nil, nil, err
	}
	var targets []sealOpenTarget
	var refused []string
	for _, name := range names {
		target, refusal, err := sealOpenJudge(storeRoot, authority, walk, name, session != "")
		if err != nil {
			return nil, nil, err
		}
		if refusal != "" {
			refused = append(refused, refusal)
		}
		if target != nil {
			targets = append(targets, *target)
		}
	}
	var sealed []*vObject
	for _, t := range targets {
		record, err := writer.sealAfterInterruption(t.sessionID, t.count, t.head, stamp(), via)
		if err != nil {
			return sealed, refused, fmt.Errorf("session %s: %w", t.sessionID, err)
		}
		sealed = append(sealed, record)
	}
	return sealed, refused, nil
}

// sealOpenAtStart is the switch at a gateway's start (sealOpenAtStart,
// --seal-open-at-start): the registry held, before anything is served, each
// session an earlier process left open whose receipts are whole is sealed
// after the interruption, sealedVia start, and said on stderr as its
// registry line. A session that is not whole, or a directory no session id
// names, is named there and left as it is, open, as it is with the switch
// off. A session that cannot be read, or a seal that cannot be appended,
// stops the start: what was left open is not known, or not all sealed.
func sealOpenAtStart(service *gatewayService, stderr io.Writer, stamp func() string) error {
	data, present, err := readRegistryBytes(service.regPath)
	if err != nil {
		return fmt.Errorf("registry: %w", err)
	}
	if !present {
		return fmt.Errorf("the registry the engine made at its start is not there: %s", service.regPath)
	}
	sealed, refused, err := sealOpenUnder(service.storeRoot, service.authority, service.registry, data, "", sealedViaStart, stamp)
	for _, record := range sealed {
		fmt.Fprintf(stderr, "start: sealed after an interruption: %s\n", canon(record))
	}
	for _, refusal := range refused {
		fmt.Fprintf(stderr, "start: %s\n", refusal)
	}
	if err != nil {
		return fmt.Errorf("sealing the sessions left open: %w; the gateway does not start", err)
	}
	return nil
}

// sealOpenOptions is the command line: the store, the seed by each name it
// is known by, the registry, the authority, and the session or all of them.
type sealOpenOptions struct {
	store, registry, authority, session string
	seedNames                           []string
}

func parseSealOpen(args []string) (sealOpenOptions, string) {
	flags := map[string]string{}
	all := false
	for rest := args; len(rest) > 0; {
		name := rest[0]
		if name == "--all" {
			if all {
				return sealOpenOptions{}, "--all is given twice"
			}
			all, rest = true, rest[1:]
			continue
		}
		switch name {
		case "--config", "--store", "--seed", "--registry", "--authority", "--session":
		default:
			return sealOpenOptions{}, ""
		}
		if len(rest) < 2 || rest[1] == "" {
			return sealOpenOptions{}, ""
		}
		if _, given := flags[name]; given {
			return sealOpenOptions{}, name + " is given twice"
		}
		flags[name] = rest[1]
		rest = rest[2:]
	}
	if all == (flags["--session"] != "") {
		return sealOpenOptions{}, ""
	}
	o := sealOpenOptions{session: flags["--session"]}
	if config := flags["--config"]; config != "" {
		for _, other := range []string{"--store", "--seed", "--registry", "--authority"} {
			if flags[other] != "" {
				return sealOpenOptions{}, "--config names the store, the seed, the registry and the authority; " + other + " is not given beside it"
			}
		}
		data, err := readBounded(config, maxEngineConfigBytes)
		if err != nil {
			return sealOpenOptions{}, fmt.Sprintf("engine configuration: %v", err)
		}
		cfg, err := parseEngineConfig(data)
		if err != nil {
			return sealOpenOptions{}, err.Error()
		}
		o.store, o.registry, o.authority, o.seedNames = cfg.store, cfg.registry, cfg.authority, []string{cfg.seed}
		// the seed by the name it resolves to as well, as serve --config
		// looks for a rotation under way beside both
		if resolved, err := filepath.EvalSymlinks(cfg.seed); err == nil && resolved != cfg.seed {
			o.seedNames = append(o.seedNames, resolved)
		}
		return o, "ok"
	}
	for _, need := range []string{"--store", "--seed", "--registry", "--authority"} {
		if flags[need] == "" {
			return sealOpenOptions{}, ""
		}
	}
	o.store, o.registry, o.authority, o.seedNames = flags["--store"], flags["--registry"], flags["--authority"], []string{flags["--seed"]}
	return o, "ok"
}

func cmdSealOpen(args []string, stdout, stderr io.Writer) int {
	return cmdSealOpenAt(args, stdout, stderr, nowStamp)
}

// cmdSealOpenAt is the command, each seal stamped by stamp.
func cmdSealOpenAt(args []string, stdout, stderr io.Writer, stamp func() string) int {
	o, msg := parseSealOpen(args)
	switch msg {
	case "ok":
	case "":
		fmt.Fprintln(stderr, sealOpenUsage)
		return 2
	default:
		fmt.Fprintf(stderr, "seal-open: %s\n%s\n", msg, sealOpenUsage)
		return 2
	}
	sealed, refused, unlocked, err := sealOpen(o, stamp)
	for _, record := range sealed {
		fmt.Fprintf(stdout, "%s\n", canon(record))
	}
	for _, refusal := range refused {
		fmt.Fprintln(stderr, "seal-open:", refusal)
	}
	if unlocked {
		fmt.Fprintln(stderr, "seal-open: this platform locks no registry, so a gateway still running was not looked for; the gateway was to be stopped")
	}
	if err != nil {
		fmt.Fprintln(stderr, "seal-open:", err)
		return 1
	}
	if len(refused) > 0 {
		return 1
	}
	if len(sealed) == 0 {
		fmt.Fprintln(stderr, "seal-open: no session in the store is left open; nothing was sealed")
	}
	return 0
}

// sealOpen is the command: the seed read, the registry there, and held as
// a gateway holds it while it runs (holdEngineRegistry) -- no rotation under
// way beside the seed, and the registry's walk ending at the seed's key,
// both seen again under the lock -- and what may be sealed sealed under it.
// unlocked is a platform that locks no registry.
func sealOpen(o sealOpenOptions, stamp func() string) (sealed []*vObject, refused []string, unlocked bool, err error) {
	seed, err := loadSeed(o.seedNames[0])
	if err != nil {
		return nil, nil, false, fmt.Errorf("seed: %w", err)
	}
	absentRegistry := fmt.Errorf("the registry is not there: %s; a gateway makes it when it starts, and a seal is recorded in it", o.registry)
	if _, present, err := readRegistryBytes(o.registry); err != nil {
		return nil, nil, false, fmt.Errorf("registry: %w", err)
	} else if !present {
		return nil, nil, false, absentRegistry
	}
	hold, err := holdEngineRegistry(o.seedNames, o.registry, seed)
	if err != nil {
		if errors.Is(err, errRegistryHeld) {
			return nil, nil, false, fmt.Errorf("%w; stop the gateway, then seal", err)
		}
		return nil, nil, false, err
	}
	defer hold.Close()
	unlocked = !registryLocked
	data, present, err := readRegistryBytes(o.registry)
	if err != nil {
		return nil, nil, unlocked, fmt.Errorf("registry: %w", err)
	}
	if !present {
		return nil, nil, unlocked, absentRegistry
	}
	writer, err := newRegistryWriter(o.registry, seed, func() (bool, error) { return true, nil })
	if err != nil {
		return nil, nil, unlocked, err
	}
	sealed, refused, err = sealOpenUnder(o.store, o.authority, writer, data, o.session, sealedViaCommand, stamp)
	return sealed, refused, unlocked, err
}
