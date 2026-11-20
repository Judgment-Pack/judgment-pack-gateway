package main

// A second, clean-room implementation of the judgment-pack gateway attestation
// format (receipt version 2), derived from SPEC.md and corpus/ alone.
//
// Subcommands:
//
//	gateway canon                                    < value.json
//	gateway verify [--ordinary-seals-only] [--artifacts <dir>] <store-root> <registry> <auth> [<decision-records>]  < publickey.raw
//	gateway export --config <engine.json> --out <dir> [--observations <file>]...
//	gateway export --check <dir>
//	gateway conform [--impl CMD] [--corpus DIR]
//	gateway adapter-conform --shape airbyte|mcp|http [--vectors DIR] [--env KEY[=VALUE]]... [--timeout SECONDS] [--max-output BYTES] [--json] ADAPTER-COMMAND
//	gateway witness verify --log <file> --public-key <file> [--marks <file>]
//	gateway witness register|retire|repair --config <engine.json> ...
//	gateway witness fetch --store <dir> --registry <file> ... --record <file> --trail <file> --runtime <path> --out <dir>
//	gateway serve <store> <seedfile> <authority> <registry> [--source NAME=CMD] [--source-shape NAME=SHAPE] [--receipt-version 2|3] [--listen ADDRESS [--accept-unauthenticated-callers]] [--port N]
//	gateway keygen [seedfile]
//	gateway rotate-key --seed <file> --registry <file>
//	gateway journal compact --store <dir> --archive <dir> --retention <duration>
//	gateway posture [--json] [--config <engine.json> | [serve] <store> <seedfile> <authority> <registry> [serve options]]
//	gateway publishers --config <engine.json> [--check] [--policy report|refuse]
//	gateway version

import (
	"cmp"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"
)

func main() {
	if refuseStrayAnchorMarker() {
		os.Exit(2)
	}
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: gateway canon | verify | export | conform | adapter-conform | witness | serve | connect | publishers | keygen | rotate-key | seal-open | remove-artifact | remove-scope | retain | journal | store | mcp | posture | version")
		os.Exit(2)
	}
	switch os.Args[1] {
	case "canon":
		os.Exit(cmdCanon())
	case "verify":
		os.Exit(cmdVerify(os.Args[2:]))
	case "export":
		os.Exit(cmdExport(os.Args[2:], os.Stdout, os.Stderr))
	case "conform":
		os.Exit(cmdConform(os.Args[2:]))
	case "adapter-conform":
		os.Exit(cmdAdapterConform(os.Args[2:]))
	case "witness":
		os.Exit(cmdWitness(os.Args[2:], os.Stdout, os.Stderr))
	case "serve":
		os.Exit(cmdServe(os.Args[2:]))
	case "connect":
		os.Exit(cmdConnect(os.Args[2:]))
	case "publishers":
		os.Exit(cmdPublishers(os.Args[2:], os.Stdout, os.Stderr))
	case "keygen":
		os.Exit(cmdKeygen(os.Args[2:]))
	case "rotate-key":
		os.Exit(cmdRotateKey(os.Args[2:], os.Stdout, os.Stderr))
	case "seal-open":
		os.Exit(cmdSealOpen(os.Args[2:], os.Stdout, os.Stderr))
	case "remove-artifact":
		os.Exit(cmdRemoveArtifact(os.Args[2:], os.Stdout, os.Stderr))
	case "retain":
		os.Exit(cmdRetain(os.Args[2:], os.Stdout, os.Stderr))
	case "remove-scope":
		os.Exit(cmdRemoveScope(os.Args[2:], os.Stdout, os.Stderr))
	case "journal":
		os.Exit(cmdJournal(os.Args[2:], os.Stdout, os.Stderr))
	case "store":
		os.Exit(cmdStore(os.Args[2:], os.Stdout, os.Stderr))
	case "mcp":
		os.Exit(cmdMCP(os.Args[2:]))
	case "posture":
		os.Exit(cmdPosture(os.Args[2:], os.Stdout, os.Stderr))
	case "version":
		os.Exit(cmdVersion(os.Stdout))
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand %q\n", os.Args[1])
		os.Exit(2)
	}
}

// refuseStrayAnchorMarker reports, and says why, when an internal marker --
// the anchor's or the posture probe's -- is present in the environment of an
// ordinary invocation. The marked modes themselves have already been taken
// by the init hooks in spawn_unix.go and posture_linux.go, which require the
// marker and the argument together; reaching main with a marker means the
// argument was absent, and refusing here keeps an inherited variable from
// turning a verify or a conform into a silent success.
func refuseStrayAnchorMarker() bool {
	for _, marker := range []string{envGroupAnchor, envPostureProbe} {
		if os.Getenv(marker) == "1" {
			fmt.Fprintf(os.Stderr, "refusing to run: %s is set, and it is an internal marker this process sets only for its own anchor or posture probe\n", marker)
			return true
		}
	}
	return false
}

// cmdVersion prints what initialize names as the server's version, so a
// released binary can be asked which release it is without a
// configuration to start it with.
func cmdVersion(w io.Writer) int {
	fmt.Fprintln(w, "gateway", buildVersion())
	return 0
}

func cmdCanon() int {
	text, err := io.ReadAll(os.Stdin)
	if err != nil {
		fmt.Fprintln(os.Stderr, "read stdin:", err)
		return 1
	}
	out, err := canonText(text)
	if err != nil {
		fmt.Fprintln(os.Stderr, "refused:", err)
		return 1
	}
	// Exactly the canonical bytes, with no trailing newline.
	if _, err := os.Stdout.Write(out); err != nil {
		fmt.Fprintln(os.Stderr, "write stdout:", err)
		return 1
	}
	return 0
}

func cmdVerify(args []string) int {
	const usage = "usage: gateway verify [--scope <identifier>] [--ordinary-seals-only] [--artifacts <dir>] [--previous <registry>] <store-root> <registry-path> <authority> [--decision-records <dir> | <dir>]"
	// --scope <identifier>, first or not at all: the verdict is cut by the
	// scope identifier (SPEC.md §4, "A verdict by scope"), and takes no
	// decision-record directory. In any later place it is a usage error,
	// as the other options are; a directory so named is given as ./--scope.
	scope := ""
	if len(args) > 0 && args[0] == "--scope" {
		if len(args) < 2 || !isScopeIdentifier(args[1]) {
			fmt.Fprintln(os.Stderr, "gateway verify: --scope names a scope identifier: "+scopeForm)
			fmt.Fprintln(os.Stderr, usage)
			return 2
		}
		scope, args = args[1], args[2:]
	}
	for _, a := range args {
		if a == "--scope" {
			fmt.Fprintln(os.Stderr, "gateway verify: --scope goes first, before every other option; a directory so named is given as ./--scope")
			fmt.Fprintln(os.Stderr, usage)
			return 2
		}
	}
	// --ordinary-seals-only, first or not at all: a session a seal made
	// after an interruption anchors is then a finding, not an observation
	// (SPEC.md §4 step 3). The option in any later place is a usage error,
	// never taken as an argument and the plain verdict run in its stead; a
	// directory of that spelling, in any place, is given as
	// ./--ordinary-seals-only.
	for i, a := range args {
		if i > 0 && a == "--ordinary-seals-only" {
			fmt.Fprintln(os.Stderr, "gateway verify: --ordinary-seals-only goes first, before the store root; a directory so named is given as ./--ordinary-seals-only")
			fmt.Fprintln(os.Stderr, usage)
			return 2
		}
	}
	ordinarySealsOnly := false
	if len(args) > 0 && args[0] == "--ordinary-seals-only" {
		ordinarySealsOnly, args = true, args[1:]
	}
	// --artifacts <dir>, the bytes a reader supplied (SPEC.md §4, "Supplied
	// bytes"): after --ordinary-seals-only, before the store root, or not at
	// all. In any later place it is a usage error, as that option is; a
	// directory of that spelling is given as ./--artifacts.
	supplied := ""
	if len(args) > 0 && args[0] == "--artifacts" {
		if len(args) < 2 || args[1] == "" {
			fmt.Fprintln(os.Stderr, usage)
			return 2
		}
		supplied, args = args[1], args[2:]
	}
	for _, a := range args {
		if a == "--artifacts" {
			fmt.Fprintln(os.Stderr, "gateway verify: --artifacts goes before the store root, after --ordinary-seals-only; a directory so named is given as ./--artifacts")
			fmt.Fprintln(os.Stderr, usage)
			return 2
		}
	}
	// --previous <registry>, the registry of the store before this one
	// (SPEC.md §3d): after --artifacts, before the store root, or not at
	// all; the verdict then holds the store continuation to that registry's
	// tail. In any later place it is a usage error, as the options before
	// it are; a directory of that spelling is given as ./--previous.
	previous := ""
	if len(args) > 0 && args[0] == "--previous" {
		if len(args) < 2 || args[1] == "" {
			fmt.Fprintln(os.Stderr, usage)
			return 2
		}
		previous, args = args[1], args[2:]
	}
	for _, a := range args {
		if a == "--previous" {
			fmt.Fprintln(os.Stderr, "gateway verify: --previous goes before the store root, after --artifacts; a directory so named is given as ./--previous")
			fmt.Fprintln(os.Stderr, usage)
			return 2
		}
	}
	if len(args) < 3 || len(args) > 5 {
		fmt.Fprintln(os.Stderr, usage)
		return 2
	}
	storeRoot, registryPath, authority := args[0], args[1], args[2]
	// The decision-record directory of SPEC.md §4 step 6: by flag, or as the
	// fourth positional argument the corpus process contract uses. Absent
	// means absent, and every version 3 action receipt then fails closed.
	// Precedence, stated: two extra arguments are the flag and its value;
	// one extra argument is the directory, whatever it is spelled -- a
	// directory named "--decision-records" is a directory, because the
	// process contract reserves no spelling; only an empty name is refused.
	decisionRecords := ""
	switch rest := args[3:]; len(rest) {
	case 0:
	case 1:
		if rest[0] == "" {
			fmt.Fprintln(os.Stderr, usage)
			return 2
		}
		decisionRecords = rest[0]
	case 2:
		if rest[0] != "--decision-records" || rest[1] == "" {
			fmt.Fprintln(os.Stderr, usage)
			return 2
		}
		decisionRecords = rest[1]
	}
	if scope != "" && decisionRecords != "" {
		fmt.Fprintln(os.Stderr, "gateway verify: a verdict by scope reads no decision records: an action receipt carries no scope")
		fmt.Fprintln(os.Stderr, usage)
		return 2
	}

	raw, err := io.ReadAll(os.Stdin)
	if err != nil {
		fmt.Fprintln(os.Stderr, "read public key from stdin:", err)
		return 1
	}
	publicKey, err := readPublicKey(raw)
	if err != nil {
		fmt.Fprintln(os.Stderr, "public key:", err)
		return 1
	}

	var verdict *report
	if scope != "" {
		verdict, err = verifyByScope(storeRoot, registryPath, authority, supplied, scope, publicKey, ordinarySealsOnly)
	} else {
		verdict, err = verifySupplied(storeRoot, registryPath, authority, decisionRecords, supplied, publicKey, ordinarySealsOnly)
	}
	if err == nil {
		err = linkPrevious(verdict, previous, publicKey)
	}
	if err != nil {
		// Could not produce a verdict at all.
		fmt.Fprintln(os.Stderr, "verify:", err)
		return 1
	}
	out, err := verdict.marshal()
	if err != nil {
		fmt.Fprintln(os.Stderr, "encode verdict:", err)
		return 1
	}
	os.Stdout.Write(out)
	os.Stdout.Write([]byte("\n"))
	return 0
}

// readPublicKey accepts the 32 raw bytes CONTRACT.md specifies. It also
// tolerates surrounding whitespace and a 64-character hex encoding, so that a
// key piped from a file such as corpus/TEST-PUBLIC-KEY still works: a stray
// trailing newline in a key file is a documented way this corpus has failed
// before, and it fails looking exactly like a format disagreement.
func readPublicKey(raw []byte) ([]byte, error) {
	if len(raw) == 32 {
		return raw, nil
	}
	trimmed := strings.TrimSpace(string(raw))
	if len(trimmed) == 32 {
		return []byte(trimmed), nil
	}
	if len(trimmed) == 64 {
		if b, err := hex.DecodeString(trimmed); err == nil {
			return b, nil
		}
	}
	return nil, fmt.Errorf("expected 32 raw bytes, got %d", len(raw))
}

// cmdKeygen writes a fresh 32-byte Ed25519 seed and reports the public key it
// implies, so an operator can pin that key out of band -- which SPEC.md §5 says
// is the only way the signature means anything.
func cmdKeygen(args []string) int {
	path := "gateway.seed"
	if len(args) > 0 {
		path = args[0]
	}
	seed := make([]byte, seedBytes)
	if _, err := rand.Read(seed); err != nil {
		fmt.Fprintln(os.Stderr, "generate seed:", err)
		return 1
	}
	if err := seedSecret(path).putSecret("seed", []byte(hex.EncodeToString(seed)+"\n")); err != nil {
		fmt.Fprintln(os.Stderr, "write seed:", err)
		return 1
	}
	// Derived from the bytes that were persisted, not from the bytes we meant
	// to persist. A short write or a filesystem that lied would otherwise print
	// a public key the operator pins out of band for a seed that is not there.
	persisted, err := readSeedFile(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "verify written seed:", err)
		return 1
	}
	public := ed25519.NewKeyFromSeed(persisted).Public().(ed25519.PublicKey)
	fmt.Printf("seed written to %s (keep it secret)\npublicKey %s\nkeyId     %s\n",
		path, hex.EncodeToString(public), keyIDFor(public))
	return 0
}

// closeInheritedDescriptors is what cmdServe calls before anything is opened.
// It is a variable so a test can observe that startup makes the call.
var closeInheritedDescriptors = markInheritedCloseOnExec

// maxSeedFileBytes bounds what loadSeed will read. A seed file is sixty-five
// bytes; the bound is generous to whitespace and refuses anything that is
// plainly not a seed file rather than reading its first page and ignoring
// the rest.
const maxSeedFileBytes = 4096

// loadSeed reads the seed as a secret value of the filesystem kind, which
// opens, judges and reads the file through one descriptor (openSeed), then
// accepts either the hex form keygen writes or 32 raw bytes.
func loadSeed(path string) ([]byte, error) {
	raw, err := seedSecret(path).getSecret("seed")
	if err != nil {
		return nil, err
	}
	if len(raw) > maxSeedFileBytes {
		return nil, fmt.Errorf("seed file is larger than a seed file can be (more than %d bytes)", maxSeedFileBytes)
	}
	seed := []byte(strings.TrimSpace(string(raw)))
	if len(seed) == 2*seedBytes {
		if decoded, err := hex.DecodeString(string(seed)); err == nil {
			seed = decoded
		}
	}
	// Judged here, where connect and serve both read it, so a seed that
	// is not one is refused before adapters are run or a store is made.
	if len(seed) != seedBytes {
		return nil, fmt.Errorf("seed file does not hold a %d-byte seed (%d bytes after decoding)", seedBytes, len(seed))
	}
	return seed, nil
}

// buildService is the part of cmdServe between a parsed command line and a
// listening socket, separated so the wiring can be checked without one.
func buildService(storeRoot string, seed []byte, authority, registryPath string, opts serveOptions) (*gatewayService, error) {
	if err := holdServedWitnesses(seed, opts); err != nil {
		return nil, err
	}
	service, err := newGatewayServiceSigned(storeRoot, seed, opts.signer, authority, registryPath, opts.sources)
	if err != nil {
		return nil, err
	}
	applyServeOptions(service, opts)
	return service, nil
}

// buildServiceOn is buildService over a kind that keeps the store and the
// registry in place of the filesystem kind at their paths (storage_kind.go).
func buildServiceOn(kind storeKind, seed []byte, authority string, opts serveOptions) (*gatewayService, error) {
	if err := holdServedWitnesses(seed, opts); err != nil {
		return nil, err
	}
	service, err := newGatewayServiceOnSigned(kind, seed, opts.signer, authority, opts.sources)
	if err != nil {
		return nil, err
	}
	applyServeOptions(service, opts)
	return service, nil
}

// holdServedWitnesses holds a witness named for a trail (ADR-0014) before
// anything is made: never this gateway's own key, by the key's bytes, and
// only where receipts are of version 3.
func holdServedWitnesses(seed []byte, opts serveOptions) error {
	if len(opts.witnessedBy) > 0 {
		if len(seed) != ed25519.SeedSize {
			return fmt.Errorf("seed is not %d bytes", ed25519.SeedSize)
		}
		own := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
		if opts.signer != nil {
			own = opts.signer.publicKey()
		}
		if err := holdWitnessedBy(opts.witnessedBy, own, opts.receiptVersion); err != nil {
			return err
		}
	}
	return nil
}

// applyServeOptions sets on a service made what the options say.
func applyServeOptions(service *gatewayService, opts serveOptions) {
	service.maxSourceOutput = opts.maxSourceOutput
	if opts.maxRequest > 0 {
		service.maxRequest = opts.maxRequest
	}
	service.receiptVersion = opts.receiptVersion
	service.requireActionKey = opts.requireActionKey
	service.identity = opts.identity
	service.decisionRecords = opts.decisionRecords
	service.witnessedBy = opts.witnessedBy
	service.seedPath = opts.seedPath
	if opts.receiptSink != nil {
		service.forwarder = newReceiptForwarder(opts.receiptSink)
	}
}

// engineStart is what serve --config judges before it loads the seed, in
// order: the isolation refusals first, so a configuration is judged as a
// configuration whatever this process may do, leaving every path resolved;
// the sources derived from those; every adapter they launch, held and
// rewritten to the path it resolved to; and the paths serve makes. Then
// come the seed and whether the switching the configuration needs is
// available. Nothing is made or started here.
func engineStart(cfg *engineConfig, bindings map[string]binding, host engineHost) ([]string, map[string]sourceSpec, error) {
	// A scoped platform's live tools, and those behind the caller form,
	// are declared read-external (ADR-0044, ADR-0046): held at the signer's
	// start, whatever the front, so no /acquire of another reaches its
	// adapter, and a configuration gateway mcp would refuse does not start
	// serve.
	if err := scopedLiveReads(*cfg, bindings); err != nil {
		return nil, nil, err
	}
	if err := currentBindingOwners(*cfg, bindings); err != nil {
		return nil, nil, err
	}
	statements, err := engineRefusals(cfg, host)
	if err != nil {
		return nil, nil, err
	}
	sources := deriveSources(*cfg, bindings)
	if err := holdAdapterSources(sources, host); err != nil {
		return nil, nil, err
	}
	if err := preflightPathsOf(cfg.store, cfg.registry, cfg.decisionRecords, cfg.storage == nil); err != nil {
		return nil, nil, err
	}
	return statements, sources, nil
}

// cmdServeEngine is `serve --config FILE`: the engine's configuration names
// platforms, the sources are derived from their bindings, and the engine
// refuses to start under a configuration the isolation claim does not
// survive (docs/design/engine-config.md). Nothing else may be given beside
// the file: a process is never named on the command line.
func cmdServeEngine(args []string) int {
	if len(args) != 1 {
		fmt.Fprintln(os.Stderr, "usage: gateway serve --config <engine.json>")
		return 2
	}
	host := osEngineHost()
	cfg, bindings, err := loadEngineConfig(args[0], host.account)
	if err != nil {
		fmt.Fprintln(os.Stderr, "start:", err)
		return 1
	}
	closeInheritedDescriptors()
	// The seed's names: as configured, the name gateway rotate-key --seed is
	// given and keeps a rotation's files beside, and as engineStart resolves
	// it, every link followed. A rotation under way is looked for beside
	// both, so that neither hides it.
	seedNames := []string{cfg.seed}
	statements, sources, err := engineStart(&cfg, bindings, host)
	if err != nil {
		fmt.Fprintln(os.Stderr, "start:", err)
		return 1
	}
	if cfg.seed != seedNames[0] {
		seedNames = append(seedNames, cfg.seed)
	}
	seed, err := loadSeed(cfg.seed)
	if err != nil {
		fmt.Fprintln(os.Stderr, "seed:", err)
		return 1
	}
	// a rotation under way beside the seed is finished first (SPEC.md §3b)
	if err := rotationPendingAtStart(cfg, seedNames); err != nil {
		fmt.Fprintln(os.Stderr, "start:", err)
		return 1
	}
	if err := requireUserSwitching(sources); err != nil {
		fmt.Fprintln(os.Stderr, "start:", err)
		return 1
	}
	// measureSandboxAtStart (engineVersion 23): each source's sandbox
	// measured as its user, now that the switch to it is known to be
	// there, and no start where a launch of one would be refused; nothing
	// has been made yet (sandbox_at_start.go).
	sandboxLine, err := sandboxAtStart(cfg, sources)
	if err != nil {
		fmt.Fprintln(os.Stderr, "start:", err)
		return 1
	}
	for _, statement := range statements {
		fmt.Fprintln(os.Stderr, "start:", statement)
	}
	if sandboxLine != "" {
		fmt.Fprintln(os.Stderr, "start:", sandboxLine)
	}
	identity, err := loadIdentity(cfg.identity)
	if err != nil {
		fmt.Fprintln(os.Stderr, "start:", err)
		return 1
	}
	if line := callerScopesStartLine(identity, sources); line != "" {
		fmt.Fprintln(os.Stderr, "start:", line)
	}
	delegation, err := loadDelegation(cfg.delegation)
	if err != nil {
		fmt.Fprintln(os.Stderr, "start:", err)
		return 1
	}
	// signingKeyVersion (ADR-0050): the key service's public key read once,
	// and checked, before anything is made; the registry's walk is held to
	// end at it below, as at the seed's
	var keyService signer
	if cfg.signingKeyVersion != "" {
		ks, line, err := newKeyServiceSignerPinned(cfg.signingKeyVersion, cfg.signingPublicKey)
		if err != nil {
			fmt.Fprintln(os.Stderr, "start:", err)
			return 1
		}
		fmt.Fprintln(os.Stderr, "start:", line)
		keyService = ks
	}
	if cfg.storage != nil {
		return serveEngineOnKind(cfg, seed, sources, identity, delegation, keyService)
	}
	// A witness is opened before the store and the registry are made: its
	// start-up checks refuse a start that a repair, a log copy or a new key
	// must answer first, and such a start leaves nothing made.
	var witness *witnessService
	if cfg.witness != nil {
		log, err := openEngineWitness(cfg.witness, seed, cfg.registry)
		if err != nil {
			fmt.Fprintln(os.Stderr, "start:", err)
			return 1
		}
		defer log.close()
		fmt.Fprintln(os.Stderr, "start:", witnessStartLine(log, cfg.witness))
		witness = newWitnessService(log, cfg.witness, os.Stderr)
	}
	// held while the engine serves, so gateway journal compact refuses; taken
	// before the service is built, so a compaction under way refuses the start
	// before anything is made in the store (#359)
	storeHold, err := holdServedStore(cfg.store)
	if err != nil {
		fmt.Fprintln(os.Stderr, "start:", err)
		return 1
	}
	defer storeHold.Close()
	served := engineServeOptions(cfg, sources, identity)
	served.signer = keyService
	service, err := buildService(cfg.store, seed, cfg.authority, cfg.registry, served)
	if err != nil {
		fmt.Fprintln(os.Stderr, "start:", err)
		return 1
	}
	if err := storeHold.made(); err != nil {
		fmt.Fprintln(os.Stderr, "start:", err)
		return 1
	}
	// held while the engine runs, so gateway rotate-key refuses; a rotation
	// begun since the check above is refused under it (SPEC.md §3b)
	registryHold, err := holdEngineRegistryKey(seedNames, cfg.registry, service.store.publicKey)
	if err != nil {
		fmt.Fprintln(os.Stderr, "start:", err)
		return 1
	}
	defer registryHold.Close()
	// under the hold, before anything is served (SPEC.md §3c), and the
	// seals pending forwarding delivered (seal_sink.go)
	if err := sealsAtStart(service, os.Stderr, nowStamp, cfg.sealOpenAtStart); err != nil {
		fmt.Fprintln(os.Stderr, "start:", err)
		return 1
	}
	service.witness = witness
	// SIGHUP: the configuration's signingKeyVersion read again, and the
	// gateway's key rotated to it while it serves (rotate_serving.go)
	service.rereadConfig = func() (engineConfig, error) {
		again, _, err := loadEngineConfig(args[0], host.account)
		return again, err
	}
	return serveEngineService(service, cfg, delegation, nil)
}

// serveEngineService serves a service made, until a signal ends it.
// keep, where it is not nil, runs beside the service for its lifetime, and
// a loss it reports stops the service, which then exits 1 (the start
// lease's renewal, store_pg_lease.go).
func serveEngineService(service *gatewayService, cfg engineConfig, delegation *delegationService, keep func(context.Context, func(error))) int {
	stopped, restore := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer restore()
	return serveUntilStopped(service, cfg, delegation, keep, serveStop{stopped: stopped, said: os.Stderr})
}

// serveStop is how a service serveUntilStopped serves stops.
type serveStop struct {
	// stopped ends at the stop signal.
	stopped context.Context
	// drain, where it is not zero, is the stop's drain (handover.go): the
	// gate closes for the stop, what it admitted finishes within drain, and
	// only then does the service's lifetime end. Zero ends it at once,
	// which kills every source in flight.
	drain time.Duration
	// retryAfter is the seconds a call refused during the drain is told to
	// wait; restore, run as the drain begins, gives the stop signals back
	// their default, so that a second one ends the process at once.
	retryAfter int
	restore    func()
	// listener is bound already (runOnKind), or nil: the service binds
	// listen.
	listener net.Listener
	said     io.Writer
}

// serveUntilStopped serves the service until s says it stops, a loss keep
// reports stops it (exit 1), or serving fails (exit 1). keep, where it is
// not nil, reports a loss of the start lease until serving has ended:
// through the drain and through the requests serveOn waits for. On the
// PostgreSQL kind it is kindStart.keep, whose renewal began at the take and
// runs until kindStart.stop.
func serveUntilStopped(service *gatewayService, cfg engineConfig, delegation *delegationService, keep func(context.Context, func(error)), s serveStop) int {
	service.attachDelegation(delegation)
	if s.drain > 0 {
		service.bindLifetime(context.Background())
		go service.drainOnStop(s)
	} else {
		service.bindLifetime(s.stopped)
	}
	defer service.cancel()
	// the signer's admission gate, for the rotation contract: SIGUSR1
	// closes it, SIGUSR2 reopens it
	installOperatorControls(service.ctx, service)
	// a loss keep reports, or a rotation at SIGHUP whose append failed,
	// stops the gateway (exit 1); room for both, so neither send waits
	lost := make(chan error, 2)
	installRotationOnHangup(service.ctx, service, said0(s.said), func(err error) {
		select {
		case lost <- err:
		default:
		}
		service.cancel()
	})
	// Every gcp-asset source's read-only check, before anything is served:
	// a refusal, or a check that did not complete, refuses the start
	// (gcp_asset_binding.go).
	said := s.said
	if said == nil {
		said = os.Stderr
	}
	if err := service.gcpAssetStart(said); err != nil {
		fmt.Fprintln(said, "start:", err)
		return 1
	}
	if keep != nil {
		// ended, and waited for, before serving returns
		kept, endKeep := context.WithCancel(context.Background())
		keeping := make(chan struct{})
		go func() {
			defer close(keeping)
			keep(kept, func(err error) {
				lost <- err
				service.cancel()
			})
		}()
		defer func() {
			endKeep()
			<-keeping
		}()
	}
	var err error
	if s.listener != nil {
		err = service.announceAndServe(s.listener)
	} else {
		err = service.listenAndServe(cfg.listen)
	}
	select {
	case why := <-lost:
		fmt.Fprintln(os.Stderr, "serve:", why)
		return 1
	default:
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "serve:", err)
		return 1
	}
	return 0
}

// rotationPendingAtStart is the start's look for a rotation under way
// beside the seed (SPEC.md §3b). With the PostgreSQL kind keeping the
// registry, gateway rotate-key, which takes the registry's path, cannot
// finish one, and a rotation's file beside the seed is a start refused by
// name all the same: it never starts beside a rotation it cannot see the
// end of.
func rotationPendingAtStart(cfg engineConfig, seedNames []string) error {
	if cfg.storage == nil {
		return rotationPendingBesideAny(seedNames, cfg.registry)
	}
	for _, seedPath := range seedNames {
		for _, suffix := range []string{recordSuffix, nextSeedSuffix} {
			if _, err := os.Lstat(seedPath + suffix); err == nil || !errors.Is(err, fs.ErrNotExist) {
				return fmt.Errorf("%w: %s is there, and %w", errRotationPending, seedPath+suffix, storageUnsupported("gateway rotate-key, which keeps the registry at a path,"))
			}
		}
	}
	return nil
}

// serveEngineOnKind is the rest of serve --config where storage names the
// PostgreSQL kind (storage_kind.go), served until a signal stops it or the
// start lease is lost; a stop drains and releases the lease, and a start
// configured to wait for the lease waits (handover.go).
func serveEngineOnKind(cfg engineConfig, seed []byte, sources map[string]sourceSpec, identity *identityConfig, delegation *delegationService, keyService signer) int {
	stopped, restore := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer restore()
	return runOnKind(cfg, seed, sources, identity, delegation, kindRun{
		period: pgStartLeasePeriod, every: pgStartLeaseRenewal,
		stopped: stopped, restore: restore, bind: listenForConfig, said: os.Stderr,
		signer: keyService,
	})
}

// kindStart is a start on the PostgreSQL kind: the kind, the lease this
// instance holds on it, the lease's renewal, and the service over it.
type kindStart struct {
	kind    *pgKind
	lease   *pgStartLease
	service *gatewayService
	// as is the name the stop's line is said under: "stop" for a start,
	// the command's name for a command that holds the lease
	as string

	// the renewal, from the take to the stop (renew): endRenewal ends it,
	// renewed closes once it ended, and lost holds the loss it reported
	endRenewal context.CancelFunc
	renewed    chan struct{}
	lost       chan error
}

// renew starts the lease's renewal (pgStartLease.keep), as soon as the
// lease is taken, so that a slow start -- the build, the registry's walk,
// the hand-off to serving -- does not outlast its own lease. It runs until
// stop; a loss it reports is held for keep.
func (s *kindStart) renew() {
	ctx, end := context.WithCancel(context.Background())
	s.endRenewal, s.renewed, s.lost = end, make(chan struct{}), make(chan error, 1)
	go func() {
		defer close(s.renewed)
		s.lease.keep(ctx, func(err error) { s.lost <- err })
	}()
}

// keep is the renewal as serveUntilStopped takes it: it reports the loss
// the renewal reported, at once where it was before serving began, until
// ctx ends.
func (s *kindStart) keep(ctx context.Context, lost func(error)) {
	select {
	case err := <-s.lost:
		lost(err)
	case <-ctx.Done():
	}
}

// stop ends the lease's renewal and waits for it, so that no renewal runs
// after the release; releases the lease, so the next instance starts at
// once -- one left behind expires; and closes the kind.
func (s *kindStart) stop(said io.Writer) {
	if s.endRenewal != nil {
		s.endRenewal()
		<-s.renewed
	}
	if err := s.lease.release(); err != nil {
		fmt.Fprintf(said, "%s: the start lease is left to expire within %s: %v\n", cmp.Or(s.as, "stop"), pgStartLeasePeriod, err)
	}
	s.kind.close()
}

// startEngineOnKind is startOnKind with the lease's periods and no stop
// signal.
func startEngineOnKind(cfg engineConfig, seed []byte, sources map[string]sourceSpec, identity *identityConfig, said io.Writer) (*kindStart, error) {
	return startOnKind(cfg, seed, sources, identity, kindRun{period: pgStartLeasePeriod, every: pgStartLeaseRenewal, stopped: context.Background(), said: said})
}

// startOnKind opens the kind the configuration names, held to its
// conditions; takes the start lease, refused while another instance's is
// live (errStartLeaseHeld), or, where storage.startWaitSeconds is set,
// once that instance released it or it expired (waitForStartLease), before
// anything is written; holds the kind to its conditions again after a wait;
// builds the service over the kind; and walks the registry it keeps as
// holdEngineRegistry walks the file. What the start makes in the kind is
// the lease's row and the registry, empty, where it is not there and no
// session is held (newRegistryWriterOn).
func startOnKind(cfg engineConfig, seed []byte, sources map[string]sourceSpec, identity *identityConfig, r kindRun) (*kindStart, error) {
	kind, err := openStorageKind(cfg.storage)
	if err != nil {
		return nil, err
	}
	kind.instance = instanceFor(cfg.storage, seed, cfg.authority)
	if r.signer != nil {
		// the lease names the key the instance signs under: every instance
		// on one database signs under one key version (admitBeside)
		kind.instance = instanceForKey(cfg.storage, r.signer.publicKey(), cfg.authority)
	}
	holder, err := newStartLeaseHolder()
	if err != nil {
		kind.close()
		return nil, err
	}
	lease, waited, err := kind.waitForStartLease(r.stopped, holder, r.period, r.every, cfg.storage.startWait, r.said)
	if err != nil {
		kind.close()
		return nil, err
	}
	started := &kindStart{kind: kind, lease: lease}
	started.renew()
	// the database may have been migrated while this start waited, and a
	// connection the pool kept idle through the wait may have been ended:
	// the checks, and what follows, open fresh ones
	if waited {
		kind.pool.dropIdle()
		err = kind.holdsItsConditions(pgShippedMigrations())
	}
	var service *gatewayService
	if err == nil {
		served := engineServeOptions(cfg, sources, identity)
		served.signer = r.signer
		service, err = buildServiceOn(kind, seed, cfg.authority, served)
	}
	if err == nil {
		_, err = service.kindRegistryWalk()
	}
	if err == nil {
		// the lease held and the registry walked, before anything is
		// served (SPEC.md §3c; seal_open_pg.go), and the seals pending
		// forwarding delivered (seal_sink.go)
		err = sealsAtStart(service, r.said, nowStamp, cfg.sealOpenAtStart)
	}
	if err == nil {
		// a lease lost while the start ran ends it here
		select {
		case err = <-started.lost:
		default:
		}
	}
	if err != nil {
		started.stop(r.said)
		return nil, err
	}
	started.service = service
	fmt.Fprintln(r.said, "start:", storageStartLine(cfg.storage))
	fmt.Fprintf(r.said, "start: gateway instance %s holds the start lease, which runs %s from each renewal by the database's clock and is renewed every %s\n", holder, r.period, r.every)
	if cfg.storage.several {
		fmt.Fprintln(r.said, "start: instances serve this database beside one another (storage.instances \"several\"): each session is held by the instance that admitted its first call, and another instance answers a call into it 409")
	}
	return started, nil
}

// writeNewSeed creates path exclusively. O_EXCL is the whole point and a
// check-then-write would not do: between a stat and a write, a rerun or a
// planted symlink decides which identity the gateway keeps. O_CREATE|O_EXCL
// also refuses a symlink outright rather than following it, so an existing
// path -- regular file, directory, or link -- is left untouched and the
// operator is told, instead of silently rotating the key every receipt and
// seal already produced was signed under.
func writeNewSeed(path string, encoded []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := file.Write(encoded); err != nil {
		file.Close()
		os.Remove(path) // best effort: do not leave a partial seed behind
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		os.Remove(path)
		return err
	}
	if err := file.Close(); err != nil {
		os.Remove(path)
		return err
	}
	return nil
}

// readSeedFile reads back exactly what keygen persists: 64 lowercase hex
// characters and one newline, decoding to a 32-byte Ed25519 seed.
func readSeedFile(path string) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	text := strings.TrimSuffix(string(raw), "\n")
	if len(text) != hex.EncodedLen(seedBytes) {
		return nil, fmt.Errorf("expected %d hex characters, got %d",
			hex.EncodedLen(seedBytes), len(text))
	}
	if text != strings.ToLower(text) {
		return nil, errors.New("seed must be lowercase hexadecimal")
	}
	seed, err := hex.DecodeString(text)
	if err != nil {
		return nil, err
	}
	if len(seed) != seedBytes {
		return nil, fmt.Errorf("expected %d seed bytes, got %d", seedBytes, len(seed))
	}
	return seed, nil
}

type serveOptions struct {
	// signer signs in place of the seed's key where it is not nil (ADR-0050)
	signer           signer
	requireActionKey bool
	sources          map[string]sourceSpec
	port             string
	// listen is the address --listen names (serve_listen.go); the zero
	// Addr when none is named, and serve listens on 127.0.0.1.
	listen netip.Addr
	// acceptUnauthenticatedCallers is --accept-unauthenticated-callers, the
	// acknowledgment a --listen address that is not loopback needs.
	acceptUnauthenticatedCallers bool
	maxSourceOutput              int64
	// maxRequest bounds an /acquire body (--max-request).
	maxRequest     int64
	receiptVersion string
	// receiptSink is the configuration's receipt sink (ADR-0049); nil for
	// none, and for serve from the command line.
	receiptSink *receiptSinkSpec
	// identity, when set, is who may call: every request that acquires,
	// seals or verifies carries a bearer token this issuer signed, and a
	// receipt names the caller it proved. Nil records caller null.
	identity *identityConfig
	// decisionRecords is the directory the runtime's audit trail is
	// expected in, from the engine configuration; an action's cited
	// decision record must be found under it before any executor runs
	// (executor.md). Empty when serve was not started from a
	// configuration, and every /act is then refused.
	decisionRecords string
	// witnessedBy is the witness named for each trail (ADR-0014), from the
	// configuration's witnessedBy or --witnessed-by.
	witnessedBy map[string]namedWitness
	// seedPath is the seed file the command line or the configuration
	// names, which /posture judges.
	seedPath string
	// sealOpenAtStart seals, at the start, each session an earlier process
	// left open, after the interruption (--seal-open-at-start; serve
	// --config reads the configuration's sealOpenAtStart; SPEC.md §3c).
	sealOpenAtStart bool
}

// validateEnvKey accepts what an environment variable name can be on the
// command line: non-empty, no "=", no NUL. Everything else is refused as
// usage, because a name that cannot be set is a declaration that would be
// silently dropped.
func validateEnvKey(key string) (string, bool) {
	switch {
	case key == "":
		return "--source-env expects NAME=KEY or NAME=KEY=VALUE", false
	case strings.ContainsRune(key, 0):
		return "--source-env key must not contain NUL", false
	}
	return "", true
}

// validatePort accepts exactly what a TCP port may be on the command line: a
// decimal number in 1-65535. It deliberately does not accept a service name
// ("http"), a host:port pair, a leading "+", surrounding space, or 0 — 0 asks
// the kernel for an arbitrary free port, which makes the printed address wrong
// and is never what an operator naming a port meant.
func validatePort(value string) (string, bool) {
	if value == "" {
		return "--port must not be empty", false
	}
	for _, r := range value {
		if r < '0' || r > '9' {
			return fmt.Sprintf("--port %q is not a number between 1 and 65535", value), false
		}
	}
	number, err := strconv.Atoi(value)
	if err != nil || number < 1 || number > 65535 {
		return fmt.Sprintf("--port %q is not a number between 1 and 65535", value), false
	}
	return "", true
}

func parseServeOptions(args []string) (serveOptions, string, bool) {
	if len(args) < 4 {
		return serveOptions{}, "usage: gateway serve --config <engine.json> | gateway serve <store> <seedfile> <authority> <registry> " +
			"[--source NAME=CMD ...] [--source-env NAME=KEY[=VALUE] ...] [--source-user NAME=USER ...] " +
			"[--source-shape NAME=airbyte|mcp|http] [--source-max-output BYTES] [--source-timeout NAME=SECONDS ...] " +
			"[--max-request BYTES] [--receipt-version 2|3] [--witnessed-by TRAIL=ORIGIN,PUBLICKEY ...] [--seal-open-at-start] [--listen ADDRESS [--accept-unauthenticated-callers]] [--port N]", false
	}

	opts := serveOptions{
		seedPath:        args[1],
		sources:         map[string]sourceSpec{},
		port:            "8787",
		maxSourceOutput: defaultMaxSourceOutput,
		maxRequest:      maxRequestBody,
		receiptVersion:  receiptVersion3,
	}
	// --source-env and --source-user name a source that may be declared
	// later on the same command line, so they are collected here and bound
	// once every --source is known.
	pendingEnv := map[string][]string{}
	pendingUser := map[string]string{}
	pendingShape := map[string]string{}
	pendingTimeout := map[string]time.Duration{}
	rest := args[4:]
	portSeen := false
	listenSeen := false
	maxOutputSeen := false
	maxRequestSeen := false
	versionSeen := false
	for i := 0; i < len(rest); i++ {
		switch {
		case rest[i] == "--receipt-version":
			if i+1 >= len(rest) {
				return opts, "--receipt-version requires a following value", false
			}
			if versionSeen {
				return opts, "duplicate --receipt-version option", false
			}
			if rest[i+1] != receiptVersion && rest[i+1] != receiptVersion3 {
				return opts, fmt.Sprintf("--receipt-version %q is neither 2 nor 3", rest[i+1]), false
			}
			opts.receiptVersion = rest[i+1]
			versionSeen = true
			i++
		case rest[i] == "--witnessed-by":
			if i+1 >= len(rest) {
				return opts, "--witnessed-by requires a following TRAIL=ORIGIN,PUBLICKEY value", false
			}
			trail, named, err := parseWitnessedByFlag(rest[i+1])
			if err != nil {
				return opts, err.Error(), false
			}
			if opts.witnessedBy == nil {
				opts.witnessedBy = map[string]namedWitness{}
			}
			if _, twice := opts.witnessedBy[trail]; twice {
				return opts, fmt.Sprintf("--witnessed-by names trail %s twice", trail), false
			}
			opts.witnessedBy[trail] = named
			i++
		case rest[i] == "--source-env":
			if i+1 >= len(rest) {
				return opts, "--source-env requires a following NAME=KEY[=VALUE] value", false
			}
			name, entry, found := strings.Cut(rest[i+1], "=")
			if !found || strings.TrimSpace(name) == "" {
				return opts, "--source-env expects NAME=KEY or NAME=KEY=VALUE", false
			}
			key, _, _ := strings.Cut(entry, "=")
			if msg, ok := validateEnvKey(key); !ok {
				return opts, msg, false
			}
			pendingEnv[name] = append(pendingEnv[name], entry)
			i++
		case rest[i] == "--source-user":
			if i+1 >= len(rest) {
				return opts, "--source-user requires a following NAME=USER value", false
			}
			name, account, found := strings.Cut(rest[i+1], "=")
			if !found || strings.TrimSpace(name) == "" || strings.TrimSpace(account) == "" {
				return opts, "--source-user expects NAME=USER", false
			}
			if _, exists := pendingUser[name]; exists {
				return opts, fmt.Sprintf("duplicate --source-user for %q", name), false
			}
			pendingUser[name] = account
			i++
		case rest[i] == "--source-shape":
			if i+1 >= len(rest) {
				return opts, "--source-shape requires a following NAME=SHAPE value", false
			}
			name, shape, found := strings.Cut(rest[i+1], "=")
			if !found || strings.TrimSpace(name) == "" || !adapterShapes[shape] {
				return opts, "--source-shape expects NAME=airbyte|mcp|http", false
			}
			if _, exists := pendingShape[name]; exists {
				return opts, fmt.Sprintf("duplicate --source-shape for %q", name), false
			}
			pendingShape[name] = shape
			i++
		case rest[i] == "--source-max-output":
			if i+1 >= len(rest) {
				return opts, "--source-max-output requires a following value", false
			}
			if maxOutputSeen {
				return opts, "duplicate --source-max-output option", false
			}
			number, err := strconv.ParseInt(rest[i+1], 10, 64)
			if err != nil || number < 1 || number > maxSourceOutputCeiling {
				return opts, fmt.Sprintf("--source-max-output %q is not a number of bytes from 1 to %d", rest[i+1], maxSourceOutputCeiling), false
			}
			opts.maxSourceOutput = number
			maxOutputSeen = true
			i++
		case rest[i] == "--max-request":
			if i+1 >= len(rest) {
				return opts, "--max-request requires a following value", false
			}
			if maxRequestSeen {
				return opts, "duplicate --max-request option", false
			}
			number, err := strconv.ParseInt(rest[i+1], 10, 64)
			if err != nil || number < 1 || number > maxRequestCeiling {
				return opts, fmt.Sprintf("--max-request %q is not a number of bytes from 1 to %d", rest[i+1], maxRequestCeiling), false
			}
			opts.maxRequest = number
			maxRequestSeen = true
			i++
		case rest[i] == "--source-timeout":
			if i+1 >= len(rest) {
				return opts, "--source-timeout requires a following NAME=SECONDS value", false
			}
			name, value, found := strings.Cut(rest[i+1], "=")
			if !found || strings.TrimSpace(name) == "" {
				return opts, "--source-timeout expects NAME=SECONDS", false
			}
			// Compared as seconds, before anything is multiplied: a count of
			// seconds past the ceiling can overflow a Duration into a small or
			// negative one that would pass a comparison made after it.
			seconds, err := strconv.ParseInt(value, 10, 64)
			if err != nil || seconds < 1 || seconds > int64(maxSourceTimeout/time.Second) {
				return opts, fmt.Sprintf("--source-timeout %q is not a whole number of seconds from 1 to %d", value, int64(maxSourceTimeout/time.Second)), false
			}
			if _, exists := pendingTimeout[name]; exists {
				return opts, fmt.Sprintf("duplicate --source-timeout for %q", name), false
			}
			pendingTimeout[name] = time.Duration(seconds) * time.Second
			i++
		case rest[i] == "--source":
			if i+1 >= len(rest) {
				return opts, "--source requires a following NAME=CMD value", false
			}
			name, command, found := strings.Cut(rest[i+1], "=")
			if !found {
				return opts, "--source expects NAME=CMD", false
			}
			if strings.TrimSpace(name) == "" {
				return opts, "--source name must not be empty", false
			}
			if _, exists := opts.sources[name]; exists {
				return opts, fmt.Sprintf("duplicate source %q", name), false
			}
			argv := strings.Fields(command)
			if len(argv) == 0 {
				return opts, "--source command must not be empty", false
			}
			if _, err := exec.LookPath(argv[0]); err != nil {
				return opts, fmt.Sprintf("--source %q command %q cannot be resolved", name, argv[0]), false
			}
			opts.sources[name] = sourceSpec{argv: argv}
			i++
		case rest[i] == "--port":
			if i+1 >= len(rest) {
				return opts, "--port requires a following value", false
			}
			// `--port` is a singleton. Accepting it twice and keeping the last
			// value starts the gateway on a port the command line also names
			// somewhere else, which is exactly the ambiguity `--source` already
			// refuses a duplicate for.
			if portSeen {
				return opts, "duplicate --port option", false
			}
			// Validated here rather than at `net.Listen`, because by then
			// `cmdServe` has read the signing seed and `newGatewayService` may
			// have created store, receipt, artifact and registry directories. A
			// malformed command line must fail as usage, before any file or
			// network side effect.
			if msg, ok := validatePort(rest[i+1]); !ok {
				return opts, msg, false
			}
			opts.port = rest[i+1]
			portSeen = true
			i++
		case rest[i] == "--listen":
			if i+1 >= len(rest) {
				return opts, "--listen requires a following value", false
			}
			// A singleton, as --port is, and validated here for the reason
			// --port is: before the seed is read or anything is made.
			if listenSeen {
				return opts, "duplicate --listen option", false
			}
			addr, msg, ok := parseListenAddress(rest[i+1])
			if !ok {
				return opts, msg, false
			}
			opts.listen = addr
			listenSeen = true
			i++
		case rest[i] == "--accept-unauthenticated-callers":
			if opts.acceptUnauthenticatedCallers {
				return opts, "duplicate --accept-unauthenticated-callers option", false
			}
			opts.acceptUnauthenticatedCallers = true
		case rest[i] == "--seal-open-at-start":
			if opts.sealOpenAtStart {
				return opts, "duplicate --seal-open-at-start option", false
			}
			opts.sealOpenAtStart = true
		case strings.HasPrefix(rest[i], "--"):
			return opts, fmt.Sprintf("unknown option %q", rest[i]), false
		default:
			return opts, fmt.Sprintf("unexpected argument %q", rest[i]), false
		}
	}
	for name, env := range pendingEnv {
		spec, declared := opts.sources[name]
		if !declared {
			return opts, fmt.Sprintf("--source-env names undeclared source %q", name), false
		}
		spec.env = append(spec.env, env...)
		opts.sources[name] = spec
	}
	for name, account := range pendingUser {
		spec, declared := opts.sources[name]
		if !declared {
			return opts, fmt.Sprintf("--source-user names undeclared source %q", name), false
		}
		spec.user = account
		opts.sources[name] = spec
	}
	for name, timeout := range pendingTimeout {
		spec, declared := opts.sources[name]
		if !declared {
			return opts, fmt.Sprintf("--source-timeout names undeclared source %q", name), false
		}
		spec.timeout = timeout
		opts.sources[name] = spec
	}
	// This form of serve authenticates no caller, so a listener other hosts
	// can reach is the operator's written choice, beside the address, and an
	// acknowledgment with no such address to acknowledge is refused rather
	// than kept for a later --listen to rely on.
	offLoopback := opts.listen.IsValid() && !opts.listen.IsLoopback()
	if offLoopback && !opts.acceptUnauthenticatedCallers {
		return opts, fmt.Sprintf("--listen %s is not a loopback address: other hosts can reach it, and serve from the command line authenticates no caller; give --accept-unauthenticated-callers as well to listen there", opts.listen), false
	}
	if opts.acceptUnauthenticatedCallers && !offLoopback {
		return opts, "--accept-unauthenticated-callers is given without a --listen address that is not loopback", false
	}
	if len(opts.witnessedBy) > 0 && opts.receiptVersion != receiptVersion3 {
		return opts, "--witnessed-by needs --receipt-version 3: the member that names a witness is a version 3 member", false
	}
	for name, shape := range pendingShape {
		spec, declared := opts.sources[name]
		if !declared {
			return opts, fmt.Sprintf("--source-shape names undeclared source %q", name), false
		}
		if opts.receiptVersion != receiptVersion3 {
			return opts, fmt.Sprintf("adapter source %q needs --receipt-version 3", name), false
		}
		spec.shape = shape
		opts.sources[name] = spec
	}
	return opts, "", true
}

func cmdServe(args []string) int {
	if len(args) > 0 && args[0] == "--config" {
		return cmdServeEngine(args[1:])
	}
	opts, msg, ok := parseServeOptions(args)
	if !ok {
		fmt.Fprintln(os.Stderr, msg)
		return 2
	}
	storeRoot, seedPath, authority, registryPath := args[0], args[1], args[2], args[3]
	// Nothing a launcher left open may reach a source, whatever user or mode
	// protects the file behind it. Marked before the seed is opened, so the
	// seed's own descriptor is never in question either.
	closeInheritedDescriptors()
	// Both refusals happen before newGatewayService creates a store, a
	// registry, or anything else on disk: a configuration under which a source
	// could read the seed, or would run as the signer when told not to, fails
	// as a configuration, with nothing to clean up.
	seed, err := loadSeed(seedPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "seed:", err)
		return 1
	}
	// a rotation under way beside the seed is finished first (SPEC.md §3b)
	if err := rotationPendingBeside(seedPath, registryPath); err != nil {
		fmt.Fprintln(os.Stderr, "start:", err)
		return 1
	}
	if err := requireUserSwitching(opts.sources); err != nil {
		fmt.Fprintln(os.Stderr, "start:", err)
		return 1
	}

	// held while the gateway serves, so gateway journal compact refuses; taken
	// before the service is built, so a compaction under way refuses the start
	// before anything is made in the store (#359)
	storeHold, err := holdServedStore(storeRoot)
	if err != nil {
		fmt.Fprintln(os.Stderr, "start:", err)
		return 1
	}
	defer storeHold.Close()
	service, err := buildService(storeRoot, seed, authority, registryPath, opts)
	if err != nil {
		fmt.Fprintln(os.Stderr, "start:", err)
		return 1
	}
	if err := storeHold.made(); err != nil {
		fmt.Fprintln(os.Stderr, "start:", err)
		return 1
	}
	// held while the gateway runs, so gateway rotate-key refuses; a rotation
	// begun since the check above is refused under it (SPEC.md §3b)
	registryHold, err := holdEngineRegistry([]string{seedPath}, registryPath, seed)
	if err != nil {
		fmt.Fprintln(os.Stderr, "start:", err)
		return 1
	}
	defer registryHold.Close()
	// under the hold, before anything is served (SPEC.md §3c), and the
	// seals pending forwarding delivered (seal_sink.go)
	if err := sealsAtStart(service, os.Stderr, nowStamp, opts.sealOpenAtStart); err != nil {
		fmt.Fprintln(os.Stderr, "start:", err)
		return 1
	}
	// Sources run in their own process groups, so the terminal's interrupt
	// no longer reaches them; the gateway's does, and it is carried to every
	// source in flight through the service's context.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	service.bindLifetime(ctx)
	installOperatorControls(ctx, service)
	listener, err := listenForServe(opts, os.Stderr)
	if err != nil {
		fmt.Fprintln(os.Stderr, "serve:", err)
		return 1
	}
	if err := service.announceAndServe(listener); err != nil {
		fmt.Fprintln(os.Stderr, "serve:", err)
		return 1
	}
	return 0
}
