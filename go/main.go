package main

// A second, clean-room implementation of the judgment-pack gateway attestation
// format (receipt version 2), derived from SPEC.md and corpus/ alone.
//
// Subcommands:
//
//	gateway canon                                    < value.json
//	gateway verify <store-root> <registry> <auth> [<decision-records>]  < publickey.raw
//	gateway conform [--impl CMD] [--corpus DIR]
//	gateway serve <store> <seedfile> <authority> <registry> [--source NAME=CMD] [--source-shape NAME=SHAPE] [--receipt-version 2|3] [--port N]
//	gateway keygen [seedfile]

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
)

func main() {
	if refuseStrayAnchorMarker() {
		os.Exit(2)
	}
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: gateway canon | verify | conform | serve | connect | keygen")
		os.Exit(2)
	}
	switch os.Args[1] {
	case "canon":
		os.Exit(cmdCanon())
	case "verify":
		os.Exit(cmdVerify(os.Args[2:]))
	case "conform":
		os.Exit(cmdConform(os.Args[2:]))
	case "serve":
		os.Exit(cmdServe(os.Args[2:]))
	case "connect":
		os.Exit(cmdConnect(os.Args[2:]))
	case "keygen":
		os.Exit(cmdKeygen(os.Args[2:]))
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand %q\n", os.Args[1])
		os.Exit(2)
	}
}

// refuseStrayAnchorMarker reports, and says why, when the internal anchor
// marker is present in the environment of an ordinary invocation. The anchor
// mode itself has already been taken by the init hook in spawn_unix.go, which
// requires the marker and the argument together; reaching main with the
// marker means the argument was absent, and refusing here keeps an inherited
// variable from turning a verify or a conform into a silent success.
func refuseStrayAnchorMarker() bool {
	if os.Getenv(envGroupAnchor) != "1" {
		return false
	}
	fmt.Fprintf(os.Stderr, "refusing to run: %s is set, and it is an internal marker this process sets only for its own anchor\n", envGroupAnchor)
	return true
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
	const usage = "usage: gateway verify <store-root> <registry-path> <authority> [--decision-records <dir> | <dir>]"
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

	report, err := verifyWithRegistryAndRecords(storeRoot, registryPath, authority, decisionRecords, publicKey)
	if err != nil {
		// Could not produce a verdict at all.
		fmt.Fprintln(os.Stderr, "verify:", err)
		return 1
	}
	out, err := report.marshal()
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
	if err := writeNewSeed(path, []byte(hex.EncodeToString(seed)+"\n")); err != nil {
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

// loadSeed opens, judges and reads the seed file through one descriptor
// (openSeed), then accepts either the hex form keygen writes or 32 raw bytes.
func loadSeed(path string) ([]byte, error) {
	raw, err := openSeed(path)
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
	service, err := newGatewayService(storeRoot, seed, authority, registryPath, opts.sources)
	if err != nil {
		return nil, err
	}
	service.maxSourceOutput = opts.maxSourceOutput
	service.receiptVersion = opts.receiptVersion
	return service, nil
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
	// The isolation refusals come first, so a configuration is judged as a
	// configuration whatever this process may do; they leave every path
	// resolved, and the sources are derived from those; then the seed, then
	// whether the switching the configuration needs is available.
	statements, err := engineRefusals(&cfg, host)
	if err != nil {
		fmt.Fprintln(os.Stderr, "start:", err)
		return 1
	}
	sources := deriveSources(cfg, bindings)
	if err := preflightPaths(cfg.store, cfg.registry, cfg.decisionRecords); err != nil {
		fmt.Fprintln(os.Stderr, "start:", err)
		return 1
	}
	seed, err := loadSeed(cfg.seed)
	if err != nil {
		fmt.Fprintln(os.Stderr, "seed:", err)
		return 1
	}
	if err := requireUserSwitching(sources); err != nil {
		fmt.Fprintln(os.Stderr, "start:", err)
		return 1
	}
	for _, statement := range statements {
		fmt.Fprintln(os.Stderr, "start:", statement)
	}
	service, err := buildService(cfg.store, seed, cfg.authority, cfg.registry, engineServeOptions(cfg, sources))
	if err != nil {
		fmt.Fprintln(os.Stderr, "start:", err)
		return 1
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	service.bindLifetime(ctx)
	if err := service.listenAndServe(cfg.listen); err != nil {
		fmt.Fprintln(os.Stderr, "serve:", err)
		return 1
	}
	return 0
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
	sources         map[string]sourceSpec
	port            string
	maxSourceOutput int64
	receiptVersion  string
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
			"[--source-shape NAME=airbyte|mcp|http] [--source-max-output BYTES] [--receipt-version 2|3] [--port N]", false
	}

	opts := serveOptions{
		sources:         map[string]sourceSpec{},
		port:            "8787",
		maxSourceOutput: defaultMaxSourceOutput,
		receiptVersion:  receiptVersion3,
	}
	// --source-env and --source-user name a source that may be declared
	// later on the same command line, so they are collected here and bound
	// once every --source is known.
	pendingEnv := map[string][]string{}
	pendingUser := map[string]string{}
	pendingShape := map[string]string{}
	rest := args[4:]
	portSeen := false
	maxOutputSeen := false
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
			if err != nil || number < 1 {
				return opts, fmt.Sprintf("--source-max-output %q is not a positive number of bytes", rest[i+1]), false
			}
			opts.maxSourceOutput = number
			maxOutputSeen = true
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
	if err := requireUserSwitching(opts.sources); err != nil {
		fmt.Fprintln(os.Stderr, "start:", err)
		return 1
	}

	service, err := buildService(storeRoot, seed, authority, registryPath, opts)
	if err != nil {
		fmt.Fprintln(os.Stderr, "start:", err)
		return 1
	}
	// Sources run in their own process groups, so the terminal's interrupt
	// no longer reaches them; the gateway's does, and it is carried to every
	// source in flight through the service's context.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	service.bindLifetime(ctx)
	if err := service.listenAndServe("127.0.0.1:" + opts.port); err != nil {
		fmt.Fprintln(os.Stderr, "serve:", err)
		return 1
	}
	return 0
}
