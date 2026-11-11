package main

// gateway posture (#314): which of the process-isolation protections
// SECURITY.md describes this host enforces, one line each, from a check
// made here and now where the platform allows one, and from what this
// reference states for the platform where it does not. The report is
// information, never a gate: the command exits 0 whatever it says, and
// serve answers the same report at /posture.

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/user"
	"runtime"
	"sort"
	"strings"
)

// not-applicable is a protection
// with nothing to hold on this host or under this configuration -- no
// source to switch, no seed named, an image this platform does not run --
// never one that is merely absent, which is not-enforced. partial is a
// protection that holds in part, its reason saying which part.
const (
	postureEnforced      = "enforced"
	posturePartial       = "partial"
	postureNotEnforced   = "not-enforced"
	postureNotApplicable = "not-applicable"
)

// The protections, in the order the report gives them.
const (
	protectionSourceUser       = "source-user-switch"
	protectionDescendants      = "descendant-reaping"
	protectionContainerCustody = "container-custody"
	protectionSeedFile         = "seed-file-protection"
	protectionOperatorPrograms = "operator-program-confinement"
	// Whether the gateway listens on a loopback address (#401), the last of
	// the lines every report gives.
	protectionListenerReach = "listener-reach"
	// The three lines a gateway configured with a delegation adds (SPEC.md
	// §11.9); a gateway without one reports none of them.
	protectionDelegationNarrowing = "delegation-narrowing"
	protectionDelegationSender    = "delegation-sender-constraint"
	protectionDelegationGrants    = "delegation-grants"
	// The line a configuration that gives some platform writeRequesters
	// adds (write_requesters.go); one that gives none reports no such line.
	protectionWriteRequesters = "write-requesters"
)

// envPostureProbe and the two probe arguments together select the probe
// modes of this executable (posture_linux.go), as envGroupAnchor and
// anchorArg select the anchor's: both are required, and main refuses to
// run with the variable set.
const (
	envPostureProbe      = "GATEWAY_INTERNAL_POSTURE_PROBE"
	postureChildArg      = "_posture-probe-child"
	postureGrandchildArg = "_posture-probe-grandchild"
)

// postureLine is one protection: its name, its state, and one sentence
// saying why.
type postureLine struct {
	name, state, reason string
}

type postureReport struct {
	platform string
	programs []postureProgram
	lines    []postureLine
}

// postureInput is the configuration a posture is judged under: the seed's
// path and the sources, with configured false where none was named. public
// is a report /posture answers: its reasons name no path and no account,
// which the command, run by the operator, may.
type postureInput struct {
	configured bool
	seed       string
	sources    map[string]sourceSpec
	public     bool
	// delegation is the configuration's delegation, which adds its three
	// lines; nil adds none.
	delegation *delegationPosture
	// listener is where the gateway listens, read where configured is true.
	// Its zero value is a listener off loopback that authenticates no
	// caller, so an input that does not say where the gateway listens is
	// never judged to listen on loopback.
	listener listenerReach
}

// listenerReach is what posture reads of the gateway's listener: whether
// its address is a loopback address, and whether the gateway authenticates
// its callers (an identity is configured). It is the class of the address,
// never the address: no report names one.
type listenerReach struct{ loopback, authenticated bool }

// delegationPosture is what posture reads of a delegation: whether a bearer
// credential is admitted for a read-only chain.
type delegationPosture struct{ bearerReadOnly bool }

// delegationLines are the lines of SPEC.md §11.9, the grants line judged
// over the sources the gateway serves.
func delegationLines(d *delegationPosture, sources map[string]sourceSpec) []postureLine {
	if d == nil {
		return nil
	}
	sender := postureLine{protectionDelegationSender, postureEnforced,
		"every delegation credential is bound to the run's proof-of-possession key (RFC 9449), and a call that does not prove it is refused"}
	if d.bearerReadOnly {
		sender = postureLine{protectionDelegationSender, postureNotEnforced,
			"the operator admits a bearer delegation credential, living at most five minutes, for a chain that admits only pure, read and read-external calls"}
	}
	return []postureLine{
		{protectionDelegationNarrowing, postureEnforced,
			"the gateway enforces each delegation's scope before dispatch; no platform's standing credential is narrowed, so the narrowing is gateway-enforced, not platform-enforced"},
		sender,
		delegationGrantsLine(sources),
	}
}

// delegationGrantsNamed bounds how many platforms the grants line names;
// the rest it counts.
const delegationGrantsNamed = 5

// delegationGrantsLine is whether every platform a delegated call can reach
// names the connection grant its delegated calls are admitted under (SPEC.md
// §10, rule 3). A delegated call names a tool: /act a write source's, and
// /acquire an mcp source's, the only shape it reads a tool of
// (acquireWithReconciliation), so a platform is reached through those, a
// platform being the part of a source's name before the slash, as the grant
// gate names it. The gate holds whatever this line says: a platform that
// names no grant refuses every delegated call (grant-unknown), so it is not
// an open boundary but one the delegation does not serve. Where no platform
// reached names one, the delegation serves no call, which is not-applicable;
// where some do, the line is enforced and names the rest. A platform names a
// grant only where every source it is reached through does; the sources are
// read in name order, so the line never rests on a map's order.
func delegationGrantsLine(sources map[string]sourceSpec) postureLine {
	names := make([]string, 0, len(sources))
	for name := range sources {
		names = append(names, name)
	}
	sort.Strings(names)
	granted := map[string]bool{}
	for _, name := range names {
		spec := sources[name]
		if spec.shape != "mcp" && !strings.HasSuffix(name, "/write") {
			continue
		}
		platform, _, _ := strings.Cut(name, "/")
		if held, seen := granted[platform]; !seen || held {
			granted[platform] = spec.grant != nil
		}
	}
	var without []string
	for platform, held := range granted {
		if !held {
			without = append(without, platform)
		}
	}
	sort.Strings(without)
	line := func(state, reason string) postureLine { return postureLine{protectionDelegationGrants, state, reason} }
	switch {
	case len(granted) == 0:
		return line(postureNotApplicable, "no source offers a tool a delegated call could name, so the delegation serves no call")
	case len(without) == 0 && len(granted) == 1:
		return line(postureEnforced, "the 1 platform a delegated call can reach names a connection grant, and every delegated call on it is admitted only under that grant")
	case len(without) == 0:
		return line(postureEnforced, fmt.Sprintf("each of the %d platforms a delegated call can reach names a connection grant, and every delegated call is admitted only under its platform's grant", len(granted)))
	}
	refuse := quotedPlatforms(without) + " names no connection grant and refuses every delegated call (grant-unknown) until it names one"
	if len(without) > 1 {
		refuse = quotedPlatforms(without) + " name no connection grant and refuse every delegated call (grant-unknown) until they name one"
	}
	if len(without) == len(granted) {
		return line(postureNotApplicable, refuse+", so the delegation serves no call")
	}
	held, verb := len(granted)-len(without), "name"
	if held == 1 {
		verb = "names"
	}
	return line(postureEnforced, fmt.Sprintf("%d of the %d platforms a delegated call can reach %s a connection grant, and every delegated call is admitted only under its platform's grant; %s", held, len(granted), verb, refuse))
}

// quotedPlatforms is `platform "a"` or `platforms "a", "b"`, naming at
// most delegationGrantsNamed of the sorted names and counting the rest.
func quotedPlatforms(names []string) string {
	shown := names
	if len(shown) > delegationGrantsNamed {
		shown = shown[:delegationGrantsNamed]
	}
	quoted := make([]string, len(shown))
	for i, name := range shown {
		quoted[i] = fmt.Sprintf("%q", name)
	}
	if len(names) == 1 {
		return "platform " + quoted[0]
	}
	text := "platforms " + strings.Join(quoted, ", ")
	if rest := len(names) - len(shown); rest > 0 {
		text += fmt.Sprintf(" and %d more", rest)
	}
	return text
}

// operatorProgramsLine is the legacy/no-evidence statement. Version 13 sources
// contribute separately probed program entries and may report partial protection.
var operatorProgramsLine = postureLine{protectionOperatorPrograms, postureNotEnforced,
	"the gateway does not confine the programs it starts: a source, or a program an adapter runs, reads what its operating-system user can read, reaches the network and writes files"}

// postureStatements is what this reference states, rather than checks, on
// a platform where a protection is not checked at run time: "unix" is a
// Unix other than Linux (macOS, the BSDs), "windows" a platform without a
// Unix credential model. Each platform's own file names its family
// (postureFamily); Linux checks every line instead.
var postureStatements = map[string]map[string]postureLine{
	"unix": {
		protectionDescendants: {protectionDescendants, postureNotEnforced,
			"elsewhere than Linux adapter-mcp does not reach the descendants a command server left outside the source's process group, which it adopts and kills on Linux"},
		protectionContainerCustody: {protectionContainerCustody, postureNotApplicable,
			"the engine image is a Linux image, and a gateway on this platform runs outside it"},
	},
	"windows": {
		protectionDescendants: {protectionDescendants, postureNotEnforced,
			"this platform has no process group: a stopped source's direct child is killed and a descendant it started is not"},
		protectionContainerCustody: {protectionContainerCustody, postureNotApplicable,
			"the engine image is a Linux image, and a gateway on this platform runs outside it"},
		protectionSeedFile: {protectionSeedFile, postureNotEnforced,
			"the seed's owner and mode are not checked on this platform, and the filesystem's own access control is what protects it"},
	},
}

// hostPosture judges every protection under the configuration given: the
// lines every report gives, the listener's last of them, then a
// delegation's, then writeRequesters', each only where the configuration
// carries it.
func hostPosture(in postureInput) postureReport {
	programs := sourceProgramPosture(in.sources)
	if in.public {
		for i := range programs {
			programs[i].report.Protection.Reason = publicProgramReason(programs[i])
		}
	}
	return postureReport{platform: runtime.GOOS, programs: programs, lines: append([]postureLine{
		sourceUserPosture(in, requireUserSwitching, sourceUserIsRoot),
		descendantPosture(),
		custodyPosture(in.public),
		seedPosture(in),
		programConfinementPosture(programs),
		listenerPosture(in),
	}, append(delegationLines(in.delegation, in.sources), writeRequestersLines(in.sources)...)...)}
}

// sourceUserPosture is whether every source runs as a user of its own
// that this process can switch to: the requirement serve holds a
// configuration to at start (requireUserSwitching), and a source user
// that is not root, which reads the seed whatever protects it.
func sourceUserPosture(in postureInput, switching func(map[string]sourceSpec) error, isRoot func(string) bool) postureLine {
	line := func(state, reason string) postureLine { return postureLine{protectionSourceUser, state, reason} }
	if !in.configured {
		return line(postureNotApplicable, "no configuration was named, so there is no source to judge")
	}
	if len(in.sources) == 0 {
		return line(postureNotApplicable, "the configuration names no source")
	}
	var asSigner, asRoot []string
	for name, spec := range in.sources {
		switch {
		case spec.user == "":
			asSigner = append(asSigner, name)
		case isRoot(spec.user):
			asRoot = append(asRoot, name)
		}
	}
	if len(asSigner) > 0 {
		sort.Strings(asSigner)
		return line(postureNotEnforced, quotedSources(asSigner, "runs as the signer's own user and reads", "run as the signer's own user and read")+" what it reads, the seed included")
	}
	if err := switching(in.sources); err != nil {
		if in.public {
			return line(postureNotEnforced, "serve refuses this configuration here: this process cannot switch every source to its user, and gateway posture, given the configuration, says why")
		}
		return line(postureNotEnforced, "serve refuses this configuration here: "+err.Error())
	}
	if len(asRoot) > 0 {
		sort.Strings(asRoot)
		return line(postureNotEnforced, quotedSources(asRoot, "runs", "run")+" as root, which reads the seed whatever protects it")
	}
	return line(postureEnforced, "every source runs as a user of its own that is not the signer's, and this process can switch to each")
}

// listenerPosture is the listener line: not-applicable where no
// configuration was named, since then there is no gateway whose listener
// could be judged, and otherwise listenerReachLine of where the gateway
// listens.
func listenerPosture(in postureInput) postureLine {
	if !in.configured {
		return postureLine{protectionListenerReach, postureNotApplicable, "no configuration was named, so there is no listener to judge"}
	}
	return listenerReachLine(in.listener.loopback, in.listener.authenticated)
}

// listenerReachLine is whether only this host reaches the gateway, judged
// from whether it listens on a loopback address and whether it
// authenticates its callers, and from nothing else. On loopback the line is
// enforced, whoever is authenticated. Off loopback with no caller
// authenticated, the one such listener there is today (serve from the
// command line with --listen and --accept-unauthenticated-callers,
// ADR-0023), it is not-enforced. Off loopback with callers authenticated,
// which no form of serve can start yet (#400), it is partial: a caller is
// held to a bearer token, which plain HTTP lets the network between read and
// replay. No reason names the address.
func listenerReachLine(loopback, authenticated bool) postureLine {
	line := func(state, reason string) postureLine { return postureLine{protectionListenerReach, state, reason} }
	switch {
	case loopback:
		return line(postureEnforced, "the gateway listens on a loopback address, which other hosts cannot reach")
	case authenticated:
		return line(posturePartial, "the gateway listens on an address that is not loopback, which other hosts can reach, and it authenticates its callers by a bearer token, which over plain HTTP can be read and replayed on the network between")
	}
	return line(postureNotEnforced, "the gateway listens on an address that is not loopback, which other hosts can reach, and it authenticates no caller, so whoever reaches it can run its sources and have receipts and seals signed under its key")
}

// listenIsLoopback is whether an engine configuration's listen, host:port,
// names a loopback IP address. The configuration is held to one when it is
// read (loopbackAddress); one this cannot read as an IP address and a port
// is taken as not loopback.
func listenIsLoopback(listen string) bool {
	host, _, err := net.SplitHostPort(listen)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// quotedSources is `source "a" <one>` or `sources "a", "b" <many>`.
func quotedSources(names []string, one, many string) string {
	quoted := make([]string, len(names))
	for i, name := range names {
		quoted[i] = fmt.Sprintf("%q", name)
	}
	if len(names) == 1 {
		return "source " + quoted[0] + " " + one
	}
	return "sources " + strings.Join(quoted, ", ") + " " + many
}

// pathless is an error's text without the path an *os.PathError carries,
// for a reason /posture answers.
func pathless(err error) string {
	var pathErr *os.PathError
	if errors.As(err, &pathErr) {
		return pathErr.Op + ": " + pathErr.Err.Error()
	}
	return err.Error()
}

// sourceUserIsRoot is whether a named source user is uid 0. A user that
// cannot be looked up is left to the switching check, which says so.
func sourceUserIsRoot(name string) bool {
	account, err := user.Lookup(name)
	return err == nil && account.Uid == "0"
}

// canonical is the report in canonical JSON (SPEC.md §1.1), so a consumer
// can compare two reports byte for byte.
func (r postureReport) canonical() []byte {
	protections := make(vArray, 0, len(r.lines))
	for _, l := range r.lines {
		entry := newObject()
		entry.set("name", vString(l.name))
		entry.set("state", vString(l.state))
		entry.set("reason", vString(l.reason))
		protections = append(protections, entry)
	}
	top := newObject()
	top.set("platform", vString(r.platform))
	top.set("protections", protections)
	if len(r.programs) > 0 {
		programs := vArray{}
		for _, p := range r.programs {
			programs = append(programs, p.value())
		}
		top.set("programs", programs)
	}
	return canon(top)
}

// text is the report for a reader: one line per protection.
func (r postureReport) text() string {
	var sb strings.Builder
	for _, l := range r.lines {
		fmt.Fprintf(&sb, "%-29s %-14s %s\n", l.name, l.state, l.reason)
	}
	for _, p := range r.programs {
		fmt.Fprintf(&sb, "%s %s %s %s %s preset=%s %s\n", p.source, p.class, p.report.Protection.Mode, p.report.Protection.Backend, p.report.Protection.State, p.report.Preset, p.report.Protection.Reason)
	}
	return sb.String()
}

const postureUsage = "usage: gateway posture [--json] [--config <engine.json> | [serve] <store> <seedfile> <authority> <registry> [serve options]]"

// cmdPosture is `gateway posture`: the report for the gateway the
// configuration given would start -- an engine configuration, or serve's
// own command line -- or, with none, for this host alone. It is judged as
// this process: run it as the user the gateway runs as. A configuration
// that cannot be read is an error; whatever the report says is not.
func cmdPosture(args []string, stdout, stderr io.Writer) int {
	asJSON := false
	if len(args) > 0 && args[0] == "--json" {
		asJSON, args = true, args[1:]
	}
	// serve's own command line may be given as it is typed, its word too
	if len(args) > 0 && args[0] == "serve" {
		args = args[1:]
	}
	in := postureInput{}
	switch {
	case len(args) == 0:
	case args[0] == "--config":
		if len(args) != 2 {
			fmt.Fprintln(stderr, postureUsage)
			return 2
		}
		var err error
		if in, err = postureOfConfig(args[1], osEngineHost().account); err != nil {
			fmt.Fprintln(stderr, "posture:", err)
			return 1
		}
	case strings.HasPrefix(args[0], "--"):
		fmt.Fprintln(stderr, postureUsage)
		return 2
	default:
		opts, msg, ok := parseServeOptions(args)
		if !ok {
			fmt.Fprintln(stderr, msg)
			fmt.Fprintln(stderr, postureUsage)
			return 2
		}
		in = postureInput{configured: true, seed: opts.seedPath, sources: opts.sources,
			listener: listenerReach{loopback: opts.listensOnLoopback(), authenticated: opts.identity != nil}}
	}
	report := hostPosture(in)
	if asJSON {
		// exactly the canonical bytes, as gateway canon writes them
		_, _ = stdout.Write(report.canonical())
		return 0
	}
	_, _ = io.WriteString(stdout, report.text())
	return 0
}

// postureOfConfig is what an engine configuration gives the report: its
// seed, the sources serve --config derives from it, each platform's user
// theirs, and the listen address serve --config binds, with callers
// authenticated where it configures an identity.
func postureOfConfig(path string, account func(string) (int, string, error)) (postureInput, error) {
	cfg, bindings, err := loadEngineConfig(path, account)
	if err != nil {
		return postureInput{}, err
	}
	in := postureInput{configured: true, seed: cfg.seed, sources: deriveSources(cfg, bindings),
		listener: listenerReach{loopback: listenIsLoopback(cfg.listen), authenticated: cfg.identity != nil}}
	if cfg.delegation != nil {
		in.delegation = &delegationPosture{bearerReadOnly: cfg.delegation.bearerReadOnly}
	}
	return in, nil
}

// seedNotNamed is the seed line where there is no seed to judge.
func seedNotNamed(in postureInput) (postureLine, bool) {
	switch {
	case !in.configured:
		return postureLine{protectionSeedFile, postureNotApplicable, "no configuration was named, so there is no seed to judge"}, true
	case in.seed == "":
		return postureLine{protectionSeedFile, postureNotApplicable, "the configuration names no seed"}, true
	}
	return postureLine{}, false
}

// seedStatPath is how the seed line reads the file: by its path, as
// openSeed opens it, following a link, and without opening it, so a FIFO
// at the path does not block the report.
var seedStatPath = os.Stat
