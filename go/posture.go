package main

// gateway posture (#314): which of the process-isolation protections
// SECURITY.md describes this host enforces, one line each, from a check
// made here and now where the platform allows one, and from what this
// reference states for the platform where it does not. The report is
// information, never a gate: the command exits 0 whatever it says, and
// serve answers the same report at /posture.

import (
	"fmt"
	"io"
	"os"
	"os/user"
	"runtime"
	"sort"
	"strings"
)

// The three states a protection can be in. not-applicable is a protection
// with nothing to hold on this host or under this configuration -- no
// source to switch, no seed named, an image this platform does not run --
// never one that is merely absent, which is not-enforced.
const (
	postureEnforced      = "enforced"
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
	lines    []postureLine
}

// postureInput is the configuration a posture is judged under: the seed's
// path and the sources, with configured false where none was named.
type postureInput struct {
	configured bool
	seed       string
	sources    map[string]sourceSpec
}

// operatorProgramsLine is the same everywhere: no backend confines what
// the gateway starts (SECURITY.md, "What none of this gives").
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
			"elsewhere than Linux a descendant that left a source's process group is not reached when the source is stopped, and adapter-mcp reaches only the command server itself"},
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

// hostPosture judges every protection under the configuration given.
func hostPosture(in postureInput) postureReport {
	return postureReport{platform: runtime.GOOS, lines: []postureLine{
		sourceUserPosture(in, requireUserSwitching, sourceUserIsRoot),
		descendantPosture(),
		custodyPosture(),
		seedPosture(in),
		operatorProgramsLine,
	}}
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
		return line(postureNotEnforced, "serve refuses this configuration here: "+err.Error())
	}
	if len(asRoot) > 0 {
		sort.Strings(asRoot)
		return line(postureNotEnforced, quotedSources(asRoot, "runs", "run")+" as root, which reads the seed whatever protects it")
	}
	return line(postureEnforced, "every source runs as a user of its own that is not the signer's, and this process can switch to each")
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
	return canon(top)
}

// text is the report for a reader: one line per protection.
func (r postureReport) text() string {
	var sb strings.Builder
	for _, l := range r.lines {
		fmt.Fprintf(&sb, "%-29s %-14s %s\n", l.name, l.state, l.reason)
	}
	return sb.String()
}

const postureUsage = "usage: gateway posture [--json] [--config <engine.json> | <store> <seedfile> <authority> <registry> [serve options]]"

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
	in := postureInput{}
	switch {
	case len(args) == 0:
	case args[0] == "--config":
		if len(args) != 2 {
			fmt.Fprintln(stderr, postureUsage)
			return 2
		}
		cfg, bindings, err := loadEngineConfig(args[1], osEngineHost().account)
		if err != nil {
			fmt.Fprintln(stderr, "posture:", err)
			return 1
		}
		in = postureInput{configured: true, seed: cfg.seed, sources: deriveSources(cfg, bindings)}
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
		in = postureInput{configured: true, seed: args[1], sources: opts.sources}
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
