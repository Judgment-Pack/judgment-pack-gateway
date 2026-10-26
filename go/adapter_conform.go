package main

// gateway adapter-conform runs an adapter as gateway serve runs a source
// declared with a shape, against requests, and reports what serve would make
// of each answer: accepted, or refused and why. Nothing is retained and
// nothing is minted; there is no store, no seed and no session.
//
//	gateway adapter-conform --shape http --vectors cases/ 'adapter-http --endpoint https://api.example --paths /read'
//	gateway adapter-conform --shape mcp --vectors cases/ -- adapter-mcp --url https://mcp.example/mcp
//	gateway adapter-conform --shape http 'my-adapter' < request.json
//
// The adapter is started as serve starts a source (runSource): resolved
// once, the canonical request on stdin, the declared environment and nothing
// else, its own process group, under the output bound and the timeout. Its
// answer is then read as acquireForTrail reads it before anything is
// retained: the canonical parse, the envelope held to its form and to the
// shape (readEnvelope), and the result as the response would carry it
// (returnableResult). The envelope's form is published as
// schema/adapter-envelope.v1.json; this command is the gateway's own reading
// of it, with the rules a schema cannot state.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const adapterConformUsage = "usage: gateway adapter-conform --shape airbyte|mcp|http [--vectors DIR] [--env KEY[=VALUE]]... " +
	"[--timeout SECONDS] [--max-output BYTES] [--json] (ADAPTER-COMMAND | -- ADAPTER [ARG...])"

// conformOptions is an adapter-conform command line, read.
type conformOptions struct {
	shape   string
	vectors string
	env     []string
	timeout time.Duration
	// maxOutput is the bound serve's --source-max-output sets.
	maxOutput int64
	json      bool
	argv      []string
}

// The classes of refusal, by what refused. The first is the adapter's own:
// it exited with a status other than 0, and serve's refusal carries the start
// of what it wrote on stderr. The others are serve's, of an adapter that ran
// out of its bounds or could not be run, or of an answer that is not one an
// acquisition takes. A case that expects a refusal names its class, and a
// refusal of another class is unexpected: an adapter that writes a broken
// envelope where it should refuse fails its case.
const (
	refusalSourceFailed  = "source-failed"
	refusalTimeout       = "timeout"
	refusalOutputBound   = "output-bound"
	refusalNotStarted    = "not-started"
	refusalNotJSON       = "not-json"
	refusalNotAnEnvelope = "not-an-envelope"
	refusalNotReturnable = "not-returnable"
)

var refusalClasses = []string{refusalSourceFailed, refusalTimeout, refusalOutputBound, refusalNotStarted, refusalNotJSON, refusalNotAnEnvelope, refusalNotReturnable}

// conformExpectations are what a case may expect: "accepted", or "refused: "
// and the class of the refusal.
var conformExpectations = func() map[string]bool {
	out := map[string]bool{"accepted": true}
	for _, class := range refusalClasses {
		out["refused: "+class] = true
	}
	return out
}()

// conformCase is one request and what the adapter's answer to it is expected
// to be (conformExpectations).
type conformCase struct {
	name    string
	request []byte
	expect  string
}

// conformOutcome is what serve would make of the adapter's answer to a case:
// accepted, or refused, of a class and for a reason.
type conformOutcome struct {
	conformCase
	refusal string // the class; empty when accepted
	reason  string
}

func (o conformOutcome) outcome() string {
	if o.refusal == "" {
		return "accepted"
	}
	return "refused"
}

// result is the outcome as a case states what it expects.
func (o conformOutcome) result() string {
	if o.refusal == "" {
		return "accepted"
	}
	return "refused: " + o.refusal
}

func (o conformOutcome) unexpected() bool { return o.result() != o.expect }

func cmdAdapterConform(args []string) int {
	// Nothing a launcher left open reaches the adapter, as nothing reaches
	// a source serve starts.
	closeInheritedDescriptors()
	// The adapter runs in its own process group, which the terminal's
	// interrupt does not reach; this process's does, through the context.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return adapterConform(ctx, args, os.Stdin, os.Stdout, os.Stderr)
}

// adapterConformOptions reads the command line. The adapter's command is
// one argument split on white space, as --source takes it, or the words
// after "--" as given; the options come before "--" and may come on either
// side of the one argument.
func adapterConformOptions(args []string) (conformOptions, string, bool) {
	opts := conformOptions{timeout: defaultSourceTimeout, maxOutput: defaultMaxSourceOutput}
	seen := map[string]bool{}
	once := func(name string) bool {
		if seen[name] {
			return false
		}
		seen[name] = true
		return true
	}
	var command []string
	commandGiven := false
	for i := 0; i < len(args); i++ {
		arg := args[i]
		takesValue := arg == "--shape" || arg == "--vectors" || arg == "--env" || arg == "--timeout" || arg == "--max-output"
		if takesValue && i+1 >= len(args) {
			return opts, arg + " requires a following value", false
		}
		if takesValue && arg != "--env" && !once(arg) {
			return opts, "duplicate " + arg + " option", false
		}
		switch {
		case arg == "--":
			if commandGiven {
				return opts, "the adapter's command is given once: as one argument, or as the words after --", false
			}
			command, commandGiven = args[i+1:], true
			i = len(args)
		case arg == "--shape":
			if !adapterShapes[args[i+1]] {
				return opts, fmt.Sprintf("--shape %q is not airbyte, mcp or http", args[i+1]), false
			}
			opts.shape = args[i+1]
			i++
		case arg == "--vectors":
			if args[i+1] == "" {
				return opts, "--vectors names no directory", false
			}
			opts.vectors = args[i+1]
			i++
		case arg == "--env":
			key, _, _ := strings.Cut(args[i+1], "=")
			if key == "" || strings.ContainsRune(args[i+1], 0) {
				return opts, "--env expects KEY or KEY=VALUE, without NUL", false
			}
			opts.env = append(opts.env, args[i+1])
			i++
		case arg == "--timeout":
			seconds, err := strconv.ParseInt(args[i+1], 10, 64)
			if err != nil || seconds < 1 || seconds > int64(maxSourceTimeout/time.Second) {
				return opts, fmt.Sprintf("--timeout %q is not a whole number of seconds from 1 to %d", args[i+1], int64(maxSourceTimeout/time.Second)), false
			}
			opts.timeout = time.Duration(seconds) * time.Second
			i++
		case arg == "--max-output":
			bytes, err := strconv.ParseInt(args[i+1], 10, 64)
			if err != nil || bytes < 1 || bytes > maxSourceOutputCeiling {
				return opts, fmt.Sprintf("--max-output %q is not a number of bytes from 1 to %d", args[i+1], maxSourceOutputCeiling), false
			}
			opts.maxOutput = bytes
			i++
		case arg == "--json":
			if !once(arg) {
				return opts, "duplicate --json option", false
			}
			opts.json = true
		case strings.HasPrefix(arg, "-"):
			return opts, fmt.Sprintf("unknown option %q: give the adapter's command as one argument, or after --", requestText(arg)), false
		default:
			if commandGiven {
				return opts, fmt.Sprintf("unexpected argument %q: the adapter's command is one argument, or the words after --", requestText(arg)), false
			}
			command, commandGiven = strings.Fields(arg), true
		}
	}
	if opts.shape == "" {
		return opts, "--shape is required: the shape the operator declares for the source with --source-shape, which says what the envelope may carry", false
	}
	if len(command) == 0 {
		return opts, "no adapter command is given", false
	}
	if _, err := exec.LookPath(command[0]); err != nil {
		return opts, fmt.Sprintf("the adapter's command %q cannot be resolved", requestText(command[0])), false
	}
	opts.argv = command
	return opts, "", true
}

// conformRequest reads a request as /acquire reads its arguments: one JSON
// value in the canonical domain, within the value budget, carried to the
// adapter in its canonical form.
func conformRequest(raw []byte) ([]byte, error) {
	v, err := parseJSONWithin(raw, maxArgumentValues)
	if err != nil {
		return nil, fmt.Errorf("the request is not one an acquire request carries: %v", err)
	}
	return canon(v), nil
}

// conformCases reads the cases of a directory: every *.json file in it, in
// the order of their names, each exactly {"request": VALUE, "expect":
// "accepted" | "refused: CLASS"}. A file that is not is refused, and so is a
// directory with none: a case that cannot be read is not a case passed.
func conformCases(dir string) ([]conformCase, error) {
	info, err := os.Stat(dir)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("%s is not a directory", dir)
	}
	paths, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil {
		return nil, err
	}
	sort.Strings(paths)
	if len(paths) == 0 {
		return nil, fmt.Errorf("%s holds no case (*.json)", dir)
	}
	var cases []conformCase
	for _, path := range paths {
		name := filepath.Base(path)
		// A regular file no larger than the largest request serve takes
		// (readBounded): a special file is refused rather than waited on.
		raw, err := readBounded(path, maxRequestCeiling)
		if err != nil {
			return nil, err
		}
		var c struct {
			Request json.RawMessage `json:"request"`
			Expect  *string         `json:"expect"`
		}
		if err := decodeVectorFile(raw, &c, true); err != nil {
			return nil, fmt.Errorf("%s: %v", name, err)
		}
		if c.Request == nil {
			return nil, fmt.Errorf(`%s: no member "request"`, name)
		}
		if c.Expect == nil || !conformExpectations[*c.Expect] {
			return nil, fmt.Errorf(`%s: member "expect" is neither "accepted" nor "refused: " and a class of refusal (%s)`, name, strings.Join(refusalClasses, ", "))
		}
		request, err := conformRequest(c.Request)
		if err != nil {
			return nil, fmt.Errorf("%s: %v", name, err)
		}
		cases = append(cases, conformCase{name: name, request: request, expect: *c.Expect})
	}
	return cases, nil
}

// conformOne runs the adapter on one case and returns the class of serve's
// refusal of its answer and the refusal, or two empty strings when serve
// would accept it.
func conformOne(g *gatewayService, spec sourceSpec, c conformCase) (class, reason string) {
	output, _, _, err := g.runSource("adapter", spec, c.request)
	if err != nil {
		return sourceRefusalClass(err.Error()), err.Error()
	}
	e, err := readEnvelope(output, spec.shape)
	if err != nil {
		return refusalNotAnEnvelope, err.Error()
	}
	if _, err := returnableResult(e.result); err != nil {
		return refusalNotReturnable, err.Error()
	}
	return "", ""
}

// sourceRefusalClass is the class of a refusal runSource made, read from
// the words it begins with there: the adapter's own failure, the timeout
// (a descendant holding the output past it among it), the output bound,
// output that is no canonical JSON value, and otherwise an adapter that
// could not be started. TestAdapterConformClassesEachRefusal holds each
// class to serve's words.
func sourceRefusalClass(reason string) string {
	switch {
	case strings.HasPrefix(reason, "source failed: "):
		return refusalSourceFailed
	case strings.HasPrefix(reason, "source did not finish within "), strings.HasPrefix(reason, "source exited but left its output open"):
		return refusalTimeout
	case strings.HasPrefix(reason, "source output exceeds "):
		return refusalOutputBound
	case strings.HasPrefix(reason, "source did not return a canonical JSON value"):
		return refusalNotJSON
	}
	return refusalNotStarted
}

func adapterConform(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	opts, msg, ok := adapterConformOptions(args)
	if !ok {
		fmt.Fprintln(stderr, msg)
		fmt.Fprintln(stderr, adapterConformUsage)
		return 2
	}
	var cases []conformCase
	if opts.vectors == "" {
		// One case, the request on stdin, expected to be accepted.
		raw, err := readBoundedFrom(stdin, "the request", maxRequestCeiling)
		if err == nil {
			var request []byte
			if request, err = conformRequest(raw); err == nil {
				cases = []conformCase{{name: "stdin", request: request, expect: "accepted"}}
			}
		}
		if err != nil {
			fmt.Fprintln(stderr, "adapter-conform: stdin:", err)
			return 2
		}
	} else {
		var err error
		if cases, err = conformCases(opts.vectors); err != nil {
			fmt.Fprintln(stderr, "adapter-conform:", err)
			return 2
		}
	}
	g := &gatewayService{maxSourceOutput: opts.maxOutput, receiptVersion: receiptVersion3, waitDelay: sourceWaitDelay}
	g.bindLifetime(ctx)
	defer g.cancel()
	spec := sourceSpec{argv: opts.argv, env: opts.env, shape: opts.shape, timeout: opts.timeout}
	var outcomes []conformOutcome
	for _, c := range cases {
		if ctx.Err() != nil {
			fmt.Fprintf(stderr, "adapter-conform: interrupted after %d of %d case(s)\n", len(outcomes), len(cases))
			return 2
		}
		class, reason := conformOne(g, spec, c)
		outcomes = append(outcomes, conformOutcome{c, class, reason})
	}
	unexpected := 0
	for _, o := range outcomes {
		if o.unexpected() {
			unexpected++
		}
	}
	if opts.json {
		writeConformJSON(stdout, opts.shape, outcomes, unexpected)
	} else {
		writeConformText(stdout, opts.shape, outcomes, unexpected)
	}
	if unexpected > 0 {
		return 1
	}
	return 0
}

// writeConformText is the report for a person: a line per case, the
// unexpected ones marked, and the count.
func writeConformText(w io.Writer, shape string, outcomes []conformOutcome, unexpected int) {
	fmt.Fprintf(w, "gateway adapter-conform: shape %s, %d case(s)\n", shape, len(outcomes))
	for _, o := range outcomes {
		line := printableText(o.name) + ": " + o.result()
		if o.reason != "" {
			line += ": " + printableText(o.reason)
		}
		if o.unexpected() {
			line = "UNEXPECTED " + line + " (expected " + o.expect + ")"
		}
		fmt.Fprintln(w, "  "+line)
	}
	fmt.Fprintf(w, "%d case(s), %d unexpected\n", len(outcomes), unexpected)
}

// writeConformJSON is the report for a program, in canonical JSON:
// {"shape", "cases": [{"case", "expect", "outcome", "refusal"?, "reason"?,
// "unexpected"}], "unexpected"}, "refusal" (the class) and "reason" present
// when the outcome is "refused".
func writeConformJSON(w io.Writer, shape string, outcomes []conformOutcome, unexpected int) {
	cases := vArray{}
	for _, o := range outcomes {
		c := newObject()
		c.set("case", vString(printableText(o.name)))
		c.set("expect", vString(o.expect))
		c.set("outcome", vString(o.outcome()))
		if o.refusal != "" {
			c.set("refusal", vString(o.refusal))
			c.set("reason", vString(printableText(o.reason)))
		}
		c.set("unexpected", vBool(o.unexpected()))
		cases = append(cases, c)
	}
	report := newObject()
	report.set("shape", vString(shape))
	report.set("cases", cases)
	report.set("unexpected", vInt(unexpected))
	// exactly the canonical bytes, as gateway canon writes them
	_, _ = w.Write(canon(report))
}
