// Command adapter-mcp is the gateway's MCP-shaped adapter, spawned by
// `gateway serve` as a source declared with `--source-shape NAME=mcp`
// (SPEC.md §6). It reads the canonical arguments on stdin -- which tool,
// with what arguments -- calls that tool on the configured server over
// stdio, and writes one envelope on stdout.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"adapters/mcp"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("adapter-mcp", flag.ContinueOnError)
	fs.SetOutput(stderr)
	image := fs.String("image", "", "pinned server image, name[:tag]@sha256:<64 hex>; or give a local server command after --")
	credentials := fs.String("credentials", "", "path of a JSON object of strings that become the server's environment")
	runtime := fs.String("runtime", "docker", "container runtime command for --image: docker or podman")
	endpoint := fs.String("endpoint", "", "the host the server reaches, as the operator names it; recorded as the receipt's endpoint")
	tools := fs.String("tools", "", "the only tools a request may name, comma-separated; all offered when empty")
	errorResults := fs.Bool("error-results", false, "envelope a tool result that reports an error as the result of the call instead of failing: what an executor needs, since a target's refusal of a write is a response to receipt")
	maxOutput := fs.Int64("max-output", 1<<20, "bound on the envelope in bytes; keep it at or below the gateway's --source-max-output")
	timeout := fs.Duration("timeout", 20*time.Second, "time allowed for the call; stopping the server takes up to nine seconds more (seven for a --command server), under the gateway's default source timeout of thirty seconds; keep the sum under the source's --source-timeout when the gateway sets one")
	check := fs.Bool("check", false, "start the server, complete the handshake and list its tools, then report on stdout instead of reading a request and calling; nothing is minted from the report")
	probe := fs.String("probe", "", "with --check, a tool to call once with no arguments, so a server that lists its tools without reaching its platform is found out; its result is read for an error and discarded")
	probeFailure := fs.String("probe-failure", "", "with --probe, text the probe's answer begins with when the platform was not reached, for a server that answers its own failure as ordinary text")
	descriptorsPlatform := fs.String("descriptors-platform", "", "with --check and --descriptors-binding, capture the allowed tools' descriptions and input schemas, and the server's identity, into the report's snapshot for this platform (docs/design/tool-descriptors.md)")
	descriptorsBinding := fs.String("descriptors-binding", "", "with --descriptors-platform, the pinned binding the snapshot is captured for, name@sha256:<64 hex>")
	// The gateway splits a source command on whitespace and parses no
	// quotes, so what comes after "--" is given word by word: a server
	// command with its arguments, or, with --image, the server's own
	// arguments inside the container. Nothing else is positional, and the
	// line is split at its first "--" before the flags are parsed: parsed
	// together, a "--" could be consumed as a flag's value, and without
	// one Go's flag parsing would stop at the first word and hand every
	// later flag to the server, silently.
	flags, positional := splitAtDelimiter(args)
	if err := fs.Parse(flags); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintln(stderr, "adapter-mcp: a server command or a server's arguments follow --; nothing else is positional")
		return 2
	}
	if *image == "" && len(positional) == 0 {
		fmt.Fprintln(stderr, "usage: adapter-mcp (--image REF@sha256:HEX [-- SERVER ARGS...] | [options] -- CMD ARGS...) [--check] [--credentials FILE] [--runtime docker|podman] [--endpoint HOST] [--tools A,B] [--max-output BYTES] [--timeout D]")
		return 2
	}
	cfg := mcp.Config{Runtime: *runtime, Image: *image, Credentials: *credentials, Endpoint: *endpoint, MaxOutput: *maxOutput}
	if *image != "" {
		cfg.Args = positional
	} else {
		cfg.Command = positional
	}
	cfg.ErrorResults = *errorResults
	if *tools != "" {
		cfg.Tools = strings.Split(*tools, ",")
	}
	if (*probe != "" && !*check) || (*probeFailure != "" && *probe == "") {
		fmt.Fprintln(stderr, "adapter-mcp: --probe is for --check, and --probe-failure for --probe")
		return 2
	}
	cfg.Probe, cfg.ProbeFailure = *probe, *probeFailure
	if (*descriptorsPlatform != "") != (*descriptorsBinding != "") || (*descriptorsPlatform != "" && !*check) {
		fmt.Fprintln(stderr, "adapter-mcp: --descriptors-platform and --descriptors-binding go together, and with --check")
		return 2
	}
	if *descriptorsPlatform != "" {
		cfg.Descriptors = &mcp.DescriptorTarget{Platform: *descriptorsPlatform, Binding: *descriptorsBinding}
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	var out []byte
	if *check {
		// No request is read: the check is the operator's, not an
		// acquisition, and stdin is whatever they left attached.
		report, err := mcp.Check(ctx, cfg)
		if err != nil {
			// The reason goes to stdout as a report of the same shape,
			// for the caller that reads reports, and to stderr for the
			// operator; the exit status says the platform did not answer.
			fmt.Fprintln(stderr, "adapter-mcp: check:", err)
			stdout.Write(mcp.FailedCheck(err.Error()))
			return 1
		}
		out = report
	} else {
		req, err := mcp.ParseRequest(stdin)
		if err != nil {
			fmt.Fprintln(stderr, "adapter-mcp:", err)
			return 1
		}
		envelope, err := mcp.Acquire(ctx, cfg, req)
		if err != nil {
			fmt.Fprintln(stderr, "adapter-mcp:", err)
			return 1
		}
		out = envelope
	}
	if _, err := stdout.Write(out); err != nil {
		fmt.Fprintln(stderr, "adapter-mcp: write stdout:", err)
		return 1
	}
	return 0
}

// splitAtDelimiter divides the command line at its first "--": the
// adapter's flags before it, the server's words after it.
func splitAtDelimiter(args []string) (flags, positional []string) {
	for i, a := range args {
		if a == "--" {
			return args[:i], args[i+1:]
		}
	}
	return args, nil
}
