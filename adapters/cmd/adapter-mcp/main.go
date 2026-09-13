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
	image := fs.String("image", "", "pinned server image, name[:tag]@sha256:<64 hex>; or use --command")
	command := fs.String("command", "", "a local server command with its arguments, quoted as one value; or use --image")
	credentials := fs.String("credentials", "", "path of a JSON object of strings that become the server's environment")
	runtime := fs.String("runtime", "docker", "container runtime command for --image: docker or podman")
	endpoint := fs.String("endpoint", "", "the host the server reaches, as the operator names it; recorded as the receipt's endpoint")
	tools := fs.String("tools", "", "the only tools a request may name, comma-separated; all offered when empty")
	maxOutput := fs.Int64("max-output", 1<<20, "bound on the envelope in bytes; keep it at or below the gateway's --source-max-output")
	timeout := fs.Duration("timeout", 20*time.Second, "time allowed for the call; stopping the server takes up to seven seconds more, under the gateway's thirty")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 || (*image == "") == (*command == "") {
		fmt.Fprintln(stderr, "usage: adapter-mcp (--image REF@sha256:HEX | --command 'CMD ARGS') [--credentials FILE] [--runtime docker|podman] [--endpoint HOST] [--tools A,B] [--max-output BYTES] [--timeout D]")
		return 2
	}
	req, err := mcp.ParseRequest(stdin)
	if err != nil {
		fmt.Fprintln(stderr, "adapter-mcp:", err)
		return 1
	}
	cfg := mcp.Config{Runtime: *runtime, Image: *image, Credentials: *credentials, Endpoint: *endpoint, MaxOutput: *maxOutput}
	if *command != "" {
		cfg.Command = strings.Fields(*command)
	}
	if *tools != "" {
		cfg.Tools = strings.Split(*tools, ",")
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	out, err := mcp.Acquire(ctx, cfg, req)
	if err != nil {
		fmt.Fprintln(stderr, "adapter-mcp:", err)
		return 1
	}
	if _, err := stdout.Write(out); err != nil {
		fmt.Fprintln(stderr, "adapter-mcp: write stdout:", err)
		return 1
	}
	return 0
}
