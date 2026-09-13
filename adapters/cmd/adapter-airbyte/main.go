// Command adapter-airbyte is the gateway's Airbyte-shaped adapter, spawned
// by `gateway serve` as a source declared with `--source-shape NAME=airbyte`
// (SPEC.md §6). It reads the canonical arguments on stdin, runs the pinned
// connector image through the operator's container runtime, and writes one
// envelope on stdout.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"adapters/airbyte"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("adapter-airbyte", flag.ContinueOnError)
	fs.SetOutput(stderr)
	image := fs.String("image", "", "pinned connector image, name[:tag]@sha256:<64 hex> (required)")
	credentials := fs.String("credentials", "", "path of the connector's configuration JSON (required)")
	runtime := fs.String("runtime", "docker", "container runtime command: docker or podman")
	endpoint := fs.String("endpoint", "", "the host the connector reaches, as the operator names it; recorded as the receipt's endpoint")
	maxRecords := fs.Int("max-records", 10000, "cap on records read in one acquisition")
	maxOutput := fs.Int64("max-output", 1<<20, "bound on the envelope in bytes; keep it at or below the gateway's --source-max-output")
	timeout := fs.Duration("timeout", 20*time.Second, "time allowed for reading; stopping the container takes up to seven seconds more, and the sum stays under the gateway's thirty, so a slow connector is reported rather than killed")
	check := fs.Bool("check", false, "run the connector's check with the credentials and report what the platform answered on stdout, instead of reading a request and a page; nothing is minted from the report")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 || *image == "" || *credentials == "" {
		fmt.Fprintln(stderr, "usage: adapter-airbyte --image REF@sha256:HEX --credentials FILE [--check] [--runtime docker|podman] [--endpoint HOST] [--max-records N] [--max-output BYTES] [--timeout D]")
		return 2
	}
	cfg := airbyte.Config{
		Runtime: *runtime, Image: *image, Credentials: *credentials, Endpoint: *endpoint,
		MaxRecords: *maxRecords, MaxOutput: *maxOutput,
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	var out []byte
	if *check {
		// No request is read: the check is the operator's, not an
		// acquisition, and stdin is whatever they left attached.
		report, err := airbyte.Check(ctx, cfg)
		if err != nil {
			// The reason goes to stdout as a report of the same shape,
			// for the caller that reads reports, and to stderr for the
			// operator; the exit status says the platform did not answer.
			fmt.Fprintln(stderr, "adapter-airbyte: check:", err)
			stdout.Write(airbyte.FailedCheck(err.Error()))
			return 1
		}
		out = report
	} else {
		req, err := airbyte.ParseRequest(stdin, *maxRecords)
		if err != nil {
			fmt.Fprintln(stderr, "adapter-airbyte:", err)
			return 1
		}
		envelope, err := airbyte.Acquire(ctx, cfg, req)
		if err != nil {
			fmt.Fprintln(stderr, "adapter-airbyte:", err)
			return 1
		}
		out = envelope
	}
	if _, err := stdout.Write(out); err != nil {
		fmt.Fprintln(stderr, "adapter-airbyte: write stdout:", err)
		return 1
	}
	return 0
}
