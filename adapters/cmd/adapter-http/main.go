// Command adapter-http is the gateway's HTTP-shaped adapter, spawned by
// `gateway serve` as a source declared with `--source-shape NAME=http`
// (SPEC.md §6). It reads the canonical arguments on stdin -- which path
// under the endpoint, by which method, with what query and body -- sends
// that one request with the credential it holds, and writes one envelope
// on stdout.
package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"adapters/httpsource"
	"adapters/internal/redact"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

// repeated is a flag given more than once, each value kept in order: a
// header per --header, since a header's value may carry a comma.
type repeated []string

func (r *repeated) String() string     { return strings.Join(*r, " ") }
func (r *repeated) Set(v string) error { *r = append(*r, v); return nil }

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("adapter-http", flag.ContinueOnError)
	// Flag diagnostics are the operator's own command line quoted back, and
	// they are bounded before they are written: a credential belongs in the
	// credentials file and never on this line, and the redactor cannot yet
	// know one, since the file's path is what the flags name.
	var flagOut bytes.Buffer
	fs.SetOutput(&flagOut)
	defer func() {
		if flagOut.Len() > 0 {
			fmt.Fprint(stderr, redact.Diagnostic(flagOut.String(), false, nil))
		}
	}()
	endpoint := fs.String("endpoint", "", "base URL every request is sent under: https, or http on a loopback host (required)")
	credentials := fs.String("credentials", "", "path of a JSON object of strings holding the endpoint's credential")
	bearer := fs.String("bearer", "", "the credentials member sent as Authorization: Bearer")
	credentialHeader := fs.String("credential-header", "", "NAME=MEMBER: the header NAME sent with that credentials member as its value")
	var headers repeated
	fs.Var(&headers, "header", "NAME=VALUE sent on every request; may be given more than once")
	paths := fs.String("paths", "", "the only paths a request may name, comma-separated (required)")
	methods := fs.String("methods", "POST", "the methods a request may name, comma-separated: GET, POST")
	maxOutput := fs.Int64("max-output", 1<<20, "bound on the envelope in bytes; keep it at or below the gateway's --source-max-output")
	timeout := fs.Duration("timeout", 20*time.Second, "time allowed for the request, under the gateway's thirty seconds")
	caFile := fs.String("ca-file", "", "PEM file of the only roots trusted for the endpoint, instead of the system's")
	check := fs.Bool("check", false, "hold the configuration and credentials to their rules and reach the endpoint, then report on stdout instead of reading a request; nothing is minted from the report")
	checkPath := fs.String("check-path", "", "with --check, a path to GET, which must answer 2xx; without it the check is the TLS handshake alone")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 || *endpoint == "" || *paths == "" {
		fmt.Fprintln(stderr, "usage: adapter-http --endpoint URL --paths /A,/B [--check [--check-path /P]] [--credentials FILE (--bearer MEMBER | --credential-header NAME=MEMBER)] [--header NAME=VALUE]... [--methods GET,POST] [--ca-file FILE] [--max-output BYTES] [--timeout D]")
		return 2
	}
	if *checkPath != "" && !*check {
		fmt.Fprintln(stderr, "adapter-http: --check-path is for --check")
		return 2
	}
	cfg := httpsource.Config{
		Endpoint: *endpoint, Credentials: *credentials, Bearer: *bearer, CredentialHeader: *credentialHeader,
		Headers: headers, Paths: split(*paths), Methods: split(*methods), MaxOutput: *maxOutput, CAFile: *caFile,
		CheckPath: *checkPath,
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	// One boundary for every diagnostic this command writes: redacted against
	// every scalar of the credentials file, and bounded. A diagnostic raised
	// before the acquisition was prepared -- a request naming a member after
	// the credential, a configuration refused for a path -- crosses it too.
	secrets := httpsource.Secrets(cfg)
	diagnostic := func(err error) string { return redact.Diagnostic(err.Error(), false, secrets) }
	var out []byte
	if *check {
		// No request is read: the check is the operator's, not an
		// acquisition, and stdin is whatever they left attached.
		report, err := httpsource.Check(ctx, cfg)
		if err != nil {
			// The reason goes to stdout as a report of the same shape,
			// for the caller that reads reports, and to stderr for the
			// operator; the exit status says the endpoint did not answer.
			reason := diagnostic(err)
			fmt.Fprintln(stderr, "adapter-http: check:", reason)
			stdout.Write(httpsource.FailedCheck(reason))
			return 1
		}
		out = report
	} else {
		req, err := httpsource.ParseRequest(stdin)
		if err != nil {
			fmt.Fprintln(stderr, "adapter-http:", diagnostic(err))
			return 1
		}
		envelope, err := httpsource.Acquire(ctx, cfg, req)
		if err != nil {
			fmt.Fprintln(stderr, "adapter-http:", diagnostic(err))
			return 1
		}
		out = envelope
	}
	if _, err := stdout.Write(out); err != nil {
		fmt.Fprintln(stderr, "adapter-http: write stdout:", err)
		return 1
	}
	return 0
}

// split divides a comma-separated list, dropping empty items.
func split(list string) []string {
	var out []string
	for _, item := range strings.Split(list, ",") {
		if item = strings.TrimSpace(item); item != "" {
			out = append(out, item)
		}
	}
	return out
}
