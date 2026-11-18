// Command adapter-gcp-asset is the gateway's read-only Cloud Asset
// Inventory adapter, spawned by `gateway serve --config` for a binding of
// the gcp-asset shape (SPEC.md §6, docs/adr/0039 and its Amendment). It
// reads the canonical arguments on stdin -- which configured project, which
// content type, which asset types and which page -- makes that one list
// call, and writes one envelope on stdout holding the page projected.
//
// Beside 1 (any other failure) and 2 (usage), it exits 3 to 6 as the token
// step does, 8 with {"referenceExpired":{"status":410}} on stdout for an
// expired page token, and 9 with {"refused":{"reason":R,"subject":S}} on
// stdout for a read-only refusal, on which the gateway closes the source.
// A check that could not finish -- a call brought back no answer, because
// its --timeout or a request's own time ended or the connection failed --
// is no refusal: it exits 1, and the gateway, which passes the time left
// on the acquisition less a margin as --timeout, fails that start or
// refresh without closing the source.
//
// With --groups-resolve (the Amendment for gateway #496), the groups an
// IAM_POLICY page's bindings outside the read-only list name are resolved:
// a principal found exits 9 as a direct binding does; an acquisition
// writes {"envelope": E, "groupBindings": {"unresolved": N, "reason": R}}
// on stdout, the count of groups left unresolved and the last one's
// reason; and under --groups-unresolved=refuse a page with a group
// unresolved exits 1, never 9, with {"groupUnresolved": {"reason": R,
// "groups": N}} on stdout and the reason alone on stderr, and the gateway
// does not close the source.
package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"adapters/gcpasset"
	"adapters/internal/redact"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("adapter-gcp-asset", flag.ContinueOnError)
	// A flag diagnostic quotes the command line back, bounded; a credential
	// belongs in the credentials file and never on this line.
	var flagOut bytes.Buffer
	fs.SetOutput(&flagOut)
	writeFlagDiagnostic := func() {
		if flagOut.Len() > 0 {
			fmt.Fprint(stderr, redact.Diagnostic(flagOut.String(), false, nil))
			flagOut.Reset()
		}
	}
	defer writeFlagDiagnostic()
	fs.Usage = func() {
		writeFlagDiagnostic()
		fmt.Fprintln(stderr, "Usage of adapter-gcp-asset:")
		fs.SetOutput(stderr)
		fs.PrintDefaults()
		fs.SetOutput(&flagOut)
	}
	parents := fs.String("parents", "", "the projects a request may name, comma-separated, each projects/<project-id> (required)")
	assetTypes := fs.String("asset-types", "", "the asset types a request may name, comma-separated, each one this version projects (required)")
	contentTypes := fs.String("content-types", "", "RESOURCE, IAM_POLICY or both, comma-separated (required)")
	members := fs.String("members", "", `"count-users" to carry the count of a binding's user members in place of them; not given, members are carried as written`)
	tokenSource := fs.String("token-source", "", `"metadata" (the metadata server of the platform's own compute) or "key" (a service account's key) (required)`)
	credentials := fs.String("credentials", "", "path of the platform's live credentials file: the service account's key for --token-source=key, an object holding sealKey for --token-source=metadata (required)")
	maxOutput := fs.Int64("max-output", 1<<20, "bound on the envelope in bytes; keep it at or below the gateway's source output bound")
	maxAnswer := fs.Int64("max-answer", gcpasset.DefaultMaxAnswer, "bound on the list call's answer in bytes, as read and before it is projected")
	timeout := fs.Duration("timeout", 20*time.Second, "time allowed for the run; the gateway passes the time left on the acquisition, less a margin for the start and the report. A read-only check this, a request's time or a failed connection leaves without an answer exits 1, not 9")
	check := fs.Bool("check", false, "obtain both tokens, hold their scopes and run the write check on every configured project, then report on stdout instead of reading a request")
	groupsResolve := fs.Bool("groups-resolve", false, "resolve the groups an IAM_POLICY page's bindings outside the read-only list name, with a third token of scope "+gcpasset.GroupsScope)
	groupsDepth := fs.Int("groups-depth", gcpasset.DefaultGroupDepth, "with --groups-resolve: the nested group levels read below a group a binding names, 0 to 4")
	groupsMembers := fs.Int("groups-members", gcpasset.DefaultGroupMembers, "with --groups-resolve: the memberships read for one acquisition, 1 to 50000")
	groupsUnresolved := fs.String("groups-unresolved", gcpasset.UnresolvedServe, `with --groups-resolve: "serve" a page with a group unresolved and report it, or "refuse" it`)
	tokenOnly := fs.Bool("token-only", false, "obtain both tokens, hold their scopes, run the write check, and write the list token on stdout sealed, instead of reading a request; an acquisition is then handed it in "+gcpasset.SealedTokenVariable)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 || *parents == "" || *assetTypes == "" || *contentTypes == "" || *tokenSource == "" || *credentials == "" {
		fmt.Fprintln(stderr, "usage: adapter-gcp-asset --parents projects/P[,...] --asset-types T[,...] --content-types RESOURCE[,IAM_POLICY] --token-source metadata|key --credentials FILE [--members count-users] [--groups-resolve [--groups-depth N] [--groups-members N] [--groups-unresolved serve|refuse]] [--max-output BYTES] [--max-answer BYTES] [--timeout D] [--check | --token-only]")
		return 2
	}
	if *tokenOnly && *check {
		fmt.Fprintln(stderr, "adapter-gcp-asset: --token-only and --check are two runs")
		return 2
	}
	groupFlag := false
	fs.Visit(func(f *flag.Flag) {
		if strings.HasPrefix(f.Name, "groups-") && f.Name != "groups-resolve" {
			groupFlag = true
		}
	})
	if groupFlag && !*groupsResolve {
		fmt.Fprintln(stderr, "adapter-gcp-asset: --groups-depth, --groups-members and --groups-unresolved are settings of --groups-resolve")
		return 2
	}
	cfg := gcpasset.Config{
		Parents: split(*parents), AssetTypes: split(*assetTypes), ContentTypes: split(*contentTypes),
		Members: *members, TokenSource: *tokenSource, Credentials: *credentials,
		MaxOutput: *maxOutput, MaxAnswer: *maxAnswer,
	}
	if *groupsResolve {
		cfg.Groups = gcpasset.Groups{Resolve: true, Depth: *groupsDepth, Members: *groupsMembers, Unresolved: *groupsUnresolved}
	}
	// A sealed token is for an acquisition; a check and a token-only run
	// obtain and check their own.
	if !*check && !*tokenOnly {
		cfg.SealedToken = os.Getenv(gcpasset.SealedTokenVariable)
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	secrets := gcpasset.Secrets(cfg)
	if cfg.SealedToken != "" {
		secrets = append(secrets, cfg.SealedToken)
	}
	diagnostic := func(err error) string { return redact.Diagnostic(err.Error(), false, secrets) }
	failed := func(err error) int {
		var refused *gcpasset.Refused
		if errors.As(err, &refused) {
			stdout.Write(refused.Report())
			return gcpasset.RefusedStatus
		}
		var expired *gcpasset.ReferenceExpired
		if errors.As(err, &expired) {
			stdout.Write(expired.Report())
			return gcpasset.ReferenceExpiredStatus
		}
		var unresolved *gcpasset.GroupUnresolved
		if errors.As(err, &unresolved) {
			stdout.Write(unresolved.Report())
			return 1
		}
		var failure *gcpasset.TokenFailure
		if errors.As(err, &failure) {
			return failure.Kind
		}
		return 1
	}
	var out []byte
	switch {
	case *tokenOnly:
		sealed, err := gcpasset.ObtainSealed(ctx, cfg)
		if err != nil {
			fmt.Fprintln(stderr, "adapter-gcp-asset: token:", diagnostic(err))
			return failed(err)
		}
		out = sealed
	case *check:
		report, err := gcpasset.Check(ctx, cfg)
		if err != nil {
			reason := diagnostic(err)
			fmt.Fprintln(stderr, "adapter-gcp-asset: check:", reason)
			var refused *gcpasset.Refused
			if errors.As(err, &refused) {
				stdout.Write(refused.Report())
				return gcpasset.RefusedStatus
			}
			stdout.Write(gcpasset.FailedCheck(reason))
			return 1
		}
		out = report
	default:
		req, err := gcpasset.ParseRequest(stdin)
		if err != nil {
			fmt.Fprintln(stderr, "adapter-gcp-asset:", diagnostic(err))
			return 1
		}
		envelope, err := gcpasset.Acquire(ctx, cfg, req)
		if err != nil {
			fmt.Fprintln(stderr, "adapter-gcp-asset:", diagnostic(err))
			return failed(err)
		}
		out = envelope
	}
	if _, err := stdout.Write(out); err != nil {
		fmt.Fprintln(stderr, "adapter-gcp-asset: write stdout:", err)
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
