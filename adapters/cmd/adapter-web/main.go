// adapter-web reads public HTTPS pages or discovers a bounded website through the gateway.
package main

import (
	"adapters/connections"
	"adapters/websource"
	"context"
	"fmt"
	"io"
	"os"
	"strings"
)

func main() { os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr)) }

// run takes its configuration from the operator's command line alone:
// --discover, or a read with --document-processing (a read may run the
// operator's OCR processor) and --redirect-policies=LIST (the cross-origin
// redirects a read may follow, docs/design/public-web-sources.md). Each at
// most once, in one word. Discovery follows no redirect policy and refuses
// the flag rather than ignore it. A list that names a policy this adapter
// does not support refuses the start, in one sentence, before stdin is read.
func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	discover, processing, policiesGiven := false, false, false
	policiesValue := ""
	for _, arg := range args {
		switch {
		case arg == "--discover" && !discover:
			discover = true
		case arg == "--document-processing" && !processing:
			processing = true
		case strings.HasPrefix(arg, connections.WebRedirectPoliciesFlag) && !policiesGiven:
			policiesGiven, policiesValue = true, strings.TrimPrefix(arg, connections.WebRedirectPoliciesFlag)
		default:
			return 2
		}
	}
	if discover && (processing || policiesGiven) {
		return 2
	}
	policies, err := connections.ParseWebRedirectPolicies(policiesValue)
	if err != nil {
		fmt.Fprintln(stderr, connections.WebRedirectPolicyRefusal)
		return 2
	}
	raw, err := io.ReadAll(io.LimitReader(stdin, 8193))
	if err != nil || len(raw) > 8192 {
		fmt.Fprintln(stderr, "web-invalid-request")
		return 1
	}
	var out []byte
	if discover {
		out, err = websource.Discover(context.Background(), raw)
	} else {
		ctx := context.Background()
		if processing {
			ctx = connections.WithDocumentProcessing(ctx)
		}
		out, err = websource.ReadWith(ctx, raw, websource.Options{RedirectPolicies: policies})
	}
	if err != nil {
		fmt.Fprintln(stderr, websource.RefusalLine(err))
		return 1
	}
	if _, err = stdout.Write(out); err != nil {
		return 1
	}
	return 0
}
