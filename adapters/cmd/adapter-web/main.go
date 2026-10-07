// adapter-web reads public HTTPS pages or discovers a bounded website through the gateway.
package main

import (
	"adapters/connections"
	"adapters/websource"
	"context"
	"fmt"
	"io"
	"os"
)

func main() { os.Exit(run()) }
func run() int {
	discover := len(os.Args) == 2 && os.Args[1] == "--discover"
	// --document-processing: a read may run the operator's OCR processor.
	processing := len(os.Args) == 2 && os.Args[1] == "--document-processing"
	if len(os.Args) != 1 && !discover && !processing {
		return 2
	}
	raw, err := io.ReadAll(io.LimitReader(os.Stdin, 8193))
	if err != nil || len(raw) > 8192 {
		fmt.Fprintln(os.Stderr, "web-invalid-request")
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
		out, err = websource.Read(ctx, raw)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		return 1
	}
	if _, err = os.Stdout.Write(out); err != nil {
		return 1
	}
	return 0
}
