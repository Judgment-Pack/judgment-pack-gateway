// adapter-web reads one explicitly selected public HTTPS page through the gateway.
package main

import (
	"adapters/websource"
	"context"
	"fmt"
	"io"
	"os"
)

func main() { os.Exit(run()) }
func run() int {
	if len(os.Args) != 1 {
		return 2
	}
	raw, err := io.ReadAll(io.LimitReader(os.Stdin, 8193))
	if err != nil || len(raw) > 8192 {
		fmt.Fprintln(os.Stderr, "web-invalid-request")
		return 1
	}
	out, err := websource.Read(context.Background(), raw)
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		return 1
	}
	if _, err = os.Stdout.Write(out); err != nil {
		return 1
	}
	return 0
}
