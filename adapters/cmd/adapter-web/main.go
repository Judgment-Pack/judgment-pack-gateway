// adapter-web reads public HTTPS pages or discovers a bounded website through the gateway.
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
	discover := len(os.Args) == 2 && os.Args[1] == "--discover"
	if len(os.Args) != 1 && !discover {
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
		out, err = websource.Read(context.Background(), raw)
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
