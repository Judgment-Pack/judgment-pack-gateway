//go:build ignore

// probe is CI's hand for what an exported filesystem cannot show: run
// inside the image as a given user, it tries to create the path it is
// given and reports the outcome, so that the root directory -- which no
// export carries -- is held by the act, for the signer and for every
// platform user. It is built by CI, mounted read-only, and never part of
// the image. Not part of either module.
package main

import (
	"fmt"
	"os"
)

func main() {
	f, err := os.OpenFile(os.Args[1], os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		fmt.Println("probe: refused:", err)
		os.Exit(3)
	}
	f.Close()
	os.Remove(os.Args[1])
	fmt.Println("probe: created", os.Args[1])
}
