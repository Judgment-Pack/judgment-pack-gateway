//go:build ignore

// mkhomes makes the users' homes inside the engine image's final stage,
// each its user's alone: mode 0700, owned by that user and its group. It
// runs there, as root, before USER engine, because a directory COPY lands
// its destination at the builder's default mode whatever the source had
// and whatever --chmod says of the files inside, and the builders differ
// in what they honour; a directory made in place is the same on every
// builder. It removes its own binary when done, so the final filesystem
// carries no helper. Not part of either module.
package main

import (
	"fmt"
	"os"
)

func main() {
	homes := map[string]int{"/home/engine": 65532}
	for n := 1; n <= 8; n++ {
		homes[fmt.Sprintf("/home/engine-%d", n)] = 65600 + n
	}
	for path, uid := range homes {
		if err := os.MkdirAll(path, 0o700); err != nil {
			panic(err)
		}
		if err := os.Chmod(path, 0o700); err != nil {
			panic(err)
		}
		if err := os.Lchown(path, uid, uid); err != nil {
			panic(err)
		}
	}
	if err := os.Remove(os.Args[0]); err != nil {
		panic(err)
	}
}
