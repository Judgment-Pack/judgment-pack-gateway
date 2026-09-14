//go:build ignore

// setcap writes the file capabilities the engine image gives the gateway
// binary: CAP_SETUID, CAP_SETGID and CAP_KILL, permitted and effective,
// nothing inheritable -- what the signer needs to switch each adapter to
// its platform's user and to stop it afterwards, and no more
// (docs/design/engine-config.md, SECURITY.md). It is run in the image's
// builder stage (Dockerfile) and writes the kernel's own attribute, so
// the builder needs no package for it. Not part of either module.
package main

import (
	"encoding/binary"
	"os"
	"syscall"
)

func main() {
	// VFS_CAP_REVISION_2 with the effective flag; permitted = SETUID (7),
	// SETGID (6), KILL (5); nothing inheritable.
	data := make([]byte, 20)
	binary.LittleEndian.PutUint32(data[0:], 0x02000001)
	binary.LittleEndian.PutUint32(data[4:], 1<<7|1<<6|1<<5)
	if err := syscall.Setxattr(os.Args[1], "security.capability", data, 0); err != nil {
		panic(err)
	}
}
