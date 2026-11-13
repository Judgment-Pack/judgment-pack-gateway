//go:build unix

package httpsource

import (
	"io/fs"
	"os"
	"syscall"
)

// federatedOpenFlags open the federated token file without following a
// link at its name and without blocking on a FIFO put there.
const federatedOpenFlags = syscall.O_NOFOLLOW | syscall.O_NONBLOCK

// ownerOf is the uid owning what info describes, -1 when it is not known.
func ownerOf(info fs.FileInfo) int {
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		return int(st.Uid)
	}
	return -1
}

// ownUID is the user the adapter runs as.
func ownUID() int { return os.Geteuid() }
