//go:build !unix

package httpsource

import "io/fs"

// federatedOpenFlags are none here: there is no flag that refuses a link
// at the name, and no FIFO to block on.
const federatedOpenFlags = 0

// ownerOf is -1: the system reports no uid, so the walk holds neither the
// owner nor the permission bits (openFederatedToken).
func ownerOf(fs.FileInfo) int { return -1 }

// ownUID is -1 for the same reason.
func ownUID() int { return -1 }
