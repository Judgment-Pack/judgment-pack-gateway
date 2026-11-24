//go:build !unix

package main

import "os"

// approvalOpenFlags opens an approval record where no flag refuses a link
// at it: the look before the open (os.Lstat) refuses one, and the file
// opened is held to be the file looked at. The engine configuration that
// names approvalRecords runs only on a Unix filesystem (engine_other.go).
const approvalOpenFlags = os.O_RDONLY
