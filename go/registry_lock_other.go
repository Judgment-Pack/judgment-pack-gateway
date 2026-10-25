//go:build !unix

package main

import "os"

// registryLocked is false elsewhere than Unix: nothing there locks a file
// through this module's standard library alone, as a witness's files are
// not kept there either (witness_log_other.go). The engine runs on Unix
// (docs/design/engine-config.md); a gateway served elsewhere holds no lock,
// and that the gateway is stopped while its key rotates is its operator's
// to see to.
const registryLocked = false

func lockRegistry(path string) (*os.File, error) { return nil, nil }
