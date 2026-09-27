//go:build !unix

package main

import "errors"

const durableOperationsSupported = false

func syncOperationDirectory(string) error {
	return errors.New("durable operations require Unix directory synchronization; use synchronous acquisition on this platform")
}
