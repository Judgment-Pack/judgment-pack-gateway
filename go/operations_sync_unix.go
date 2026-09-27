//go:build unix

package main

import "os"

const durableOperationsSupported = true

// Unlike receipt cleanup, admission must fail closed on a directory sync error:
// losing an acknowledged claim could otherwise repeat an external operation.
func syncOperationDirectory(path string) error {
	root, err := os.OpenRoot(path)
	if err != nil {
		return err
	}
	defer root.Close()
	return syncDirectory(root, ".")
}
