//go:build !unix

package main

import (
	"errors"
	"fmt"
	"os"
)

// openRegular opens a path and judges the descriptor it got; there is no
// FIFO to block on here.
func openRegular(path string) (*os.File, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		file.Close()
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	return file, nil
}

func fileOwnerOf(path string) (fileOwnership, error) {
	return fileOwnership{}, errors.New("the engine configuration's isolation checks need a Unix filesystem; run the engine on Linux")
}

func accountOf(name string) (int, string, error) {
	return 0, "", errors.New("the engine configuration needs OS users to run adapters as, which this platform does not switch to; run the engine on Linux")
}

func osEngineHost() engineHost {
	return engineHost{euid: -1, sockets: hostRuntimeSockets, fileOwner: fileOwnerOf, readLink: os.Readlink, account: accountOf, switching: requireUserSwitching, executable: executableFacts}
}
