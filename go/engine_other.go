//go:build !unix

package main

import "errors"

func fileOwnerOf(path string) (fileOwnership, error) {
	return fileOwnership{}, errors.New("the engine configuration's isolation checks need a Unix filesystem; run the engine on Linux")
}

func accountOf(name string) (int, string, error) {
	return 0, "", errors.New("the engine configuration needs OS users to run adapters as, which this platform does not switch to; run the engine on Linux")
}

func osEngineHost() engineHost {
	return engineHost{euid: -1, sockets: hostRuntimeSockets, fileOwner: fileOwnerOf, account: accountOf}
}
