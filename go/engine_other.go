//go:build !unix

package main

import (
	"errors"
	"os"
)

func credentialsOwnerOf(path string) (int, os.FileMode, error) {
	return 0, 0, errors.New("the engine configuration's isolation checks need a Unix filesystem; run the engine on Linux")
}

func userIDOf(name string) (int, error) {
	return 0, errors.New("the engine configuration needs OS users to run adapters as, which this platform does not switch to")
}

func engineEUID() int { return -1 }
