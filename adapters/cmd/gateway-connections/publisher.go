package main

import (
	"adapters/connections"
	"bytes"
	_ "embed"
)

// Release tooling replaces this file in an isolated build tree. The repository
// ships no real registration. Embedding keeps the publisher configuration under
// the companion binary's checksum, outside browser and project configuration.
//
//go:embed publisher-google.json
var publisherRegistration []byte

func publisherClient(raw []byte) (connections.Client, error) {
	if bytes.Equal(bytes.TrimSpace(raw), []byte("{}")) {
		return connections.Client{}, nil
	}
	return connections.ParseGoogleDesktopClient(raw)
}
