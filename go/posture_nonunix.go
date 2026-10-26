//go:build !unix

package main

// postureFamily names this platform's row of postureStatements.
const postureFamily = "windows"

// seedPosture is stated here: a seed's owner and mode are not checked on
// this platform (spawn_other.go, openSeed).
func seedPosture(in postureInput) postureLine {
	if line, ok := seedNotNamed(in); ok {
		return line
	}
	return postureStatements[postureFamily][protectionSeedFile]
}
