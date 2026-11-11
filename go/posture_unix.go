//go:build unix

package main

import (
	"errors"
	"os"
)

// postureFamily names this platform's row of postureStatements; on Linux
// nothing is read from it.
const postureFamily = "unix"

// seedPosture holds the seed file to what serve holds it to at start
// (verifySeedInfo): a regular file, owned by this process's user,
// readable by nobody else.
func seedPosture(in postureInput) postureLine {
	if line, ok := seedNotNamed(in); ok {
		return line
	}
	return judgeSeed(in.seed, seedStatPath, os.Geteuid(), in.public)
}

// judgeSeed reads the seed as openSeed opens it -- through a link to the
// file it names -- and holds it to verifySeedInfo; a public reason names
// no path, and no owner, uid or mode.
func judgeSeed(path string, stat func(string) (os.FileInfo, error), euid int, public bool) postureLine {
	line := func(state, reason string) postureLine { return postureLine{protectionSeedFile, state, reason} }
	info, err := stat(path)
	if err != nil {
		if public {
			return line(postureNotEnforced, "the seed file could not be examined: "+pathless(err))
		}
		return line(postureNotEnforced, "the seed could not be examined: "+err.Error())
	}
	if err := verifySeedInfo(info, euid); err != nil {
		if public {
			return line(postureNotEnforced, publicSeedRefusal(err))
		}
		return line(postureNotEnforced, "serve refuses this seed: "+err.Error())
	}
	return line(postureEnforced, "the seed is a regular file owned by the signer's user and readable by nobody else by its mode bits, which do not show an access-control list")
}

// publicSeedRefusal is the seed line's reason for a seed serve refuses, as
// /posture answers it: a fixed sentence chosen by what verifySeedInfo
// refused, never its text, which names the file's owner, the gateway's uid
// and the file's mode. gateway posture, run by the operator, keeps that text.
func publicSeedRefusal(err error) string {
	switch {
	case errors.Is(err, errSeedNotRegular):
		return "serve refuses this seed: it is not a regular file"
	case errors.Is(err, errSeedOwner):
		return "serve refuses this seed: it is not owned by the gateway's own user"
	case errors.Is(err, errSeedPermissions):
		return "serve refuses this seed: it is readable by group or other"
	}
	return "serve refuses this seed; gateway posture, given the configuration, says why"
}
