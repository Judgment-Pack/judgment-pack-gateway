//go:build unix

package main

import (
	"fmt"
	"os"
	"os/user"
	"strconv"
	"syscall"
)

// fileOwnerOf is who owns a file, a directory or a symbolic link and how it
// is protected, as the filesystem reports them of that entry itself: a link
// is judged as a link, by its owner, and its target through the resolved
// chain.
func fileOwnerOf(path string) (fileOwnership, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return fileOwnership{}, err
	}
	link := info.Mode()&os.ModeSymlink != 0
	if !link && !info.Mode().IsRegular() && !info.IsDir() {
		return fileOwnership{}, fmt.Errorf("%s is neither a regular file nor a directory", path)
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fileOwnership{}, fmt.Errorf("%s: ownership could not be determined", path)
	}
	return fileOwnership{uid: int(st.Uid), mode: info.Mode().Perm(), dir: info.IsDir(), link: link, sticky: info.Mode()&os.ModeSticky != 0}, nil
}

// accountOf is the uid and home directory of a named OS user.
func accountOf(name string) (int, string, error) {
	account, err := user.Lookup(name)
	if err != nil {
		return 0, "", fmt.Errorf("user %q: %v", name, err)
	}
	uid, err := strconv.Atoi(account.Uid)
	if err != nil {
		return 0, "", fmt.Errorf("user %q: uid %q is not a number", name, account.Uid)
	}
	if account.HomeDir == "" {
		return 0, "", fmt.Errorf("user %q has no home directory, which a container runtime needs", name)
	}
	return uid, account.HomeDir, nil
}

// openRegular opens a path without blocking -- a FIFO put in a regular
// file's place would otherwise hold the open until a writer came -- and
// judges the descriptor it got: a regular file, or refused.
func openRegular(path string) (*os.File, error) {
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
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

// osEngineHost is the operating system as the engine's host.
func osEngineHost() engineHost {
	return engineHost{
		euid:         os.Geteuid(),
		sockets:      hostRuntimeSockets,
		capabilities: processCapabilities,
		fileOwner:    fileOwnerOf,
		readLink:     os.Readlink,
		account:      accountOf,
	}
}
