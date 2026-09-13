//go:build unix

package main

import (
	"fmt"
	"os"
	"os/user"
	"strconv"
	"syscall"
)

// credentialsOwnerOf is who owns a credentials file and how it is protected,
// as the filesystem reports them.
func credentialsOwnerOf(path string) (int, os.FileMode, error) {
	info, err := os.Stat(path)
	if err != nil {
		return 0, 0, err
	}
	if !info.Mode().IsRegular() {
		return 0, 0, fmt.Errorf("%s is not a regular file", path)
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, fmt.Errorf("%s: ownership could not be determined", path)
	}
	return int(st.Uid), info.Mode().Perm(), nil
}

// userIDOf is the uid of a named OS user.
func userIDOf(name string) (int, error) {
	account, err := user.Lookup(name)
	if err != nil {
		return 0, fmt.Errorf("user %q: %v", name, err)
	}
	uid, err := strconv.Atoi(account.Uid)
	if err != nil {
		return 0, fmt.Errorf("user %q: uid %q is not a number", name, account.Uid)
	}
	return uid, nil
}

func engineEUID() int { return os.Geteuid() }
