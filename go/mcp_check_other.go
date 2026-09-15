//go:build !linux

package main

// Off Linux there are no capability sets to hold empty; the rest of the
// check applies.
func capabilitySetsEmpty() (bool, string) { return true, "" }
