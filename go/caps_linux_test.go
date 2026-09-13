//go:build linux

package main

import "testing"

// The kernel's capability sets are read from the status the kernel writes.
func TestCapabilitiesIn(t *testing.T) {
	effective, ambient, known := capabilitiesIn("Name:\tgateway\nCapInh:\t0000000000000000\nCapPrm:\t00000000000000e0\nCapEff:\t00000000000000e0\nCapBnd:\t000001ffffffffff\nCapAmb:\t0000000000000080\n")
	if !known || effective != 0xe0 || ambient != 0x80 {
		t.Fatalf("effective %x ambient %x known %v", effective, ambient, known)
	}
	if _, _, known := capabilitiesIn("Name:\tgateway\n"); known {
		t.Fatal("a status without CapEff is not known")
	}
}
