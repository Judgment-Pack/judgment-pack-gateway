//go:build linux

package main

import "testing"

// The kernel's capability sets are read from the status the kernel writes.
func TestCapabilitiesIn(t *testing.T) {
	sets := capabilitiesIn("Name:\tgateway\nCapInh:\t0000000000000040\nCapPrm:\t00000000000000e0\nCapEff:\t00000000000000e0\nCapBnd:\t000001ffffffffff\nCapAmb:\t0000000000000080\n")
	if !sets.known || sets.effective != 0xe0 || sets.permitted != 0xe0 || sets.inheritable != 0x40 || sets.ambient != 0x80 {
		t.Fatalf("%+v", sets)
	}
	if sets := capabilitiesIn("Name:\tgateway\n"); sets.known {
		t.Fatal("a status without CapEff is not known")
	}
}
