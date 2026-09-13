//go:build linux

package main

import (
	"strings"
	"testing"
)

// The kernel's capability sets are read from the status the kernel writes.
func TestCapabilitiesIn(t *testing.T) {
	// The permitted set carries a DAC bit the effective set does not, so
	// each set is read as its own, and the refusal follows from the parse.
	sets := capabilitiesIn("Name:\tgateway\nCapInh:\t0000000000000040\nCapPrm:\t00000000000000e4\nCapEff:\t00000000000000e0\nCapBnd:\t000001ffffffffff\nCapAmb:\t0000000000000080\n")
	if !sets.known || sets.effective != 0xe0 || sets.permitted != 0xe4 || sets.inheritable != 0x40 || sets.ambient != 0x80 {
		t.Fatalf("%+v", sets)
	}
	if err := capabilityRefusal(sets); err == nil || !strings.Contains(err.Error(), "CAP_DAC_OVERRIDE or CAP_DAC_READ_SEARCH") {
		t.Fatalf("a permitted-only DAC capability read from the status is refused: %v", err)
	}
	clean := capabilitiesIn("CapInh:\t0000000000000000\nCapPrm:\t00000000000000e0\nCapEff:\t00000000000000e0\nCapAmb:\t0000000000000000\n")
	if err := capabilityRefusal(clean); err != nil {
		t.Fatalf("the three as file capabilities pass: %v", err)
	}
	if sets := capabilitiesIn("Name:\tgateway\n"); sets.known {
		t.Fatal("a status without CapEff is not known")
	}
}
