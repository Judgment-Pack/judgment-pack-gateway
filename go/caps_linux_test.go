//go:build linux

package main

import (
	"bytes"
	"os"
	"os/exec"
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

// The helper modes of this test binary: "report" prints the NoNewPrivs
// value the kernel holds for it; "held" starts a "report" as the gateway
// starts a source that runs as itself, then one as it starts a switched
// source, in a process of its own, so what each inherits is seen fresh.
const envPrivilegesHelper = "GATEWAY_TEST_PRIVILEGES_HELPER"

func init() {
	if os.Getenv(envPrivilegesHelper) != "1" {
		return
	}
	if len(os.Args) < 2 {
		os.Exit(2)
	}
	switch os.Args[1] {
	case "report":
		status, _ := os.ReadFile("/proc/self/status")
		os.Stdout.WriteString(noNewPrivilegesIn(string(status)))
		os.Exit(0)
	case "held":
		report := func(switched bool) string {
			cmd := exec.Command(os.Args[0], "report")
			cmd.Env = []string{envPrivilegesHelper + "=1"}
			var out bytes.Buffer
			cmd.Stdout = &out
			if err := (&sourceGroup{switched: switched}).start(cmd); err != nil {
				return "start: " + err.Error()
			}
			cmd.Wait()
			return out.String()
		}
		os.Stdout.WriteString("control=" + report(false) + " held=" + report(true))
		os.Exit(0)
	}
	os.Exit(2)
}

// A source started as a switched one inherits no_new_privs, which is the
// kernel's promise that executing the gateway binary -- or any file that
// would grant privilege -- grants it nothing; one started as the gateway
// itself does not.
func TestSwitchedSourcesAreHeldToNoNewPrivileges(t *testing.T) {
	cmd := exec.Command(os.Args[0], "held")
	cmd.Env = []string{envPrivilegesHelper + "=1"}
	out, err := cmd.Output()
	if err != nil || string(out) != "control=0 held=1" {
		t.Fatalf("a switched source inherits no_new_privs and one run as the gateway does not: %q %v", out, err)
	}
	if err := denyNewPrivilegesHere(); err != nil {
		t.Fatalf("holding a thread: %v", err)
	}
	if noNewPrivilegesIn("Name:\tx\nNoNewPrivs:\t1\nSeccomp:\t0\n") != "1" || noNewPrivilegesIn("Name:\tx\n") != "" {
		t.Fatal("the NoNewPrivs value is read from the status line that carries it")
	}
}

// Preparing a source with a user marks it as one to be started held;
// preparing one without does not.
func TestPreparingASwitchedSourceMarksItHeld(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("as root, root is the gateway's own identity")
	}
	cmd := exec.Command(os.Args[0], "report")
	group, err := prepareSourceProcess(cmd, "root")
	if err != nil {
		t.Fatal(err)
	}
	defer group.reap()
	if !group.switched || cmd.SysProcAttr == nil || cmd.SysProcAttr.Credential == nil || cmd.SysProcAttr.Credential.Uid != 0 {
		t.Fatalf("a source with a user is switched and held: %+v", group)
	}
	plain, err := prepareSourceProcess(exec.Command(os.Args[0], "report"), "")
	if err != nil {
		t.Fatal(err)
	}
	defer plain.reap()
	if plain.switched {
		t.Fatal("a source run as the gateway is not held")
	}
}
