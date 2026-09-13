//go:build linux

package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
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
// source, then one as the gateway again, in a process of its own, so
// what each inherits is seen fresh and no thread of the test runner is
// ever marked; "facts" waits for a byte on stdin, then reports what
// executableFacts says of the running image.
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
		// Then one as the gateway again: the mark must not have come
		// back with the thread that carried it -- and the thread itself
		// must be gone, not waiting in the scheduler's pool: no task of
		// this process holds the mark once the held start has returned.
		marked := func() int {
			n := 0
			tasks, _ := filepath.Glob("/proc/self/task/*/status")
			for _, task := range tasks {
				if status, err := os.ReadFile(task); err == nil && noNewPrivilegesIn(string(status)) == "1" {
					n++
				}
			}
			return n
		}
		line := "control=" + report(false) + " held=" + report(true) + " after=" + report(false)
		for deadline := time.Now().Add(3 * time.Second); marked() > 0 && time.Now().Before(deadline); {
			time.Sleep(10 * time.Millisecond)
		}
		os.Stdout.WriteString(line + " marked=" + strconv.Itoa(marked()))
		os.Exit(0)
	case "facts":
		io.ReadFull(os.Stdin, make([]byte, 1))
		facts, err := executableFacts()
		if err != nil {
			os.Stdout.WriteString("error: " + err.Error())
			os.Exit(0)
		}
		fmt.Printf("%04o %v %s", facts.mode, facts.capabilities, facts.path)
		os.Exit(0)
	}
	os.Exit(2)
}

// A source started as a switched one inherits no_new_privs, which is the
// kernel's promise that executing the gateway binary -- or any file that
// would grant privilege -- grants it nothing; one started as the gateway
// itself does not.
func TestSwitchedSourcesAreHeldToNoNewPrivileges(t *testing.T) {
	// A runner already under the mark -- a sandbox that sets it -- cannot
	// show the difference, since everything it starts inherits it.
	if status, err := os.ReadFile("/proc/self/status"); err == nil && noNewPrivilegesIn(string(status)) == "1" {
		t.Skip("this test runner already runs under no_new_privs")
	}
	cmd := exec.Command(os.Args[0], "held")
	cmd.Env = []string{envPrivilegesHelper + "=1"}
	out, err := cmd.Output()
	if err != nil || string(out) != "control=0 held=1 after=0 marked=0" {
		t.Fatalf("a switched source inherits no_new_privs, one run as the gateway does not, before or after, and no thread keeps the mark: %q %v", out, err)
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

// What getxattr answers is read as presence, confirmed absence, or not
// known -- and not known is never taken for absence.
func TestAttributePresent(t *testing.T) {
	for _, tc := range []struct {
		n    int
		err  error
		want bool
		fail bool
	}{
		{20, nil, true, false},
		{0, nil, false, false},
		{0, syscall.ERANGE, true, false},
		{0, syscall.ENODATA, false, false},
		{0, syscall.ENOTSUP, false, false},
		{0, syscall.EIO, false, true},
		{0, syscall.EPERM, false, true},
		{0, syscall.EACCES, false, true},
		{0, errors.New("other"), false, true},
	} {
		present, err := attributePresent(tc.n, tc.err)
		if present != tc.want || (err != nil) != tc.fail {
			t.Errorf("%d %v: got %v %v, want %v fail=%v", tc.n, tc.err, present, err, tc.want, tc.fail)
		}
	}
}

// The facts are read through the descriptor: the attribute is seen once
// set, and the file that was opened is the one judged after its path is
// gone.
func TestFactsOfReadTheOpenFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "binary")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	facts, err := factsOf(f, "user.gateway-test")
	if err != nil || facts.capabilities || facts.mode != 0o755 {
		t.Fatalf("without the attribute: %+v %v", facts, err)
	}
	if err := syscall.Setxattr(path, "user.gateway-test", []byte{1}, 0); err != nil {
		if errors.Is(err, syscall.ENOTSUP) || errors.Is(err, syscall.EPERM) {
			t.Skipf("this filesystem holds no user attributes: %v", err)
		}
		t.Fatal(err)
	}
	if facts, err := factsOf(f, "user.gateway-test"); err != nil || !facts.capabilities {
		t.Fatalf("with the attribute: %+v %v", facts, err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if facts, err := factsOf(f, "user.gateway-test"); err != nil || !facts.capabilities || facts.mode != 0o755 {
		t.Fatalf("the open file, after its path is gone: %+v %v", facts, err)
	}
}

// The running image is what is judged: this test binary, its mode, and
// no capability on it.
func TestExecutableFactsReadTheRunningImage(t *testing.T) {
	facts, err := executableFacts()
	if err != nil {
		t.Fatal(err)
	}
	link, err := os.Readlink("/proc/self/exe")
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(link)
	if err != nil {
		t.Fatal(err)
	}
	if facts.path != link || facts.mode != info.Mode().Perm() || facts.capabilities {
		t.Fatalf("the running image: %+v, want %s %04o without capabilities", facts, link, info.Mode().Perm())
	}
}

// What is judged is the running image, not what sits at its path: a
// helper copied to a path of its own, replaced there by a file of
// another mode while it runs, still reports its own mode, and a path
// the kernel marks as deleted.
func TestExecutableFactsSurviveReplacementOfThePath(t *testing.T) {
	dir := t.TempDir()
	helper := filepath.Join(dir, "helper")
	copyFile(t, os.Args[0], helper, 0o700)
	cmd := exec.Command(helper, "facts")
	cmd.Env = []string{envPrivilegesHelper + "=1"}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	// The replacement: another file, another mode, renamed over the
	// helper's path while the helper runs.
	replacement := filepath.Join(dir, "replacement")
	if err := os.WriteFile(replacement, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(replacement, helper); err != nil {
		t.Fatal(err)
	}
	if _, err := stdin.Write([]byte{'\n'}); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("%v: %s", err, out.String())
	}
	if got := out.String(); !strings.HasPrefix(got, "0700 false ") || !strings.HasSuffix(got, " (deleted)") {
		t.Fatalf("the running image, not the file now at its path: %q", got)
	}
}

func copyFile(t *testing.T, from, to string, mode os.FileMode) {
	t.Helper()
	src, err := os.Open(from)
	if err != nil {
		t.Fatal(err)
	}
	defer src.Close()
	dst, err := os.OpenFile(to, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(dst, src); err != nil {
		t.Fatal(err)
	}
	if err := dst.Close(); err != nil {
		t.Fatal(err)
	}
}
