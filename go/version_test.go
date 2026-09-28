package main

import (
	"bytes"
	"testing"
)

// A release build's tag is what the executable says of itself, ahead of
// anything the toolchain recorded; without one, the answer is what it was
// before there was a release build.
func TestReleaseVersionLeadsBuildVersion(t *testing.T) {
	before := buildVersion()
	releaseVersion = "v9.8.7"
	t.Cleanup(func() { releaseVersion = "" })
	if v := buildVersion(); v != "v9.8.7" {
		t.Fatalf("buildVersion() is %q with a release version set", v)
	}
	var out bytes.Buffer
	if code := cmdVersion(&out); code != 0 || out.String() != "gateway v9.8.7\n" {
		t.Fatalf("version printed %q and returned %d", out.String(), code)
	}
	releaseVersion = ""
	if v := buildVersion(); v != before {
		t.Fatalf("buildVersion() is %q without a release version, and was %q", v, before)
	}
}
