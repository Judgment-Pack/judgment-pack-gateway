package main

import (
	"bytes"
	"testing"
)

// A release build's tag is what the executable says of itself, ahead of
// anything the toolchain recorded; without one, the answer is what it was
// before there was a release build. The test holds both whether or not
// the build under test was given a version of its own, and leaves the
// variable as it found it.
func TestReleaseVersionLeadsBuildVersion(t *testing.T) {
	given := releaseVersion
	t.Cleanup(func() { releaseVersion = given })

	releaseVersion = ""
	without := buildVersion()
	if without == "" || without == "(devel)" {
		t.Fatalf("buildVersion() is %q without a release version", without)
	}

	releaseVersion = "v9.8.7"
	if v := buildVersion(); v != "v9.8.7" {
		t.Fatalf("buildVersion() is %q with a release version set", v)
	}
	var out bytes.Buffer
	if code := cmdVersion(&out); code != 0 || out.String() != "gateway v9.8.7\n" {
		t.Fatalf("version printed %q and returned %d", out.String(), code)
	}

	releaseVersion = ""
	if v := buildVersion(); v != without {
		t.Fatalf("buildVersion() is %q once the release version is cleared, and was %q", v, without)
	}
}
