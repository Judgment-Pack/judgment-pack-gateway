package main

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

// A citation's kind and id each name one level under the approval-record
// directory, or the citation names no record (ADR-0063, decision 4).
func TestAnApprovalRecordSegmentIsOnePathSegment(t *testing.T) {
	for _, s := range []string{"", ".", "..", "a/b", "/a", "a/", `a\b`, `\a`, "a\x00b", "a\x01b", "a\tb", "a\x7fb", "a\u0085b", "é", "Å", "е", "一", "\xff"} {
		if approvalRecordSegment(s) {
			t.Errorf("%q names a record", s)
		}
	}
	for _, s := range []string{"change-1042", "single", "standing", "...", ".a", "a..b", "CHG 7", "café", "Ångström", "˿"} {
		if !approvalRecordSegment(s) {
			t.Errorf("%q names no record", s)
		}
	}
}

// approvalRecords is a version-52 member, the gateway's and a platform's,
// refused by name below it; at 52 a configuration without it is the one
// it is at 51.
func TestTheApprovalRecordsMemberIsRefusedByNameBelow52(t *testing.T) {
	base := storageConfig(t, "", ``, ``)
	at := func(version, extra string) string {
		return strings.Replace(base, `"engineVersion":"24"`, `"engineVersion":"`+version+`"`+extra, 1)
	}
	dir := abs(t, t.TempDir(), "approvals")
	member := `,"approvalRecords":"` + strings.ReplaceAll(dir, `\`, `\\`) + `"`
	if _, err := parseEngineConfig([]byte(at("51", member))); err == nil || err.Error() != "engine configuration: approvalRecords is a version-52 member; engineVersion 51 has no approvalRecords" {
		t.Fatalf("below 52: %v", err)
	}
	cfg, err := parseEngineConfig([]byte(at(approvalRecordsVersion, member)))
	if err != nil || cfg.approvalRecords != dir {
		t.Fatalf("at 52: %q %v", cfg.approvalRecords, err)
	}
	if _, err := parseEngineConfig([]byte(at(approvalRecordsVersion, `,"approvalRecords":"approvals"`))); err == nil || !strings.Contains(err.Error(), "approvalRecords must be an absolute path") {
		t.Fatalf("a relative directory: %v", err)
	}
	p, err := parseJSON([]byte(`{"approvalRecords":"/records/b"}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parsePlatformApprovalRecords(p.(*vObject), "tickets", "51", true, callerScopeB); err == nil || err.Error() != "engine configuration: platform tickets: approvalRecords is a version-52 member; engineVersion 51 has no approvalRecords" {
		t.Fatalf("a platform's below 52: %v", err)
	}
	before, err := parseEngineConfig([]byte(at("51", "")))
	if err != nil {
		t.Fatal(err)
	}
	after, err := parseEngineConfig([]byte(at(approvalRecordsVersion, "")))
	if err != nil {
		t.Fatal(err)
	}
	after.version = before.version
	if !reflect.DeepEqual(before, after) {
		t.Fatalf("a configuration without the member reads otherwise at 52:\n%#v\n%#v", before, after)
	}
}

// A platform's directory is a scoped write's alone, and every scoped
// write names its own where the gateway names one; each is apart from the
// gateway's and from every other scope's, as decisionRecords are.
func TestTheApprovalRecordDirectoriesArePlacedAsDecisionRecordsAre(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("these cases name POSIX paths, and a scoped write needs durable keyed actions, which this platform does not have")
	}
	p, err := parseJSON([]byte(`{"approvalRecords":"/records/b"}`))
	if err != nil {
		t.Fatal(err)
	}
	own := p.(*vObject)
	for _, c := range []struct {
		name  string
		write bool
		scope string
	}{{"an unscoped write", true, ""}, {"a scoped read", false, callerScopeB}} {
		if _, err := parsePlatformApprovalRecords(own, "tickets", approvalRecordsVersion, c.write, c.scope); err == nil || !strings.Contains(err.Error(), "the platform is not one") {
			t.Errorf("%s: %v", c.name, err)
		}
	}
	if dir, err := parsePlatformApprovalRecords(own, "tickets", approvalRecordsVersion, true, callerScopeB); err != nil || dir != "/records/b" {
		t.Fatalf("a scoped write's own: %q %v", dir, err)
	}
	platforms := func(dirs ...string) []platformConfig {
		var out []platformConfig
		for i, d := range dirs {
			scope := callerScopeA
			if i%2 == 1 {
				scope = callerScopeB
			}
			out = append(out, platformConfig{name: fmt.Sprintf("p%d", i), scope: scope, write: true, approvalRecords: d})
		}
		return out
	}
	for _, c := range []struct {
		name, gateway string
		platforms     []platformConfig
		want          string
	}{
		{"the gateway's directory", "/approvals", platforms("/approvals"), "is the gateway's approvalRecords"},
		{"beneath the gateway's", "/approvals", platforms("/approvals/a"), "is the gateway's approvalRecords"},
		{"above the gateway's", "/approvals/gateway", platforms("/approvals"), "is the gateway's approvalRecords"},
		{"another scope's directory", "", platforms("/approvals/a", "/approvals/a"), "fixed to different scope identifiers"},
		{"beneath another scope's", "", platforms("/approvals/a", "/approvals/a/b"), "fixed to different scope identifiers"},
		{"a scoped write without its own", "/approvals", platforms("/approvals-a", ""), "needs its own"},
	} {
		if err := approvalRecordsApart(c.gateway, c.platforms, nestedAsSpelled); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v", c.name, err)
		}
	}
	same := []platformConfig{{name: "p0", scope: callerScopeB, write: true, approvalRecords: "/approvals/b"}, {name: "p1", scope: callerScopeB, write: true, approvalRecords: "/approvals/b"}}
	if err := approvalRecordsApart("/approvals/gateway", append(same, platformConfig{name: "p2", scope: callerScopeA, write: true, approvalRecords: "/approvals/a"}), nestedAsSpelled); err != nil {
		t.Fatalf("apart directories, one shared within a scope: %v", err)
	}
	if err := approvalRecordsApart("", platforms("/approvals/a", ""), nestedAsSpelled); err != nil {
		t.Fatalf("no gateway directory, one scope without one: %v", err)
	}
}

// A name is listed only as it is stored, byte for byte: a look by another
// case of it, which a file system that folds case answers, is not the name.
func TestAnApprovalNameIsListedByItsExactBytes(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "change-a"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]bool{"change-a": true, "Change-a": false, "CHANGE-A": false, "change-": false, "change-a ": false} {
		if got := approvalNameListed(dir, name); got != want {
			t.Fatalf("%q listed: %v, want %v", name, got, want)
		}
	}
	if approvalNameListed(filepath.Join(dir, "absent"), "change-a") {
		t.Fatal("a directory that is not there lists a name")
	}
}
