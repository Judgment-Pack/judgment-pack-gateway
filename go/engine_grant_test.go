package main

import (
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// A platform's grant member (engineVersion 16, SPEC.md §10 rule 3): the
// connection grant its delegated writes are admitted under, held to its
// forms, its user held apart, and the write source derived with the gate.
func TestEngineGrantMember(t *testing.T) {
	catalog := catalogWith(t, map[string]string{"postgres": postgresBinding})
	ref := "postgres@" + digestOf(postgresBinding)
	bin := abs(t, t.TempDir(), "bin")
	stateDir := abs(t, t.TempDir(), "custody")
	member := func(provider, connection, dir, principal, user string) string {
		return `,"grant":{"provider":"` + provider + `","connection":"` + connection + `","stateDir":"` + dir + `","principal":"` + principal + `","user":"` + user + `"}`
	}
	good := member("azure-devops", "boards", stateDir, "operator", "engine-desk")
	text := func(version, platformExtra string) string {
		s := engineJSON(t, catalog, `,"adapters":"`+bin+`"`, platformJSONFor(t, "warehouse", ref, "engine-warehouse", platformExtra, "history", "live", "write"))
		return strings.Replace(s, `"engineVersion":"1"`, `"engineVersion":"`+version+`"`, 1)
	}
	cfg, sources, err := load(t, text("16", `,"write":true`+good))
	if err != nil {
		t.Fatal(err)
	}
	clean := func(p string) string { return strings.ReplaceAll(p, `\\`, `\`) }
	if g := cfg.platforms[0].grant; g == nil || *g != (platformGrant{provider: "azure-devops", connection: "boards", stateDir: clean(stateDir), principal: "operator", user: "engine-desk", uid: 1003}) {
		t.Fatalf("the grant: %+v", cfg.platforms[0].grant)
	}
	want := &grantGate{
		argv: []string{filepath.Join(clean(bin), "gateway-connections"), "--state-dir=" + clean(stateDir), "--principal=operator", "--provider=azure-devops"},
		env:  []string{}, user: "engine-desk", provider: "azure-devops", connection: "boards",
	}
	if got := sources["warehouse/write"].grant; !reflect.DeepEqual(got, want) {
		t.Fatalf("the write's gate: %+v, want %+v", got, want)
	}
	if sources["warehouse/live"].grant != nil || sources["warehouse/history"].grant != nil {
		t.Fatal("a read is given a grant gate")
	}
	if _, sources, err := load(t, text("16", `,"write":true`)); err != nil || sources["warehouse/write"].grant != nil {
		t.Fatalf("a platform naming no grant: %v", err)
	}
	for _, c := range []struct{ name, version, extra, want string }{
		{"a version-15 file", "15", `,"write":true` + good, "grant is a version-16 member"},
		{"a platform that allows no write", "16", good, "the platform does not set write: true"},
		{"a provider with no grant", "16", `,"write":true` + member("obsidian", "boards", stateDir, "operator", "engine-desk"), "grant.provider must be one of"},
		{"a connection not a flat token", "16", `,"write":true` + member("azure-devops", "../boards", stateDir, "operator", "engine-desk"), "grant.connection must be a flat token"},
		{"a relative custody", "16", `,"write":true` + member("azure-devops", "boards", "custody", "operator", "engine-desk"), "grant.stateDir must be an absolute path"},
		{"a principal of another form", "16", `,"write":true` + member("azure-devops", "boards", stateDir, "the operator", "engine-desk"), "grant.principal must be"},
		{"no user", "16", `,"write":true` + member("azure-devops", "boards", stateDir, "operator", ""), "grant.user must name"},
		{"a user the host has not", "16", `,"write":true` + member("azure-devops", "boards", stateDir, "operator", "engine-nobody"), "grant.user:"},
		{"a member it does not have", "16", `,"write":true` + strings.Replace(good, `"user"`, `"owner"`, 1), `unknown member "owner"`},
	} {
		if _, _, err := load(t, text(c.version, c.extra)); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: want %q, got %v", c.name, c.want, err)
		}
	}
}

// The custody's user is never root, the signer, the MCP server's or a
// platform's: its program reads the custody's credentials.
func TestEngineRefusesAGrantUserThatIsNotApart(t *testing.T) {
	seed := filepath.Join(string(filepath.Separator), "var", "lib", "engine", "gateway.seed")
	credentials := filepath.Join(string(filepath.Separator), "run", "secrets", "warehouse")
	fs := goodFilesystem(seed, credentials, 1000, 1001)
	host := engineHost{euid: 1000, sockets: func(string) []string { return []string{filepath.Join(t.TempDir(), "absent.sock")} }, capabilities: func() capabilitySets {
		three := uint64(1<<capSetuid | 1<<capSetgid | 1<<capKill)
		return capabilitySets{known: true, effective: three, permitted: three}
	}, fileOwner: fs.owner, readLink: readLinkStub}
	config := func(user string, uid int) *engineConfig {
		return &engineConfig{runtime: "docker", seed: seed, platforms: []platformConfig{{
			name: "warehouse", credentials: map[string]string{"write": credentials}, user: "engine-warehouse", uid: 1001, write: true,
			grant: &platformGrant{provider: "azure-devops", connection: "boards", stateDir: "/var/lib/custody", principal: "operator", user: user, uid: uid},
		}}}
	}
	if _, err := engineRefusals(config("engine-custody", 1005), host); err != nil {
		t.Fatalf("a custody user of its own: %v", err)
	}
	for _, c := range []struct {
		user string
		uid  int
		want string
	}{
		{"root", 0, "grant.user root is root"},
		{"engine-signer", 1000, "is the signer's own"},
		{frontendUser, frontendUID, "is the MCP server's"},
		{"engine-warehouse", 1001, "is platform warehouse's"},
	} {
		if _, err := engineRefusals(config(c.user, c.uid), host); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: want %q, got %v", c.user, c.want, err)
		}
	}
}
