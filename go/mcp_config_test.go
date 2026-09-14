package main

import (
	"path/filepath"
	"strings"
	"testing"
)

// A version-2 configuration carries the mcp member (docs/design/mcp-server.md);
// a version-1 one does not, and a version the engine does not read is refused.
func TestVersionTwoCarriesTheMCPMember(t *testing.T) {
	catalog := t.TempDir()
	v2 := func(mcp string) string {
		text := engineJSON(t, catalog, `,"mcp":`+mcp, ``)
		return strings.Replace(text, `"engineVersion":"1"`, `"engineVersion":"2"`, 1)
	}
	cfg, err := parseEngineConfig([]byte(v2(`{"listen":"127.0.0.1:8788"}`)))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.version != "2" || cfg.mcp == nil || cfg.mcp.listen != "127.0.0.1:8788" || cfg.mcp.resource != "" || len(cfg.mcp.origins) != 0 {
		t.Fatalf("mcp parsed as %+v", cfg.mcp)
	}
	if cfg.mcp.sessions != 64 || cfg.mcp.idleSeconds != 1800 || cfg.mcp.concurrency != 8 || cfg.mcp.callsPerMinute != 120 {
		t.Fatalf("the bounds' defaults are %+v", cfg.mcp)
	}
	full := v2(`{"listen":"[::1]:8788","resource":"https://engine.example.internal/mcp","origins":["http://localhost:5173","https://desk.example.internal"],"sessions":1,"idleSeconds":60,"concurrency":64,"callsPerMinute":6000}`)
	cfg, err = parseEngineConfig([]byte(full))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.mcp.resource != "https://engine.example.internal/mcp" || len(cfg.mcp.origins) != 2 || cfg.mcp.sessions != 1 || cfg.mcp.idleSeconds != 60 || cfg.mcp.concurrency != 64 || cfg.mcp.callsPerMinute != 6000 {
		t.Fatalf("mcp parsed as %+v", cfg.mcp)
	}
	// a version-1 file still loads without the member, and carries none
	if cfg, err := parseEngineConfig([]byte(engineJSON(t, catalog, ``, ``))); err != nil || cfg.version != "1" || cfg.mcp != nil {
		t.Fatalf("version 1: %v %+v", err, cfg.mcp)
	}
	// a version-2 file without the member loads too
	if cfg, err := parseEngineConfig([]byte(strings.Replace(engineJSON(t, catalog, ``, ``), `"engineVersion":"1"`, `"engineVersion":"2"`, 1))); err != nil || cfg.version != "2" || cfg.mcp != nil {
		t.Fatalf("version 2 without mcp: %v %+v", err, cfg.mcp)
	}
	refused := []struct{ name, text, want string }{
		{"version 1 with mcp", engineJSON(t, catalog, `,"mcp":{"listen":"127.0.0.1:8788"}`, ``), "mcp is a version-2 member"},
		{"version 3", strings.Replace(engineJSON(t, catalog, ``, ``), `"engineVersion":"1"`, `"engineVersion":"3"`, 1), `engineVersion "3" is not "1" or "2"`},
		{"mcp not an object", v2(`"127.0.0.1:8788"`), "mcp"},
		{"an unknown mcp member", v2(`{"listen":"127.0.0.1:8788","transport":"http"}`), "transport"},
		{"no listen", v2(`{"resource":"https://e/mcp"}`), "listen"},
		{"listen not loopback", v2(`{"listen":"0.0.0.0:8788"}`), "loopback"},
		{"listen port zero", v2(`{"listen":"127.0.0.1:0"}`), "port 0"},
		{"resource http", v2(`{"listen":"127.0.0.1:8788","resource":"http://engine/mcp"}`), "absolute https URL"},
		{"resource with a fragment", v2(`{"listen":"127.0.0.1:8788","resource":"https://engine/mcp#x"}`), "fragment"},
		{"resource without a host", v2(`{"listen":"127.0.0.1:8788","resource":"https:///mcp"}`), "absolute https URL"},
		{"an origin with a path", v2(`{"listen":"127.0.0.1:8788","origins":["http://localhost/app"]}`), "not an origin"},
		{"an origin with a trailing slash", v2(`{"listen":"127.0.0.1:8788","origins":["http://localhost/"]}`), "not an origin"},
		{"an origin that is not a string", v2(`{"listen":"127.0.0.1:8788","origins":[1]}`), "each a string"},
		{"sessions below range", v2(`{"listen":"127.0.0.1:8788","sessions":0}`), "sessions 0 is outside 1 to 4096"},
		{"sessions above range", v2(`{"listen":"127.0.0.1:8788","sessions":4097}`), "outside"},
		{"idleSeconds below range", v2(`{"listen":"127.0.0.1:8788","idleSeconds":59}`), "idleSeconds 59 is outside 60 to 86400"},
		{"concurrency above range", v2(`{"listen":"127.0.0.1:8788","concurrency":65}`), "concurrency 65 is outside 1 to 64"},
		{"callsPerMinute above range", v2(`{"listen":"127.0.0.1:8788","callsPerMinute":6001}`), "callsPerMinute 6001 is outside 1 to 6000"},
		{"a bound that is not an integer", v2(`{"listen":"127.0.0.1:8788","sessions":"64"}`), "must be an integer"},
		{"the signer's listen at port zero", strings.Replace(v2(`{"listen":"127.0.0.1:8788"}`), `"listen":"127.0.0.1:8787"`, `"listen":"127.0.0.1:0"`, 1), "listen names port 0"},
	}
	for _, c := range refused {
		if _, err := parseEngineConfig([]byte(c.text)); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: want %q, got %v", c.name, c.want, err)
		}
	}
	// the signer's own port zero is still allowed without mcp, as before
	if _, err := parseEngineConfig([]byte(strings.Replace(engineJSON(t, catalog, ``, ``), `"listen":"127.0.0.1:8787"`, `"listen":"127.0.0.1:0"`, 1))); err != nil {
		t.Fatalf("port zero without mcp: %v", err)
	}
}

// The identifiers the frontend holds its configuration to.
func TestResourceAndIssuerIdentifiers(t *testing.T) {
	for _, s := range []string{"https://engine.example.internal/mcp", "https://engine.example.internal", "https://e:8443/mcp"} {
		if err := validResourceURL(s); err != nil {
			t.Errorf("%s: %v", s, err)
		}
	}
	for _, s := range []string{"http://e/mcp", "https:///mcp", "https://e/mcp#f", "e/mcp", ""} {
		if err := validResourceURL(s); err == nil {
			t.Errorf("%s accepted as a resource", s)
		}
	}
	for _, s := range []string{"https://issuer.example", "https://issuer.example/realms/engine"} {
		if err := validIssuerURL(s); err != nil {
			t.Errorf("%s: %v", s, err)
		}
	}
	for _, s := range []string{"https://issuer.example/?x=1", "https://issuer.example/#f", "http://issuer.example"} {
		if err := validIssuerURL(s); err == nil {
			t.Errorf("%s accepted as an issuer", s)
		}
	}
	for _, s := range []string{"http://localhost", "http://127.0.0.1:5173", "https://desk.example", "http://[::1]:3000"} {
		if err := validOrigin(s); err != nil {
			t.Errorf("%s: %v", s, err)
		}
	}
	for _, s := range []string{"http://localhost/", "http://localhost/app", "localhost", "ftp://x", "http://u@localhost", "http://localhost?q"} {
		if err := validOrigin(s); err == nil {
			t.Errorf("%s accepted as an origin", s)
		}
	}
}

// No platform may run as the MCP server's user: a credentials file would
// then belong to the user that process runs as.
func TestARefusalOnThePlatformThatIsTheFrontendsUser(t *testing.T) {
	seed := filepath.Join(string(filepath.Separator), "var", "lib", "engine", "gateway.seed")
	credentials := filepath.Join(string(filepath.Separator), "run", "secrets", "warehouse")
	both := func(path string) map[string]string { return map[string]string{"history": path, "live": path} }
	noSockets := []string{filepath.Join(t.TempDir(), "absent.sock")}
	three := uint64(1<<capSetuid | 1<<capSetgid | 1<<capKill)
	caps := func() capabilitySets { return capabilitySets{known: true, effective: three, permitted: three} }
	for _, c := range []struct {
		name string
		user string
		uid  int
	}{
		{"by uid", "engine-warehouse", frontendUID},
		{"by name", frontendUser, 1001},
	} {
		cfg := engineConfig{runtime: "docker", seed: seed, platforms: []platformConfig{{name: "warehouse", credentials: both(credentials), user: c.user, uid: c.uid}}}
		fs := goodFilesystem(seed, credentials, 1000, c.uid)
		h := engineHost{euid: 1000, sockets: func(string) []string { return noSockets }, capabilities: caps, fileOwner: fs.owner, readLink: readLinkStub}
		if _, err := engineRefusals(ptr(cfg), h); err == nil || !strings.Contains(err.Error(), "is the MCP server's") {
			t.Errorf("%s: want the frontend-user refusal, got %v", c.name, err)
		}
	}
}
