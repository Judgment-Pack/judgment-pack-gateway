package containers

import (
	"strings"
	"testing"
)

func TestSaysAbsent(t *testing.T) {
	const name = "jp-adapter-0123456789abcdef"
	for _, yes := range []string{
		"Error: No such object: " + name,
		"error: NO SUCH OBJECT: " + name,
		"Error: No such container: " + name + "\n",
		"Error: inspecting object: no such container " + name,
		`Error: no such object: "` + name + `"`,
	} {
		if !SaysAbsent(yes, name) {
			t.Errorf("%q must read as absent", yes)
		}
	}
	for _, no := range []string{
		"Error: No such object: " + name + "x",
		"Error: No such object: " + name + ".other",
		`Error: no such container "` + name + `.other"`,
		"Error: No such container: " + name + "-2",
		"Error: No such container: " + name + "_b",
		"Error: No such object: " + strings.ToUpper(name),
		`Error: no such container "` + strings.ToUpper(name) + `"`,
		`Get "http://dockerd/v1.47/containers/` + name + `/json": dial tcp: lookup dockerd: no such host`,
		"no such host " + name,
		"Cannot connect to the Docker daemon",
		"",
	} {
		if SaysAbsent(no, name) {
			t.Errorf("%q must not read as absent", no)
		}
	}
}

func TestParseImage(t *testing.T) {
	const digest = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	for ref, want := range map[string]Image{
		"airbyte/source-postgres:3.6.1@" + digest: {"airbyte/source-postgres", "3.6.1", digest},
		"airbyte/source-postgres@" + digest:       {"airbyte/source-postgres", "", digest},
		"registry.example:5000/x/y:v1@" + digest:  {"registry.example:5000/x/y", "v1", digest},
		"registry.example:5000/x/y@" + digest:     {"registry.example:5000/x/y", "", digest},
	} {
		got, err := ParseImage(ref)
		if err != nil || got != want {
			t.Errorf("%s: %+v %v, want %+v", ref, got, err, want)
		}
	}
	for _, ref := range []string{"airbyte/source-postgres:3.6.1", "airbyte/source-postgres@sha256:abc", "@" + digest, "x@md5:" + digest[7:]} {
		if _, err := ParseImage(ref); err == nil {
			t.Errorf("%s must be refused", ref)
		}
	}
}

func TestParseImageHoldsTheReferenceShape(t *testing.T) {
	digest := "@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	for _, ref := range []string{"alpine", "airbyte/source-postgres:3.8.5", "ghcr.io/example/mcp-postgres:2.1", "localhost:5000/x/y:v1.0-rc_2", "a.b-c_d/e"} {
		if _, err := ParseImage(ref + digest); err != nil {
			t.Errorf("%s: %v", ref, err)
		}
	}
	for _, ref := range []string{"--label=probe=value", "-x", "ghcr.io/-example/mcp", "a/b:-tag", "a b", "a//b", "/a", "a/", "a:b:c", ""} {
		if _, err := ParseImage(ref + digest); err == nil {
			t.Errorf("%q: accepted", ref)
		}
	}
}
