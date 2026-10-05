package main

// The engine configuration's `witness` member (witness_config.go;
// docs/adr/0013-checkpoint-witness.md §4, "Configuration"): its shape, its
// version, what it needs beside it, and what the engine refuses to start
// with.

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// witnessConfigJSON is a version-6 configuration with an identity, no
// platform, and the witness member given.
func witnessConfigJSON(t *testing.T, base, witness string) string {
	t.Helper()
	return `{"engineVersion":"6","authority":"gateway:witness","seed":"` + abs(t, base, "gateway.seed") + `","store":"` + abs(t, base, "store") + `",` +
		`"registry":"` + abs(t, base, "registry.jsonl") + `","decisionRecords":"` + abs(t, base, "decisions") + `","listen":"127.0.0.1:8787",` +
		`"catalog":"` + abs(t, base, "catalog") + `",` +
		`"identity":{"issuer":"https://issuer.example","audience":"gateway:witness","keys":"` + abs(t, base, "keys.json") + `"},` +
		`"witness":` + witness + `,"platforms":{}}`
}

// witnessMember is a witness member whose log and marks are in base, with
// extra members after them.
func witnessMember(t *testing.T, base, extra string) string {
	t.Helper()
	return `{"log":"` + abs(t, base, "log", "witness.log") + `","marks":"` + abs(t, base, "marks", "witness.marks") + `"` + extra + `}`
}

func TestWitnessMemberParses(t *testing.T) {
	base := t.TempDir()
	cfg, err := parseEngineConfig([]byte(witnessConfigJSON(t, base, witnessMember(t, base, ""))))
	if err != nil {
		t.Fatal(err)
	}
	w := cfg.witness
	if w == nil || w.firstSubmission || w.submittersGiven || w.submitters != nil || w.trailsPerSubmitter != 100 || w.submissionsPerMinute != 60 ||
		w.paths.log != filepath.Join(base, "log", "witness.log") || w.paths.marks != filepath.Join(base, "marks", "witness.marks") {
		t.Fatalf("the defaults: %+v", w)
	}
	cfg, err = parseEngineConfig([]byte(witnessConfigJSON(t, base, witnessMember(t, base,
		`,"registration":"first-submission","submitters":[{"issuer":"https://issuer.example","subject":"deliverer-a"},{"issuer":"https://issuer.example","subject":"deliverer-b"}],"trailsPerSubmitter":100000,"submissionsPerMinute":6000`))))
	if err != nil {
		t.Fatal(err)
	}
	w = cfg.witness
	if !w.firstSubmission || !w.submittersGiven || len(w.submitters) != 2 || w.submitters[1].subject != "deliverer-b" || w.trailsPerSubmitter != 100000 || w.submissionsPerMinute != 6000 {
		t.Fatalf("every member given, at the bounds' tops: %+v", w)
	}
	cfg, err = parseEngineConfig([]byte(witnessConfigJSON(t, base, witnessMember(t, base, `,"registration":"operator","submitters":[],"trailsPerSubmitter":1,"submissionsPerMinute":1`))))
	if err != nil {
		t.Fatal(err)
	}
	if w = cfg.witness; w.firstSubmission || !w.submittersGiven || len(w.submitters) != 0 || w.trailsPerSubmitter != 1 || w.submissionsPerMinute != 1 {
		t.Fatalf("submitters present and empty, the bounds at their floors: %+v", w)
	}
}

func TestWitnessMemberRefusals(t *testing.T) {
	base := t.TempDir()
	good := witnessConfigJSON(t, base, witnessMember(t, base, ""))
	member := func(extra string) string { return witnessConfigJSON(t, base, witnessMember(t, base, extra)) }
	paths := func(log, marks string) string {
		return witnessConfigJSON(t, base, `{"log":"`+log+`","marks":"`+marks+`"}`)
	}
	logPath := abs(t, base, "log", "witness.log")
	for _, c := range []struct{ name, text, want string }{
		{"version 5", strings.Replace(good, `"engineVersion":"6"`, `"engineVersion":"5"`, 1), "witness is a version-6 member; engineVersion 5 has no witness"},
		{"no identity", strings.Replace(good, `"identity":{"issuer":"https://issuer.example","audience":"gateway:witness","keys":"`+abs(t, base, "keys.json")+`"},`, ``, 1), "witness needs identity"},
		{"not an object", witnessConfigJSON(t, base, `[]`), `member "witness" is not an object`},
		{"an unknown member", member(`,"log2":"x"`), `witness: unknown member "log2"`},
		{"no log", witnessConfigJSON(t, base, `{"marks":"`+abs(t, base, "m")+`"}`), `witness: missing member "log"`},
		{"no marks", witnessConfigJSON(t, base, `{"log":"`+logPath+`"}`), `witness: missing member "marks"`},
		{"a relative log", paths("witness.log", abs(t, base, "m")), "witness.log must be an absolute path"},
		{"a marks path not clean", paths(logPath, abs(t, base)+"/marks/../m"), "witness.marks must be a clean path"},
		{"marks that are the log", paths(logPath, logPath), "are the log or a file kept beside it"},
		{"marks that are the registrations", paths(logPath, logPath+".registrations"), "are the log or a file kept beside it"},
		{"marks that are the set-aside file", paths(logPath, logPath+".set-aside"), "are the log or a file kept beside it"},
		{"another registration", member(`,"registration":"anyone"`), `witness.registration "anyone" is not "operator" or "first-submission"`},
		{"a registration not a string", member(`,"registration":true`), `witness.registration must be`},
		{"submitters not an array", member(`,"submitters":{}`), "witness.submitters must be an array"},
		{"a submitter not an object", member(`,"submitters":["deliverer-a"]`), "witness.submitters[0] must be an object"},
		{"a submitter with another member", member(`,"submitters":[{"issuer":"https://issuer.example","subject":"a","role":"x"}]`), `witness.submitters[0]: unknown member "role"`},
		{"a submitter without a subject", member(`,"submitters":[{"issuer":"https://issuer.example"}]`), `witness.submitters[0]: missing member "subject"`},
		{"a submitter with an empty subject", member(`,"submitters":[{"issuer":"https://issuer.example","subject":""}]`), "witness.submitters[0].subject must be a non-empty string"},
		{"a submitter with an empty issuer", member(`,"submitters":[{"issuer":"","subject":"a"}]`), "witness.submitters[0].issuer must be a non-empty string"},
		{"a submitter of another issuer", member(`,"submitters":[{"issuer":"https://other.example","subject":"a"}]`), "names issuer \"https://other.example\", which is not identity.issuer"},
		{"a submitter twice", member(`,"submitters":[{"issuer":"https://issuer.example","subject":"a"},{"issuer":"https://issuer.example","subject":"a"}]`), `witness.submitters[1] names subject "a" again`},
		{"trailsPerSubmitter 0", member(`,"trailsPerSubmitter":0`), "witness.trailsPerSubmitter 0 is outside 1 to 100000"},
		{"trailsPerSubmitter one past", member(`,"trailsPerSubmitter":100001`), "witness.trailsPerSubmitter 100001 is outside 1 to 100000"},
		{"submissionsPerMinute 0", member(`,"submissionsPerMinute":0`), "witness.submissionsPerMinute 0 is outside 1 to 6000"},
		{"submissionsPerMinute one past", member(`,"submissionsPerMinute":6001`), "witness.submissionsPerMinute 6001 is outside 1 to 6000"},
		{"submissionsPerMinute not an integer", member(`,"submissionsPerMinute":"60"`), "witness.submissionsPerMinute must be an integer"},
		{"a log that is the seed", paths(abs(t, base, "gateway.seed"), abs(t, base, "m")), "witness.log " + filepath.Join(base, "gateway.seed") + " is the seed"},
		{"marks that are the registry", paths(logPath, abs(t, base, "registry.jsonl")), "witness.marks " + filepath.Join(base, "registry.jsonl") + " is the registry"},
		{"registrations that are the registry", paths(abs(t, base, "registry"), abs(t, base, "m")), "the witness's registrations " + filepath.Join(base, "registry.registrations")},
		{"a log in the store", paths(abs(t, base, "store", "witness.log"), abs(t, base, "m")), "is in the store"},
		{"marks in the decision records", paths(logPath, abs(t, base, "decisions", "deep", "m")), "is in the decisionRecords"},
	} {
		t.Run(c.name, func(t *testing.T) {
			if c.name == "registrations that are the registry" {
				c.text = strings.Replace(c.text, `"registry":"`+abs(t, base, "registry.jsonl")+`"`, `"registry":"`+abs(t, base, "registry.registrations")+`"`, 1)
			}
			if _, err := parseEngineConfig([]byte(c.text)); err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("want %q, got %v", c.want, err)
			}
		})
	}
	// a path that only begins as the store does is not in it
	if _, err := parseEngineConfig([]byte(paths(abs(t, base, "store-witness", "witness.log"), abs(t, base, "m")))); err != nil {
		t.Fatalf("a log beside the store, its name beginning as the store's: %v", err)
	}
}

// The engine refuses to start without a platform unless it is a witness,
// and, with a witness, where a witness keeps no files and with marks on the
// device of the log's directory.
func TestWitnessEngineRefusals(t *testing.T) {
	seed := filepath.Join(string(filepath.Separator), "var", "lib", "engine", "gateway.seed")
	logDir := filepath.Join(string(filepath.Separator), "var", "lib", "witness")
	marksDir := filepath.Join(string(filepath.Separator), "mnt", "marks")
	spec := &witnessSpec{paths: witnessPaths{log: filepath.Join(logDir, "witness.log"), marks: filepath.Join(marksDir, "witness.marks")}}
	cfg := engineConfig{runtime: "docker", seed: seed, witness: spec}
	devices := map[string]uint64{logDir: 1, marksDir: 2}
	host := engineHost{euid: 1000, fileOwner: goodFilesystem(seed, filepath.Join(string(filepath.Separator), "run", "unused"), 1000, 1001).owner, readLink: readLinkStub,
		device: func(path string) (uint64, error) {
			if d, ok := devices[path]; ok {
				return d, nil
			}
			return 0, errors.New("no such directory")
		}}
	_, err := engineRefusals(ptr(cfg), host)
	if !witnessFilesKept {
		if !errors.Is(err, errWitnessFilesNotKept) {
			t.Fatalf("off Unix a witness is refused for keeping no files: %v", err)
		}
		return
	}
	if err != nil {
		t.Fatalf("a witness with no platform, its marks on a device of their own: %v", err)
	}
	// a host runtime's socket reaches no adapter where no platform is
	socket := filepath.Join(t.TempDir(), "docker.sock")
	if err := os.WriteFile(socket, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	withSocket := host
	withSocket.sockets = func(string) []string { return []string{socket} }
	if statements, err := engineRefusals(ptr(cfg), withSocket); err != nil || len(statements) != 0 {
		t.Fatalf("a witness with no platform beside a host runtime's socket: %v %v", err, statements)
	}
	noWitness := cfg
	noWitness.witness = nil
	if _, err := engineRefusals(ptr(noWitness), host); err == nil || !strings.Contains(err.Error(), "platforms names no platform") {
		t.Fatalf("no platform and no witness: %v", err)
	}
	devices[marksDir] = 1
	if _, err := engineRefusals(ptr(cfg), host); err == nil || !strings.Contains(err.Error(), "witness.marks: its directory "+marksDir+" is on the device of the log's directory "+logDir) {
		t.Fatalf("marks on the log's device: %v", err)
	}
	delete(devices, marksDir)
	if _, err := engineRefusals(ptr(cfg), host); err == nil || !strings.Contains(err.Error(), "witness.marks: its directory "+marksDir+": no such directory") {
		t.Fatalf("a marks directory not there: %v", err)
	}
	delete(devices, logDir)
	if _, err := engineRefusals(ptr(cfg), host); err == nil || !strings.Contains(err.Error(), "witness.log: its directory "+logDir+": no such directory") {
		t.Fatalf("a log directory not there: %v", err)
	}
}

// The real host's device lookup tells a directory's device apart from
// another's where they differ, and finds them one where they are one.
func TestWitnessDeviceOfIsTheDirectorysOwn(t *testing.T) {
	host := osEngineHost()
	if host.device == nil {
		if witnessFilesKept {
			t.Fatal("a Unix host looks up no device")
		}
		t.Skip("no witness is kept here, and no device looked up")
	}
	dir := t.TempDir()
	sub := filepath.Join(dir, "sub")
	if err := os.Mkdir(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	a, errA := host.device(dir)
	b, errB := host.device(sub)
	if errA != nil || errB != nil || a != b {
		t.Fatalf("one directory and another inside it: %d %v, %d %v", a, errA, b, errB)
	}
	if _, err := host.device(filepath.Join(dir, "absent")); err == nil {
		t.Fatal("a directory not there has a device")
	}
}
