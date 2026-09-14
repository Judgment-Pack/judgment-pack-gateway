package agreement

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"adapters/airbyte"
	"adapters/mcp"
)

// The golden record of the postgres platform: the World sample database's
// city with id 1 (docs/design/both-paths-agreement.md). The live query asks
// the database to render the row as JSON; the history request names the
// stream and reads the page that holds the row.
const (
	worldImage    = "ghusta/postgres-world-db:2.15.1@sha256:879d0919fdccb39a2508a21fe784d046f7a6f2b51ef4de5ba845eabdb93eb8c3"
	goldenQuery   = "SELECT to_jsonb(c) AS record FROM city c WHERE id = 1"
	untypedQuery  = "SELECT id, name, country_code, district, population, local_name FROM city WHERE id = 1"
	goldenKey     = "id"
	goldenKeyJSON = "1"
	goldenFacts   = `{"country_code":"AFG","district":"Kabol","id":1,"local_name":null,"name":"Kabul","population":1780000}`
)

func fixture(t *testing.T, name string) Envelope {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "postgres", name))
	if err != nil {
		t.Fatal(err)
	}
	e, err := Parse(data)
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return e
}

// pinned reads the digests the shipped binding pins for each operation, so
// a fixture captured under another artifact cannot pass as the platform's.
func pinned(t *testing.T) (history, live string) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "catalog", "postgres.json"))
	if err != nil {
		t.Fatal(err)
	}
	var b struct {
		Operations struct {
			History struct {
				Image string `json:"image"`
			} `json:"history"`
			Live struct {
				Server struct {
					Image string `json:"image"`
				} `json:"server"`
			} `json:"live"`
		} `json:"operations"`
	}
	if err := json.Unmarshal(data, &b); err != nil {
		t.Fatal(err)
	}
	digest := func(image string) string { return image[strings.LastIndex(image, "@")+1:] }
	return digest(b.Operations.History.Image), digest(b.Operations.Live.Server.Image)
}

func TestTheGoldenRecordDerivesToTheSameFactsThroughBothShapes(t *testing.T) {
	history, live := fixture(t, "history.json"), fixture(t, "live.json")
	historyPin, livePin := pinned(t)
	if history.Acquisition.Adapter.Digest != historyPin || live.Acquisition.Adapter.Digest != livePin {
		t.Fatalf("the fixtures were not captured under the shipped binding's artifacts: %s / %s", history.Acquisition.Adapter.Digest, live.Acquisition.Adapter.Digest)
	}
	if !strings.Contains(live.Acquisition.Statement, goldenQuery) {
		t.Fatalf("the live fixture did not ask for the golden record: %s", live.Acquisition.Statement)
	}
	if !strings.Contains(history.Acquisition.Statement, `"stream":"city"`) || !strings.Contains(history.Acquisition.Statement, `"namespace":"public"`) {
		t.Fatalf("the history fixture did not read the city stream: %s", history.Acquisition.Statement)
	}
	h, err := HistoryFacts(history, goldenKey, json.RawMessage(goldenKeyJSON))
	if err != nil {
		t.Fatal(err)
	}
	l, err := LiveFacts(live)
	if err != nil {
		t.Fatal(err)
	}
	if string(h) != string(l) {
		t.Fatalf("the two shapes disagree:\nhistory: %s\nlive:    %s", h, l)
	}
	if string(h) != goldenFacts {
		t.Fatalf("the facts are not the golden record's:\n%s", h)
	}
}

// The rule asks the database to render the row because a driver's typing is
// not the database's: through the same server, a plain SELECT hands the two
// bigint columns back as strings, and the row then differs from the
// connector's on exactly those members. Kept so the rule's reason is pinned.
func TestADriverTypedRowIsNotTheConnectorsRecord(t *testing.T) {
	history, untyped := fixture(t, "history.json"), fixture(t, "live-driver-typed.json")
	if !strings.Contains(untyped.Acquisition.Statement, untypedQuery) {
		t.Fatalf("the untyped fixture is not the plain SELECT: %s", untyped.Acquisition.Statement)
	}
	h, err := HistoryFacts(history, goldenKey, json.RawMessage(goldenKeyJSON))
	if err != nil {
		t.Fatal(err)
	}
	u, err := LiveRowFacts(untyped)
	if err != nil {
		t.Fatal(err)
	}
	if string(h) == string(u) {
		t.Fatalf("a driver-typed row agreed with the connector's record; the rule no longer needs to_jsonb, revise the design note")
	}
	var hm, um map[string]json.RawMessage
	if err := json.Unmarshal(h, &hm); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(u, &um); err != nil {
		t.Fatal(err)
	}
	var differ []string
	for k := range hm {
		if string(hm[k]) != string(um[k]) {
			differ = append(differ, k)
		}
	}
	if strings.Join(sortedStrings(differ), ",") != "id,population" {
		t.Fatalf("the members that differ are %v, not the two bigint columns", differ)
	}
	if string(um["id"]) != `"1"` || string(um["population"]) != `"1780000"` {
		t.Fatalf("the driver rendered the bigints as %s and %s, not as strings", um["id"], um["population"])
	}
}

func sortedStrings(s []string) []string {
	out := append([]string(nil), s...)
	for i := range out {
		for j := i + 1; j < len(out); j++ {
			if out[j] < out[i] {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	return out
}

func TestDerivationRefusals(t *testing.T) {
	history := fixture(t, "history.json")
	if _, err := HistoryFacts(history, goldenKey, json.RawMessage("999999")); err == nil || !strings.Contains(err.Error(), "no record has") {
		t.Fatalf("a key no record carries: %v", err)
	}
	if _, err := HistoryFacts(history, "country_code", json.RawMessage(`"AFG"`)); err == nil || !strings.Contains(err.Error(), "more than one record") {
		t.Fatalf("a key many records carry: %v", err)
	}
	untyped := fixture(t, "live-driver-typed.json")
	if _, err := LiveFacts(untyped); err == nil || !strings.Contains(err.Error(), "to_jsonb") {
		t.Fatalf("a live answer without the rendered record: %v", err)
	}
	// a well-formed answer that the server nonetheless marks as an error is not a fact
	errored := fixture(t, "live.json")
	var members map[string]json.RawMessage
	if err := json.Unmarshal(errored.Result, &members); err != nil {
		t.Fatal(err)
	}
	members["isError"] = json.RawMessage("true")
	errored.Result, _ = json.Marshal(members)
	if _, err := LiveFacts(errored); err == nil {
		t.Fatal("an error result derived facts")
	}
	if _, err := Parse([]byte(`{"acquisition":{"adapter":{}},"result":[]}`)); err == nil {
		t.Fatal("an envelope without an adapter digest parsed")
	}
}

// TestBothPathsAgreeOnAFreshFetch fetches the golden record both ways
// against a World database started in the container runtime AGREEMENT_RUNTIME
// names (docker or podman), through the adapters as the engine runs them,
// under a role Postgres holds to reading, and holds the fresh facts to each
// other and to the fixtures'. Without the variable it is skipped: the
// fixtures above are the offline record, and this is the test that keeps
// them honest wherever a runtime is at hand (the CI job "both paths agree").
func TestBothPathsAgreeOnAFreshFetch(t *testing.T) {
	runtime := os.Getenv("AGREEMENT_RUNTIME")
	if runtime == "" {
		t.Skip("set AGREEMENT_RUNTIME=docker (or podman) to fetch the golden record both ways")
	}
	historyPin, livePin := pinned(t)
	historyImage, liveImage := shippedImages(t)
	name := fmt.Sprintf("jp-agreement-%d", os.Getpid())
	run := func(args ...string) ([]byte, error) {
		cmd := exec.Command(runtime, args...)
		out, err := cmd.CombinedOutput()
		return out, err
	}
	if out, err := run("run", "-d", "--name", name, "-e", "POSTGRES_PASSWORD=world123", worldImage); err != nil {
		t.Fatalf("starting the World database: %v\n%s", err, out)
	}
	defer run("rm", "-f", name)
	// The image's first start loads the data through a temporary server
	// that answers on the socket alone and then restarts; ready is when a
	// query over TCP sees every city.
	deadline := time.Now().Add(3 * time.Minute)
	for {
		out, err := run("exec", name, "psql", "-h", "127.0.0.1", "-U", "world", "-d", "world-db", "-Atc", "SELECT count(*) FROM city")
		if err == nil && strings.TrimSpace(string(out)) == "4079" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the World database did not become ready: %v\n%s", err, out)
		}
		time.Sleep(time.Second)
	}
	// the reading role the binding's README requires of a live connection string
	grants := "CREATE ROLE reader LOGIN PASSWORD 'reader123'; GRANT CONNECT ON DATABASE \"world-db\" TO reader; GRANT USAGE ON SCHEMA public TO reader; GRANT SELECT ON ALL TABLES IN SCHEMA public TO reader; ALTER ROLE reader SET default_transaction_read_only = on;"
	if out, err := run("exec", name, "psql", "-h", "127.0.0.1", "-U", "world", "-d", "world-db", "-Atc", grants); err != nil {
		t.Fatalf("creating the reading role: %v\n%s", err, out)
	}
	ipOut, err := run("inspect", "-f", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", name)
	if err != nil {
		t.Fatalf("inspecting the database container: %v\n%s", err, ipOut)
	}
	ip := strings.TrimSpace(string(ipOut))
	if !regexp.MustCompile(`^\d+\.\d+\.\d+\.\d+$`).MatchString(ip) {
		t.Fatalf("no address for the database container: %q", ip)
	}
	dir := t.TempDir()
	liveCreds := filepath.Join(dir, "live.json")
	if err := os.WriteFile(liveCreds, []byte(fmt.Sprintf(`{"DSN": "postgresql://reader:reader123@%s:5432/world-db"}`, ip)), 0o600); err != nil {
		t.Fatal(err)
	}
	historyCreds := filepath.Join(dir, "history.json")
	if err := os.WriteFile(historyCreds, []byte(fmt.Sprintf(`{"host": "%s", "port": 5432, "database": "world-db", "username": "reader", "password": "reader123", "schemas": ["public"], "ssl_mode": {"mode": "disable"}, "replication_method": {"method": "Standard"}}`, ip)), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	liveCfg := mcp.Config{Runtime: runtime, Image: liveImage, Args: []string{"--transport", "stdio"}, Credentials: liveCreds, Endpoint: ip, Tools: []string{"execute_sql", "search_objects"}, MaxOutput: 1 << 20}
	liveReq, err := mcp.ParseRequest(strings.NewReader(fmt.Sprintf(`{"tool":"execute_sql","arguments":{"sql":%q}}`, goldenQuery)))
	if err != nil {
		t.Fatal(err)
	}
	liveOut, err := mcp.Acquire(ctx, liveCfg, liveReq)
	if err != nil {
		t.Fatalf("live fetch: %v", err)
	}
	live, err := Parse(liveOut)
	if err != nil {
		t.Fatal(err)
	}
	// the reading role holds: a write through it is Postgres's refusal, reported as an error result and so a failed acquisition
	writeReq, _ := mcp.ParseRequest(strings.NewReader(`{"tool":"execute_sql","arguments":{"sql":"UPDATE city SET population = population WHERE id = 1"}}`))
	if _, err := mcp.Acquire(ctx, liveCfg, writeReq); err == nil || !strings.Contains(err.Error(), "read-only transaction") {
		t.Fatalf("a write through the reading role was not refused by Postgres: %v", err)
	}

	historyCfg := airbyte.Config{Runtime: runtime, Image: historyImage, Credentials: historyCreds, Endpoint: ip, MaxRecords: 5000, MaxOutput: 8 << 20}
	historyReq, err := airbyte.ParseRequest(strings.NewReader(`{"stream":"city","namespace":"public","limit":5000}`), 5000)
	if err != nil {
		t.Fatal(err)
	}
	historyOut, err := airbyte.Acquire(ctx, historyCfg, historyReq)
	if err != nil {
		t.Fatalf("history fetch: %v", err)
	}
	history, err := Parse(historyOut)
	if err != nil {
		t.Fatal(err)
	}
	if history.Acquisition.Adapter.Digest != historyPin || live.Acquisition.Adapter.Digest != livePin {
		t.Fatalf("the fresh fetch ran under other artifacts: %s / %s", history.Acquisition.Adapter.Digest, live.Acquisition.Adapter.Digest)
	}
	h, err := HistoryFacts(history, goldenKey, json.RawMessage(goldenKeyJSON))
	if err != nil {
		t.Fatal(err)
	}
	l, err := LiveFacts(live)
	if err != nil {
		t.Fatal(err)
	}
	if string(h) != string(l) || string(h) != goldenFacts {
		t.Fatalf("a fresh fetch disagrees:\nhistory: %s\nlive:    %s\ngolden:  %s", h, l, goldenFacts)
	}
	fh, _ := HistoryFacts(fixture(t, "history.json"), goldenKey, json.RawMessage(goldenKeyJSON))
	if string(fh) != string(h) {
		t.Fatalf("the fixtures no longer say what a fresh fetch says:\nfixture: %s\nfresh:   %s", fh, h)
	}
}

// shippedImages reads the pinned image references of both operations from the shipped binding.
func shippedImages(t *testing.T) (history, live string) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "catalog", "postgres.json"))
	if err != nil {
		t.Fatal(err)
	}
	var b struct {
		Operations struct {
			History struct {
				Image string `json:"image"`
			} `json:"history"`
			Live struct {
				Server struct {
					Image string `json:"image"`
				} `json:"server"`
			} `json:"live"`
		} `json:"operations"`
	}
	if err := json.Unmarshal(data, &b); err != nil {
		t.Fatal(err)
	}
	if b.Operations.History.Image == "" || b.Operations.Live.Server.Image == "" {
		t.Fatal(errors.New("the binding names no images"))
	}
	return b.Operations.History.Image, b.Operations.Live.Server.Image
}
