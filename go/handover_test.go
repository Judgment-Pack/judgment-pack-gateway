package main

// The hand-over between instances on the PostgreSQL kind (handover.go):
// two instances of serve --config run in this process against one database,
// as the binary runs them, each with a stop of the test's and a listener the
// test bound.

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// pgHandoverConfig is a version-25 configuration on the kind whose start
// waits up to wait seconds for the start lease.
func pgHandoverConfig(t *testing.T, db *pgTestDB, wait string) engineConfig {
	t.Helper()
	dir := tempDirAt(t, 0o700)
	connection := filepath.Join(dir, "connection")
	if err := os.WriteFile(connection, []byte(pgTestURL(db.runtime)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	records := filepath.Join(dir, "decisions")
	if err := os.Mkdir(records, 0o700); err != nil {
		t.Fatal(err)
	}
	text := `{"engineVersion":"25","authority":"gateway:test","seed":"` + abs(t, dir, "gateway.seed") + `","storage":{"kind":"postgresql","connection":{"file":"` + abs(t, connection) + `"},"connections":2,"startWaitSeconds":` + wait + `},` +
		`"decisionRecords":"` + abs(t, records) + `","listen":"127.0.0.1:8787","catalog":"` + abs(t, dir, "catalog") + `","platforms":{}}`
	cfg, err := parseEngineConfig([]byte(text))
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

// handoverInstance is one instance of serve --config on the kind.
type handoverInstance struct {
	url  string
	stop context.CancelFunc
	said *syncBuffer
	done chan struct{}
	exit int
}

// startHandoverInstance runs serve --config on the kind with the lease's
// periods given, until the test stops it.
func startHandoverInstance(t *testing.T, cfg engineConfig, sources map[string]sourceSpec, period, every time.Duration) *handoverInstance {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	return runHandoverInstance(t, cfg, sources, period, every, listener.Addr().String(),
		func(string, io.Writer) (net.Listener, error) { return listener, nil })
}

// runHandoverInstance runs serve --config on the kind, reached at addr,
// with the bind given, until the test stops it.
func runHandoverInstance(t *testing.T, cfg engineConfig, sources map[string]sourceSpec, period, every time.Duration, addr string, bind func(string, io.Writer) (net.Listener, error)) *handoverInstance {
	t.Helper()
	stopped, stop := context.WithCancel(context.Background())
	i := &handoverInstance{url: "http://" + addr, stop: stop, said: &syncBuffer{}, done: make(chan struct{})}
	run := kindRun{period: period, every: every, stopped: stopped, said: i.said, bind: bind}
	go func() {
		defer close(i.done)
		i.exit = runOnKind(cfg, testSeed, sources, nil, nil, run)
	}()
	t.Cleanup(func() {
		stop()
		select {
		case <-i.done:
		case <-time.After(90 * time.Second):
			t.Error("an instance did not stop")
		}
	})
	return i
}

// wait is the instance's exit code, once it ended within the time given.
func (i *handoverInstance) wait(t *testing.T, within time.Duration) int {
	t.Helper()
	select {
	case <-i.done:
		return i.exit
	case <-time.After(within):
		t.Fatalf("the instance did not end within %s: %s", within, i.said.String())
		return -1
	}
}

// handoverAnswer is one answer of an instance: its status, Retry-After and
// body, or the error that stood in for it.
type handoverAnswer struct {
	at         time.Time
	code       int
	retryAfter string
	body       string
	err        error
}

var handoverClient = &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{}}

func handoverAsk(method, url, body string) handoverAnswer {
	req, err := http.NewRequest(method, url, strings.NewReader(body))
	if err != nil {
		return handoverAnswer{at: time.Now(), err: err}
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := handoverClient.Do(req)
	if err != nil {
		return handoverAnswer{at: time.Now(), err: err}
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return handoverAnswer{at: time.Now(), code: resp.StatusCode, retryAfter: resp.Header.Get("Retry-After"), body: string(raw)}
}

func handoverAcquire(i *handoverInstance, session, arguments string) handoverAnswer {
	return handoverAsk(http.MethodPost, i.url+"/acquire", `{"session":"`+session+`","source":"screening","arguments":`+arguments+`}`)
}

// handoverUntil asks until the answer is the one wanted, within the time
// given, and returns that answer.
func handoverUntil(t *testing.T, within time.Duration, ask func() handoverAnswer, want func(handoverAnswer) bool, what string) handoverAnswer {
	t.Helper()
	deadline := time.Now().Add(within)
	for {
		a := ask()
		if want(a) {
			return a
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s: not within %s; the last answer %d %q %v", what, within, a.code, a.body, a.err)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// requireWaitingAnswer holds an answer to the waiting instance's: 503, the
// Retry-After of its poll and the fixed body.
func requireWaitingAnswer(t *testing.T, a handoverAnswer, retryAfter, what string) {
	t.Helper()
	if a.err != nil || a.code != http.StatusServiceUnavailable || a.retryAfter != retryAfter || a.body != string(waitingBody) {
		t.Fatalf("%s while the instance waits: %d %q %q %v", what, a.code, a.retryAfter, a.body, a.err)
	}
}

func pgLeaseHolder(t *testing.T, db *pgTestDB) string {
	t.Helper()
	rows := pgTestQuery(t, db.runtime, "SELECT holder FROM gateway.start_lease")
	if len(rows.rows) != 1 {
		return ""
	}
	return string(rows.rows[0][0])
}

func pgLeaseLive(t *testing.T, db *pgTestDB) bool {
	t.Helper()
	rows := pgTestQuery(t, db.runtime, "SELECT expires > pg_catalog.clock_timestamp() FROM gateway.start_lease")
	if len(rows.rows) != 1 {
		return false
	}
	live, _ := pgBool(rows.rows[0][0])
	return live
}

// A roll-out on one database: the new instance, started while the old one
// serves, listens and answers every route 503 and holds no lease; the old
// one, stopped with an acquisition in flight, admits nothing more (503 with
// Retry-After) and lets that acquisition finish, then releases the lease;
// the new one takes it at its next poll and serves. A caller of the new
// instance meets nothing but 503s, then nothing but answers.
func TestThePostgresInstanceWaitsAndTakesOverWhenTheHolderStops(t *testing.T) {
	db := newPgTestDB(t)
	db.migrate(t)
	t.Setenv(envSourceHelper, "1")
	sources := map[string]sourceSpec{"screening": {argv: []string{os.Args[0]}, env: helperEnv}}
	cfg := pgHandoverConfig(t, db, "60")
	ok := func(a handoverAnswer) bool { return a.err == nil && a.code == http.StatusOK }

	first := startHandoverInstance(t, cfg, sources, pgStartLeasePeriod, pgStartLeaseRenewal)
	handoverUntil(t, 30*time.Second, func() handoverAnswer { return handoverAsk(http.MethodGet, first.url+"/publickey", "") }, ok, "the first instance serves")
	holder := pgLeaseHolder(t, db)

	every := time.Second
	second := startHandoverInstance(t, cfg, sources, pgStartLeasePeriod, every)
	handoverUntil(t, 30*time.Second, func() handoverAnswer { return handoverAsk(http.MethodGet, second.url+"/publickey", "") },
		func(a handoverAnswer) bool { return a.err == nil && a.code == http.StatusServiceUnavailable }, "the second instance listens while it waits")
	for _, ask := range []struct{ method, path, body string }{
		{http.MethodGet, "/publickey", ""}, {http.MethodGet, "/registry", ""}, {http.MethodGet, "/posture", ""},
		{http.MethodPost, "/acquire", `{"session":"waiting-1","source":"screening","arguments":{"q":"acme"}}`},
		{http.MethodPost, "/seal", `{"session":"waiting-1"}`},
	} {
		requireWaitingAnswer(t, handoverAsk(ask.method, second.url+ask.path, ask.body), "1", ask.path)
	}
	waitingLine := "start: waiting up to 1m0s for the start lease, polled every 1s: start-lease-held: the database is served by gateway instance " + holder
	handoverUntil(t, 10*time.Second, func() handoverAnswer { return handoverAnswer{body: second.said.String()} },
		func(a handoverAnswer) bool { return strings.Contains(a.body, waitingLine) }, "the waiting start says what it waits for")
	if a := handoverAcquire(first, "before-1", `{"q":"acme"}`); !ok(a) {
		t.Fatalf("the first instance, beside a waiting one: %d %s %v", a.code, a.body, a.err)
	}
	if got := pgLeaseHolder(t, db); got != holder || !pgLeaseLive(t, db) {
		t.Fatalf("the waiting instance took or changed the lease: %q, the first's %q", got, holder)
	}

	// an acquisition in flight on the first when it is stopped
	barrier := t.TempDir()
	inFlight := make(chan handoverAnswer, 1)
	go func() {
		arguments, _ := json.Marshal(barrierArgPrefix + barrier)
		inFlight <- handoverAcquire(first, "in-flight-1", string(arguments))
	}()
	handoverUntil(t, 30*time.Second, func() handoverAnswer {
		_, err := os.Stat(filepath.Join(barrier, startedFile))
		return handoverAnswer{err: err}
	}, func(a handoverAnswer) bool { return a.err == nil }, "the acquisition in flight runs its source")

	// a caller of the second instance, from before the stop to after it serves
	var mu sync.Mutex
	var answers []handoverAnswer
	asking, stopAsking := context.WithCancel(context.Background())
	asked := make(chan struct{})
	go func() {
		defer close(asked)
		for n := 0; asking.Err() == nil; n++ {
			a := handoverAcquire(second, "caller-"+strings.Repeat("x", n%3)+time.Now().Format("150405.000000000"), `{"q":"acme"}`)
			mu.Lock()
			answers = append(answers, a)
			mu.Unlock()
			time.Sleep(50 * time.Millisecond)
		}
	}()
	defer stopAsking()

	first.stop()
	stopping := handoverUntil(t, 10*time.Second, func() handoverAnswer { return handoverAcquire(first, "during-1", `{"q":"acme"}`) },
		func(a handoverAnswer) bool { return a.err == nil && a.code == http.StatusServiceUnavailable }, "the stopping instance admits nothing more")
	if stopping.retryAfter != "10" || !strings.Contains(stopping.body, "this gateway instance is stopping and admits nothing more") {
		t.Fatalf("the stopping instance's refusal: %q %s", stopping.retryAfter, stopping.body)
	}
	if got := pgLeaseHolder(t, db); got != holder || !pgLeaseLive(t, db) {
		t.Fatalf("the lease left its holder while an acquisition was in flight: %q", got)
	}
	select {
	case a := <-inFlight:
		t.Fatalf("the acquisition in flight ended before its source did: %d %s %v", a.code, a.body, a.err)
	default:
	}
	if err := os.WriteFile(filepath.Join(barrier, releaseFile), []byte("go\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	select {
	case a := <-inFlight:
		if !ok(a) || !strings.Contains(a.body, `"receipt"`) {
			t.Fatalf("the acquisition in flight at the stop: %d %s %v", a.code, a.body, a.err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("the acquisition in flight at the stop did not finish")
	}
	if code := first.wait(t, 30*time.Second); code != 0 {
		t.Fatalf("the first instance's stop exits %d: %s", code, first.said.String())
	}
	released := time.Now()

	// the second takes the lease at its next poll, and serves
	served := handoverUntil(t, every+5*time.Second, func() handoverAnswer { return handoverAcquire(second, "after-1", `{"q":"acme"}`) }, ok,
		"the waiting instance serves once the stopped one released the lease")
	if took := served.at.Sub(released); took > every+4*time.Second {
		t.Fatalf("the waiting instance served %s after the release", took)
	}
	time.Sleep(200 * time.Millisecond)
	stopAsking()
	<-asked
	mu.Lock()
	defer mu.Unlock()
	servedAt := -1
	for n, a := range answers {
		switch {
		case a.err != nil:
			t.Fatalf("a caller of the second instance was refused outside the 503 window: %v", a.err)
		case a.code == http.StatusOK:
			if servedAt < 0 {
				servedAt = n
			}
		case a.code == http.StatusServiceUnavailable && servedAt < 0:
			requireWaitingAnswer(t, a, "1", "/acquire")
		default:
			t.Fatalf("answer %d of %d to a caller of the second instance: %d %s", n, len(answers), a.code, a.body)
		}
	}
	if servedAt < 1 {
		t.Fatalf("the caller saw no wait and then service: %d answers, served from %d", len(answers), servedAt)
	}
	if got := pgLeaseHolder(t, db); got == holder || got == "" {
		t.Fatalf("the lease after the hand-over: %q", got)
	}
	second.stop()
	if code := second.wait(t, 60*time.Second); code != 0 {
		t.Fatalf("the second instance's stop exits %d", code)
	}
	if pgLeaseLive(t, db) {
		t.Fatal("a clean stop left its lease live")
	}
}

// A new instance started beside the old one on the same host and address
// finds the address in use: it waits without listening, while the old one
// serves there, and binds the address and serves once the old one stopped
// and released the lease.
func TestThePostgresInstanceOnTheHoldersAddressWaitsWithoutListeningAndTakesOver(t *testing.T) {
	db := newPgTestDB(t)
	db.migrate(t)
	cfg := pgHandoverConfig(t, db, "60")
	ok := func(a handoverAnswer) bool { return a.err == nil && a.code == http.StatusOK }

	first := startHandoverInstance(t, cfg, map[string]sourceSpec{}, pgStartLeasePeriod, pgStartLeaseRenewal)
	handoverUntil(t, 30*time.Second, func() handoverAnswer { return handoverAsk(http.MethodGet, first.url+"/publickey", "") }, ok, "the first instance serves")
	holder := pgLeaseHolder(t, db)

	same := cfg
	same.listen = strings.TrimPrefix(first.url, "http://")
	second := runHandoverInstance(t, same, map[string]sourceSpec{}, pgStartLeasePeriod, time.Second, same.listen, listenForConfig)
	handoverUntil(t, 10*time.Second, func() handoverAnswer { return handoverAnswer{body: second.said.String()} },
		func(a handoverAnswer) bool {
			return strings.Contains(a.body, "start: "+same.listen+" is in use") && strings.Contains(a.body, "start: waiting up to 1m0s for the start lease")
		}, "the second instance waits without listening")
	select {
	case <-second.done:
		t.Fatalf("the instance on the holder's address ended at once, exit %d: %s", second.exit, second.said.String())
	default:
	}
	if a := handoverAsk(http.MethodGet, first.url+"/publickey", ""); !ok(a) {
		t.Fatalf("the first instance, beside one waiting on its address: %d %s %v", a.code, a.body, a.err)
	}
	if got := pgLeaseHolder(t, db); got != holder || !pgLeaseLive(t, db) {
		t.Fatalf("the waiting instance took or changed the lease: %q, the first's %q", got, holder)
	}

	first.stop()
	if code := first.wait(t, 30*time.Second); code != 0 {
		t.Fatalf("the first instance's stop exits %d: %s", code, first.said.String())
	}
	handoverUntil(t, 20*time.Second, func() handoverAnswer { return handoverAsk(http.MethodGet, second.url+"/publickey", "") }, ok,
		"the second instance serves on the address once the first released the lease")
	if got := pgLeaseHolder(t, db); got == holder || got == "" {
		t.Fatalf("the lease after the hand-over: %q", got)
	}
	second.stop()
	if code := second.wait(t, 60*time.Second); code != 0 {
		t.Fatalf("the second instance's stop exits %d: %s", code, second.said.String())
	}
}

// A holder that ends without releasing its lease -- a crash, a kill -- is
// taken over by the waiting instance once the lease expires by the
// database's clock, and not before.
func TestThePostgresWaitingInstanceTakesACrashedHoldersLeaseOnceItExpires(t *testing.T) {
	db := newPgTestDB(t)
	db.migrate(t)
	cfg := pgHandoverConfig(t, db, "60")
	period := 3 * time.Second
	crashed := pgTakeForTest(t, db.open(t, nil), period, time.Second)
	taken := time.Now()

	every := 500 * time.Millisecond
	second := startHandoverInstance(t, cfg, map[string]sourceSpec{}, pgStartLeasePeriod, every)
	requireWaitingAnswer(t, handoverUntil(t, 10*time.Second, func() handoverAnswer { return handoverAsk(http.MethodGet, second.url+"/registry", "") },
		func(a handoverAnswer) bool { return a.err == nil }, "the waiting instance listens"), "1", "/registry")
	served := handoverUntil(t, period+every+10*time.Second, func() handoverAnswer { return handoverAsk(http.MethodGet, second.url+"/publickey", "") },
		func(a handoverAnswer) bool { return a.err == nil && a.code == http.StatusOK }, "the waiting instance serves once the crashed holder's lease expired")
	if early := served.at.Sub(taken); early < period-time.Second {
		t.Fatalf("the waiting instance served %s after the take, before the lease of %s expired", early, period)
	}
	if got := pgLeaseHolder(t, db); got == crashed.holder || got == "" {
		t.Fatalf("the lease after the takeover: %q", got)
	}
	if !strings.Contains(second.said.String(), "start-lease-held: the database is served by gateway instance "+crashed.holder) ||
		!strings.Contains(second.said.String(), "start: the start lease was released or expired, and this instance took it after waiting") {
		t.Fatalf("the start does not say what it waited for: %s", second.said.String())
	}
	second.stop()
	if code := second.wait(t, 60*time.Second); code != 0 {
		t.Fatalf("the second instance's stop exits %d", code)
	}
}

// The connections the pool kept idle through the wait, which the server
// may end meanwhile, are not what the start's checks after the wait use:
// they open fresh ones, and the start serves.
func TestThePostgresStartAfterAWaitChecksOnFreshConnections(t *testing.T) {
	db := newPgTestDB(t)
	db.migrate(t)
	cfg := pgHandoverConfig(t, db, "60")
	period := 6 * time.Second
	pgTakeForTest(t, db.open(t, nil), period, time.Second)
	second := startHandoverInstance(t, cfg, map[string]sourceSpec{}, pgStartLeasePeriod, 500*time.Millisecond)
	handoverUntil(t, 10*time.Second, func() handoverAnswer { return handoverAnswer{body: second.said.String()} },
		func(a handoverAnswer) bool { return strings.Contains(a.body, "start: waiting up to") }, "the instance waits")
	// end the sessions that sat idle from before the wait: the pool's, and
	// the crashed holder's; a poll's own connection lives for one poll
	time.Sleep(1500 * time.Millisecond)
	rows := pgTestQuery(t, db.runtime, "SELECT count(pg_catalog.pg_terminate_backend(pid)) FROM pg_catalog.pg_stat_activity "+
		"WHERE datname = pg_catalog.current_database() AND usename = current_user AND pid <> pg_catalog.pg_backend_pid() "+
		"AND state = 'idle' AND backend_start < pg_catalog.clock_timestamp() - interval '1 second'")
	if n, _ := pgInt8(rows.rows[0][0]); n < 1 {
		t.Fatalf("no idle session was ended: %d", n)
	}
	handoverUntil(t, period+10*time.Second, func() handoverAnswer { return handoverAsk(http.MethodGet, second.url+"/publickey", "") },
		func(a handoverAnswer) bool { return a.err == nil && a.code == http.StatusOK }, "the instance serves after the wait")
	second.stop()
	if code := second.wait(t, 60*time.Second); code != 0 {
		t.Fatalf("the instance's stop exits %d: %s", code, second.said.String())
	}
}

// A wait that runs out is the start refused as one that does not wait is:
// exit 1, start-lease-held, naming the holder. It took nothing and wrote
// nothing, and the listener it answered on is closed.
func TestThePostgresStartWhoseWaitRunsOutIsRefusedStartLeaseHeld(t *testing.T) {
	db := newPgTestDB(t)
	db.migrate(t)
	cfg := pgHandoverConfig(t, db, "1")
	held := pgTakeForTest(t, db.open(t, nil), pgStartLeasePeriod, pgStartLeaseRenewal)
	began := time.Now()
	waiting := startHandoverInstance(t, cfg, map[string]sourceSpec{}, pgStartLeasePeriod, 300*time.Millisecond)
	if code := waiting.wait(t, 20*time.Second); code != 1 {
		t.Fatalf("a start whose wait ran out exits %d: %s", code, waiting.said.String())
	}
	if waited := time.Since(began); waited < time.Second {
		t.Fatalf("the start was refused after %s, before its wait of 1s", waited)
	}
	if !strings.Contains(waiting.said.String(), "start: start-lease-held: the database is served by gateway instance "+held.holder) {
		t.Fatalf("the refusal: %s", waiting.said.String())
	}
	if got := pgLeaseHolder(t, db); got != held.holder || !pgLeaseLive(t, db) {
		t.Fatalf("the waiting start changed the lease: %q", got)
	}
	if rows := pgTestQuery(t, db.runtime, "SELECT count(*) FROM gateway.logs"); len(rows.rows) != 1 {
		t.Fatal("the registry's logs could not be counted")
	} else if n, _ := pgInt8(rows.rows[0][0]); n != 0 {
		t.Fatalf("the waiting start made the registry: %d logs", n)
	}
	if a := handoverAsk(http.MethodGet, waiting.url+"/publickey", ""); a.err == nil {
		t.Fatalf("the refused start's listener still answers: %d", a.code)
	}
}

// A stop while the start waits ends it, exit 0: it never held the lease.
func TestThePostgresStopWhileWaitingEndsTheStartHoldingNothing(t *testing.T) {
	db := newPgTestDB(t)
	db.migrate(t)
	cfg := pgHandoverConfig(t, db, "60")
	held := pgTakeForTest(t, db.open(t, nil), pgStartLeasePeriod, pgStartLeaseRenewal)
	waiting := startHandoverInstance(t, cfg, map[string]sourceSpec{}, pgStartLeasePeriod, 300*time.Millisecond)
	handoverUntil(t, 10*time.Second, func() handoverAnswer { return handoverAsk(http.MethodGet, waiting.url+"/publickey", "") },
		func(a handoverAnswer) bool { return a.err == nil && a.code == http.StatusServiceUnavailable }, "the instance waits")
	waiting.stop()
	if code := waiting.wait(t, 10*time.Second); code != 0 || !strings.Contains(waiting.said.String(), "stop: "+errStoppedWaiting.Error()) {
		t.Fatalf("a stop while waiting exits %d: %s", code, waiting.said.String())
	}
	if got := pgLeaseHolder(t, db); got != held.holder || !pgLeaseLive(t, db) {
		t.Fatalf("the stopped wait changed the lease: %q", got)
	}
}
