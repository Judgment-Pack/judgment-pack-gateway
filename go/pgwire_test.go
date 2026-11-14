package main

// The PostgreSQL client's login and its connection string, held without a
// database: a server in the test speaks the protocol's login as a server
// would, and as a server that is not the database would.

import (
	"bufio"
	"bytes"
	"crypto/pbkdf2"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"testing/fstest"
	"time"
)

// A connection string out of form is refused with one sentence that holds
// nothing of it, and one in form prints as a fixed phrase.
func TestAConnectionStringIsNeverPrinted(t *testing.T) {
	const password, user, host = "pw-not-to-print", "user-not-to-print", "host-not-to-print.invalid"
	for _, text := range []string{
		"postgresql://" + user + ":" + password + "@" + host + ":5432/db?sslmode=require",
		"postgresql://" + user + ":" + password + "@" + host + ":5432/db?sslmode=disable",
		"postgresql://" + user + ":" + password + "@" + host + ":5432/db?sslmode=verify-full&sslmode=verify-full",
		"postgresql://" + user + ":" + password + "@" + host + ":5432/db?application_name=x",
		"postgresql://" + user + ":" + password + "@" + host + ":99999/db",
		"postgresql://" + user + ":" + password + "@" + host + ":5432/",
		"postgresql://" + user + "@" + host + ":5432/db",
		"postgresql://" + user + ":@" + host + ":5432/db",
		"postgresql://" + user + "@127.0.0.1:5432/db?sslmode=disable",
		"postgresql://" + user + ":" + password + "@127.0.0.1:5432/db?sslmode=disable&sslrootcert=/x",
		"mysql://" + user + ":" + password + "@" + host + "/db",
		"host=" + host + " user=" + user + " password=" + password,
	} {
		_, err := parsePgDSN(text)
		if err == nil {
			t.Fatalf("a connection string out of form was taken")
		}
		if !errors.Is(err, errPgDSN) {
			t.Fatalf("a connection string out of form was refused otherwise than with errPgDSN: %v", err)
		}
		for _, secret := range []string{password, user, host} {
			if strings.Contains(err.Error(), secret) {
				t.Fatalf("the refusal of a connection string quotes it: %v", err)
			}
		}
	}
	d, err := parsePgDSN("postgresql://" + user + ":" + password + "@" + host + ":5432/db?sslmode=verify-full&connect_timeout=5")
	if err != nil {
		t.Fatal(err)
	}
	printed := fmt.Sprintf("%v %+v %#v %s %v", d, d, d, d, &d)
	for _, secret := range []string{password, user, host, "5432"} {
		if strings.Contains(printed, secret) {
			t.Fatalf("a connection string printed holds its fields: %s", printed)
		}
	}
	if d.connectTimeout != 5*time.Second || !d.tls || d.port != "5432" {
		t.Fatalf("the connection string read as %+v", []any{d.connectTimeout, d.tls, d.port})
	}
}

// pgFake is a server in the test: it reads the startup message and then
// runs its script against the client, recording every byte the client sent.
type pgFake struct {
	ln   net.Listener
	mu   sync.Mutex
	sent bytes.Buffer
	done chan struct{}
}

type pgFakeConn struct {
	c    net.Conn
	r    *bufio.Reader
	fake *pgFake
}

func (f *pgFakeConn) send(kind byte, body []byte) {
	msg := []byte{kind, 0, 0, 0, 0}
	binary.BigEndian.PutUint32(msg[1:], uint32(len(body)+4))
	f.c.Write(append(msg, body...))
}

func (f *pgFakeConn) auth(code uint32, rest []byte) {
	body := binary.BigEndian.AppendUint32(nil, code)
	f.send('R', append(body, rest...))
}

func (f *pgFakeConn) ready() { f.send('Z', []byte{'I'}) }

// receive reads one message of the client's.
func (f *pgFakeConn) receive() (byte, []byte, error) {
	var header [5]byte
	if _, err := io.ReadFull(f.r, header[:]); err != nil {
		return 0, nil, err
	}
	body := make([]byte, binary.BigEndian.Uint32(header[1:])-4)
	_, err := io.ReadFull(f.r, body)
	return header[0], body, err
}

type pgTee struct {
	net.Conn
	fake *pgFake
}

func (t pgTee) Read(p []byte) (int, error) {
	n, err := t.Conn.Read(p)
	t.fake.mu.Lock()
	t.fake.sent.Write(p[:n])
	t.fake.mu.Unlock()
	return n, err
}

func newPgFake(t *testing.T, script func(*pgFakeConn)) (*pgFake, pgDSN) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	fake := &pgFake{ln: ln, done: make(chan struct{})}
	go func() {
		defer close(fake.done)
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(20 * time.Second))
		conn := &pgFakeConn{c: c, r: bufio.NewReader(pgTee{c, fake}), fake: fake}
		var length [4]byte
		if _, err := io.ReadFull(conn.r, length[:]); err != nil {
			return
		}
		if _, err := io.ReadFull(conn.r, make([]byte, binary.BigEndian.Uint32(length[:])-4)); err != nil {
			return
		}
		script(conn)
	}()
	t.Cleanup(func() {
		ln.Close()
		<-fake.done
	})
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	return fake, pgDSN{host: "127.0.0.1", port: port, user: "u", password: "pw-of-the-test", database: "d", connectTimeout: 10 * time.Second}
}

func (f *pgFake) clientSent() []byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	return bytes.Clone(f.sent.Bytes())
}

// scramServer runs a server's side of SCRAM-SHA-256 for password, with the
// salt and count given, and ends it with signature, unless forge is set,
// when it ends it with a signature of another verifier's.
type scramServer struct {
	password   string
	iterations int
	nonce      func(client string) string
	forge      bool
}

func (s scramServer) run(f *pgFakeConn) bool {
	f.auth(10, []byte("SCRAM-SHA-256\x00\x00"))
	kind, body, err := f.receive()
	if err != nil || kind != 'p' {
		return false
	}
	mechanism, rest, _ := bytes.Cut(body, []byte{0})
	if string(mechanism) != "SCRAM-SHA-256" || len(rest) < 4 {
		return false
	}
	clientFirst := string(rest[4:])
	bare := strings.TrimPrefix(clientFirst, "n,,")
	clientNonce := bare[strings.Index(bare, "r=")+2:]
	salt := []byte("salt-of-the-test")
	nonce := clientNonce + "server-part"
	if s.nonce != nil {
		nonce = s.nonce(clientNonce)
	}
	serverFirst := "r=" + nonce + ",s=" + base64.StdEncoding.EncodeToString(salt) + ",i=" + strconv.Itoa(s.iterations)
	f.auth(11, []byte(serverFirst))
	kind, body, err = f.receive()
	if err != nil || kind != 'p' {
		return false
	}
	final := string(body)
	withoutProof := final[:strings.Index(final, ",p=")]
	password := s.password
	if s.forge {
		password = "another password"
	}
	salted, _ := pbkdf2.Key(sha256.New, password, salt, s.iterations, sha256.Size)
	signature := pgHMAC(pgHMAC(salted, "Server Key"), bare+","+serverFirst+","+withoutProof)
	f.auth(12, []byte("v="+base64.StdEncoding.EncodeToString(signature)))
	return true
}

// The login holds the server to the protocol's signature that it holds the
// password's verifier: a server that cannot make the signature, admits the
// login without the exchange, asks for the password in the clear or by MD5,
// or bends the exchange out of its bounds, is refused, and is sent no
// password.
func TestTheLoginHoldsTheServerToTheSCRAMExchange(t *testing.T) {
	const password = "pw-of-the-test"
	t.Run("a server that holds the verifier is admitted", func(t *testing.T) {
		_, dsn := newPgFake(t, func(f *pgFakeConn) {
			if (scramServer{password: password, iterations: 4096}).run(f) {
				f.auth(0, nil)
				f.send('S', []byte("server_version_num\x00160015\x00"))
				f.ready()
			}
		})
		c, err := pgConnect(dsn, time.Now().Add(20*time.Second))
		if err != nil {
			t.Fatalf("a server that holds the verifier: %v", err)
		}
		if c.params["server_version_num"] != "160015" {
			t.Fatalf("the server's parameters read as %v", c.params)
		}
		c.close()
	})
	cases := []struct {
		name   string
		script func(*pgFakeConn)
		want   string
	}{
		{"a signature of another verifier", func(f *pgFakeConn) {
			if (scramServer{password: password, iterations: 4096, forge: true}).run(f) {
				f.auth(0, nil)
				f.ready()
			}
		}, "login signature"},
		{"an admission with no signature", func(f *pgFakeConn) {
			f.auth(10, []byte("SCRAM-SHA-256\x00\x00"))
			f.receive()
			f.auth(0, nil)
			f.ready()
		}, "before it proved"},
		{"an admission with no exchange", func(f *pgFakeConn) {
			f.auth(0, nil)
			f.ready()
		}, "without the password exchange"},
		{"a password in the clear", func(f *pgFakeConn) {
			f.auth(3, nil)
			f.receive()
		}, "other than SCRAM-SHA-256"},
		{"a password by MD5", func(f *pgFakeConn) {
			f.auth(5, []byte("salt"))
			f.receive()
		}, "other than SCRAM-SHA-256"},
		{"a count of iterations below the bound", func(f *pgFakeConn) {
			(scramServer{password: password, iterations: 1024}).run(f)
		}, "iteration count"},
		{"a nonce that does not extend the client's", func(f *pgFakeConn) {
			(scramServer{password: password, iterations: 4096, nonce: func(client string) string { return strings.Repeat("x", len(client)+8) }}).run(f)
		}, "out of form"},
		{"a ready message before the login", func(f *pgFakeConn) {
			f.ready()
		}, "before it admitted"},
		{"a mechanism other than SCRAM-SHA-256", func(f *pgFakeConn) {
			f.auth(10, []byte("SCRAM-SHA-256-PLUS\x00\x00"))
			f.receive()
		}, "no SCRAM-SHA-256"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fake, dsn := newPgFake(t, tc.script)
			c, err := pgConnect(dsn, time.Now().Add(20*time.Second))
			if err == nil {
				c.close()
				t.Fatal("the login was admitted")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("the login was refused as %q, want %q", err, tc.want)
			}
			fake.ln.Close()
			<-fake.done
			if bytes.Contains(fake.clientSent(), []byte(password)) {
				t.Fatal("the client sent the password itself")
			}
		})
	}
}

// A server's refusal of the login, and a server that cannot be reached,
// are named by their class alone: nothing of the user, the database, the
// host or the port, and nothing the server wrote, is in the error.
func TestALoginFailureQuotesNothing(t *testing.T) {
	_, dsn := newPgFake(t, func(f *pgFakeConn) {
		var body []byte
		for _, field := range []string{"SFATAL", "C28P01", "Mpassword authentication failed for user \"u-of-the-test\"", "Ddetail-of-the-server"} {
			body = append(append(body, field...), 0)
		}
		f.send('E', append(body, 0))
	})
	dsn.user, dsn.database = "u-of-the-test", "db-of-the-test"
	_, err := pgConnect(dsn, time.Now().Add(20*time.Second))
	if err == nil || !strings.Contains(err.Error(), "28P01") {
		t.Fatalf("a refused login: %v", err)
	}
	for _, quoted := range []string{"u-of-the-test", "db-of-the-test", dsn.port, "detail-of-the-server", "authentication failed"} {
		if strings.Contains(err.Error(), quoted) {
			t.Fatalf("a refused login's error quotes %q: %v", quoted, err)
		}
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	ln.Close()
	_, err = pgConnect(pgDSN{host: "127.0.0.1", port: port, user: "u", database: "d", connectTimeout: 5 * time.Second}, time.Now().Add(5*time.Second))
	if err == nil {
		t.Fatal("a connection to a closed port succeeded")
	}
	if strings.Contains(err.Error(), port) || strings.Contains(err.Error(), "127.0.0.1") {
		t.Fatalf("an unreachable database's error quotes its address: %v", err)
	}
}

// pgPeerAs is a connection whose remote address reads as addr: what a
// resolver that answers a loopback host's name with another address gives.
type pgPeerAs struct {
	net.Conn
	addr net.Addr
}

func (c pgPeerAs) RemoteAddr() net.Addr { return c.addr }

// A connection without TLS is used only to a peer at a loopback address:
// the host localhost, answered by the resolver with another address, is
// closed after the dial with nothing sent on it, the password least of
// all. The same dial to a loopback peer sends the startup message.
func TestADisabledTLSConnectionToAPeerOffLoopbackIsRefused(t *testing.T) {
	cases := []struct {
		name     string
		peer     net.Addr
		admitted bool
	}{
		{"a peer off loopback", &net.TCPAddr{IP: net.ParseIP("192.0.2.10"), Port: 5432}, false},
		{"an IPv6 peer off loopback", &net.TCPAddr{IP: net.ParseIP("2001:db8::10"), Port: 5432}, false},
		{"a peer that is no TCP address", &net.UnixAddr{Name: "socket", Net: "unix"}, false},
		{"an IPv4 loopback peer", &net.TCPAddr{IP: net.ParseIP("127.0.0.2"), Port: 5432}, true},
		{"an IPv6 loopback peer", &net.TCPAddr{IP: net.IPv6loopback, Port: 5432}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fake, dsn := newPgFake(t, func(f *pgFakeConn) {})
			address := net.JoinHostPort(dsn.host, dsn.port)
			dial := pgDial
			t.Cleanup(func() { pgDial = dial })
			pgDial = func(_ string, deadline time.Time) (net.Conn, error) {
				c, err := dial(address, deadline)
				if err != nil {
					return nil, err
				}
				return pgPeerAs{c, tc.peer}, nil
			}
			text := "postgresql://u:pw-of-the-test@localhost:" + dsn.port + "/d?sslmode=disable"
			d, err := parsePgDSN(text)
			if err != nil {
				t.Fatalf("the host localhost with sslmode=disable: %v", err)
			}
			c, err := pgConnect(d, time.Now().Add(10*time.Second))
			if err == nil {
				c.close()
			}
			fake.ln.Close()
			<-fake.done
			sent := fake.clientSent()
			if tc.admitted {
				if len(sent) == 0 {
					t.Fatalf("a loopback peer was sent nothing: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), "not a loopback address") {
				t.Fatalf("a connection without TLS to %v: %v", tc.peer, err)
			}
			if len(sent) != 0 {
				t.Fatalf("a peer off loopback was sent %d bytes", len(sent))
			}
		})
	}
}

// An error the server reports reaches the caller as its SQLSTATE alone:
// the message, the detail, the hint and every other field the server
// filled -- where it quotes a statement's values, a caller's bytes -- are
// not in it.
func TestAServerErrorReachesTheCallerWithNoneOfItsText(t *testing.T) {
	const marker = "caller-bytes-marker"
	const password = "pw-of-the-test"
	_, dsn := newPgFake(t, func(f *pgFakeConn) {
		if !(scramServer{password: password, iterations: 4096}).run(f) {
			return
		}
		f.auth(0, nil)
		f.ready()
		var body []byte
		for _, field := range []string{"SERROR", "VERROR", "C22P02", "Minvalid input syntax for type integer: \"" + marker + "\"",
			"D" + marker + " in the detail", "H" + marker + " in the hint", "W" + marker + " in the context", "n" + marker + "_constraint",
			"t" + marker + "_table", "c" + marker + "_column", "s" + marker + "_schema"} {
			body = append(append(body, field...), 0)
		}
		for {
			kind, _, err := f.receive()
			if err != nil {
				return
			}
			switch kind {
			case 'S':
				f.send('E', append(body, 0))
				f.ready()
			case 'Q':
				f.send('E', append(body, 0))
				f.ready()
			case 'X':
				return
			}
		}
	})
	c, err := pgConnect(dsn, time.Now().Add(20*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer c.close()
	_, execErr := c.exec(`SELECT $1::text::int`, marker)
	scriptErr := c.script(`SELECT 1`)
	for name, err := range map[string]error{"a statement": execErr, "a script": scriptErr} {
		if err == nil || pgCode(err) != "22P02" || !strings.Contains(err.Error(), "SQLSTATE 22P02") {
			t.Fatalf("%s the server refused: %v", name, err)
		}
		if strings.Contains(err.Error(), "marker") || strings.Contains(err.Error(), "invalid input") {
			t.Fatalf("%s's error quotes the server's text: %v", name, err)
		}
	}
}

// pgSQLText is the SQL the kind sends and carries: its migration files and
// every string literal of the Go files that hold its statements.
func pgSQLText(t *testing.T) map[string]string {
	t.Helper()
	text := map[string]string{}
	for _, name := range []string{"store_pg.go", "store_pg_migrate.go", "pgwire.go"} {
		data, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		literals := regexp.MustCompile("`[^`]*`|\"(?:[^\"\\\\\\n]|\\\\.)*\"").FindAllString(string(data), -1)
		text[name] = strings.Join(literals, "\n")
	}
	files, err := filepath.Glob(filepath.Join("store_pg", "migrations", "*.sql"))
	if err != nil {
		t.Fatal(err)
	}
	files = append(files, filepath.Join("store_pg", "grants.sql"))
	for _, name := range files {
		data, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		text[name] = string(data)
	}
	return text
}

// The kind reads no clock of the database but in the start lease: no
// statement it sends or schema file it carries names one, so no time it
// holds is the server's (ADR-0031, decision 9). The lease's statements
// alone read it, as clock_timestamp() and nothing else, each on the lease's
// table: an expiry several instances judge is the database's.
func TestThePostgresKindReadsNoDatabaseClock(t *testing.T) {
	clock := regexp.MustCompile(`(?i)\b(now|clock_timestamp|statement_timestamp|transaction_timestamp|timeofday|pg_postmaster_start_time)\s*\(|\b(current_timestamp|current_date|current_time|localtimestamp|localtime)\b`)
	for name, text := range pgSQLText(t) {
		if found := clock.FindString(text); found != "" {
			t.Errorf("%s names the database's clock: %q", name, found)
		}
	}
	data, err := os.ReadFile("store_pg_lease.go")
	if err != nil {
		t.Fatal(err)
	}
	read := 0
	for _, literal := range regexp.MustCompile("`[^`]*`|\"(?:[^\"\\\\\\n]|\\\\.)*\"").FindAllString(string(data), -1) {
		found := clock.FindAllString(literal, -1)
		for _, f := range found {
			if strings.ToLower(f) != "clock_timestamp(" {
				t.Errorf("the start lease names %q, and reads the database's clock by clock_timestamp() alone", f)
			}
		}
		if len(found) > 0 {
			read++
			if !strings.Contains(literal, "gateway.start_lease") {
				t.Errorf("a statement that reads the database's clock is not the start lease's: %s", literal)
			}
		}
	}
	if read != 6 {
		t.Errorf("%d of the start lease's statements read the database's clock; holder, take over, take first, renew, release and fence do", read)
	}
}

// pgSQLCode is SQL without its comments.
func pgSQLCode(text string) string {
	var out []string
	for _, line := range strings.Split(text, "\n") {
		if i := strings.Index(line, "--"); i >= 0 {
			line = line[:i]
		}
		out = append(out, line)
	}
	return strings.Join(out, "\n")
}

// The schema's files make no role, set nothing on a role, a database or
// the server, define no function (SECURITY DEFINER or not), and count
// nothing by a sequence; only grants.sql grants, and only it reads the
// setting that names the run-time role.
func TestTheSchemaFilesMakeNoRoleSettingOrFunction(t *testing.T) {
	refused := []*regexp.Regexp{
		regexp.MustCompile(`(?i)\b(CREATE|ALTER|DROP)\s+(ROLE|USER|GROUP)\b`),
		regexp.MustCompile(`(?i)\bALTER\s+(DATABASE|SYSTEM)\b`),
		regexp.MustCompile(`(?i)\bSECURITY\s+DEFINER\b`),
		regexp.MustCompile(`(?i)\bCREATE\s+(OR\s+REPLACE\s+)?(FUNCTION|PROCEDURE|SEQUENCE|EXTENSION|TRIGGER|RULE|VIEW)\b`),
		regexp.MustCompile(`(?i)\b(SMALLSERIAL|BIGSERIAL|SERIAL)\b|\bAS\s+IDENTITY\b|\bnextval\b`),
		regexp.MustCompile(`(?i)\bSET\s+(SESSION\s+|LOCAL\s+)?(ROLE|SESSION\s+AUTHORIZATION)\b|\bset_config\b`),
		regexp.MustCompile(`(?i)\bALTER\s+DEFAULT\s+PRIVILEGES\b|\bOWNER\s+TO\b`),
	}
	for name, text := range pgSQLText(t) {
		if !strings.HasSuffix(name, ".sql") {
			continue
		}
		code := pgSQLCode(text)
		for _, r := range refused {
			if found := r.FindString(code); found != "" {
				t.Errorf("%s holds %q", name, found)
			}
		}
		if grants := regexp.MustCompile(`(?i)\bGRANT\b`).FindString(code); grants != "" && filepath.Base(name) != "grants.sql" {
			t.Errorf("%s grants: only grants.sql does", name)
		}
	}
	set := pgShippedMigrations()
	if len(set.versions) == 0 || set.versions[0].version != 1 {
		t.Fatalf("the schema carried: %v", set.versions)
	}
}

// The schema's files are recorded by digest: a file changed and its digest
// not, a file the record does not list, or a gap in the numbering, refuses
// the set the binary would carry.
func TestTheSchemaFilesHoldToTheirRecordedDigests(t *testing.T) {
	read := func(name string) []byte {
		data, err := os.ReadFile(filepath.Join("store_pg", name))
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	shipped, err := filepath.Glob(filepath.Join("store_pg", "migrations", "*.sql"))
	if err != nil || len(shipped) == 0 {
		t.Fatalf("the migrations: %v", err)
	}
	tree := func() map[string][]byte {
		files := map[string][]byte{"SHA256SUMS": read("SHA256SUMS"), "grants.sql": read("grants.sql")}
		for _, path := range shipped {
			files["migrations/"+filepath.Base(path)] = read(filepath.Join("migrations", filepath.Base(path)))
		}
		return files
	}
	next := len(shipped) + 1
	if _, err := readPgMigrationSet(pgMapFS(tree())); err != nil {
		t.Fatalf("the schema as committed: %v", err)
	}
	changed := tree()
	changed["migrations/0001_contract_spaces.sql"] = append(changed["migrations/0001_contract_spaces.sql"], "-- one more line\n"...)
	if _, err := readPgMigrationSet(pgMapFS(changed)); err == nil || !strings.Contains(err.Error(), "does not match its digest") {
		t.Fatalf("a migration changed under its recorded digest: %v", err)
	}
	unlisted := tree()
	unlisted[fmt.Sprintf("migrations/%04d_more.sql", next)] = []byte("SELECT 1;\n")
	if _, err := readPgMigrationSet(pgMapFS(unlisted)); err == nil || !strings.Contains(err.Error(), "SHA256SUMS does not list") {
		t.Fatalf("a migration the record does not list: %v", err)
	}
	gap := tree()
	gap[fmt.Sprintf("migrations/%04d_more.sql", next+1)] = []byte("SELECT 1;\n")
	if _, err := readPgMigrationSet(pgMapFS(gap)); err == nil || !strings.Contains(err.Error(), fmt.Sprintf("is not numbered %04d", next)) {
		t.Fatalf("a gap in the migrations' numbers: %v", err)
	}
	grants := tree()
	grants["grants.sql"] = append(grants["grants.sql"], "-- more\n"...)
	if _, err := readPgMigrationSet(pgMapFS(grants)); err == nil || !strings.Contains(err.Error(), "grants.sql does not match") {
		t.Fatalf("grants changed under their recorded digest: %v", err)
	}
}

func pgMapFS(files map[string][]byte) fs.FS {
	tree := fstest.MapFS{}
	for name, data := range files {
		tree[name] = &fstest.MapFile{Data: data, Mode: 0o644}
	}
	return tree
}

// Where the PostgreSQL tests are required, as in the CI job that runs
// them, a server not named fails them rather than skipping them.
func TestThePostgresTestsDoNotSkipWhereRequired(t *testing.T) {
	env := func(values map[string]string) func(string) string {
		return func(name string) string { return values[name] }
	}
	if _, skip, fail := pgTestAdminFrom(env(map[string]string{pgTestRequiredVariable: "1"})); fail == "" || skip != "" {
		t.Fatalf("required and no server: skip %q, fail %q", skip, fail)
	}
	if _, skip, fail := pgTestAdminFrom(env(nil)); skip == "" || fail != "" {
		t.Fatalf("not required and no server: skip %q, fail %q", skip, fail)
	}
	if _, skip, fail := pgTestAdminFrom(env(map[string]string{pgTestDSNVariable: "postgresql://u:secret-pw@db.invalid/d?sslmode=disable"})); fail == "" || skip != "" || strings.Contains(fail, "secret-pw") {
		t.Fatalf("a connection string out of form: skip %q, fail %q", skip, fail)
	}
	if d, skip, fail := pgTestAdminFrom(env(map[string]string{pgTestDSNVariable: "postgresql://u:pw@127.0.0.1:5432/d?sslmode=disable"})); skip != "" || fail != "" || d.database != "d" {
		t.Fatalf("a server named: skip %q, fail %q", skip, fail)
	}
}
