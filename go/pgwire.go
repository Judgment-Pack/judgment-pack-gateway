package main

// A client of the PostgreSQL frontend/backend protocol, version 3.0, as far
// as the PostgreSQL storage kind needs it (store_pg.go,
// docs/adr/0031-a-second-storage-kind-on-postgresql.md). The core links the
// standard library alone (ADR-0001, boundary_test.go), so the kind cannot
// take a driver: this file is the part of one it uses, and no more.
//
// What it does: a TCP connection, TLS through the protocol's SSLRequest with
// the server's certificate checked against its host name (or no TLS at all,
// to a loopback host only, and only once the connection's remote address is
// a loopback address), the SCRAM-SHA-256 login with the server's
// signature checked, and statements through the extended query protocol with
// every parameter bound -- never spliced into the text -- and every value in
// the binary format. What it refuses: a cleartext or MD5 password exchange,
// TLS without a checked certificate, a message past its bound, and anything
// the protocol does not say a server sends at that point.
//
// Nothing here quotes the connection string, its password, its user, its
// host or its database in an error: a connection string is a credential,
// and an error is written where credentials are not (ADR-0031, "The
// connection string"). Errors name what failed by a fixed sentence and, for
// an error the server reported, by its SQLSTATE alone: the server's message
// is never kept, since it quotes the statement's values -- a caller's bytes
// -- as its detail does.

import (
	"bufio"
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	pgProtocolVersion = 3 << 16 // 3.0
	pgSSLRequestCode  = 80877103
	// pgMaxValue bounds one value the kind writes or reads: a blob, an
	// entry, a document, a log record. pgMaxMessage bounds a message the
	// server sends, a row of such a value with its framing.
	pgMaxValue   = 64 << 20
	pgMaxMessage = pgMaxValue + 64<<10
	// a SCRAM iteration count outside these bounds is refused: below, the
	// server holds a weak verifier; above, a server could make a login
	// spend minutes deriving a key
	pgMinScramIterations = 4096
	pgMaxScramIterations = 10_000_000
	pgDefaultPort        = "5432"
	pgDefaultConnect     = 10 * time.Second
	pgMaxConnect         = 300 * time.Second
)

// The parameter type identifiers (pg_type.oid) the kind binds.
const (
	pgOidBool  = 16
	pgOidBytea = 17
	pgOidInt8  = 20
	pgOidInt4  = 23
	pgOidText  = 25
)

// pgDSN is a parsed connection string. Nothing prints it: formatted, it is
// a fixed phrase that holds none of its fields (String, GoString).
type pgDSN struct {
	host     string
	port     string
	user     string
	password string
	database string
	// tls is false only for sslmode=disable, which a loopback host alone
	// is admitted with
	tls            bool
	rootCertFile   string
	connectTimeout time.Duration
}

const pgDSNPrinted = "(the store's connection string)"

func (pgDSN) String() string   { return pgDSNPrinted }
func (pgDSN) GoString() string { return pgDSNPrinted }

// errPgDSN is the one sentence a connection string out of form is refused
// with: it quotes nothing of the string.
var errPgDSN = errors.New("the store's connection string is not a postgresql:// URL naming a host, a user and a database, with sslmode verify-full or, to a loopback host, disable, and no other parameter than sslrootcert and connect_timeout")

// parsePgDSN reads a connection string of the URL form,
// postgresql://user:password@host:port/database?sslmode=...: the one form
// the kind takes. A parameter it does not read is refused, never ignored.
func parsePgDSN(text string) (pgDSN, error) {
	text = strings.TrimSpace(text)
	u, err := url.Parse(text)
	if err != nil || (u.Scheme != "postgresql" && u.Scheme != "postgres") || u.Opaque != "" || u.User == nil || u.Fragment != "" {
		return pgDSN{}, errPgDSN
	}
	d := pgDSN{host: u.Hostname(), port: u.Port(), user: u.User.Username(), tls: true, connectTimeout: pgDefaultConnect}
	d.password, _ = u.User.Password()
	d.database = strings.TrimPrefix(u.Path, "/")
	if d.port == "" {
		d.port = pgDefaultPort
	}
	if d.host == "" || d.user == "" || d.database == "" || strings.Contains(d.database, "/") ||
		strings.ContainsRune(d.user+d.database+d.password, 0) {
		return pgDSN{}, errPgDSN
	}
	if n, err := strconv.Atoi(d.port); err != nil || n < 1 || n > 65535 {
		return pgDSN{}, errPgDSN
	}
	query, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return pgDSN{}, errPgDSN
	}
	for name, values := range query {
		if len(values) != 1 {
			return pgDSN{}, errPgDSN
		}
		value := values[0]
		switch name {
		case "sslmode":
			switch value {
			case "verify-full":
				d.tls = true
			case "disable":
				d.tls = false
			default:
				return pgDSN{}, errPgDSN
			}
		case "sslrootcert":
			if value == "" {
				return pgDSN{}, errPgDSN
			}
			d.rootCertFile = value
		case "connect_timeout":
			seconds, err := strconv.Atoi(value)
			if err != nil || seconds < 1 || time.Duration(seconds)*time.Second > pgMaxConnect {
				return pgDSN{}, errPgDSN
			}
			d.connectTimeout = time.Duration(seconds) * time.Second
		default:
			return pgDSN{}, errPgDSN
		}
	}
	if !d.tls && !pgLoopback(d.host) {
		return pgDSN{}, errPgDSN
	}
	if !d.tls && d.rootCertFile != "" {
		return pgDSN{}, errPgDSN
	}
	return d, nil
}

// pgLoopback reports a host that names this machine's loopback interface:
// the one place a connection without TLS is admitted. The name localhost is
// admitted here and held after the dial (pgPeerIsLoopback): a resolver need
// not answer it with a loopback address.
func pgLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// pgPeerIsLoopback reports a connection's remote address that is a
// loopback address. A connection without TLS is used only to such a peer:
// a host name the resolver answered otherwise is closed before a byte is
// sent on it.
func pgPeerIsLoopback(addr net.Addr) bool {
	tcp, ok := addr.(*net.TCPAddr)
	return ok && tcp.IP.IsLoopback()
}

// pgError is an error the server reported: its SQLSTATE alone. The message,
// the detail and the hint are not kept, since the server quotes the values
// of a statement and of a row there, and those are a caller's bytes.
type pgError struct {
	code string
}

func (e *pgError) Error() string {
	return fmt.Sprintf("the database refused the statement (SQLSTATE %s)", e.code)
}

// pgCode is the SQLSTATE of a server's error, or "" for any other error.
func pgCode(err error) string {
	var e *pgError
	if errors.As(err, &e) {
		return e.code
	}
	return ""
}

// The SQLSTATEs the kind tells apart.
const (
	pgUniqueViolation     = "23505"
	pgForeignKeyViolation = "23503"
	pgCheckViolation      = "23514"
	pgInsufficientPriv    = "42501"
	pgSerialization       = "40001"
)

// pgTransportError is a failure of the connection itself: the connection is
// not used again, and nothing it was sending is known to have been done or
// not done.
type pgTransportError struct{ what string }

func (e *pgTransportError) Error() string { return "the database connection failed: " + e.what }

// pgTransport turns an I/O failure into a sentence that names its class and
// nothing of the address it was to.
func pgTransport(err error) error {
	var netErr net.Error
	switch {
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		return &pgTransportError{"the server closed the connection"}
	case errors.As(err, &netErr) && netErr.Timeout():
		return &pgTransportError{"the operation's deadline passed"}
	case errors.Is(err, os.ErrDeadlineExceeded):
		return &pgTransportError{"the operation's deadline passed"}
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return &pgTransportError{"the database's host name did not resolve"}
	}
	var certErr *tls.CertificateVerificationError
	if errors.As(err, &certErr) {
		return &pgTransportError{"the database's certificate is not trusted for its host"}
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		if opErr.Op == "dial" {
			return &pgTransportError{"the database could not be reached"}
		}
		return &pgTransportError{"the connection broke"}
	}
	var protocolErr *pgTransportError
	if errors.As(err, &protocolErr) {
		return protocolErr
	}
	return &pgTransportError{"the connection broke"}
}

// pgConn is one connection, used by one operation at a time.
type pgConn struct {
	conn   net.Conn
	r      *bufio.Reader
	out    []byte
	status byte // the last ReadyForQuery's transaction status
	broken bool
	params map[string]string
}

// pgDial opens the TCP connection; a test replaces it.
var pgDial = func(address string, deadline time.Time) (net.Conn, error) {
	dialer := net.Dialer{Deadline: deadline, KeepAliveConfig: pgKeepAlive}
	return dialer.Dial("tcp", address)
}

// pgKeepAlive is the client's TCP keepalive on every connection: a server
// or a path that went away is known within about 20 seconds of quiet, not
// the hours of the system's default.
var pgKeepAlive = net.KeepAliveConfig{Enable: true, Idle: 5 * time.Second, Interval: 5 * time.Second, Count: 3}

// pgConnect opens a connection and logs in, within the deadline.
func pgConnect(d pgDSN, deadline time.Time) (*pgConn, error) {
	if until := time.Now().Add(d.connectTimeout); until.Before(deadline) {
		deadline = until
	}
	raw, err := pgDial(net.JoinHostPort(d.host, d.port), deadline)
	if err != nil {
		return nil, pgTransport(err)
	}
	if !d.tls && !pgPeerIsLoopback(raw.RemoteAddr()) {
		raw.Close()
		return nil, &pgTransportError{"sslmode=disable reached a remote address that is not a loopback address; nothing was sent"}
	}
	if err := raw.SetDeadline(deadline); err != nil {
		raw.Close()
		return nil, pgTransport(err)
	}
	conn := raw
	if d.tls {
		conn, err = pgStartTLS(raw, d)
		if err != nil {
			raw.Close()
			return nil, err
		}
	}
	c := &pgConn{conn: conn, r: bufio.NewReaderSize(conn, 32<<10), params: map[string]string{}}
	if err := c.startup(d); err != nil {
		c.conn.Close()
		return nil, err
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		c.conn.Close()
		return nil, pgTransport(err)
	}
	return c, nil
}

// pgStartTLS asks for TLS and checks the server's certificate against the
// host the connection string names. The answer to the request is read as
// one byte from the connection itself, with no buffer in between: bytes a
// server or a party on the path sent after it, before the handshake, are
// never read as if TLS had carried them.
func pgStartTLS(raw net.Conn, d pgDSN) (net.Conn, error) {
	var request [8]byte
	binary.BigEndian.PutUint32(request[0:], 8)
	binary.BigEndian.PutUint32(request[4:], pgSSLRequestCode)
	if _, err := raw.Write(request[:]); err != nil {
		return nil, pgTransport(err)
	}
	var answer [1]byte
	if _, err := io.ReadFull(raw, answer[:]); err != nil {
		return nil, pgTransport(err)
	}
	if answer[0] != 'S' {
		return nil, &pgTransportError{"the server does not offer TLS, and the connection string asks for it"}
	}
	config := &tls.Config{ServerName: d.host, MinVersion: tls.VersionTLS12}
	if d.rootCertFile != "" {
		pem, err := readBounded(d.rootCertFile, 1<<20)
		if err != nil {
			return nil, &pgTransportError{"the sslrootcert file could not be read"}
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, &pgTransportError{"the sslrootcert file holds no certificate"}
		}
		config.RootCAs = pool
	}
	secured := tls.Client(raw, config)
	if err := secured.Handshake(); err != nil {
		return nil, pgTransport(err)
	}
	return secured, nil
}

// --- messages --------------------------------------------------------------

func (c *pgConn) begin(kind byte) {
	c.out = append(c.out, kind, 0, 0, 0, 0)
}

func (c *pgConn) finish(start int) {
	binary.BigEndian.PutUint32(c.out[start+1:], uint32(len(c.out)-start-1))
}

func (c *pgConn) int16(v int)      { c.out = binary.BigEndian.AppendUint16(c.out, uint16(v)) }
func (c *pgConn) int32(v int)      { c.out = binary.BigEndian.AppendUint32(c.out, uint32(v)) }
func (c *pgConn) cstring(s string) { c.out = append(append(c.out, s...), 0) }

func (c *pgConn) flush() error {
	_, err := c.conn.Write(c.out)
	c.out = c.out[:0]
	if err != nil {
		c.broken = true
		return pgTransport(err)
	}
	return nil
}

// receive reads one message: its type and its body.
func (c *pgConn) receive() (byte, []byte, error) {
	var header [5]byte
	if _, err := io.ReadFull(c.r, header[:]); err != nil {
		c.broken = true
		return 0, nil, pgTransport(err)
	}
	length := binary.BigEndian.Uint32(header[1:])
	if length < 4 || length-4 > pgMaxMessage {
		c.broken = true
		return 0, nil, &pgTransportError{"the server sent a message past its bound"}
	}
	body := make([]byte, length-4)
	if _, err := io.ReadFull(c.r, body); err != nil {
		c.broken = true
		return 0, nil, pgTransport(err)
	}
	return header[0], body, nil
}

// pgFields reads an ErrorResponse's or a NoticeResponse's fields.
func pgFields(body []byte) map[byte]string {
	fields := map[byte]string{}
	for len(body) > 0 && body[0] != 0 {
		code := body[0]
		end := 1
		for end < len(body) && body[end] != 0 {
			end++
		}
		fields[code] = string(body[1:end])
		if end >= len(body) {
			break
		}
		body = body[end+1:]
	}
	return fields
}

// startupRefused is the sentence a server's refusal of the login is given:
// by its SQLSTATE's class, quoting nothing the server said, since its text
// names the user and the database.
func startupRefused(code string) error {
	switch {
	case code == "28P01" || code == "28000":
		return &pgTransportError{"the database refused the login (SQLSTATE " + code + ")"}
	case code == "3D000":
		return &pgTransportError{"the database the connection string names is not there (SQLSTATE 3D000)"}
	case strings.HasPrefix(code, "53"):
		return &pgTransportError{"the database has no connection to spare (SQLSTATE " + code + ")"}
	case pgSQLStateForm(code):
		return &pgTransportError{"the database refused the connection (SQLSTATE " + code + ")"}
	}
	return &pgTransportError{"the database refused the connection"}
}

func pgSQLStateForm(code string) bool {
	if len(code) != 5 {
		return false
	}
	for _, r := range code {
		if !(r >= '0' && r <= '9' || r >= 'A' && r <= 'Z') {
			return false
		}
	}
	return true
}

func (c *pgConn) startup(d pgDSN) error {
	start := len(c.out)
	c.out = append(c.out, 0, 0, 0, 0)
	c.int32(pgProtocolVersion)
	// The session's idle bound is set at its start, so even the moment
	// between a BEGIN and the transaction's own settings is bounded.
	idle := strconv.FormatInt(pgIdleInTransaction.Milliseconds(), 10)
	for _, kv := range [][2]string{{"user", d.user}, {"database", d.database}, {"client_encoding", "UTF8"}, {"application_name", "gateway"}, {"idle_in_transaction_session_timeout", idle}} {
		c.cstring(kv[0])
		c.cstring(kv[1])
	}
	c.out = append(c.out, 0)
	binary.BigEndian.PutUint32(c.out[start:], uint32(len(c.out)-start))
	if err := c.flush(); err != nil {
		return err
	}
	var scram *pgScram
	authenticated := false
	for {
		kind, body, err := c.receive()
		if err != nil {
			return err
		}
		switch kind {
		case 'R':
			if len(body) < 4 {
				return &pgTransportError{"the server sent an authentication request out of form"}
			}
			code := binary.BigEndian.Uint32(body)
			switch code {
			case 0: // AuthenticationOk
				if scram == nil && d.password != "" {
					// a login the connection string gives a password for is
					// a SCRAM exchange, in which the server proves it holds
					// the password's verifier; one admitted without it is
					// refused, as libpq's require_auth=scram-sha-256 does
					return &pgTransportError{"the server admitted the login without the password exchange the connection string asks for"}
				}
				if scram != nil && !scram.verified {
					return &pgTransportError{"the server ended the login before it proved it holds the password's verifier"}
				}
				authenticated = true
			case 10: // AuthenticationSASL
				if scram != nil {
					return &pgTransportError{"the server asked for a second login exchange"}
				}
				if !pgOffers(body[4:], "SCRAM-SHA-256") {
					return &pgTransportError{"the server offers no SCRAM-SHA-256 login"}
				}
				scram, err = newPgScram(d.password)
				if err != nil {
					return err
				}
				first := scram.clientFirst()
				m := len(c.out)
				c.begin('p')
				c.cstring("SCRAM-SHA-256")
				c.int32(len(first))
				c.out = append(c.out, first...)
				c.finish(m)
				if err := c.flush(); err != nil {
					return err
				}
			case 11: // AuthenticationSASLContinue
				if scram == nil || scram.final != "" {
					return &pgTransportError{"the server continued a login exchange that was not under way"}
				}
				final, err := scram.clientFinal(string(body[4:]))
				if err != nil {
					return err
				}
				m := len(c.out)
				c.begin('p')
				c.out = append(c.out, final...)
				c.finish(m)
				if err := c.flush(); err != nil {
					return err
				}
			case 12: // AuthenticationSASLFinal
				if scram == nil || scram.final == "" {
					return &pgTransportError{"the server ended a login exchange that was not under way"}
				}
				if err := scram.serverFinal(string(body[4:])); err != nil {
					return err
				}
			default:
				// 3 cleartext, 5 MD5, and every other exchange
				return &pgTransportError{"the server asks for a password exchange other than SCRAM-SHA-256, which is the one this gateway uses"}
			}
		case 'S':
			name, value, ok := pgParameterStatus(body)
			if ok {
				c.params[name] = value
			}
		case 'K', 'N':
		case 'E':
			c.broken = true
			return startupRefused(pgFields(body)['C'])
		case 'Z':
			if len(body) != 1 {
				return &pgTransportError{"the server sent a ready message out of form"}
			}
			if !authenticated {
				return &pgTransportError{"the server was ready before it admitted the login"}
			}
			c.status = body[0]
			return nil
		default:
			return &pgTransportError{"the server sent a message the login does not expect"}
		}
	}
}

// script runs text of several statements, binding nothing, through the
// simple query protocol: the migration files the binary carries, and
// nothing a caller wrote. It answers the first error the server reported.
func (c *pgConn) script(text string) error {
	if c.broken {
		return &pgTransportError{"the connection is not usable"}
	}
	m := len(c.out)
	c.begin('Q')
	c.cstring(text)
	c.finish(m)
	if err := c.flush(); err != nil {
		return err
	}
	var failure error
	for {
		kind, body, err := c.receive()
		if err != nil {
			return err
		}
		switch kind {
		case 'T', 'D', 'C', 'I', 'N', 'A':
		case 'S':
			if name, value, ok := pgParameterStatus(body); ok {
				c.params[name] = value
			}
		case 'E':
			if failure == nil {
				fields := pgFields(body)
				failure = &pgError{code: fields['C']}
			}
		case 'Z':
			if len(body) != 1 {
				c.broken = true
				return &pgTransportError{"the server sent a ready message out of form"}
			}
			c.status = body[0]
			return failure
		default:
			// a COPY or anything else no migration file asks for
			c.broken = true
			return &pgTransportError{"the server sent a message a migration does not expect"}
		}
	}
}

func pgParameterStatus(body []byte) (string, string, bool) {
	name, rest, ok := strings.Cut(string(body), "\x00")
	if !ok {
		return "", "", false
	}
	value, _, ok := strings.Cut(rest, "\x00")
	return name, value, ok
}

func pgOffers(list []byte, mechanism string) bool {
	for _, m := range strings.Split(string(list), "\x00") {
		if m == mechanism {
			return true
		}
	}
	return false
}

// pgScram is the client's side of a SCRAM-SHA-256 exchange (RFC 5802,
// RFC 7677) as PostgreSQL runs it: no channel binding, the user named by
// the startup message rather than in the exchange.
type pgScram struct {
	password    string
	nonce       string
	firstBare   string
	final       string
	serverSig   []byte
	verified    bool
	authMessage string
}

func newPgScram(password string) (*pgScram, error) {
	var raw [18]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return nil, &pgTransportError{"no random nonce for the login"}
	}
	nonce := base64.StdEncoding.EncodeToString(raw[:])
	return &pgScram{password: password, nonce: nonce, firstBare: "n=,r=" + nonce}, nil
}

func (s *pgScram) clientFirst() string { return "n,," + s.firstBare }

var errPgScram = &pgTransportError{"the server's login exchange is out of form"}

func (s *pgScram) clientFinal(serverFirst string) (string, error) {
	var nonce, salt string
	iterations := 0
	for i, attr := range strings.Split(serverFirst, ",") {
		key, value, ok := strings.Cut(attr, "=")
		if !ok {
			return "", errPgScram
		}
		switch {
		case i == 0 && key == "r":
			nonce = value
		case i == 1 && key == "s":
			salt = value
		case i == 2 && key == "i":
			n, err := strconv.Atoi(value)
			if err != nil {
				return "", errPgScram
			}
			iterations = n
		case i < 3:
			return "", errPgScram
		}
	}
	if len(nonce) <= len(s.nonce) || !strings.HasPrefix(nonce, s.nonce) || strings.ContainsAny(nonce, ",") {
		return "", errPgScram
	}
	saltBytes, err := base64.StdEncoding.DecodeString(salt)
	if err != nil || len(saltBytes) == 0 {
		return "", errPgScram
	}
	if iterations < pgMinScramIterations || iterations > pgMaxScramIterations {
		return "", &pgTransportError{"the server's SCRAM iteration count is outside the bounds this gateway admits"}
	}
	salted, err := pbkdf2.Key(sha256.New, s.password, saltBytes, iterations, sha256.Size)
	if err != nil {
		return "", errPgScram
	}
	withoutProof := "c=biws,r=" + nonce
	s.authMessage = s.firstBare + "," + serverFirst + "," + withoutProof
	clientKey := pgHMAC(salted, "Client Key")
	stored := sha256.Sum256(clientKey)
	signature := pgHMAC(stored[:], s.authMessage)
	proof := make([]byte, len(clientKey))
	subtle.XORBytes(proof, clientKey, signature)
	s.serverSig = pgHMAC(pgHMAC(salted, "Server Key"), s.authMessage)
	s.final = withoutProof + ",p=" + base64.StdEncoding.EncodeToString(proof)
	return s.final, nil
}

// serverFinal holds the server to the signature only a holder of the
// password's verifier can make: a server that cannot is not the database
// the password was set on, and the login is refused.
func (s *pgScram) serverFinal(message string) error {
	value, ok := strings.CutPrefix(message, "v=")
	if !ok {
		return &pgTransportError{"the server refused the login exchange"}
	}
	if end := strings.IndexByte(value, ','); end >= 0 {
		value = value[:end]
	}
	got, err := base64.StdEncoding.DecodeString(value)
	if err != nil || !hmac.Equal(got, s.serverSig) {
		return &pgTransportError{"the server's login signature is not the one the password's verifier makes"}
	}
	s.verified = true
	return nil
}

func pgHMAC(key []byte, message string) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(message))
	return mac.Sum(nil)
}

// --- statements ------------------------------------------------------------

// pgRows is what one statement returned: its rows, each a list of values
// in the binary format (nil for NULL), and its command tag.
type pgRows struct {
	rows [][][]byte
	tag  string
}

// exec runs one statement with its parameters bound, through the extended
// query protocol, and reads its result to the server's ReadyForQuery. A
// parameter is a string (text), a []byte (bytea), an int64 (int8), an int
// (int4) or a bool; every value travels in the binary format.
func (c *pgConn) exec(query string, args ...any) (pgRows, error) {
	if c.broken {
		return pgRows{}, &pgTransportError{"the connection is not usable"}
	}
	oids := make([]int, len(args))
	values := make([][]byte, len(args))
	for i, a := range args {
		switch v := a.(type) {
		case string:
			oids[i], values[i] = pgOidText, []byte(v)
		case []byte:
			if v == nil {
				v = []byte{}
			}
			oids[i], values[i] = pgOidBytea, v
		case int64:
			oids[i], values[i] = pgOidInt8, binary.BigEndian.AppendUint64(nil, uint64(v))
		case int:
			oids[i], values[i] = pgOidInt4, binary.BigEndian.AppendUint32(nil, uint32(int32(v)))
		case bool:
			b := byte(0)
			if v {
				b = 1
			}
			oids[i], values[i] = pgOidBool, []byte{b}
		default:
			return pgRows{}, fmt.Errorf("store: a parameter of type %T is not one the client binds", a)
		}
		if len(values[i]) > pgMaxValue {
			return pgRows{}, storeFailure(faultRefused, "bind", fmt.Errorf("store: a value of %d bytes is past the kind's bound of %d", len(values[i]), pgMaxValue))
		}
	}
	m := len(c.out)
	c.begin('P')
	c.cstring("")
	c.cstring(query)
	c.int16(len(oids))
	for _, oid := range oids {
		c.int32(oid)
	}
	c.finish(m)
	m = len(c.out)
	c.begin('B')
	c.cstring("")
	c.cstring("")
	c.int16(1)
	c.int16(1) // every parameter binary
	c.int16(len(values))
	for _, v := range values {
		c.int32(len(v))
		c.out = append(c.out, v...)
	}
	c.int16(1)
	c.int16(1) // every result column binary
	c.finish(m)
	m = len(c.out)
	c.begin('E')
	c.cstring("")
	c.int32(0)
	c.finish(m)
	m = len(c.out)
	c.begin('S')
	c.finish(m)
	if err := c.flush(); err != nil {
		return pgRows{}, err
	}
	var result pgRows
	var failure error
	for {
		kind, body, err := c.receive()
		if err != nil {
			return pgRows{}, err
		}
		switch kind {
		case '1', '2', 'n', 'I', 'N', 'A':
		case 'S':
			if name, value, ok := pgParameterStatus(body); ok {
				c.params[name] = value
			}
		case 'D':
			row, err := pgDataRow(body)
			if err != nil {
				c.broken = true
				return pgRows{}, err
			}
			result.rows = append(result.rows, row)
		case 'C':
			result.tag = strings.TrimSuffix(string(body), "\x00")
		case 'E':
			fields := pgFields(body)
			failure = &pgError{code: fields['C']}
		case 'Z':
			if len(body) != 1 {
				c.broken = true
				return pgRows{}, &pgTransportError{"the server sent a ready message out of form"}
			}
			c.status = body[0]
			if failure != nil {
				return pgRows{}, failure
			}
			return result, nil
		default:
			c.broken = true
			return pgRows{}, &pgTransportError{"the server sent a message a statement does not expect"}
		}
	}
}

func pgDataRow(body []byte) ([][]byte, error) {
	if len(body) < 2 {
		return nil, &pgTransportError{"the server sent a row out of form"}
	}
	n := int(binary.BigEndian.Uint16(body))
	body = body[2:]
	row := make([][]byte, n)
	for i := 0; i < n; i++ {
		if len(body) < 4 {
			return nil, &pgTransportError{"the server sent a row out of form"}
		}
		length := int32(binary.BigEndian.Uint32(body))
		body = body[4:]
		if length < 0 {
			continue
		}
		if int(length) > len(body) {
			return nil, &pgTransportError{"the server sent a row out of form"}
		}
		row[i] = body[:length:length]
		body = body[length:]
	}
	if len(body) != 0 {
		return nil, &pgTransportError{"the server sent a row out of form"}
	}
	return row, nil
}

// close ends the session, telling the server so where the connection still
// serves.
func (c *pgConn) close() {
	if !c.broken {
		c.conn.SetDeadline(time.Now().Add(time.Second))
		m := len(c.out)
		c.begin('X')
		c.finish(m)
		c.flush()
	}
	c.broken = true
	c.conn.Close()
}

// The binary forms of the result columns the kind reads.

func pgInt8(v []byte) (int64, bool) {
	if len(v) != 8 {
		return 0, false
	}
	return int64(binary.BigEndian.Uint64(v)), true
}

func pgBool(v []byte) (bool, bool) {
	if len(v) != 1 {
		return false, false
	}
	return v[0] == 1, true
}
