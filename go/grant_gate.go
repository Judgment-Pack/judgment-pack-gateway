package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
	"sync/atomic"
	"time"
)

// The connection grant a platform's delegated calls are admitted under
// (SPEC.md §10, rule 3; gateway #368, #372). A platform's sources take their
// tokens from the credentials files the configuration names, and the
// connection custody holds the grant: its owner, its idle expiry, its state
// and its scopes. The signer never reads the custody (ADR-0001), so the
// check is the custody's own, run as a program under the custody's user.
// A delegated write through /act and a delegated acquisition through
// /acquire are checked in two parts around the delegation's counting
// admission (SPEC.md §11.5): `gateway-connections --grants check` before
// it, the grant's state alone, so a grant that is not live refuses before
// the issuing host is read; and `--grants admit` after it answers admit,
// the check and the record every use of the custody's credentials passes,
// the owner read included, so an owner refusal follows the delegation's own
// (RFC 0030 §2). The read-back of a delegated key's uncertain action makes
// no admission read and counts nothing, so it is held to `admit` alone
// before it runs: a grant that is not live, or whose owner is refused,
// serves no read-back, and the key stays uncertain (RFC 0030 §5, rule 5).
// A delegated
// call on a platform that names no grant is refused before anything is
// admitted.

// platformGrant is a platform's `grant` member (engineVersion 16): the
// custody connection its delegated calls are admitted under, where that
// custody is kept and for whom, and the user its program runs as.
type platformGrant struct {
	provider   string
	connection string
	stateDir   string
	principal  string
	user       string
	uid        int // resolved from the user database
}

// grantGate is what a delegated call on a platform's source is admitted
// through: the custody program's command line, to which the operation is
// added, run under user with an environment of env alone, and the
// connection it asks for.
type grantGate struct {
	argv       []string
	env        []string
	user       string
	provider   string
	connection string
}

// grantProviders are the providers whose connections the custody keeps a
// grant record of (docs/design/connection-grants.md).
var grantProviders = []string{"google-drive", "gmail", "notion", "databricks", "azure-devops"}

// grantPrincipal is the custody's principal form.
var grantPrincipal = regexp.MustCompile(`^[A-Za-z0-9_-]{1,200}$`)

var platformGrantMembers = map[string]bool{"provider": true, "connection": true, "stateDir": true, "principal": true, "user": true}

// grantGateTimeout bounds the custody's answer: its lock, its owner read
// and a revocation it makes at an idle expiry each have their own bound
// inside it. A test shortens it.
var grantGateTimeout = 30 * time.Second

// grantAnswerBytes bounds what the custody may write on either stream.
const grantAnswerBytes = 4096

// The custody's two operations for a delegated call (SPEC.md §10, rule 3).
const (
	grantCheck = "check" // before the counting admission: the state alone
	grantAdmit = "admit" // after it answers admit, and before a read-back: the use, the owner read included
)

// The refusals of a delegated call's grant (SPEC.md §10, rule 3). Each but
// grant-unreadable is the custody's own refusal of a use.
const (
	refusalGrantUnknown     = "grant-unknown"
	refusalGrantUnreadable  = "grant-unreadable"
	refusalGrantQuarantined = "grant-quarantined"
	refusalGrantRevoked     = "grant-revoked"
	refusalGrantIdle        = "grant-idle-expired"
	refusalOwnerRemoved     = "owner-removed"
	refusalOwnerUnknown     = "owner-unknown"
	refusalExcessScope      = "excess-scope"
)

// grantRefusals are the custody's answers a refusal is made of, and what
// the requester is told of each: never the custody's own text, which names
// scopes and is the operator's to read in the report.
var grantRefusals = map[string]string{
	refusalGrantUnknown:     "the connection custody holds no grant of the platform's connection",
	refusalGrantQuarantined: "the platform's connection grant is quarantined",
	refusalGrantRevoked:     "the platform's connection grant is revoked",
	refusalGrantIdle:        "the platform's connection grant passed its idle expiry and is revoked",
	refusalOwnerRemoved:     "the owner of the platform's connection grant was removed",
	refusalOwnerUnknown:     "the standing of the owner of the platform's connection grant could not be read",
	refusalExcessScope:      "the platform's connection grant holds a scope no operation declares",
}

// grantOwnerRefusals are the refusals of the owner read, which only admit
// makes: from check they are not read as themselves.
var grantOwnerRefusals = []string{refusalOwnerRemoved, refusalOwnerUnknown}

// grantRefused is a refusal of a delegated call's grant: 403, refused at
// `grant` for /act.
func grantRefused(name, reason string) *delegationRefusal {
	return &delegationRefusal{name: name, reason: reason, at: "grant"}
}

// parsePlatformGrant reads a platform's grant member.
func parsePlatformGrant(v value) (*platformGrant, error) {
	obj, ok := v.(*vObject)
	if !ok {
		return nil, errors.New("grant must be an object")
	}
	if err := exactlyMembers(obj, platformGrantMembers, "grant"); err != nil {
		return nil, err
	}
	g := &platformGrant{}
	var err error
	if g.provider, err = requireString(obj, "provider"); err != nil || !contains(grantProviders, g.provider) {
		return nil, fmt.Errorf("grant.provider must be one of %s, a provider whose connections have a grant", strings.Join(grantProviders, ", "))
	}
	if g.connection, err = requireString(obj, "connection"); err != nil || !flatToken(g.connection) {
		return nil, errors.New("grant.connection must be a flat token, [A-Za-z0-9._-]{1,128} and never . or .., the connection's name in custody")
	}
	if g.stateDir, err = requireAbsolutePath(obj, "stateDir"); err != nil {
		return nil, fmt.Errorf("grant.%v", err)
	}
	if g.principal, err = requireString(obj, "principal"); err != nil || !grantPrincipal.MatchString(g.principal) {
		return nil, errors.New("grant.principal must be the custody's principal, [A-Za-z0-9_-]{1,200}")
	}
	if g.user, err = requireString(obj, "user"); err != nil || g.user == "" {
		return nil, errors.New("grant.user must name the OS user the custody belongs to and its program runs as")
	}
	return g, nil
}

// flatToken is RFC 0030's flat token: [A-Za-z0-9._-]{1,128}, never . or ..
func flatToken(s string) bool {
	if s == "" || len(s) > 128 || s == "." || s == ".." {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '_' || r == '-') {
			return false
		}
	}
	return true
}

// grantGateOf is the gate a platform's sources are admitted through,
// with custody the custody program; nil for a platform with no grant.
func grantGateOf(p platformConfig, custody string) *grantGate {
	if p.grant == nil {
		return nil
	}
	return &grantGate{
		argv:     []string{custody, "--state-dir=" + p.grant.stateDir, "--principal=" + p.grant.principal, "--provider=" + p.grant.provider},
		env:      []string{},
		user:     p.grant.user,
		provider: p.grant.provider, connection: p.grant.connection,
	}
}

// askCustody runs one of the custody's operations for a delegated call
// under the platform's grant, grantCheck or grantAdmit, and is the refusal,
// or nil where it passes. Only the two answers the custody gives are read:
// the operation's own answer, naming the provider and connection asked
// for, with exit 0 and nothing on stderr; or one refusal the custody makes
// of a use, alone on stderr, with exit 1 and nothing on stdout, an owner
// refusal only from admit. Anything else -- a program that cannot be
// started, a custody that cannot be read, a failure, a timeout, an answer
// too long or of another form -- is grant-unreadable: what could not be
// read is never taken for a grant that is not there, nor for one that
// admits.
func (g *gatewayService) askCustody(gate *grantGate, operation string) *delegationRefusal {
	unreadable := grantRefused(refusalGrantUnreadable, "the connection custody's answer for the platform's grant could not be read")
	if gate == nil || len(gate.argv) == 0 {
		return grantRefused(refusalGrantUnknown, grantRefusals[refusalGrantUnknown])
	}
	path, err := exec.LookPath(gate.argv[0])
	if err != nil {
		return unreadable
	}
	request := newObject()
	request.set("provider", vString(gate.provider))
	request.set("connection", vString(gate.connection))
	ctx, cancel := context.WithTimeout(g.ctx, grantGateTimeout)
	defer cancel()
	args := append(append([]string{}, gate.argv[1:]...), "--grants="+operation)
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Stdin = bytes.NewReader(append(canon(request), '\n'))
	// An explicit environment, so that nothing of the signer's is handed on.
	cmd.Env = append([]string{}, gate.env...)
	group, err := prepareSourceProcess(cmd, gate.user)
	if err != nil {
		return unreadable
	}
	var cancelled atomic.Bool
	cmd.Cancel = recordCancellation(cmd.Cancel, &cancelled)
	cmd.WaitDelay = g.waitDelay
	stdout := &boundedBuffer{limit: grantAnswerBytes, stop: cancel}
	stderr := &boundedBuffer{limit: grantAnswerBytes, stop: cancel}
	cmd.Stdout, cmd.Stderr = stdout, stderr
	if err := group.start(cmd); err != nil {
		group.reap()
		return unreadable
	}
	waitErr := cmd.Wait()
	group.reap()
	if stdout.overflowed || stderr.overflowed || ctx.Err() != nil || cancelled.Load() {
		return unreadable
	}
	if waitErr == nil {
		answer := newObject()
		if operation == grantAdmit {
			answer.set("admission", vString("admit"))
		} else {
			answer.set("check", vString("pass"))
		}
		answer.set("connection", vString(gate.connection))
		answer.set("provider", vString(gate.provider))
		answer.set("version", vInt(1))
		if stderr.buf.Len() == 0 && stdout.buf.String() == string(canon(answer))+"\n" {
			return nil
		}
		return unreadable
	}
	var exit *exec.ExitError
	if !errors.As(waitErr, &exit) || exit.ExitCode() != 1 || stdout.buf.Len() != 0 {
		return unreadable
	}
	line, found := strings.CutPrefix(stderr.buf.String(), "grants: ")
	code, ended := strings.CutSuffix(line, "\n")
	if !found || !ended || strings.Contains(code, "\n") {
		return unreadable
	}
	// The custody names the extra scopes after excess-scope, always.
	if extra, excess := strings.CutPrefix(code, refusalExcessScope+": "); excess && extra != "" {
		return grantRefused(refusalExcessScope, grantRefusals[refusalExcessScope])
	}
	reason, known := grantRefusals[code]
	if !known || code == refusalExcessScope || operation != grantAdmit && contains(grantOwnerRefusals, code) {
		return unreadable
	}
	return grantRefused(code, reason)
}
