package main

import (
	"encoding/json"
	"errors"
	"os"
)

// The first scope of a key (SPEC.md §1.2b): one private file per key under
// actions/index/, published whole or not at all, never rewritten, and kept by
// compaction. A request sending keyScope and a delegated run's actor create it. It is
// what refuses every other scope, flagged or not, before anything new is reserved or
// sent; it takes nothing a scope already holds. It says who first held the key,
// nothing more: a closure lives in the reservation's dispatch marker, the one name a
// dispatch also needs. A first scope proves the same subject, not the same owner: the
// gateway holds no lease.
//
// The record is one store's. The file's name hashes the key alone, and the record names
// the authority, so that a changed authority string finds the record and answers a
// conflict, rather than finding nothing and answering that nothing was sent. A second
// store under the same authority finds nothing: see the Known limits.

const (
	actionIndexDirectory = "index"
	actionIndexVersion   = "1"
	actionIndexLimit     = 16 << 10
)

// The refusals of an authority-scoped or reconciling request (SPEC.md §1.2b).
const (
	refusalKeyScopeConflict  = "action-key-scope-conflict"
	refusalKeyClosed         = "action-key-closed"
	refusalKeyNotDispatched  = "action-key-not-dispatched"
	refusalKeyOutcomeUnknown = "action-key-outcome-unknown"
)

// actionKeyMembers are the members of /act that say what a request asks of its
// key. A request that sends neither keyScope nor reconcile behaves as it did.
type actionKeyMembers struct {
	key, keyScope, reconcile json.RawMessage
}

// parseActionKeyScope reads keyScope and reconcile at the action-key step.
func parseActionKeyScope(members actionKeyMembers, key string, delegated *delegatedSender) (scoped, reconcile bool, err error) {
	if len(members.keyScope) > 0 {
		text, err := parseString("keyScope", members.keyScope)
		if err != nil || text != "authority" {
			return false, false, actRefusal{"action-key", `keyScope must be the string "authority"`}
		}
		scoped = true
	}
	if len(members.reconcile) > 0 {
		v, err := parseMember("reconcile", members.reconcile)
		if err != nil || v != vBool(true) {
			return false, false, actRefusal{"action-key", "reconcile must be the value true"}
		}
		reconcile = true
	}
	switch {
	case !scoped && !reconcile:
	case key == "":
		return false, false, actRefusal{"action-key", "keyScope and reconcile need an actionKey"}
	case scoped && delegated != nil:
		return false, false, actRefusal{"action-key", "a delegated request's key scope is its chain's (SPEC.md §11.8): it sends no keyScope"}
	case reconcile && !scoped && delegated == nil:
		return false, false, actRefusal{"action-key", `reconcile needs keyScope "authority" under no delegation: without a first scope, a close stops nobody else`}
	}
	return scoped, reconcile, nil
}

// actionKeyFirstScope is the record of a key's first scope for one request.
type actionKeyFirstScope struct {
	file   string
	key    string
	record []byte
}

// actionFirstScope is the record this request's scope would make. The entries it names
// let an operator tell, from the journal alone, which entries are this key's: an entry
// does not hold its key, and neither does a subject record.
func (g *gatewayService) actionFirstScope(who *caller, key, namespace string) actionKeyFirstScope {
	name := newObject()
	name.set("key", vString(key))
	var scope *vObject
	var subjectRecord string
	if who.delegated != nil {
		scope = who.delegated.scope.value()
		subjectRecord = g.actionSubjectNamespace(who.delegated, key)
	} else {
		scope = newObject()
		scope.set("issuer", vString(who.issuer))
		scope.set("subject", vString(who.subject))
	}
	record := newObject()
	record.set("indexVersion", vString(actionIndexVersion))
	record.set("authority", vString(g.authority))
	record.set("key", vString(key))
	record.set("reservation", vString(namespace))
	record.set("scope", scope)
	if subjectRecord != "" {
		record.set("subjectRecord", vString(subjectRecord))
	}
	return actionKeyFirstScope{file: actionHash("action-key-index", name) + ".json", key: key, record: canon(record)}
}

// errActionKeyFirstScope is a key whose recorded first scope is not this request's.
var errActionKeyFirstScope = errors.New("action-key-scope-conflict: this key's first scope is another's")

// keyIndexed reads the key's first scope, making nothing: a request that sends
// neither member and finds none behaves as it did. It answers whether one is
// recorded, errActionKeyFirstScope if it is another's, and a refusal if it does
// not read: an unreadable record never grants.
func (j *actionJournal) keyIndexed(first actionKeyFirstScope) (bool, error) {
	if _, err := j.root.Lstat(actionIndexDirectory); errors.Is(err, os.ErrNotExist) {
		return false, nil
	} else if err != nil {
		return false, errors.New("action-journal-unavailable: cannot read the action key index")
	}
	index, err := openActionDirectory(j.root, actionIndexDirectory)
	if err != nil {
		return false, err
	}
	defer index.Close()
	return readKeyIndex(index, first)
}

func readKeyIndex(index *os.Root, first actionKeyFirstScope) (bool, error) {
	raw, err := readActionRecord(index, first.file, actionIndexLimit)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	invalid := errors.New("action-journal-invalid: the action key index record does not read; dispatch is forbidden")
	if err != nil {
		return false, invalid
	}
	v, err := parseJSON(raw)
	if err != nil {
		return false, invalid
	}
	object, err := requireObject(v, "action key index")
	if err != nil {
		return false, invalid
	}
	if err = exactlyMembers(object, map[string]bool{"indexVersion": true, "authority": true, "key": true, "reservation": true, "scope": true, "subjectRecord": false}, "action key index"); err != nil {
		return false, invalid
	}
	version, _ := memberString(object, "indexVersion")
	key, _ := memberString(object, "key")
	if version != actionIndexVersion || key != first.key {
		return false, invalid
	}
	if string(raw) != string(first.record) {
		return false, errActionKeyFirstScope
	}
	return true, nil
}

// holdKeyIndex makes this request's scope the key's first scope, or finds that it
// is, and makes that durable before returning; errActionKeyFirstScope if another's
// is there. Exactly one scope can win, across processes. What is found is synced
// as what is written is: its publisher may have died before syncing it.
func (j *actionJournal) holdKeyIndex(first actionKeyFirstScope) error {
	if err := j.root.Mkdir(actionIndexDirectory, 0700); err != nil && !errors.Is(err, os.ErrExist) {
		return errors.New("action-journal-unavailable: cannot create the action key index")
	}
	index, err := openActionDirectory(j.root, actionIndexDirectory)
	if err != nil {
		return err
	}
	defer index.Close()
	held, err := readKeyIndex(index, first)
	if err != nil {
		return err
	}
	if !held {
		err = publishActionRecord(index, actionRecord{first.file, first.record, actionIndexLimit})
		if errors.Is(err, errActionRecordExists) {
			if _, err = readKeyIndex(index, first); err != nil {
				return err
			}
		} else if err != nil {
			return err
		}
	}
	if err = syncActionDirectory(index); err != nil {
		return err
	}
	return syncActionDirectory(j.root)
}

// closedAnswer is the answer to a reconciling request on a closed key, once what
// it rests on is durable: the close, found or made, and the first scope. Anyone
// else's request then finds the key closed or finds it taken. A sender other than
// the actor never makes a record, so one that finds none is refused. It is not a
// statement about the target beyond this gateway's dispatch.
func (g *gatewayService) closedAnswer(journal *actionJournal, claim *actionClaim, first actionKeyFirstScope, indexed bool, delegated *delegatedSender) error {
	if delegated != nil && delegated.kind != "actor" && !indexed {
		return refuse(refusalActorOnly, "no evidence is retained under this key that a sender other than the run's actor can reach")
	}
	if err := syncActionDirectory(claim.root); err != nil {
		return actRefusal{"action-key", err.Error()}
	}
	g.actionStepped("close-durable")
	if err := journal.holdKeyIndex(first); errors.Is(err, errActionKeyFirstScope) {
		return refuse(refusalKeyScopeConflict, "this key's first scope is another's")
	} else if err != nil {
		return actRefusal{"action-key", err.Error()}
	}
	g.actionStepped("close-indexed")
	return refuse(refusalKeyNotDispatched, "nothing was dispatched under this key, and it is closed: nothing will be")
}

// actionStepped is a test's way of dying at a named point of a keyed request.
func (g *gatewayService) actionStepped(point string) {
	if g.actionStep != nil {
		g.actionStep(point)
	}
}
