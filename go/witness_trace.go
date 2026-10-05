package main

// The order of a witness's operations on its files, held to the rule they
// exist for (witness_log.go): nothing is relied on, served or built upon
// until the bytes it rests on are durable. A witnessTrace wraps the one seam
// every operation goes through (witnessIO) and checks each operation, as it
// is attempted, against the invariants below. It keeps a count, the last few
// operations and the first one that breaks an invariant -- never the whole
// sequence, so a trace of any length costs a few lines. The recovery vectors'
// runner holds every vector to it (conform_witness_recovery.go), and so do
// the witness's tests.
//
// The invariants, each checked before the operation it names:
//
//  1. no mark is appended while the log holds a line not synced since it
//     was written;
//  2. no statement is published, and no witness starts, while the log, the
//     marks or the registrations hold bytes not synced since they were
//     written;
//  3. no file is cut until the bytes it loses were appended to the
//     set-aside file, that file was synced, and the records were read back
//     from it as its reader reads them;
//  4. after a file is made, its directory is synced before anything is
//     written, cut, published or started;
//  5. what a start, a repair or a registration read -- each file, and the
//     directory it is in -- is synced before anything is written, cut, made,
//     published or started after it;
//  6. a repair and an offline registration end with every file they wrote
//     synced and every directory they made a file in synced;
//  7. no statement is appended while the registrations hold bytes not
//     synced, so a statement never rests on a registration that may be lost;
//  8. no file is read before it is locked, in the same hold of the files.

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
)

type witnessTrace struct {
	mu       sync.Mutex
	count    int
	recent   []string
	broken   string
	dirty    map[string]bool
	unsynced map[string]bool
	pending  map[string]bool
	locked   map[string]bool
	// asideSynced: the set-aside file written and synced since the last
	// cut; asideReadBack: and its records read back since.
	asideSynced, asideReadBack bool
}

func newWitnessTrace() *witnessTrace {
	tr := &witnessTrace{}
	tr.reset()
	return tr
}

// reset forgets the state of every file, as when the operator puts files
// in place; the count, the recent operations and a broken invariant stay.
func (tr *witnessTrace) reset() {
	tr.mu.Lock()
	defer tr.mu.Unlock()
	tr.dirty, tr.unsynced, tr.pending, tr.locked = map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]bool{}
	tr.asideSynced, tr.asideReadBack = false, false
}

// violation is the first operation that broke an invariant, or "".
func (tr *witnessTrace) violation() string {
	tr.mu.Lock()
	defer tr.mu.Unlock()
	return tr.broken
}

// last is the most recent operations, at most sixteen, oldest first.
func (tr *witnessTrace) last() []string {
	tr.mu.Lock()
	defer tr.mu.Unlock()
	return append([]string(nil), tr.recent...)
}

func directoryOf(file string) string {
	if file == "marks" {
		return "marks-dir"
	}
	return "log-dir"
}

// onIn is the names a set holds, in order, joined, or "".
func onIn(set map[string]bool) string {
	var names []string
	for name, on := range set {
		if on {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return strings.Join(names, ", ")
}

// before checks an operation against the invariants, as it is attempted.
func (tr *witnessTrace) before(op, file string) {
	tr.mu.Lock()
	defer tr.mu.Unlock()
	tr.count++
	tr.recent = append(tr.recent, op+" "+file)
	if len(tr.recent) > 16 {
		tr.recent = tr.recent[1:]
	}
	if tr.broken != "" {
		return
	}
	why := ""
	unsynced, pending := onIn(tr.unsynced), onIn(tr.pending)
	switch op {
	case "write", "truncate", "create", "publish", "start":
		if unsynced != "" {
			why = "what was read (" + unsynced + ") was not yet synced" // 5
		}
	}
	if why == "" {
		switch op {
		case "write", "truncate", "publish", "start":
			if pending != "" {
				why = "the directory of a file made (" + pending + ") was not yet synced" // 4
			}
		}
	}
	if why == "" {
		switch {
		case op == "write" && file == "marks" && tr.dirty["log"]:
			why = "a mark appended before the log line it names was synced" // 1
		case op == "write" && file == "log" && tr.dirty["registrations"]:
			why = "a statement appended before the registration it rests on was synced" // 7
		case op == "truncate" && (!tr.asideReadBack || tr.dirty["set-aside"]):
			why = "a file cut before the bytes it loses were kept in the set-aside file, synced and read back" // 3
		case op == "read" && !tr.locked[file]:
			why = "a file read before it was locked" // 8
		case op == "publish" || op == "start":
			for _, f := range []string{"log", "marks", "registrations"} {
				if tr.dirty[f] {
					why = "the " + f + " held bytes not synced" // 2
				}
			}
		case op == "repaired" || op == "registered":
			if d := onIn(tr.dirty); d != "" {
				why = "it ended with " + d + " not synced" // 6
			} else if pending != "" {
				why = "it ended with the directory of a file made (" + pending + ") not synced" // 6
			}
		}
	}
	if why != "" {
		tr.broken = fmt.Sprintf("operation %d, %s %s: %s", tr.count, op, file, why)
	}
}

// after records what an operation did: a write or a cut leaves its file not
// synced whether or not it failed; a sync that succeeded makes its file, or
// directory, synced.
func (tr *witnessTrace) after(op, file string, err error) {
	tr.mu.Lock()
	defer tr.mu.Unlock()
	switch op {
	case "write":
		tr.dirty[file] = true
	case "truncate":
		tr.dirty[file] = true
		tr.asideSynced, tr.asideReadBack = false, false
	case "sync":
		if err == nil {
			if file == "set-aside" && tr.dirty[file] {
				tr.asideSynced, tr.asideReadBack = true, false
			}
			tr.dirty[file], tr.unsynced[file] = false, false
		}
	case "readback":
		tr.asideReadBack = tr.asideSynced && !tr.dirty["set-aside"]
	case "hold":
		tr.locked = map[string]bool{}
	case "lock":
		if err == nil {
			tr.locked[file] = true
		}
	case "syncdir":
		if err == nil {
			tr.pending[file], tr.unsynced[file] = false, false
		}
	case "create":
		if err == nil {
			tr.pending[directoryOf(file)] = true
		}
	case "read":
		tr.unsynced[file], tr.unsynced[directoryOf(file)] = true, true
	}
}

// wrap is base, every operation of it checked and recorded.
func (tr *witnessTrace) wrap(base witnessIO) witnessIO {
	base = base.orOS()
	return witnessIO{
		write: func(file string, f *os.File, data []byte) (int, error) {
			tr.before("write", file)
			n, err := base.write(file, f, data)
			tr.after("write", file, err)
			return n, err
		},
		sync: func(file string, f *os.File) error {
			tr.before("sync", file)
			err := base.sync(file, f)
			tr.after("sync", file, err)
			return err
		},
		truncate: func(file string, f *os.File, size int64) error {
			tr.before("truncate", file)
			err := base.truncate(file, f, size)
			tr.after("truncate", file, err)
			return err
		},
		create: func(file string, dir *os.Root, name string) (*os.File, error) {
			tr.before("create", file)
			made, err := base.create(file, dir, name)
			tr.after("create", file, err)
			return made, err
		},
		syncDir: func(dir string, d *os.File) error {
			tr.before("syncdir", dir)
			err := base.syncDir(dir, d)
			tr.after("syncdir", dir, err)
			return err
		},
		lock: func(file string, f *os.File) error {
			tr.before("lock", file)
			err := base.lock(file, f)
			tr.after("lock", file, err)
			return err
		},
		note: func(op, file string) {
			tr.before(op, file)
			tr.after(op, file, nil)
			base.note(op, file)
		},
	}
}
