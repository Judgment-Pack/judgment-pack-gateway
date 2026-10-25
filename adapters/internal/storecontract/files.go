package storecontract

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"strings"
)

// Policy is how the filesystem kind keeps one document, as the custody
// kept it before the contract: the bound a read holds it to, whether a
// name the open reports missing is absent only when a look at the entry
// finds nothing there too (a link that leads nowhere is no absence),
// whether a write syncs the directory after its rename, and the prefix of
// its staging name.
type Policy struct {
	Limit          int64
	ConfirmAbsence bool
	SyncDirectory  bool
	Staging        string
}

// Files is the custody's filesystem kind: each document a file in the
// custody's held directory, private to its owner, read through one
// descriptor that follows no link and blocks on nothing and judged by what
// was opened, and replaced by renaming a synced staging file over it. A
// document's revision is the digest of its bytes. A compare-and-set
// compares and then renames, so it is atomic among writers that hold the
// custody lock, as every writer of the custody does.
type Files struct {
	root     *os.Root
	fallback Policy
	policies map[string]Policy
}

var _ Documents = (*Files)(nil)

// NewFiles is the kind over a held directory: policies name the documents
// kept otherwise than fallback says.
func NewFiles(root *os.Root, fallback Policy, policies map[string]Policy) *Files {
	return &Files{root: root, fallback: fallback, policies: policies}
}

func (f *Files) policy(name string) Policy {
	if p, ok := f.policies[name]; ok {
		return p
	}
	return f.fallback
}

func revisionOf(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func plainName(name string) bool {
	return name != "" && name != "." && name != ".." && !strings.ContainsAny(name, `/\`) && name != AnyRevision
}

func (f *Files) Get(name string) ([]byte, string, error) {
	if !plainName(name) {
		return nil, NoRevision, failure(Refused, "get", errors.New("store: not a document's name"))
	}
	p := f.policy(name)
	file, err := f.root.OpenFile(name, os.O_RDONLY|NoFollow|NonBlock, 0)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			if !p.ConfirmAbsence {
				return nil, NoRevision, failure(Absent, "get", err)
			}
			// os.Root may report ENOENT for a link that leads nowhere:
			// only an entry that is not there is proof of an absence
			if _, statErr := f.root.Lstat(name); errors.Is(statErr, os.ErrNotExist) {
				return nil, NoRevision, failure(Absent, "get", err)
			}
		}
		return nil, NoRevision, failure(Unreadable, "get", err)
	}
	defer file.Close()
	st, err := file.Stat()
	if err != nil || !st.Mode().IsRegular() || Private(st) != nil || st.Size() > p.Limit {
		return nil, NoRevision, failure(Unreadable, "get", errors.New("store: the document is not a private regular file within its bound"))
	}
	b, err := io.ReadAll(io.LimitReader(file, p.Limit+1))
	if err != nil || int64(len(b)) > p.Limit {
		return nil, NoRevision, failure(Unreadable, "get", errors.New("store: the document could not be read within its bound"))
	}
	return b, revisionOf(b), nil
}

// at reports the revision a document is at now, for a compare.
func (f *Files) at(op, name string) (string, error) {
	_, revision, err := f.Get(name)
	switch FaultOf(err) {
	case "":
		return revision, nil
	case Absent:
		return NoRevision, nil
	}
	return NoRevision, err
}

func (f *Files) Put(name string, data []byte, expected string) (string, error) {
	if !plainName(name) {
		return NoRevision, failure(Refused, "put", errors.New("store: not a document's name"))
	}
	if expected != AnyRevision {
		current, err := f.at("put", name)
		if err != nil {
			return NoRevision, err
		}
		if current != expected {
			return NoRevision, failure(Conflict, "put", errors.New("store: the document is at another revision"))
		}
	}
	p := f.policy(name)
	tmp := p.Staging + randomID()
	file, err := f.root.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL|NoFollow, 0600)
	if err != nil {
		return NoRevision, failure(Durability, "put", err)
	}
	defer f.root.Remove(tmp)
	if _, err = file.Write(data); err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil || closeErr != nil {
		return NoRevision, failure(Durability, "put", errors.Join(err, closeErr))
	}
	if err = f.root.Rename(tmp, name); err != nil {
		return NoRevision, failure(Durability, "put", err)
	}
	if p.SyncDirectory {
		dir, err := f.root.Open(".")
		if err != nil {
			return NoRevision, failure(Durability, "put", err)
		}
		defer dir.Close()
		if err = dir.Sync(); err != nil {
			return NoRevision, failure(Durability, "put", err)
		}
	}
	return revisionOf(data), nil
}

func (f *Files) Delete(name, expected string) error {
	if !plainName(name) {
		return failure(Refused, "delete", errors.New("store: not a document's name"))
	}
	if expected != AnyRevision {
		current, err := f.at("delete", name)
		if err != nil {
			return err
		}
		if current == NoRevision {
			return failure(Absent, "delete", nil)
		}
		if current != expected {
			return failure(Conflict, "delete", errors.New("store: the document is at another revision"))
		}
	}
	if err := f.root.Remove(name); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return failure(Absent, "delete", err)
		}
		return failure(Durability, "delete", err)
	}
	return nil
}

func (f *Files) List(limit int) ([]string, error) {
	directory, err := f.root.Open(".")
	if err != nil {
		return nil, failure(Unreadable, "list", err)
	}
	defer directory.Close()
	names, err := directory.Readdirnames(limit)
	if err != nil && err != io.EOF {
		return nil, failure(Unreadable, "list", err)
	}
	return names, nil
}

// randomID is a staging name's unpredictable part.
func randomID() string {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("secure randomness unavailable")
	}
	return hex.EncodeToString(b[:])
}
