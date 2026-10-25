package storecontract

import (
	"errors"
	"sort"
	"strconv"
	"sync"
)

var _ Documents = (*memory)(nil)

// memory is the custody's documents kept in a map, for tests: the second
// kind the conformance cases hold to the contract.
type memory struct {
	mu   sync.Mutex
	docs map[string][]byte
	revs map[string]int64
}

func newMemory() *memory {
	return &memory{docs: map[string][]byte{}, revs: map[string]int64{}}
}

func (m *memory) current(name string) string {
	if _, there := m.docs[name]; !there {
		return NoRevision
	}
	return strconv.FormatInt(m.revs[name], 10)
}

func (m *memory) Get(name string) ([]byte, string, error) {
	if !plainName(name) {
		return nil, NoRevision, failure(Refused, "get", errors.New("memory: not a document's name"))
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	data, there := m.docs[name]
	if !there {
		return nil, NoRevision, failure(Absent, "get", nil)
	}
	return append([]byte(nil), data...), m.current(name), nil
}

func (m *memory) Put(name string, data []byte, expected string) (string, error) {
	if !plainName(name) {
		return NoRevision, failure(Refused, "put", errors.New("memory: not a document's name"))
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if expected != AnyRevision && expected != m.current(name) {
		return NoRevision, failure(Conflict, "put", errors.New("memory: another revision"))
	}
	m.revs[name]++
	m.docs[name] = append([]byte(nil), data...)
	return m.current(name), nil
}

func (m *memory) Delete(name, expected string) error {
	if !plainName(name) {
		return failure(Refused, "delete", errors.New("memory: not a document's name"))
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	current := m.current(name)
	if current == NoRevision {
		return failure(Absent, "delete", nil)
	}
	if expected != AnyRevision && expected != current {
		return failure(Conflict, "delete", errors.New("memory: another revision"))
	}
	delete(m.docs, name)
	return nil
}

func (m *memory) List(limit int) ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var names []string
	for name := range m.docs {
		names = append(names, name)
	}
	sort.Strings(names)
	if limit > 0 && len(names) > limit {
		names = names[:limit]
	}
	return names, nil
}
