//go:build gateway_acquisition_fixture && (linux || darwin)

package connections

import (
	"adapters/document"
	"adapters/internal/acquisitionfixture"
	"encoding/json"
	"testing"
)

// markedBuild makes the test run as the builder stamps the fixture; a test of
// the refusal of an unmarked build sets the version itself.
func markedBuild(t *testing.T) {
	t.Helper()
	was := document.Version
	document.Version = "fixture.test"
	t.Cleanup(func() { document.Version = was })
}

// fixtureChange writes a change to the store's one connection and returns it.
func fixtureChange(t *testing.T, store *Store, change func(*SearchConnection)) SearchConnection {
	t.Helper()
	var changed SearchConnection
	err := store.locked(func(v *state) error {
		change(&v.Search.Connections[0])
		changed = v.Search.Connections[0]
		return store.write("state.json", v)
	})
	if err != nil {
		t.Fatal(err)
	}
	return changed
}

func fixtureDescription(c SearchConnection) []byte {
	raw, _ := json.Marshal(map[string]string{"connection": c.ID, "revision": c.Revision})
	return raw
}

func fixtureRead(c SearchConnection) []byte {
	raw, _ := json.Marshal(SearchRequest{Connection: c.ID, Revision: c.Revision, Query: "synthetic fixture sources", MaxResults: 3})
	return raw
}

func TestAcquisitionFixtureSearchRefusesAnUnmarkedBuild(t *testing.T) {
	store, _, connection := searchFixture(t)
	was := document.Version
	document.Version = "0"
	t.Cleanup(func() { document.Version = was })
	if _, err := ReadSearchAcquisitionFixture(t.Context(), store, fixtureRead(connection)); err != ErrFixtureBuild {
		t.Fatal("unmarked build read", err)
	}
	if _, err := DescribeSearchAcquisitionFixture(store, fixtureDescription(connection)); err != ErrFixtureBuild {
		t.Fatal("unmarked build described", err)
	}
}

// A real store holds a real key: the fixture must refuse it before it charges
// the connection's durable allowance, and report the fixture's own code and
// not credentials-required.
func TestAcquisitionFixtureSearchRefusesAStoreThatIsNotTheFixturesBeforeCharging(t *testing.T) {
	markedBuild(t)
	store, _, connection := searchFixture(t)
	connection = fixtureChange(t, store, func(c *SearchConnection) { c.DailyLimit = 1 })
	if connection.Provider != "tavily" || connection.Credential == "" {
		t.Fatal("setup changed")
	}
	for range 2 {
		if _, err := ReadSearchAcquisitionFixture(t.Context(), store, fixtureRead(connection)); err != ErrFixtureStore {
			t.Fatal("non-fixture credential read", err)
		}
		if _, err := DescribeSearchAcquisitionFixture(store, fixtureDescription(connection)); err != ErrFixtureStore {
			t.Fatal("non-fixture credential described", err)
		}
	}
	store.locked(func(v *state) error {
		if v.Search.Connections[0].Requests != 0 {
			t.Fatal("a refused request was charged", v.Search.Connections[0].Requests)
		}
		return nil
	})
	// The fixture credential is not enough: the provider must be tavily too.
	for _, provider := range []string{"google-grounding", "unknown-provider"} {
		connection = fixtureChange(t, store, func(c *SearchConnection) {
			c.Provider = provider
			c.Credential = acquisitionfixture.Credential
		})
		if _, err := ReadSearchAcquisitionFixture(t.Context(), store, fixtureRead(connection)); err != ErrFixtureStore {
			t.Fatal("fixture credential under", provider, "read", err)
		}
		if _, err := DescribeSearchAcquisitionFixture(store, fixtureDescription(connection)); err != ErrFixtureStore {
			t.Fatal("fixture credential under", provider, "described", err)
		}
		store.locked(func(v *state) error {
			if v.Search.Connections[0].Requests != 0 {
				t.Fatal("a refused request was charged", provider)
			}
			return nil
		})
	}
	if ErrFixtureStore.Error() != "fixture-store-required" {
		t.Fatal("refusal code changed")
	}
}
