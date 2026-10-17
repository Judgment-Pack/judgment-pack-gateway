//go:build gateway_acquisition_fixture && (linux || darwin)

package connections

import (
	"adapters/attachment"
	"adapters/document"
	"adapters/internal/acquisitionfixture"
	"encoding/json"
	"strings"
	"testing"
)

func TestAcquisitionFixtureSearchKeepsIdentityValidationAndBudget(t *testing.T) {
	store, broker, connection := searchFixture(t)
	connection.Credential = acquisitionfixture.Credential
	connection.DailyLimit = 1
	raw, _ := json.Marshal(connection)
	if _, err := broker.Handle(t.Context(), "configure", raw); err != nil {
		t.Fatal(err)
	}
	store.locked(func(state *state) error { connection = state.Search.Connections[0]; return nil })
	request := SearchRequest{Connection: connection.ID, Revision: connection.Revision, Query: "synthetic fixture sources", MaxResults: 3}
	encoded, _ := json.Marshal(request)
	for _, bad := range []string{`null`, `{"connection":"demo","revision":"bad","query":"fixture","maxResults":1}`, string(encoded[:len(encoded)-1]) + `,"query":"duplicate"}`} {
		if _, err := ReadSearchAcquisitionFixture(t.Context(), store, []byte(bad)); err == nil {
			t.Fatal("malformed request admitted", bad)
		}
	}
	stale := request
	stale.Revision = strings.Repeat("0", 64)
	bad, _ := json.Marshal(stale)
	if _, err := ReadSearchAcquisitionFixture(t.Context(), store, bad); err != ErrChanged {
		t.Fatal("stale revision admitted", err)
	}
	raw, err := ReadSearchAcquisitionFixture(t.Context(), store, encoded)
	if err != nil {
		t.Fatal(err)
	}
	var envelope struct {
		Acquisition struct {
			Adapter                attachment.Identity
			Endpoint, PeerIdentity string
		}
		Result SearchResult
	}
	identity, err := document.OwnIdentity()
	identity.Name = "adapter-sources"
	if err != nil || json.Unmarshal(raw, &envelope) != nil || envelope.Acquisition.Adapter != identity || envelope.Acquisition.Endpoint != acquisitionfixture.SearchEndpoint || !strings.HasPrefix(envelope.Acquisition.PeerIdentity, "tls:sha256:") || envelope.Result.Query != request.Query || len(envelope.Result.Hits) != 3 || envelope.Result.Hits[0].URL != acquisitionfixture.CompanyURL || strings.Contains(string(raw), acquisitionfixture.Credential) {
		t.Fatal("search normalization/identity/credential boundary changed", string(raw))
	}
	description, _ := json.Marshal(map[string]string{"connection": connection.ID, "revision": connection.Revision})
	described, err := DescribeSearchBinding(store, description)
	var descriptor ResearchBindingDescriptor
	if err != nil || json.Unmarshal(described, &descriptor) != nil || descriptor.Adapter != identity || descriptor.Endpoint != envelope.Acquisition.Endpoint {
		t.Fatal("descriptor and actual fixture acquisition differ", err)
	}
	if _, err := ReadSearchAcquisitionFixture(t.Context(), store, encoded); err != Error("search-budget-exhausted") {
		t.Fatal("production durable daily cap bypassed", err)
	}
}
