//go:build gateway_acquisition_fixture

package websource

import (
	"adapters/attachment"
	"adapters/document"
	"adapters/internal/acquisitionfixture"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestAcquisitionFixturePageUsesProductionBodyAndOwnIdentity(t *testing.T) {
	markedBuild(t)
	requested := "https://example.com/fixtures/start?submitted=unchanged%2Fbytes"
	raw, err := ReadAcquisitionFixture(t.Context(), []byte(`{"url":"`+requested+`"}`))
	if err != nil {
		t.Fatal(err)
	}
	var envelope struct {
		Acquisition struct {
			Adapter                                     attachment.Identity
			Endpoint, Snapshot, PeerIdentity, Statement string
		}
		Result attachment.Record
	}
	if json.Unmarshal(raw, &envelope) != nil {
		t.Fatal("invalid acquisition envelope")
	}
	identity, err := document.OwnIdentity()
	identity.Name = "adapter-web"
	sum := sha256.Sum256([]byte(acquisitionfixture.CompanyHTML))
	if err != nil || envelope.Acquisition.Adapter != identity || envelope.Acquisition.Endpoint != acquisitionfixture.CompanyURL || envelope.Acquisition.Snapshot != "sha256:"+hex.EncodeToString(sum[:]) || !strings.HasPrefix(envelope.Acquisition.PeerIdentity, "tls:sha256:") || !strings.Contains(envelope.Acquisition.Statement, requested) {
		t.Fatal("page identity, endpoint, exact request or response digest changed", string(raw))
	}
	if envelope.Result.Provenance.Source.RequestedURL != requested || envelope.Result.Provenance.Source.URL != acquisitionfixture.CompanyURL+"?view=full" || !strings.Contains(envelope.Result.Content.Pages[0].Text, "Example Fixture Company") || strings.Contains(envelope.Result.Content.Pages[0].Text, "Never retain") {
		t.Fatal("production redirect/extraction/provenance path not used")
	}
	record, _ := json.Marshal(envelope.Result)
	if err := attachment.Check(record); err != nil {
		t.Fatal(err)
	}
	described, err := DescribeResearchBinding()
	var descriptor PageBindingDescriptor
	if err != nil || json.Unmarshal(described, &descriptor) != nil || descriptor.Adapter != identity {
		t.Fatal("descriptor differs from actual fixture binary identity", err)
	}
}

func TestAcquisitionFixturePageKeepsRequestAndNetworkRefusals(t *testing.T) {
	markedBuild(t)
	for _, raw := range []string{`{"url":"https://example.com/fixtures/company","url":"https://example.com/fixtures/company"}`, `{"URL":"https://example.com/fixtures/company"}`, `{"url":"https://example.com/fixtures/company","headers":{}}`, `null`} {
		if _, err := ReadAcquisitionFixture(t.Context(), []byte(raw)); !errors.Is(err, ErrRequest) {
			t.Fatal("malformed request admitted", raw, err)
		}
	}
	for _, raw := range []string{`{"url":"https://unrouted.example.org/fixtures/company"}`, `{"url":"https://127.0.0.1/private"}`, `{"url":"https://example.com/fixtures/private-redirect"}`} {
		if _, err := ReadAcquisitionFixture(t.Context(), []byte(raw)); err == nil {
			t.Fatal("unrouted/private request admitted", raw)
		}
	}
	// The adapter owns origin policy; the consumer owns endpointScope. A
	// same-origin hop outside a consumer prefix must remain visible in the
	// real envelope for Runner's final endpoint check, not be forged here.
	raw, err := ReadAcquisitionFixture(t.Context(), []byte(`{"url":"https://example.com/fixtures/leave-scope"}`))
	if err != nil || !strings.Contains(string(raw), `"endpoint":"https://example.com/outside/company"`) {
		t.Fatal("final endpoint hidden", err)
	}
}
