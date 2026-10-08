package connections

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestGroundedSearchWaitsWithinTheTotalRequestBudget(t *testing.T) {
	p := googleProvider()
	transport := p.client.Transport.(*http.Transport)
	if transport.ResponseHeaderTimeout != 0 || p.client.Timeout != SearchMaxTimeoutSeconds*time.Second {
		t.Fatal("grounded search must use the configured total budget without the 15-second metadata timeout")
	}
	if google().client.Transport.(*http.Transport).ResponseHeaderTimeout != 15*time.Second {
		t.Fatal("other Google integrations lost their header timeout")
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	request, _ := http.NewRequestWithContext(ctx, http.MethodGet, server.URL, nil)
	_, err := p.client.Do(request)
	if err == nil || searchRequestFailure(err, ErrProvider) != Error("search-timeout") {
		t.Fatal("an unresponsive provider must still stop at its deadline with a timeout reason")
	}
}
func TestSearchRequestFailureDoesNotMislabelProviderErrors(t *testing.T) {
	for _, fallback := range []Error{ErrProvider, Error("credentials-required")} {
		if searchRequestFailure(context.DeadlineExceeded, fallback) != Error("search-timeout") {
			t.Fatal("deadline was hidden")
		}
		if searchRequestFailure(errors.New("untrusted provider detail"), fallback) != fallback {
			t.Fatal("non-timeout changed classification")
		}
	}
}
