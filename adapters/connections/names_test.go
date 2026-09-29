package connections

import (
	"strings"
	"testing"
)

// The two readers of a request take a member by its name as written. Each
// request here is one the decoder alone takes, reading the member that
// comes last; it is refused, and nothing of it is kept.
func TestARequestIsReadByItsNamesAsWritten(t *testing.T) {
	revision := strings.Repeat("a", 64)
	for name, raw := range map[string]string{
		"a name in capitals":               `{"connection":"absent","revision":"` + revision + `","QUERY":"first","maxResults":1}`,
		"every name in capitals":           `{"CONNECTION":"absent","REVISION":"` + revision + `","QUERY":"first","MAXRESULTS":1}`,
		"a name beside itself in capitals": `{"connection":"absent","revision":"` + revision + `","query":"first","QUERY":"second","maxResults":1}`,
		"a name with a long s":             `{"connection":"absent","revision":"` + revision + `","query":"first","maxRe` + "ſ" + `ults":1}`,
	} {
		var q SearchRequest
		if err := decode([]byte(raw), &q); err != ErrRequest {
			t.Errorf("%s: %v, read as %+v", name, err, q)
		}
	}
	var q SearchRequest
	if err := decode([]byte(`{"connection":"absent","revision":"`+revision+`","query":"first","maxResults":1}`), &q); err != nil || q.Query != "first" || q.MaxResults != 1 {
		t.Fatal("a request named as written was refused", err)
	}
}

func TestAStorageRequestIsReadByItsNamesAsWritten(t *testing.T) {
	for name, raw := range map[string]string{
		"a name in capitals":               `{"folder":"","QUERY":"notes","pageToken":""}`,
		"a name beside itself in capitals": `{"folder":"","query":"notes","Query":"other","pageToken":""}`,
		"a name with a Kelvin sign":        `{"folder":"","query":"notes","pageTo` + "K" + `en":""}`,
	} {
		var q StorageQuery
		if err := decodeStorage([]byte(raw), &q); err != ErrRequest {
			t.Errorf("%s: %v, read as %+v", name, err, q)
		}
	}
	for name, raw := range map[string]string{
		"an action in capitals":               `{"context":"c","ACTION":"delete","id":"i","folder":"","name":"n","revision":"r","mediaType":"text/plain","contentBase64":""}`,
		"an identifier beside itself, folded": `{"context":"c","action":"rename","id":"kept","ID":"replaced","folder":"","name":"n","revision":"r","mediaType":"text/plain","contentBase64":""}`,
	} {
		var q StorageChange
		if err := decodeStorage([]byte(raw), &q); err != ErrRequest {
			t.Errorf("%s: %v, read as %+v", name, err, q)
		}
	}
	var q StorageQuery
	if err := decodeStorage([]byte(`{"folder":"","query":"notes","pageToken":""}`), &q); err != nil || q.Query != "notes" {
		t.Fatal("a request named as written was refused", err)
	}
}
