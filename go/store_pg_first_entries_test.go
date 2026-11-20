package main

import (
	"bytes"
	"fmt"
	"testing"
)

// The first entry of every series, read in one statement, is the one a
// series at a time reads: in listSeries' order, the lowest of each series'
// names as listEntries sorts them ("10" before "2"), a series of no entry
// passed over, and another scope's series not among them.
func TestAPostgresStoreReadsEachSeriesFirstEntryInOneStatement(t *testing.T) {
	db := newPgTestDB(t)
	db.migrate(t)
	kind := db.open(t, nil)
	receipts := kind.receipts()
	for _, s := range []struct {
		name    string
		indexes []int64
	}{{"s-c", []int64{2, 10, 11}}, {"s-a", []int64{3}}, {"s-empty", nil}, {"s-b", []int64{1, 0}}} {
		if _, err := receipts.makeSeries(s.name); err != nil {
			t.Fatal(err)
		}
		for _, i := range s.indexes {
			if err := receipts.createIndexed(s.name, i, []byte(fmt.Sprintf(`{"series":%q,"index":%d}`, s.name, i))); err != nil {
				t.Fatal(err)
			}
		}
	}
	scoped, err := kind.inScope("scope-a")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := kind.scopeViews([]string{"scope-a"}); err != nil {
		t.Fatal(err)
	}
	if _, err := scoped.receipts().makeSeries("s-other"); err != nil {
		t.Fatal(err)
	}
	if err := scoped.receipts().createIndexed("s-other", 0, []byte(`{}`)); err != nil {
		t.Fatal(err)
	}

	var want []seriesFirst
	series, err := receipts.listSeries()
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range series {
		entries, err := receipts.listEntries(s)
		if err != nil {
			t.Fatal(err)
		}
		if len(entries) == 0 {
			continue
		}
		data, err := receipts.getEntry(s, entries[0])
		if err != nil {
			t.Fatal(err)
		}
		want = append(want, seriesFirst{series: s, data: data})
	}
	got, err := receipts.(firstEntriesReader).firstEntries()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(want) || len(want) != 3 {
		t.Fatalf("%d first entries read at once, %d one series at a time", len(got), len(want))
	}
	for i := range want {
		if got[i].series != want[i].series || !bytes.Equal(got[i].data, want[i].data) {
			t.Errorf("series %d: %s %s, not %s %s", i, got[i].series, got[i].data, want[i].series, want[i].data)
		}
	}
	if !bytes.Contains(got[2].data, []byte(`"index":10`)) {
		t.Errorf("the first entry of s-c is not the lowest name in byte order: %s", got[2].data)
	}
}
