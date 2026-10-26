package connections

import "testing"

// The custody keeps each document as it did before the contract: the
// storage intent, the operation journal of a file change, is bounded by its
// line, absent only when its entry is not there, and synced with its
// directory (the sync itself: storecontract's
// TestFilesSyncTheDirectoryWhereThePolicySaysSo); every other document is
// bounded by 64 KiB and its directory is not synced.
func TestTheStorageIntentIsSyncedWithItsDirectory(t *testing.T) {
	intent, ok := custodyDocuments["storage-intent.json"]
	if !ok || !intent.SyncDirectory || !intent.ConfirmAbsence || intent.Limit != StorageLineBytes {
		t.Fatalf("the storage intent's policy: %+v", intent)
	}
	if len(custodyDocuments) != 1 || custodyDocument.SyncDirectory || custodyDocument.ConfirmAbsence || custodyDocument.Limit != 64<<10 {
		t.Fatalf("every other document's policy: %+v, %d kept otherwise", custodyDocument, len(custodyDocuments))
	}
}
