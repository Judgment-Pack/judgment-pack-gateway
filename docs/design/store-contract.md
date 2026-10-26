# The store contract, its kinds, and the audit export

Status: implemented (#315). This note describes how the gateway keeps its durable state; it is not
normative and changes nothing in `SPEC.md`. Every receipt, seal, registry line, witness statement
and verification is the same bytes it was before the contract: the frozen corpus and `gateway
conform` pass unchanged, and every corpus store exports, restores and verifies byte for byte.

## Why

The gateway keeps five durable stores, and each grew its own atomicity, locks and recovery: the
receipts and artifacts with the seal registry (`go/store.go`), the connection custody's state and
the operation journal of a file change (`adapters/connections/store.go`, `storage.go`), the
descriptor snapshots `connect` pins (`go/connect.go`), the witness's log, marks and registrations
(`go/witness_log.go`), and the recurring bindings' operation records, the observation journal
(`adapters/connections/source_observations.go`). Each was filesystem code all the way down, so
nothing but the filesystem could keep them, and a backup or an external verifier had no single
consistent cut of them. The other repositories of the line are moving their state behind a store
contract with storage kinds; this is the gateway's.

## The contract

`go/store_contract.go` states seven primitives. None names a path: where a kind keeps its bytes,
and how it judges what it finds there, is the kind's.

| Primitive | Operations | What the gateway keeps in it today |
|---|---|---|
| Immutable content-addressed blobs (`blobSpace`) | `putBlob`, `getBlob`, `listBlobs` | the retained artifacts; the descriptor snapshots |
| Exclusive indexed creation (`indexedSpace`) | `makeSeries`, `createIndexed`, `listSeries`, `listEntries`, `getEntry` | the receipts, a session a series and a receipt an entry at its `callIndex` |
| Durable append-only logs (`appendLog`) | `appendRecord`, `readLog` from a cursor, `createLog` | the seal registry; the witness's log, marks and registrations |
| Versioned documents (`documentSpace`) | `getDocument`, `putDocument` and `deleteDocument` by compare-and-set against a revision, `listDocuments` | the connection custody's documents (below) |
| Secret values (`secretSpace`) | `putSecret` once, `getSecret` | the signing seed |
| Leases with fencing tokens (`leaseSpace`) | `acquireLease`, `renewLease`, `releaseLease`, `checkFence` | nothing yet (below) |
| An atomic snapshot of a consistent cut (`storeKind.snapshot`) | one read-only `storeCut` of the blobs, the entries, the documents and the log | the audit export |

What each asks of a kind:

- **A blob** is named by `sha256:` and the hex of its bytes. Putting bytes the space holds already
  succeeds. A kind returns a blob's bytes as it holds them and does not re-digest them: a reader
  that relies on them re-digests, as verification does an artifact (SPEC.md §1.4, order 8).
- **An entry** is made once at its index: a second create at the index is refused (`faultTaken`)
  and the entry is never replaced. `makeSeries` says whether this call made the series; one that
  another call made, at any moment before, is never this call's (`sessionState.created` rests on
  it).
- **A log** is bytes, appended whole and made durable, read in order from a cursor; the next cursor
  is the last one plus what was read. A record's framing is its writer's: SPEC.md §3 frames a seal
  as a line, and the registry writer ends an unterminated last line before it appends, as it
  always has. An append that fails says how many of its bytes may be in the log (`written`) and
  whether they were written whole and making them durable failed (`committing`); the registry
  writer takes a seal written in part, or whole and not synced, as one that may be there
  (`sealMayBeWritten`), exactly as before.
- **A document** is replaced only at the revision its writer read: `noRevision` for one that is not
  there; any other revision is a conflict (`faultConflict`). A deleted document is absent, and one
  made again takes a revision of its own. A document named `lease-...` is a lease's (below): the
  kind's document space reads and lists it as any other, and refuses a put or a delete of it
  (`faultRefused`). The prefix is compared without regard to case, since on a filesystem that
  folds case (the macOS and Windows defaults) `LEASE-job` is the lease's own document.
- **A secret** is made once and never replaced; it never leaves through a cut.
- **A lease** grants a name to a holder until it expires. Its fencing token grows with every grant
  of the name, so a holder whose lease expired and was granted to another carries a token
  `checkFence` refuses (`faultStaleFence`), and its renewal and release are refused alike. Any
  kind with documents gives leases through them (`go/store_leases.go`): a grant is a
  compare-and-set of the lease's document, so two granters cannot both take a name. A token never
  starts again: the next grant counts from the token the lease's document holds, and that document
  is the leases' own -- a kind's `documents()` is wrapped in `leaseDocumentsReserved`, which
  refuses a put or a delete of a `lease-` document, and only the lease space writes through the
  unwrapped one. Were the document deleted, the next grant would count from nothing and give a
  token the name gave before, which a holder from before the delete would still carry. The token
  is not derived from the document's revision instead: a revision is a kind's opaque string (the
  custody's is a digest of the bytes, which comes back when the bytes do), and a document that is
  not there has no revision to count from. What the reservation cannot stop is an older copy of the
  store's documents directory put back by hand, outside the gateway, which would rewind a lease's
  record; a restore of an export cannot, since an export carries no documents.
- **A fault** is typed (`storeFault`): absent, taken, conflict, lease held, stale fence, durability,
  unreadable, refused. A write that was not made durable is a `faultDurability` error the caller
  sees, never a success and never a verdict. The error's text is its cause's own, so every message
  the gateway gave before the contract reads as it did.

## The consistent cut

A writer makes its writes durable in one order: a blob before an entry that names it, an entry
before a document or a log record that counts it. The gateway's writes are in that order: an
artifact is retained before the receipt that names it is stamped, and a session's receipts are
stamped before its seal is appended. A cut holds, for everything in it, everything its writer
wrote before. The in-memory kind's cut copies every space under one lock: it is a state the kind
was in. The filesystem kind cannot take such a lock without stopping the writer, so its cut reads
the spaces in the reverse of the writer's order -- the log first, then the documents, then the
series and their entries, the blobs last -- and relies on an entry and a blob never being rewritten
once made and a log never being cut by a writer: a seal in the cut counts only receipts stamped
before it was appended, and those are listed when the receipts are read after it; a receipt listed
names an artifact retained before it, which is listed when the artifacts are read after it. Names
are listed at the cut; an entry's and a blob's bytes are read when asked.

So the export of a live store holds no seal whose receipts it lacks and no receipt whose artifact it
lacks: a session minted after the registry was read is in the export unregistered, as it was in the
store at that read, and one minted after its receipts were listed is not in the export at all
(`TestTheExportOfALiveStoreIsAConsistentCut`).

## The filesystem kind

`go/store_fs.go` is the code that kept the files before the contract, moved and not changed. Path,
link and owner checks stay inside it, and in the holders that open what a space is given.

| Space | Kept as |
|---|---|
| artifacts (`fsBlobs`) | `<store>/artifacts/<hex>`, a synced staging file renamed into place |
| receipts (`fsIndexed`) | `<store>/receipts/<session>/<callIndex>.json`, a synced staging file linked into place, which never replaces a name; the session directory made by an exclusive `mkdir`, never outside the receipts root |
| registry (`fsLog`) | the registry file, read through verification's own classifier (SPEC.md §4.1), its spelling judged before a directory is made for it, made empty only where nothing is, appended to at its end and synced |
| witness log, marks, registrations (`fsHeldLog`) | each file held open, locked and judged by the witness, written and synced through the witness's I/O seam, so the order its recovery vectors hold is the order kept |
| descriptor snapshots (`fsHeldPins`) | `<config>.descriptors/<hex>.json` in the held directory, staged, given the snapshot's mode and the configuration's owner, synced and linked; a name taken is reused only when it is that snapshot |
| documents (`fsDocuments`) | under a directory named for them: a document a directory of its revisions, each made once by a link, so two writers that expect one revision cannot both make the next; a revision a newer one stands over is emptied and never removed, so no revision is made twice. No configuration names one today. |
| secrets (`fsSecrets`) | the seed at the path its configuration names, opened once and judged by what was opened before a byte is read (`openSeed`), made by an exclusive create (`writeNewSeed`) |

What stays filesystem-specific, and is no part of the contract: the receipts' and artifacts'
directory sync is as far as the platform can (`syncDir`: Windows cannot sync a directory, and a
failure there is not reported, as it never was); the witness's start-up checks, its repair's cut
of a torn tail and its set-aside file; the held directories and the owners of the descriptor
snapshots; the seed's owner and mode.

## The connection custody's side

The adapters module never imports the core (ADR-0001), so the primitives the custody uses are
stated again in `adapters/internal/storecontract`: versioned documents with the same faults, held to the
document cases (below). Its filesystem kind (`Files`) keeps each document as the custody always
has -- a private file in the principal's held directory, read through one descriptor that
follows no link and blocks on nothing, replaced by renaming a synced staging file over it -- with a
document's policy where it was kept otherwise: the operation journal of a file change
(`storage-intent.json`) is bounded by its line, taken as absent only when its entry is not there,
and synced with its directory; every other document is bounded by 64 KiB and its directory is not
synced, as before. A revision is the digest of a document's bytes, so a document written again
with bytes it held before is at that earlier revision again, unlike a core kind's, where one made
again takes a revision of its own; nothing compares a custody revision today, since every custody
write replaces under the lock. A compare-and-set compares and then renames, so it is atomic among
writers that hold the custody lock, as every custody writer does; the custody's own writes replace
a document under that lock (`AnyRevision`), as they did. The custody's reads and writes, its
grants' listing and removal, the operation journal, and the consent record's removal at a
disconnect go through it.

The observation journal leaves the custody through `gateway-connections --state-dir <dir>
--principal <name> --export-observations`: the journal as the custody holds it, read under the
custody lock once it reads as a journal, or the empty journal where none is kept yet. It holds the
recurring bindings' operation records -- operation, binding, connection and epoch identifiers, the
account and the resource -- and no credential. A custody that is not there is refused and nothing
is made for it. The signer never reads the custody (ADR-0020): the export takes the journal as a
file the custody's owner gives it.

## The audit export

`gateway export --config <engine.json> --out <dir> [--observations <file>]...` (`go/export.go`)
writes one cut of an engine's durable state in the store layout SPEC.md §1.3 states, beside the
inputs `gateway verify` takes:

```
manifest.json                       the authority, the key by its id, every file by digest and size
registry                            the registry at the cut, when there was one
store/receipts/<session>/<n>.json   every session at the cut, an empty one too, and its receipts
store/artifacts/<hex>               every artifact at the cut, as held
decision-records/...                every regular file verification would read (links never followed), when the directory was there
descriptors/<hex>.json              each snapshot a platform pins, for itself or for one of its operations, digested to its pin
observations/<i>.json               each journal given
```

The manifest's `descriptors` name each pinned snapshot by its pin and its platform and, for an
operation's (`operationDescriptors`), the operation; `sessions` name every session, an empty one
too, since a directory is no file.

The decision records are the runtime's files, in no space of a kind; they are read after the cut,
so a record written before an action receipt the cut holds is in the export. The export copies
what is there, damage included: a receipt that is misfiled, an artifact that does not digest, a
session with no receipt are exported as they are, so verification of the export says what it says
of the store. A receipt or an artifact that is a link refuses the export: no file of the store is
read through a link, wherever it leads, as no decision record is; a link that leads nowhere is the
absence verification finds there, and the export holds none for it. A name an export could not
write as one clean, slash-separated path -- a backslash
in a name on Linux -- refuses the export, as a store that cannot be read does; nothing is skipped
silently. `--out` must not be there yet, nor be inside the store or the decision records, where it
would add a session or a record. The manifest is written last: an export without one is an export
that stopped.

The seed is in no file of the export, and neither is the public key: the manifest names the key by
its id, and a verifier pins the key out of band (SECURITY.md), as it does for a live store. After a
key rotation (SPEC.md §3b) `keyId` is the key the gateway signs with now, which is not the key a
verifier pins: the manifest then names, as `firstKeyId`, the key the registry's first rotation rotated
from, the one to pin, and a verifier follows the rotations from it. A registry with no rotation gives
no `firstKeyId`, and the manifest is the one it was before the member existed. The
manifest is not signed; receipts and seals carry their own signatures, and the manifest is the
transport's check.

`gateway export --check <dir>` holds an export, or a restore of one, to its manifest: every file it
names there, of its size and digesting to its digest; nothing there it does not name; every
session it names a directory, and no other; the decision-record directory there exactly when it
says one was. It prints `{"findings":[{"path","status"}],"ok"}`, a status one of `missing`,
`unlisted`, `size-mismatch`, `digest-mismatch` and `not-a-file`, and exits 0 when it reaches a
verdict, as `verify` does. A manifest it cannot read -- missing, empty, past its bound, not in the
canonical form it is written in, of another `exportVersion`, naming a path no export writes, a file
twice, a file in a session it does not name -- is no verdict. A restore is a copy of the export's
files back into place; `--check` and `gateway verify` read the restore as they read the export
(`TestEveryCorpusStoreExportsAndARestoreVerifiesByteForByte` runs every corpus store through an
export and a restore).

## What a kind must pass

`go/store_conformance_test.go` runs every case on every kind in `storeKindsUnderTest`: the
filesystem kind and the in-memory kind (`go/store_memory_test.go`). A kind is added by adding it
there and passing:

- a blob is named by its digest, kept once, and a name it never held is absent;
- an entry is created once, a second create at its index is refused and leaves it as it was, a
  series made already is never this call's, and a create into a series never made is absent and
  makes none;
- a document is replaced only at the revision read, a create of one that is there and a write or a
  delete at a stale revision are conflicts, and concurrent compare-and-set loops lose no write;
- a log is absent until made, an append to it before is absent with nothing written, appends read
  back in order from any cursor, and a cursor past the end is refused;
- a secret is made once;
- a lease is held until it expires, its expired holder's token is refused for the check, the
  renewal and the release once the name is granted again -- and so are they for a lease that
  expired and was not granted again -- every grant's token exceeds the last, a released lease's
  token is refused, and another holder presenting the current token renews and releases nothing
  (the fence is the token's alone);
- a lease's document cannot be deleted or rewritten through the kind's documents, whatever the case
  of its name, so a grant after the attempt still gives a token above the last and the token from
  before is refused;
- a snapshot taken while a writer writes in the contract's order is a consistent cut;
- a write the kind does not keep is a durability fault, never a success, and nothing is listed for
  it.

The filesystem kind's own safeguards, which no case can see from outside a kind, have tests of
their own: the staging file of a receipt or an artifact is synced, holding every byte, before its
name is put in place, through the `stagedSync` seam (`go/store_fs_test.go`); a series that would
not be a directory directly under the receipts root is refused by every operation before anything
is made; a pinned snapshot is read only at the snapshot's mode and an owner the MCP server accepts
(`go/store_fs_unix_test.go`); and the custody's storage intent has its directory synced after its
rename, through the `Files` directory-sync seam, while no other custody document does.

The custody's documents answer to the document cases in `adapters/internal/storecontract`. The
in-memory kind, whose compare-and-set is atomic on its own, is held to the core's concurrent case:
writers that share no lock, each retrying a refused write, lose no write. The custody's filesystem
kind, whose compare-and-set is atomic only under the custody lock, is held to a lock-discipline
case instead: under the lock each holder sees the last holder's revision, and a put at the
revision it read before its own put is refused.

## Not changed

- **Verification reads the §1.3 layout directly** (`verify.go`, the engine's `/verify`, the
  citation lookup of `/act`). It is SPEC.md's procedure over files, and its outcomes for absent
  and unreadable inputs are normative (§4.1); a store of another kind is verified through its
  export, which writes that layout.
- **An action's session is taken by its own `mkdir`** (`admitAction`, and the look of
  `sessionMintedHere`). Routing it through `makeSeries`, which remakes a receipts directory that
  went away as a stamp always has, would change what an action does when the directory is gone.
- **The custody's locks and the witness's file locks stay locks**, not leases -- the custody
  lock (`state.lock`), the lock around a token refresh (`refresh.lock`), and the lock each witness
  file is held under: a lock has no expiry, and a lease that can expire under a slow holder is
  another behaviour. Leases are for a kind with no shared lock.
- **Directory durability stays as shipped**: the receipts' and artifacts' directory sync is best
  effort, and the custody's documents other than the operation journal are renamed into place
  without a directory sync. The contract asks a kind to make a write durable; these are the
  filesystem kind's stated bounds, not something a new kind may copy.
- **The witness's reads, start-up checks and repair**, which judge and cut the held files, and the
  set-aside file, whose records are appended in parts and synced once; the MCP server's own read of
  a pinned snapshot, which judges the directory and the file before and after each open as another
  user; the engine configuration's replacement by `connect`; and `keygen`'s read-back of the seed it
  wrote, which reads the file as written and does not judge its owner.
