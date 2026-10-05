---
status: proposed
date: 2026-10-04
deciders: maintainer
---

# A gateway another party runs may witness a decision trail's checkpoints: it signs a statement of its own, not a receipt, over the runtime's checkpoint line, chains its statements per trail and serves them by trail identity; the runtime's verifier reads the whole chain, from its first statement, under a key the reader supplies

Issue #199. Runtime ADR-0047 §3, accepted on 2026-10-01, names a gateway witness for
decision-trail checkpoints as later work that "needs a design of its own". This record is that
design. It is proposed: nothing in it is built, and the questions at the end are the maintainer's
to answer before it is accepted.

**What it was checked against.** Gateway `main` at `9a95e7f`. Runtime `v0.26.0` at `1d38cda`.
Desk `main` at `3a8450a`. The specification repository's `main` at `a902dc7`, for RFC 0010 and
RFC 0012, both drafts. The byte counts below are derived from the runtime's checkpoint form and
the statement's members. No witness exists, so nothing here was measured on one.

## Context and problem statement

**What the runtime has** (`v0.26.0`, `docs/building-with-packs.md` and `internal/audit/`):

- A chained trail. Each new record carries `trail` (128 random bits, 32 lowercase hex),
  `sequence` (its line number) and `previous` (the SHA-256 of the exact bytes of the line before,
  or of the whole unchained prefix before it).
- `jpack audit checkpoint` prints one line,
  `{"checkpointVersion":"1","recordDigest":"sha256:…","sequence":N,"trail":"…"}`, in its RFC 8785
  canonical form with a newline (`EncodeCheckpoint`, `internal/audit/checkpoint.go`).
  `recordDigest` is the SHA-256 of the record's exact line bytes without the newline: the digest
  the next record's `previous` holds, and the one a gateway action receipt's
  `decision.recordDigest` names for the same record. For a three-digit sequence the line is 172
  bytes without its newline and 173 with it; Desk measured "about 170" (Desk ADR-0010 §2).
- `audit checkpoint --since <sequence> --limit <n>` prints every checkpoint after a sequence, for a
  deliverer that hands each new one to a holder.
- `audit verify --expect <file>` holds the trail to every checkpoint in a holder's file
  (`checkHeld`, `internal/audit/verify.go`). The line at each one's sequence must be a chained
  record of its trail with its digest; otherwise `checkpoint-beyond-trail`,
  `checkpoint-not-chained`, `checkpoint-trail-mismatch` or `checkpoint-record-mismatch`. The
  records up to the highest checkpoint that matched, with no failed check at or before it, are
  **witnessed**; the chained records after it are **unwitnessed**.
  `--require-checkpoint-through <sequence>` fails with `checkpoint-coverage-missing` while any
  record up to it is unwitnessed.
- `audit stamp` sends a time-stamping authority the SHA-256 of the checkpoint line without its
  newline (`CheckpointDigest`, `internal/audit/stamp.go:86`), and keeps the token in
  `stamps.jsonl` beside the trail.
- Every public key the runtime reads is held to `CheckPublicKey` (`internal/audit/publickey.go`),
  and every signature to one equation, both written down in the guide's "Record signatures,
  exactly".

**What that leaves open.** A held checkpoint is as good as its holder's independence and
retention, and it reaches a verifier by whatever channel the holder uses. A stamp shows that a
checkpoint existed by a time, but an authority serves nothing back. The stamps file is the
operator's: an operator who rewrites a trail can present an older complete copy with the stamps
that still match it, and nothing tells the verifier that a later stamp exists. Rollback is
answered only by a party the verifier can ask, without the operator, "what is the latest you hold
for this trail?". ADR-0047 §3: "It is the strongest answer to rollback, and the only one that
needs a third party to run a service."

**What the gateway has.** One Ed25519 seed (`SPEC.md` §5). A canonical form (§1.1). Receipts of
versions 2 and 3 (§1.2, §1.2a). A seal, which the gateway signs under a prefix of its own and
which is not a receipt (§3). The registry served raw at `/registry`, and `/publickey` as a
convenience (§6). Version 3 admits two kinds, `acquisition` and `action`, and a receipt of any
other kind is `malformed` at §1.4 order 1. The engine listens on a loopback address only;
reaching it from another host means a TLS-terminating front the operator runs
(`docs/design/engine-config.md`). With `identity` configured the signer verifies a bearer token
on every endpoint but `/registry` and `/publickey`, which stay open because "a verifier holds no
token" (`go/serve.go:1502`). A token establishes an issuer and a subject, nothing more.
`SECURITY.md` names multi-tenancy, rate limiting and access control as not in scope for the
reference.

**What Desk plans** (Desk ADR-0010, accepted 2026-10-03):

- Holders, each with a label and a channel, and a cursor per holder and per trail identity: the
  last sequence handed over (§2).
- Download or copy first. Second, for a holder who runs one, an HTTPS endpoint: "Desk POSTs the
  same bytes, `application/jsonl`, on a schedule. Retries are idempotent by each line's SHA-256. A
  2xx answer moves the cursor" (§2, "Channels"; delivery PR 10).
- The local managed gateway is not offered as a holder: "It is the operator's, and its key was
  generated in the operator's store" (§2, "What is not a holder").
- "A gateway witness run by another party" is not in its line ("Delivery, after acceptance").

**A word already in use.** In this repository "witness" has also meant an MCP gateway plugin
that observes tool calls the engine did not make (ADR-0003, `docs/design/plugins.md`). The
specification's RFC 0012 uses it for any party that signs a history head it observed. This
record's witness is that second sense applied to one object: a gateway that countersigns the
runtime's checkpoints. Nothing here touches the plugin question.

## Decision drivers

- A verifier learns how far a trail was witnessed from the witness, without the operator's
  cooperation and without trusting the operator's copy.
- A verifier never accepts a chain of statements that starts late: the evidence a rewrite fails
  against is an early statement, and whoever presents the chain can leave it out.
- The witness signs the runtime's checkpoint as the runtime prints it. No re-encoding, and no new
  digest of the record: the bytes are the ones `--expect`, a stamp and `decision.recordDigest`
  already name (ADR-0047, "Exact bytes, wherever a record travels").
- The witness learns digests, a trail identity and sequences, never a record's contents
  (ADR-0047, "Privacy").
- Nothing a released verifier reads changes meaning: every receipt, seal and registry verifies as
  before.
- Nothing on the decision path waits for a witness. A record not yet covered is pending and
  reported unwitnessed (ADR-0047, decision 4).
- The witness never erases or rewrites a statement it acknowledged; damage is recovered without
  losing evidence.
- Each part says what it establishes and what it does not, and the runtime's report says it in
  fixed sentences.
- Each candidate clause of RFC 0012 (attribution, delivery, enforcement, coverage, retention,
  recency, non-collusion) gets an answer or a stated gap, with per-record and per-set limits and a
  bound on verification work.

## Considered options

**What the witness signs.**

- **S1. The checkpoint itself**: its four members, carried as an object whose canonical form is
  the checkpoint line, byte for byte.
- **S2. The checkpoint's digest only**, as a time-stamping authority stamps it. The witness then
  knows no trail and no sequence. It cannot keep a trail's statements in order, cannot refuse a
  second record for a sequence, and cannot answer "the latest for this trail". That is a stamp
  with a weaker clock.
- **S3. The record line, or the trail's last line.** It discloses a record's contents (ADR-0047,
  "Privacy"). Declined.
- **S4. A salted checkpoint.** It hides the record digest from the witness, and loses the byte
  identity with `--expect`, the stamp and `decision.recordDigest`. ADR-0047 says a salt "must be
  decided before deployment". Not now.

**What carries the signature.**

- **F1. Version 3 receipts.** A third `kind` is not possible: the enumeration of two is a
  structural condition of §1.4 order 1, so every released verifier reports such a receipt
  `malformed` (`corpus/v3/stores/v3-malformed-kind.json`, whose second receipt has kind
  `"other"`). A version 3 receipt can carry witness material in a signed extension member, or as
  an acquired artifact, since a verifier "tolerates a member it does not know at any depth" (§6,
  "Adapter sources"). But no released verifier enforces any witness meaning then: it verifies the
  receipt as an acquisition of bytes a source returned, and nothing in the format says otherwise.
- **F2. Receipt version 4, with a kind `witness`.** The gateway would still make every witness
  receipt itself, as it makes every receipt (§5: a client "cannot supply a receipt", meaning it
  cannot manufacture the gateway's signature; receipts already bind values a client supplies).
  The costs are of meaning and of consumers. Every §1.2a member — `source`, `argumentsCommitment`
  (whose salt travels in the response and is never retained or signed), `caller`, `authority`, a
  retained artifact — needs a meaning for a countersignature, or version 4 relaxes them for one
  kind. And a receipt's consumer follows §5a: a store verified against its registry, store-wide
  by default (§5a.1, which also allows a deliberate session-scoped verdict). A witness's consumer
  follows another contract: one trail's chain, complete from its first statement, against a head
  fetched from the witness and a trail copy (§6 below).
- **F3. A statement of its own, beside the seal.** Its own version member and context prefix, the
  same canonical form (§1.1) and key, and the coverage rule of §1.2: everything but `signature`.
  The seal is the precedent: a record the gateway signs, under a prefix of its own, that is not a
  receipt (§3).

**Where it is served.**

- **E1. A source behind `/acquire`.** It would mint acquisition receipts that "attest" checkpoints
  as bytes a source returned, with F1's problem.
- **E2. Endpoints of their own, under `/witness/`.**

**How the runtime reads it.**

- **V1. A converter** that checks the statements and writes a plain file for `--expect`. The
  signature and chain checks are then the converter's word, and `--expect` cannot tell a
  witness's checkpoint from a holder's.
- **V2. `audit verify --witness`**, which checks the chain under a key the reader supplies and
  then holds the trail to it.

## Decision outcome (proposed)

Proposed: **S1, F3, E2 and V2.** S1 keeps the bytes every other check of a checkpoint already
uses. F3 gives the witness's assertion a format and a consumer contract of its own, and changes
nothing a receipt verifier reads. E2 keeps the witness off the receipt path. V2 leaves the check
with the reader, as `--tsa-roots` does for stamps.

### 1. What a witness is, and is not

- **A witness is a gateway, run by a party other than the trail's operator,** configured to sign
  and serve checkpoint statements (determination 4). It is a holder in runtime ADR-0047 §2a's
  sense, "the counterparty, an auditor, or a store the operator does not control", as Desk
  ADR-0010 §2 keeps them, that also signs what it holds and serves it to any verifier who names
  the trail.
- **What makes it a witness is who holds its key, not its software.** A gateway whose key the
  operator can use is no witness against the operator (runtime ADR-0047 §1, "The existing action
  receipts"). Desk's managed local gateway generates its key in the operator's own store, so it is
  not one, and Desk ADR-0010 §2 already does not offer it as a holder. Nothing in a statement can
  show independence: the witness cannot know who runs it. A verifier decides which witness keys it
  trusts, as it decides which time-stamping roots (RFC 0012, clause 7: independence "is a
  governance property").
- **How it differs from a plain holder:**
  - its copy is signed, so a statement is evidence in anyone's hands, the operator's included; a
    holder's file is evidence only as far as the channel it came by;
  - a verifier fetches it from the witness by trail identity, without the holder's or the
    operator's help;
  - it refuses, at submission, a second record for a sequence it holds, and keeps the attempt
    (determination 3).
- **What it is not.**
  - It does not see the trail. It cannot check that a checkpoint names a real record, that a
    later checkpoint extends an earlier one, or that the lines of one submission describe one
    history: the chain links exact record bytes, and checking a link needs the records, which
    ADR-0047 "Privacy" keeps from it. Those checks stay the verifier's, against a trail copy.
  - It is not a time-stamping authority. Its time is its own clock's claim, under no certificate
    policy.
  - It does not know who is entitled to submit for a trail. A token names an issuer and a subject;
    whether that subject is the trail's operator is what registration (determination 4) records,
    and nothing in a checkpoint shows it.

### 2. The witnessed object

- **The bytes.** The witness signs the checkpoint as `jpack audit checkpoint` prints it: the object
  `{checkpointVersion, recordDigest, sequence, trail}`, held to the runtime's shape
  (`ParseCheckpoint`, `internal/audit/checkpoint.go`). That is exactly those four members;
  `checkpointVersion` `"1"`; `trail` 32 lowercase hex; `sequence` an integer from 1 to 2⁵³−2;
  `recordDigest` `"sha256:"` and 64 lowercase hex.
- **Its canonical form is the checkpoint line.** Under §1.1 the canonical form of that object is
  the checkpoint line without its newline, byte for byte. The member names are ASCII and already
  in code-point order, and the values are hex strings and an integer below 2⁵³
  (`internal/result/audit.go` says the same of RFC 8785). So the bytes inside the witness's signing
  input are the bytes `--expect` reads, and their SHA-256 is what a stamp imprints.
- **Never re-encoded.** The witness accepts a submitted line only in that canonical form. A line
  that parses to the same value with other bytes is refused.
- **Why the whole checkpoint and not its digest.** The trail and the sequence let the witness keep
  a trail's statements in order, refuse a second record for a sequence, and serve the latest by
  trail. Those are the answer to rollback (S2). They disclose the trail's identity, 128 random
  bits, and how many lines the trail had at each submission.
- **How a verifier recomputes it from a trail copy.** For a statement's sequence `N`, take line
  `N`'s exact bytes without the newline. Their SHA-256 is `recordDigest`, and the line's `trail`
  member is `trail`. The checkpoint is those two, with `checkpointVersion` `"1"` and `sequence`
  `N`. That is the comparison `--expect` already makes, with the same four findings.

### 3. The witness statement

**Members.** All are required, and the set is closed: a reader refuses a member it does not
know, because a new member is a new `witnessVersion`. Unlike a receipt, whose verifier tolerates
unknown members, an unaware reader then refuses rather than skips (RFC 0010, "Compatibility").

| Member | Type | Meaning |
|---|---|---|
| `witnessVersion` | the string `"1"` | this format |
| `kind` | `"checkpoint"`, `"conflict"` or `"retirement"` | below |
| `checkpoint` | the object of determination 2 | for `"checkpoint"`, the checkpoint witnessed; for `"conflict"`, the one offered and refused; for `"retirement"`, the trail's latest witnessed checkpoint, repeated |
| `index` | integer from 0, contiguous per trail | this statement's place in the witness's chain for `checkpoint.trail` |
| `prevSignature` | the `signature` of the statement at `index` − 1 for the same trail; `null` at 0 | the chain |
| `witnessedAt` | `YYYY-MM-DDThh:mm:ssZ`, UTC, whole seconds, the form `servedAt` takes (§6) | the witness's clock when it signed; never earlier than the previous statement's for the trail |
| `keyId` | as in §1.2 | the witness's key |
| `signature` | 128 lowercase hexadecimal characters | below |

A statement at index 7 and sequence 120, its hex elided here, is 608 bytes without its newline
and 609 as a logged line:

```
{"checkpoint":{"checkpointVersion":"1","recordDigest":"sha256:…","sequence":120,"trail":"…"},"index":7,"keyId":"…","kind":"checkpoint","prevSignature":"…","signature":"…","witnessVersion":"1","witnessedAt":"2026-10-04T12:00:00Z"}
```

**What the signature covers.** `"judgment-pack-gateway/witness/1:"`, followed by `canon` of the
statement with its top-level `signature` removed and every other member retained, the nested
`checkpoint` included. That is §1.2's rule: appending anything anywhere invalidates the
signature. The prefix differs from the receipt's and the seal's, so none can be replayed as
another. Every value is an ASCII string, an integer below 2⁵³ or `null`, so the canonical form is
also the RFC 8785 form. A reader without the gateway's `canon`, such as the runtime, can build it.

**The key, and the one equation.** Every reader of a witness key — the runtime's `--witness-key`,
`gateway witness verify`, and Desk's pin of a witness — holds it to the runtime's public-key rule
(`CheckPublicKey`, `internal/audit/publickey.go`; the guide, "Record signatures, exactly"; and
determination 1 of [ADR-0012](0012-hold-a-write-to-a-signed-record.md)), before reading anything
signed: 32 bytes that are the canonical encoding (RFC 8032 §5.1.2) of a point of the curve whose
order does not divide 8. A key that is not canonical, encodes no point, or is one of the eight
points of small order is refused; the all-zero key, a plausible placeholder, is one of them, and
under it a signature can be made without a private key. A signature is accepted by the
runtime's equation and no other: `S` below L, and the canonical encoding of [S]B − [h]A equal to
`R` byte for byte, h being SHA-512 of `R` ‖ `A` ‖ the signed bytes, reduced modulo L. The
cofactored check, which accepts more, is not used. The witness's own key, derived from its seed,
is never refused.

**The chain, per trail.**

- Along a trail's chain, the sequences of its `checkpoint` statements strictly increase. The
  witness's **head** for a trail is its last statement, of any kind. The **latest witnessed
  checkpoint** is its last `checkpoint` statement, and coverage is always stated by that one: a
  `conflict` at sequence 100 appended after a checkpoint at 200 does not move coverage back to
  100.
- A `conflict` statement records that a submitter allowed for the trail offered another
  `recordDigest` for a sequence at which the witness holds a `checkpoint` statement. There is at
  most one per sequence: the first offer is the evidence, and later ones are answered with it. It
  joins the chain, so the witness cannot drop it unnoticed. Since the witness holds only sequences
  it signed, a conflict's sequence is always at or below the latest checkpoint statement's before
  it. That is what a reader checks of it (determination 6), because it needs no statement but the
  latest checkpoint; that the sequence was held, and that no sequence has two conflicts, are the
  witness's rules, which a reader does not check.
- A `retirement` statement is the last of its chain: the witness accepts nothing more for the
  trail, and keeps and serves the chain as before (question 4). Its `checkpoint` repeats the
  latest witnessed checkpoint, so it names the trail and pins where the chain ended.
- Each statement names the previous one's signature, so the head commits to every statement
  before it for that trail. A witness that drops, reorders or alters a statement it served breaks
  the chain for anyone who holds a later one.

**Why the latest alone is not enough.** The witness cannot check that a checkpoint extends the
last one (determination 1). Take an operator who rewrites a trail from sequence `k` on, where an
earlier statement's sequence is `k` or above, and then submits a checkpoint above the witness's
head: the witness signs it. What catches the rewrite is the verifier holding the trail to that
**earlier** statement, which no longer matches. A verifier given only the latest statement, or
the statements from some index after the earlier one, holds the rewritten trail to statements
that match it. So a verifier takes the trail's chain from its first statement (determination 6),
and the head, fetched from the witness, tells it how far the chain reaches. ADR-0047 §3 and issue
#199 speak of serving "the latest one it holds". This is why the latest is served as the end of
the chain, not in place of it.

**What a statement establishes, and what it does not.**

| | Establishes | Does not establish |
|---|---|---|
| A `checkpoint` statement, verified under a key the verifier trusts | the key's holder was given this checkpoint and signed it as statement `index` of its chain for the trail, and states that it did so at `witnessedAt` | that the checkpoint names a real record; that it extends the one before; that the submitter was the trail's operator; that `witnessedAt` is true; anything against a witness that colludes, or whose key is stolen |
| The same, held against a trail copy | lines 1 to its sequence are the lines that existed when the witness signed, if the witness is independent of the operator | anything after that sequence; that this is the project's only trail; that the records are true, or that every decision was recorded |
| A chain read from index 0, every statement present and linked, up to the signature of a head the reader fetched from the witness | the reader holds every statement of the chain that head commits to, as the witness signed them: none is missing, out of order or altered, and none starts late | that the head is still the witness's head after the fetch: a signature does not say when it was fetched; that the witness signed no second chain for the trail, for another audience; that it will serve these tomorrow |
| The same chain read only as far as it was supplied, with no head | the same, up to the highest statement supplied | anything about statements after it: the reading is historical |
| A `conflict` statement | a submitter the witness allowed for the trail offered another record for a sequence the witness held | which of the two is the trail's; who that submitter was, beyond the witness's own registration |
| A `retirement` statement | the witness accepts no more statements for the trail, and the chain ends there | why; whether the trail's operator went on under another trail |

### 4. Endpoints and storage

**Configuration.** A `witness` member of the engine configuration, at the next `engineVersion`.
That is `"6"` unless ADR-0007's `services` takes it first: the engine reads `"1"` to `"5"`
(`docs/design/engine-config.md`). Its members:

- `log`, an absolute path: the witness log, and the registrations beside it (below);
- `marks`, an absolute path on storage apart from the log's, another device or volume: the marks
  file (below);
- `registration`, `"operator"` (the default) or `"first-submission"` (below; question 2);
- `submitters`, optional: the `{issuer, subject}` pairs allowed to submit at all; absent, any
  subject the configured issuer's tokens name;
- `trailsPerSubmitter`, from 1 to 100000, default 100, and `submissionsPerMinute`, from 1 to 6000,
  default 60, on the precedent of the MCP server's bounds.

The engine refuses to start with `witness` and without `identity`, since submission is
authenticated. With `witness`, `platforms` may be empty, so a party can run a witness and nothing
else; today an engine with no platform is refused (`go/engine.go:1118`). The witness runs in the
signer, which holds the seed and stays standard-library-only (ADR-0001); its endpoints are the
signer's.

**Registration.** A trail is registered to exactly one issuer and subject before anything is
signed for it. Under `"operator"`, the witness's operator registers it with `gateway witness
register --trail <id> --issuer <issuer> --subject <subject>`, and a submission for an unregistered
trail is `403`. Under `"first-submission"`, the first accepted submission registers the trail to
its submitter. Either way a submission for a trail registered to another subject is `403`, a
registration is never in a statement, and changing one is an act of the witness's operator,
recorded and never served. What registration does not do, stated because a token proves only an
issuer and a subject:

- **Under `"first-submission"`, another allowed subject can squat.** A customer of the same
  issuer who learns an unregistered trail's identity — from a checkpoint handed to it as a holder,
  say — can submit first, and the trail's operator is then refused. `submitters` narrows who can;
  it does not stop a subject it allows.
- **Every deliverer of one trail shares its subject.** Several of the operator's deliverers
  submitting for one trail use one registered subject, and the witness cannot tell them apart, or
  tell the operator from a thief of the operator's credential.
- **A stolen submission credential can poison a trail.** Whoever holds the registered subject's
  token can submit a well-formed checkpoint at sequence 9007199254740990 with any digest. The
  witness signs it; every later honest checkpoint is then below the latest, and none can exceed
  it. Revoking the token, or registering the trail anew, does not unsign it: the statement stays
  in the chain, and every verification of that trail against it fails (`checkpoint-beyond-trail`).
  Recovery is retirement, not erasure (question 10).

**Signed, durable, marked, published.** A statement is *signed* when the witness has made it in
memory; *durable* when it is appended to the log and the log is synced; *marked* when a line
naming it — its trail, index and signature — is appended to the marks file and that file is
synced; *published* when it is acknowledged in an answer or served by a read. The order is fixed:
sign, make durable, mark, publish. The witness publishes only marked statements, so a statement
no mark names was never published: that is what "demonstrably unpublished" means below. A marked
statement may go unacknowledged — a lost response, or a crash after the mark — and the submitter
recovers it by sending the same checkpoint again, or by reading the trail.

**`POST /witness/checkpoints`: submit.**

- **The body.** `application/jsonl`: one or more checkpoint lines as `audit checkpoint --since`
  prints them, each canonical and ended by a newline, all of one trail, with sequences strictly
  increasing. At most 1 MiB, the engine's request bound (`maxRequestBody`, `go/serve.go:515`),
  which is about 6,000 lines of 173 bytes. Each line at most 4096 bytes, the runtime's
  `MaxCheckpointBytes`. These are the bytes Desk ADR-0010 §2 sends to an HTTPS holder.
- **Only the last line is signed.** A statement for it constrains the prefix of the trail that
  matches it. It does not show that the other lines of the request describe that prefix: the
  witness cannot check that, and lines from two histories of one trail identity can arrive
  together. The earlier lines are compared with what the witness holds, for conflicts, and are
  otherwise discarded, and with them the evidence of what they said (question 7).
- **The answers.** Submissions for one trail are taken one at a time, and the write step of every
  trail is serialized under one writer lock (below).
  - **The trail is retired**: `409`, `reason: "retired"`, with the retirement statement.
  - **A line conflicts**: the witness holds a `checkpoint` statement at its sequence with another
    `recordDigest`. `409`, `{"error", "reason": "conflict", "statements": [<held>, <conflict>]}`,
    each statement given as a JSON string holding its exact line. The conflict statement is made
    durable if it is the first for that sequence; otherwise the first one is returned, and it is
    not an acknowledgement of the digest just offered. Nothing else is appended.
  - **The last line is held**: same trail, sequence and digest as a `checkpoint` statement.
    `200`, with that statement. Nothing is appended. This is the idempotent retry: the same
    checkpoint twice gives the same statement.
  - **The last line is below the latest checkpoint statement's sequence, and not held.** `409`,
    `reason: "below-head"`, with the head statement. Nothing is appended. A deliverer whose cursor
    fell behind learns where the witness is.
  - **Otherwise** the witness signs a `checkpoint` statement at the next index, makes it durable
    and marks it, and only then answers `200` with it, `application/jsonl`.
  - **The append, a sync or the mark fails**: `503`. A statement was signed and may be durable;
    it is not published. The log or the marks file may now end in a torn line, so the witness
    signs nothing more, for any trail, until it restarts and has checked both (below): it never
    signs a second statement at an index whose first may be durable.
  - `400` for a body out of shape, `401` without a valid token, `403` for a trail unregistered or
    registered to another subject, `413` over the bound, and `429` over `submissionsPerMinute`, or
    for a new trail over `trailsPerSubmitter`.

**`GET /witness/trails/{trail}/head`.** The trail's last statement, `application/jsonl`, exactly
as logged. `404` for a trail the witness holds nothing for. `{trail}` must be 32 lowercase hex, or
`400`.

**`GET /witness/trails/{trail}/statements?from=<index>&limit=<n>`.** The statements from `index`
(default 0), at most `n` (1 to 1000, default 1000), in index order, exactly as logged. A verifier
asks again from the next index until it reaches the head's.

**Both reads are open,** like `/registry` and `/publickey`: a verifier holds no token. Knowing a
trail's identity is what lets one read it, and no endpoint lists trails. They serve only marked
statements of a log the witness checked when it started, and never bytes a repair set aside. The
reference bounds no read. A party that exposes a witness puts it behind the TLS-terminating front
`engine-config.md` already requires for any other host, and bounds reads there.

**What the witness stores, and in what order.**

- **The witness log**: one canonical statement per line, newline-ended, append-only. A complete
  line is never rewritten or removed.
- **The marks**: one line per statement, `{trail, index, signature}`, appended and synced after
  the statement is durable and before it is published. The file lives on storage apart from the
  log's and is **never restored from a backup**: it is the witness's own record of every
  statement it may have published, against which a log, restored or not, is judged. It is about
  200 bytes a statement.
- **The registrations**: one line per registration or change, `{trail, issuer, subject}`, beside
  the log, appended and synced **before** anything is signed for the trail, and never served. So
  a crash leaves at most a registration with no statement, which is harmless, and never a
  statement with no registration.
- **Retirement** is a statement in the chain, signed when the witness's operator runs `gateway
  witness retire --trail <id>`, and marked like any other, so it needs no state of its own.
- **Retention**: every statement, for as long as the witness runs. Nothing is pruned (question 4).

**Start-up, and repair.** Before it serves anything, the witness reads its whole log, its marks
and its registrations, and checks them:

- every complete line of the log is a statement that verifies under its key;
- each trail's chain runs from index 0, contiguous and linked, with checkpoint sequences
  increasing, each conflict's sequence at or below the latest checkpoint statement's before it,
  and a retirement only last;
- **the log reaches every mark**: each mark names a statement the log holds, by trail, index and
  signature;
- the statements no mark names are at most one, the log's last line, since one writer appends
  for every trail;
- every trail with a statement has a registration.

It refuses to start on any failure, naming it, and repairs nothing by itself.

**One writer.** One lock covers the log-and-marks pair for the whole witness: a statement's append
and sync and its mark's append and sync happen under it, for every trail and every kind,
retirements and conflicts included, and a failure under it stops all signing (the `503` above).
Submissions of different trails are taken in parallel up to that step and serialized at it, which
the rate bound already keeps cheap. So one crash tears at most one of the two files. That is for
liveness, so that an honest crash rarely costs a key; it is not what makes recovery safe. The
rules below are, and under them two torn files are a new key whatever tore them.

**Recovery, in three rules.** `gateway witness repair` does what these allow and nothing else.

1. **An index is released in exactly one case.** The marks file ends cleanly, the log's last line
   is torn (bytes after its last newline that are not a whole statement), and the log without
   those bytes reaches every mark. Then the torn bytes were never marked, so never published.
   Repair sets them aside, in a file beside the log that is kept and never served, ends the log at
   its last newline, and their index is free for the trail's next statement. They may hold a
   signature over a statement the witness then signs again, differently, at that index; whoever
   holds that file holds a statement no reader was ever served, and the record says so rather
   than pretending the bytes were never signed.
2. **No mark is ever made from damaged evidence.** Repair never writes a mark in place of one that
   is torn, missing or unreadable, and never discards a mark line. The one mark it writes is the
   step the fixed order was about to take: with the marks file ending cleanly, the log's whole
   last statement, passing the checks, that no mark names (or the log's torn last bytes when they
   are such a statement short of its newline only, the newline added). Both files are intact up
   to it, so completing it infers nothing, and it releases nothing.
3. **Everything else is a new key.** A torn, unreadable or otherwise damaged mark line; both files
   torn; a lost marks file; and a log that does not reach every mark of an intact marks file — a
   stale backup, a published statement cut short, a damaged line, an erased retirement — unless
   a copy of the log that passes the start-up checks against that marks file is put in its place.
   That copy is not a repair: it is the log as the checks find it, and it holds every statement
   the witness may have published. Otherwise nothing shows which indexes were published, so none
   is inferred and none released: the witness goes on only under a **new key**, a new witness
   whose chains begin at index 0 for trails registered anew. The old key signs nothing more. Its
   chains stay readable under its pin, as historical readings from the statements readers kept.
   Under question 6's shared key, that is a new key for the gateway's receipts and seals too.

**The cost, accepted.** A torn mark line costs a key, even when only a crash in the middle of its
append tore it. That is accepted because the marks file is small, about 200 bytes a statement,
written one line per statement under the writer lock, so a crash tears it only in that one
append; and because the alternative is to infer from damaged evidence what was published, and a
wrong inference reuses a published index under the same key, which is a second chain. Discarding
a torn mark as an interrupted write is such an inference: if it was a published statement's mark,
damaged later, a stale log restored behind it reaches every remaining mark and starts, and that
statement's index, a retirement's perhaps, is signed again.

**What this cannot catch.** An operator who restores the marks file from a backup as well, or
loses log and marks together and restores both, leaves the witness nothing to judge by; so does a
marks file that loses whole lines at its end, which reads like an older one. The rule that marks
are never restored is the operator's to keep, and a witness that breaks it can sign a second chain
without colluding with anyone; readers who kept statements still expose it (§5).

**How the witness is itself checked.** `gateway witness verify --log <file> --public-key <file>`,
over a copy of its log, applies the start-up checks, all but the registrations, and gives its
verdict in its JSON, as `gateway verify` does (§5a.2). That shows a copy is internally
consistent. It does not authenticate registrations, show that every trail or statement was kept,
or show that the copy is the log the witness serves now. A statement someone kept that the copy
lacks or contradicts shows that.

### 5. Trust and privacy

**What the witness learns,** per trail: its identity; the sequences submitted, so how many lines
the trail had; the record digests at those sequences; when; and the registered submitter. Not a
record's contents, pack, inputs or outcome. A record digest covers a random `run` id, so it is not
trivially guessable, and it is not confidential either (ADR-0047, "Privacy").

**What open reads disclose.** Anyone who knows a trail's identity — any holder of even one old
checkpoint — learns, for as long as the witness serves the trail, its continuing activity: the
sequence progression, when each statement was signed, and every conflict. ADR-0047 accepts that
digests are not confidential and that a stamp discloses a checkpoint's digest; it does not itself
settle publishing a trail's continuing activity to every past recipient of a checkpoint. That is
question 3's decision.

**What it establishes against an operator,** given a trail copy and the trail's chain read from
its first statement: no record up to the latest checkpoint statement's sequence was edited,
removed, inserted or moved since the witness signed the first statement covering it; a copy cut
short below that sequence fails; and a rewrite from any sequence at or below an earlier
statement's fails at that statement, even when a later checkpoint of the rewrite was signed.

**What it does not establish:**

- **Anything against a witness that colludes, or whose key is stolen.** It can sign any checkpoint
  at any stated time, and a second chain for a trail for another audience. Two statements for one
  trail and one index that differ, both verifying, prove the witness signed two chains; a statement
  someone kept that the served chain lacks exposes the second chain to whoever holds both. One
  witness gives no non-collusion (RFC 0012, clause 7).
- **Who submitted.** The witness cannot tell the operator from a holder of the operator's
  credential, and a verifier cannot either. A poisoned statement fails verification; it does not
  say whose it was.
- **Anything about an operator who stops submitting.** The records after the latest checkpoint
  statement stay unwitnessed, and a copy cut back to that statement's sequence passes: those
  records were never witnessed. `--require-checkpoint-through` turns the gap into a failure for a
  reader who expects more.
- **Anything about records after the latest checkpoint statement,** or about a trail rewritten
  before its first submission.
- **That the trail is the project's only one.** An operator can start another trail. The verifier
  must hold the trail identities it expects (ADR-0047, "What a verifier must hold independently").
- **That the witness keeps what it signed.** A witness that loses or withholds its latest
  statements serves an older head that is internally consistent and looks complete to a fresh
  verifier. For a trail it holds nothing for, it answers `404`, which reads like a trail never
  submitted. This cannot be prevented, only shown: the submitter can obtain every published
  statement for its trail, from a `200` or by sending the same checkpoint again, and a statement
  with a higher index than the head the witness serves shows the served view is not the whole
  one. It does not show whether the witness forgot or withholds (RFC 0012, clauses 2 and 5). An
  honest witness whose log is damaged does not forget silently under its key: it refuses to start
  until a log that reaches its marks is restored, or goes on under a new key (determination 4).
- **When anything happened.** `witnessedAt` is the witness's clock: an upper bound on when it held
  the checkpoint, as it states. Like a stamp's time, but without the policy, accuracy and
  certificate chain an RFC 3161 token carries. It says nothing of when a record was made. A
  record's `at` stays the operator's word.

**Rollback, as the verifier sees it,** given the chain from its first statement, the head fetched
from the witness, and a trail copy:

- a copy shorter than the latest checkpoint statement's sequence: `checkpoint-beyond-trail`;
- another record at a statement's sequence: `checkpoint-record-mismatch`;
- a copy of another trail: `checkpoint-trail-mismatch`;
- a copy that matches every statement: the records up to the latest are the ones the witness saw.

Where the reading ends is the reader's policy (RFC 0012, clause 6, recency). Ending at the head
the reader fetched refuses an older copy presented as current. Ending at an earlier index, with
no head, audits an older copy on purpose, and the report calls that reading historical. A reading
may end early; it never starts late.

**The clock.** A statement's time is never earlier than the previous one's for the trail: the
witness takes the later of its clock and that time. A verifier compares nothing to a clock.

### 6. How the runtime's verifier reads it

`jpack audit verify` gains:

- `--witness <file>`, repeatable: statements, one per line, as the witness serves them;
- `--witness-head <file>`: one statement, the head the reader fetched from the witness;
- `--witness-resume <file>`: a continuation the reader's own earlier successful reading of the
  same trail saved (below);
- `--witness-save <file>`: where to save a continuation, written only when the verification has
  no finding at all;
- `--witness-key <file>`, repeatable: a witness's public key, obtained out of band and held to
  `CheckPublicKey` before anything is read (`/publickey` is a convenience only, §5);
- `--require-countersigned-through <sequence>`.

**The chain a verification reads.** The statements of every `--witness` file, the head and the
continuation's two statements are one set, whatever files they came in and in whatever order:

- each must be of the trail being verified, the identity its chained records carry, or
  `witness-trail-mismatch`;
- each is checked once, under the key its `keyId` names among those supplied. A `keyId` that
  names none, or a signature that fails the equation of determination 3, is
  `witness-signature-invalid`. Such a statement is never skipped, whatever it claims (RFC 0012,
  clause 1): it fails the verification;
- a statement of another `witnessVersion` or `kind`, or out of shape, is `witness-malformed`;
- two statements with the same canonical bytes are one. Two that verify, are of one index and
  differ are `witness-equivocation`: the witness signed two chains;
- in `index` order the set must begin at index 0, with `prevSignature` `null`, or, with a
  continuation, at the index after its last statement, with that statement's signature as
  `prevSignature`; and it must hold every index from there to its highest, each `prevSignature`
  the signature of the statement before. Each checkpoint statement's sequence must exceed the
  latest checkpoint statement's before it; each conflict's sequence must be at or below it; a
  retirement must be last and repeat its checkpoint. Otherwise `witness-chain-broken`. A set that
  begins late is never read from where it begins. With a continuation, statements at or below its
  index are not supplied: they are refused before anything is read, never passed over;
- with `--witness-head`, the head must be the chain's statement at its index, by its signature,
  or `witness-head-unreached`. The chain may run past it: statements the witness signed after the
  reader's fetch, supplied from elsewhere, are checked like the rest. The reading is then
  **current**, as of the reader's fetch. Without `--witness-head` it is **historical**: it ends at
  the highest statement supplied and says nothing about any after it;
- with a continuation, a head at its last index must be its last statement, by signature, or
  `witness-equivocation`; a head below it is `witness-head-behind`: the witness serves an older
  head than a statement this reader's own earlier reading checked, so it forgot or withholds, or
  the reader supplied a stale head.

**Continuing.** A verification with no finding at all, given `--witness-save`, saves a
**continuation**: `{"continuationVersion":"1","last":<statement>,"latestCheckpoint":<statement>}`,
the last statement it read, of any kind, and the latest checkpoint statement at or before it,
both as signed. Every check of determination 6 needs only the statement before and the latest
checkpoint statement, so a later reading given the continuation as `--witness-resume` goes on
from the index after `last` and checks what a reading from index 0 would have checked:

- both statements are checked under the keys supplied, and `latestCheckpoint` must be a
  `checkpoint` statement at or before `last`'s index, or `witness-chain-broken`;
- `latestCheckpoint`'s checkpoint is held against the trail again, like the others. That keeps
  every earlier constraint: the checkpoint commits, through the trail's own chain, to every line
  before it, so a copy that still matches it holds the prefix every earlier statement was checked
  against;
- the continuation advances after any statement, conflicts and retirements included, so a chain
  of any length and any mix of kinds is read in steps, each starting where the last one saved;
- a continuation is saved only by a reading that failed nothing, so no failure is stepped over:
  a step that fails saves nothing, and the reader starts again from the continuation it had;
- **only the reader's own successful reading may become a continuation.** A statement whose
  signature verifies, handed over by the operator or anyone else, is not one: it says the witness
  signed it, not that this reader read everything before it. The runtime cannot tell a saved
  continuation from one written by someone else, so the report says the reading continued, from
  which index, and a fixed sentence says whose word that is.

For the statements a reading reads, a chain read in steps over one trail copy gives the findings
and coverage a whole reading would. The head is also judged against the continuation (above).
Vectors read the same chains whole and in steps, with the step's bound lowered in the test: a
conflict at 100 after checkpoints at 100 and 200, continued from index 1, which passes as it does
whole; a conflict above the latest checkpoint, which fails either way; and a long run of
conflicts after the last checkpoint, which the steps get through. Others hold the continuation's
own rules: a head at the continuation's index that matches it, and one that differs
(`witness-equivocation`); a head below it (`witness-head-behind`); statements at or below its
index supplied, refused before anything is read; its checkpoint held again after the trail copy
changed, failing where the copy no longer matches; a statement after a continuation whose last
statement is a retirement (`witness-chain-broken`); a failing step, which leaves the saved
continuation as it was; and the bounds, with the continuation's two statements counted.

**What is credited.** Every verified `checkpoint` statement's checkpoint is held against the trail
exactly as `--expect`'s are, so a mismatch is always reported. But only a chain with no witness
finding is credited: on any `witness-*` finding, `countersigned` is `failed`, and no statement's
checkpoint counts toward `witnessed`. `conflict` and `retirement` statements are never credited.

**What `witnessed` then means.** As now: the chained records up to the highest held checkpoint that
matched with no failed check at or before it, whether a holder's file or a credited witness
statement supplied it. `--require-checkpoint-through` keeps its meaning. A new coverage member
says how far a witness's signature reaches:

- `countersigned`: `not-checked` without `--witness-key`; `failed` on a witness finding; `through`
  the latest checkpoint statement's sequence when it matched with no failed check at or before it;
  otherwise `through` the highest credited sequence that did, or `none`.
- `--require-countersigned-through` fails (`countersigned-coverage-missing`, exit 1) while the
  records up to that sequence are not all countersigned. It is the "whose evidence" floor of
  RFC 0012 clause 3, where `--require-checkpoint-through` is the "how much".
- A report section, `witness`: the statements read and checked; the keys supplied; where the
  reading began (index 0, or continued after an index) and where it ended (current, at the head's
  index, or historical, at the highest supplied); the latest checkpoint statement's sequence and
  `witnessedAt`; each conflict statement's sequence; and whether the chain is retired. A conflict
  fails nothing by itself, and is reported with a fixed sentence.

**Bounds of one verification** (question 11). At most 16 `--witness-key`. The `--witness`,
`--witness-head` and `--witness-resume` files together at most 64 MiB, and at most 110,000
statements, the continuation's two counted: about 110,000 logged lines of 609 bytes, where one file
at the bound of a held file (`MaxHeldBytes`, 16 MiB) holds about 27,500. Over either bound, the
verification is refused before any statement is checked, never truncated. Each statement costs one
Ed25519 verification, under the one key its `keyId` names, so the work is bounded by the statement
count. A longer chain is read in steps, each continuing from the continuation the step before saved,
so every step advances, through conflicts as through checkpoints. How long a chain grows is the
deliverer's cadence: 110,000 statements is about 30 hours at the default ceiling of 60 submissions a
minute, and about 12 years at one an hour.

The fixed sentences, proposed:

- Establishes: "Lines 1 to N are the lines that existed when a witness under a key supplied signed
  its statement for checkpoint N, which it states it did at T, if that witness is independent of
  the trail's operator."
- Does not establish: "Lines after N are covered by no statement of a witness under a key
  supplied."
- Does not establish, current: "That the witness's head for this trail is still index K: the head
  supplied is as current as the reader's fetch of it, and a signature does not say when it was
  fetched."
- Does not establish, historical: "That the witness held no statement for this trail after index
  K: no head fetched from the witness was supplied, so the chain was read only as far as it was
  supplied."
- Does not establish, continued: "Anything about statements up to index K, which this reading did
  not read: it continued from a continuation supplied as the reader's own earlier successful
  reading, which the runtime cannot tell from one someone else wrote, and is as complete as that
  reading was."
- Does not establish: "Anything against a witness that is not independent of the operator: one
  that colludes can sign what it is asked, at any time it states, and a second history for another
  audience; a key supplied is trusted because the verifier chose it."
- Does not establish: "Who submitted any checkpoint: a statement does not name its submitter, and
  the witness cannot tell the trail's operator from a holder of the operator's credential."
- Does not establish: "When any record was made: the time a witness states is its own clock's, for
  when it held the checkpoint."

The runtime fetches nothing. The reader fetches the chain and the head (Desk, a script, `curl`),
as it brings its own revocation lists for stamps.

### 7. Delivery, after acceptance

One pull request each, in this order.

| # | Repository | What | Needs |
|---|---|---|---|
| 1 | gateway | `SPEC.md` gains the witness statement (format, key rule and equation, coverage, chain, what it establishes) and §6 rows for the endpoints. `corpus/witness/` vectors: valid chains, a chain beginning late, equivocation, a head unreached, a non-canonical key, a small-order key, a signature only the cofactored check accepts, `S` of L or more, and the bounds at and one past each limit. The same PR teaches `gateway conform` and verify-ts to read them, with the corpus README's stated counts, so no vector lands unread | this record accepted; a cross-vendor review (public-surface, documented-claim, conformance, security) |
| 2 | gateway | The witness log, marks, registrations, statement signing in the order sign, durable, marked, published, start-up checks and repair in the core module, and `gateway witness verify`. Recovery vectors: a stale valid backup behind the marks, refused; an acknowledged last statement cut short, refused; a retirement erased by a stale restoration, refused; a whole unmarked last statement with the marks file ending cleanly, its mark completed; a torn unmarked last line with the marks file ending cleanly, set aside and its index released; a torn published mark with a stale backup log, `S[k]` a retirement, refused and a new key; a torn mark line from a crash mid-append, a new key; both last lines torn, a new key; one crash under the writer lock with two trails submitting, at most one file torn | 1 |
| 3 | gateway | The engine's `witness` member at the next `engineVersion`, `gateway witness register` and `retire`, the endpoints, bounds, and `SECURITY.md`'s scope line for them | 2; questions 2, 3, 4, 6 and 10 |
| 4 | runtime | `audit verify --witness`, `--witness-head`, `--witness-resume`, `--witness-save`, `--witness-key` and `--require-countersigned-through`; the chain rule, continuations, the bounds, the `countersigned` coverage, the findings and sentences; the vectors of PR 1 in its tests, and determination 6's vectors read whole and in steps and of the continuation's own rules; a guide section | 1 (the format and vectors), not the service; questions 8, 9 and 11 |
| 5 | desk | A new Desk ADR for a witness as a holder: ADR-0010 §2's HTTPS channel to the witness's form; the cursor moved only by a `checkpoint` statement that verifies under the pinned key, held to `CheckPublicKey`, and whose checkpoint is the last line sent (trail, sequence and digest); the statements kept; the panel passing `--witness` and a head it fetched | 3 and 4 released; questions 5 and 7 |
| 6 | desk | Its implementation, as ADR-0010's delivery PR 10 | 5; Desk's pins moved |

Runner needs nothing. Its chain of runs is handed over through Desk (Desk ADR-0010 §5), and the
runtime prints that chain's checkpoints in the same form.

### Consequences

- Good, because a verifier can ask a party other than the operator how far a trail was witnessed,
  and hold an older or rewritten copy to the answer. A stamp cannot tell it that a later stamp
  exists.
- Good, because a reading never starts late, so the early statement a rewrite fails against cannot
  be left out by whoever presents the chain.
- Good, because the witness signs the checkpoint's exact bytes, and every receipt, seal and
  registry verifies as before. A released verifier never reads a statement.
- Good, because a statement is evidence in any hands, the operator's included, so a witness whose
  served view is not the whole one can be shown to be.
- Good, because the runtime reads a statement with one Ed25519 check, under the key rule and
  equation it already applies to record signatures, over a canonical form of strings and integers
  it already builds (`internal/audit/sign.go:246`).
- Bad, because the witness is the first surface meant to be reached from other hosts by other
  parties. Multi-tenancy, registration, rate bounds and a TLS front become part of running one,
  where `SECURITY.md` lists them as out of scope for the reference.
- Bad, because a submission credential is enough to poison a trail at that witness for good, and
  recovery is a new trail.
- Bad, because the witness learns each trail's identity, its length at each submission and its
  record digests, and every holder of an old checkpoint can follow the trail's activity.
- Bad, because a verifier reads a trail's whole chain, which grows by one statement, 609 bytes at
  small numbers, per submission, or keeps its own continuation.
- Bad, because nothing here helps against a witness that colludes. One key is one party.
- Bad, because retention is the witness's promise. Nothing makes it checkable beyond the statements
  others kept.
- Bad, because a log that cannot be shown to reach the marks, lost marks, or a single torn mark
  line, even from a crash mid-append, cost the witness its key, and with question 6's shared key
  the gateway's key for receipts and seals too.
- Bad, because the rule that marks are never restored from a backup is the witness operator's to
  keep: broken, it lets an honest witness sign a second chain.
- Bad, because a second signed format sits beside the receipt, with vectors of its own.
- Revisit when a reader wants statements from two witnesses; when the record digest must be hidden
  from the witness (a salt, ADR-0047 "Privacy"); when a submission should prove possession of the
  trail rather than of a token, for instance with the runtime's record signature over the
  checkpointed record; when the gateway's own registry is to be witnessed (RFC 0010 §4; RFC 0012,
  unresolved question 4); or when the specification takes up the witness contract.

### How this sits with earlier records

- **Runtime ADR-0047 §3.** This is its design. It refines "serves the latest one it holds" to the
  chain whose end is the latest, read from its first statement (determinations 3 and 6).
- **[ADR-0012](0012-hold-a-write-to-a-signed-record.md).** It names "when the gateway witnesses a
  trail" as a time to revisit. Nothing in `requireSignedRecord` changes here. Its determination 1's
  key rule is the one a witness key is held to.
- **[ADR-0011](0011-hold-a-write-to-its-decision.md) and ADR-0012** gave `engineVersion` 4 and
  5, and [ADR-0007](0007-the-engine-serves-the-adapters-it-ships.md)'s `services` takes the next
  one when it is built. `witness` takes the next one free when it is built.
- **[ADR-0003](0003-a-fifth-process-speaks-mcp.md).** Its witness question, a plugin observing
  calls the engine did not make, is untouched.
- **Desk ADR-0010.** Its §2 HTTPS channel moves the cursor on any 2xx. For a witness, the new Desk
  ADR moves it on a verified statement for the last line sent, and states what a witness statement
  establishes in the manner of ADR-0010 §7's table.
- **RFC 0012 (draft).** Its scope note places a witness record format, for a currency registry, in
  the runtime, and proposes no change to the gateway. This record is for the runtime's decision
  trail, under ADR-0047 §3, which places the witness in a gateway. It answers the RFC's candidate
  clauses as follows.

| Clause | Here |
|---|---|
| Attribution | by a signature under a key the reader supplies, held to the key rule and one equation; a statement that does not verify fails, and is never skipped |
| Delivery | the reader fetches from the witness; a chain is read from its first statement, so an omission before or inside it fails; an absent trail reads like one never submitted |
| Enforcement | `--require-checkpoint-through` (how much) and `--require-countersigned-through` (whose) |
| Coverage | a statement constrains the lines up to its sequence, and nothing after; coverage is stated by the latest checkpoint statement |
| Retention | the witness's undertaking (question 4); not checkable beyond the statements others kept |
| Recency | where the reading ends: at a head the reader fetched (current) or earlier (historical); never where it starts |
| Non-collusion | none, with one witness; two differing statements at one index are reported as proof of two chains |
| Limits | per record (a statement's shape), per set and per verification (determination 6, question 11) |

## Questions for the maintainer

1. **A statement of its own, or receipt version 4?** A third kind inside version 3 is not on
   offer, and carrying witness material in a version 3 receipt leaves its meaning unenforced (F1).
   **Recommendation:** a statement of its own (F3), with its own version member and prefix, beside
   the seal. Its assertion — this key's holder was given this checkpoint for this trail, at this
   place in its chain — and its consumer contract — one trail's chain, read from its first
   statement, against a fetched head and a trail copy — are not a receipt's, and version 4 would
   carry members that mean nothing for it into a consumer contract built for stores.
2. **How is a trail registered, and who may submit for it?**
   **Recommendation:** a bearer token from the witness's configured issuer, and a trail registered
   to one issuer and subject **by the witness's operator** before anything is signed for it
   (`registration: "operator"`, the default). Registration on first submission only as an opt-in,
   for a witness whose allowed subjects do not compete, since any allowed subject can squat an
   unregistered trail and an allowlist does not stop a subject it allows. Several deliverers of one
   operator share the trail's one subject, and that is the operator's affair: statements never name
   a submitter. Re-registration is the witness's operator's act, recorded and never served.
3. **Who may read?**
   **Recommendation:** anyone who names the trail, as `/registry` is open, with no listing of
   trails, accepting explicitly what that discloses: every holder of even one old checkpoint can
   follow the trail's continuing activity — sequence progression, timing and conflicts — for as
   long as the witness serves it, which ADR-0047 does not itself settle. Reads behind a token would
   make every verifier a customer of the witness, and the identity would still leak to every
   holder.
4. **What does the witness retain, and how does a trail end?**
   **Recommendation:** every statement, for as long as the witness runs; nothing pruned and
   nothing removed by the reference. A trail ends by a signed `retirement` statement, made by the
   witness's operator, kept and served like the rest; after it, submissions are `409`. A party
   running a witness publishes its retention period. Removing a trail's statements, for a party
   that must, is a later decision of its own; until then removal is forgetting (§5).
5. **What acknowledges a hand-over to a witness?** Whether Desk's HTTPS hand-over and the witness
   are one endpoint or two matters less than what moves the cursor.
   **Recommendation:** one wire form — Desk POSTs the same `application/jsonl` checkpoint lines to
   either — and two acknowledgements. For a plain HTTPS holder, a 2xx, as ADR-0010 says. For a
   witness, only a `checkpoint` statement that verifies under the witness's pinned key and whose
   checkpoint is the last line sent, by trail, sequence and digest; a `409` returning a first
   conflict acknowledges nothing.
6. **Does the witness sign with the gateway's existing key?**
   **Recommendation:** yes, the existing seed, under the witness's own prefix, as the seal is. A
   party that wants the two roles apart runs a second gateway with its own seed. A second key in
   one signer is a custody path `SECURITY.md` does not describe.
7. **Does a submission sign only its last line, or every line?**
   **Recommendation:** only the last, and say what it costs. The chain grows by one statement per
   submission instead of one per record. A statement for the last line constrains the trail prefix
   that matches it, not the other lines of the request, and those lines are discarded once
   compared: lines from two histories of one trail identity, sent together, leave no evidence
   that the earlier ones were sent. Desk's hand-over says so to its owner.
8. **How does the runtime report it?**
   **Recommendation:** a credited statement's checkpoint joins the held checkpoints, so
   `witnessed` and `--require-checkpoint-through` keep their meaning, and a separate
   `countersigned` coverage and `--require-countersigned-through` say how far a witness's signature
   reaches. A chain with any witness finding is credited nothing.
9. **What is a complete and current verification, and what may a partial or historical one
   claim?**
   **Recommendation:** complete means the chain read from index 0, or continued from a
   continuation the reader's own earlier successful reading saved — never from a statement merely
   because its signature verifies — with every statement present and linked; there is no partial
   reading, since a set that begins late fails. Current means the
   chain reaches, by signature, a head the reader fetched from the witness itself, and is current
   as of that fetch. A historical reading ends earlier, without a head, and claims nothing about
   statements after its end; the report says which reading it was, and Desk's panel always reads
   to a head it fetched.
10. **How are a stolen submission credential and poisoned or damaged witness state recovered,
    without erasing evidence?**
    **Recommendation:** never by removing or rewriting a statement a mark names, and never by
    releasing an index whose statement may have been published. A stolen credential is revoked at
    the issuer; what it got signed stays. A trail poisoned by it is retired by the witness's
    operator, its honest history stays readable as a historical reading ending before the first
    poisoned statement, and the trail's operator goes on under a new trail identity, registered anew
    (moving a trail aside is the runtime's and Desk's decision, Desk ADR-0010 question 9). Damaged
    state follows determination 4's three rules: an index is released only for a torn last log line
    that no mark can name, the marks file ending cleanly; no mark is ever made from damaged
    evidence, so a torn or unreadable mark line is a new key; same-key recovery of a damaged log is
    a copy that reaches every mark, the marks file itself never being restored from a backup.
    Anything less — a stale backup, a published statement cut short, a damaged or lost marks file —
    is recovered under a new key, published as a new witness, the old key's chains staying readable
    as historical under its pin: never a new or older log under the old key.
11. **What limits bound one verification?**
    **Recommendation:** at most 16 witness keys; statement files together at most 64 MiB and
    110,000 statements, refused above either, never truncated; one Ed25519 verification per
    statement, under the key its `keyId` names; longer chains read in steps, each continuing from
    the continuation the step before saved, which advances after any statement. The vectors test
    each limit at and one past it.

## More information

- `SPEC.md` §1.1, §1.2, §1.2a, §1.4, §3, §4.1, §5, §5a and §6;
  `corpus/v3/stores/v3-malformed-kind.json`; [engine-config.md](../design/engine-config.md);
  [SECURITY.md](../../SECURITY.md); `go/serve.go` (`maxRequestBody`, the open endpoints) and
  `go/engine.go` (an engine with no platform), at `9a95e7f`.
- The runtime at `v0.26.0`: ADR-0047, sections 1, 2a, 3 and "Privacy";
  `docs/building-with-packs.md`, "Checking a trail, and handing over a checkpoint", "Handing every
  new checkpoint to a holder", "Stamping checkpoints with a time-stamping authority" and "Record
  signatures, exactly"; `internal/audit/checkpoint.go`, `internal/audit/verify.go`,
  `internal/audit/stamp.go`, `internal/audit/sign.go`, `internal/audit/publickey.go` and
  `internal/result/audit.go`.
- Desk ADR-0010, sections 2, 5 and 7, question 9, and "Delivery, after acceptance".
- The specification repository: RFC 0010 §4 and "Compatibility"; RFC 0012, its candidate clauses,
  "Security and privacy" and unresolved question 4. Both are drafts.
- Issue #199.
- Material-decision categories, when accepted: public-surface, documented-claim, conformance,
  security.
