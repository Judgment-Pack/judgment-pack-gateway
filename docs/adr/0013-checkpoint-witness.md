---
status: proposed
date: 2026-10-04
deciders: maintainer
---

# A gateway another party runs may witness a decision trail's checkpoints: it signs a statement of its own, not a receipt, over the runtime's checkpoint line, chains its statements per trail and serves them by trail identity; the runtime's verifier checks them under a key the reader supplies

Issue #199. Runtime ADR-0047 §3, accepted on 2026-10-01, names a gateway witness for
decision-trail checkpoints as later work that "needs a design of its own". This record is that
design. It is proposed: nothing in it is built, and the questions at the end are the maintainer's
to answer before it is accepted.

**What it was checked against.** Gateway `main` at `9a95e7f`. Runtime `v0.26.0` at `1d38cda`.
Desk `main` at `3a8450a`. The specification repository's `main` at `a902dc7`, for RFC 0010 and
RFC 0012, both drafts. The byte counts below are computed from the runtime's checkpoint form. No
witness exists, so nothing here was measured on one.

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
  `decision.recordDigest` names for the same record. The line is 172 bytes for a three-digit
  sequence; Desk measured "about 170" (Desk ADR-0010 §2).
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
token" (`go/serve.go:1502`). `SECURITY.md` names multi-tenancy, rate limiting and access
control as not in scope for the reference.

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
- The witness signs the runtime's checkpoint as the runtime prints it. No re-encoding, and no new
  digest of the record: the bytes are the ones `--expect`, a stamp and `decision.recordDigest`
  already name (ADR-0047, "Exact bytes, wherever a record travels").
- The witness learns digests, a trail identity and sequences, never a record's contents
  (ADR-0047, "Privacy").
- Nothing a released verifier reads changes meaning: every receipt, seal and registry verifies as
  before.
- Nothing on the decision path waits for a witness. A record not yet covered is pending and
  reported unwitnessed (ADR-0047, decision 4).
- Each part says what it establishes and what it does not, and the runtime's report says it in
  fixed sentences.
- Each candidate clause of RFC 0012 (attribution, delivery, enforcement, coverage, retention,
  recency, non-collusion) gets an answer or a stated gap.

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

- **F1. A third kind inside receipt version 3**, the "negotiated extension" of issue #199.
  Version 3's `kind` is an enumeration of two, and the enumeration is a structural condition of
  §1.4 order 1: every released verifier reports a receipt of another kind `malformed`
  (`corpus/v3/stores/v3-malformed-kind.json`, whose second receipt has kind `"other"`). An
  extension member riding on an `acquisition` receipt is worse. A verifier "tolerates a member it
  does not know at any depth" (§6, "Adapter sources"), so it would verify the countersignature as
  an acquisition of bytes a source returned. Version 3 cannot carry a witness either way.
- **F2. Receipt version 4, with a kind `witness`.** It carries every §1.2a member: `source`,
  `argumentsCommitment` and its salts, `caller`, `authority`, a retained artifact. None has a
  meaning for a countersignature, unless version 4 relaxes them for one kind. A receipt says that
  a configured source returned bytes or that a target answered an action, and "a client … cannot
  supply a receipt" (§5). A witness signs a value the client supplies. In a store, its entries
  would also be judged store-wide with the acquisitions (§5a.1).
- **F3. A statement of its own, beside the seal.** Its own version member and context prefix, the
  same canonical form (§1.1) and key, and the coverage rule of §1.2: everything but `signature`.
  The seal is the precedent: a record the gateway signs, under a prefix of its own, that is not a
  receipt (§3).

**Where it is served.**

- **E1. A source behind `/acquire`.** It would mint acquisition receipts that "attest" checkpoints
  as bytes a source returned. Declined, for F1's reason.
- **E2. Endpoints of their own, under `/witness/`.**

**How the runtime reads it.**

- **V1. A converter** that checks the statements and writes a plain file for `--expect`. The
  signature check is then the converter's word, and `--expect` cannot tell a witness's checkpoint
  from a holder's.
- **V2. `audit verify --witness`**, which checks each statement under a key the reader supplies and
  then holds the trail to it.

## Decision outcome (proposed)

Proposed: **S1, F3, E2 and V2.** S1 keeps the bytes every other check of a checkpoint already
uses. F3 says exactly what a witness asserts, and changes nothing a receipt verifier reads. E2
keeps a value the client supplies off the receipt path. V2 leaves the check with the reader, as
`--tsa-roots` does for stamps.

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
  - It does not see the trail. It cannot check that a checkpoint names a real record, or that a
    later checkpoint extends an earlier one: the chain links exact record bytes, and checking a
    link needs the records, which ADR-0047 "Privacy" keeps from it. Those checks stay the
    verifier's, against a trail copy.
  - It is not a time-stamping authority. Its time is its own clock's claim, under no certificate
    policy.

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
| `kind` | `"checkpoint"` or `"conflict"` | below |
| `checkpoint` | the object of determination 2 | for `"checkpoint"`, the checkpoint witnessed; for `"conflict"`, the one offered and refused |
| `index` | integer from 0, contiguous per trail | this statement's place in the witness's chain for `checkpoint.trail` |
| `prevSignature` | the `signature` of the statement at `index` − 1 for the same trail; `null` at 0 | the chain |
| `witnessedAt` | `YYYY-MM-DDThh:mm:ssZ`, UTC, whole seconds, the form `servedAt` takes (§6) | the witness's clock when it signed; never earlier than the previous statement's for the trail |
| `keyId` | as in §1.2 | the witness's key |
| `signature` | 128 lowercase hexadecimal characters, an Ed25519 signature | below |

A statement, with its hex elided, is 608 bytes at index 7 and sequence 120:

```
{"checkpoint":{"checkpointVersion":"1","recordDigest":"sha256:…","sequence":120,"trail":"…"},"index":7,"keyId":"…","kind":"checkpoint","prevSignature":"…","signature":"…","witnessVersion":"1","witnessedAt":"2026-10-04T12:00:00Z"}
```

**What the signature covers.** `"judgment-pack-gateway/witness/1:"`, followed by `canon` of the
statement with its top-level `signature` removed and every other member retained, the nested
`checkpoint` included. That is §1.2's rule: appending anything anywhere invalidates the
signature. The prefix differs from the receipt's and the seal's, so none can be replayed as
another. Every value is an ASCII string, an integer below 2⁵³ or `null`, so the canonical form is
also the RFC 8785 form. A reader without the gateway's `canon`, such as the runtime, can build it.

**The chain, per trail.**

- Along a trail's chain, the sequences of its `checkpoint` statements strictly increase. The
  witness's **head** for a trail is its last statement. The latest witnessed checkpoint is its
  last `checkpoint` statement.
- A `conflict` statement records that a submitter allowed for the trail offered another
  `recordDigest` for a sequence at which the witness holds a `checkpoint` statement. There is at
  most one per sequence: the first offer is the evidence, and later ones are answered with it. It
  joins the chain, so the witness cannot drop it unnoticed.
- Each statement names the previous one's signature, so the head commits to every statement
  before it for that trail. A witness that drops, reorders or alters a statement it served breaks
  the chain for anyone who holds a later one.

**Why the latest alone is not enough.** The witness cannot check that a checkpoint extends the
last one (determination 1). Take an operator who rewrites a trail from sequence `k` on, where an
earlier statement's sequence is `k` or above, and then submits a checkpoint above the witness's
head: the witness signs it. What catches the rewrite is the verifier holding the trail to that
**earlier** statement, which no longer matches. A verifier given only the latest statement holds
the rewritten trail to the rewritten head, and it matches.
So a verifier takes the trail's whole chain, and the head, fetched from the witness, tells it the
chain is whole. ADR-0047 §3 and issue #199 speak of serving "the latest one it holds". This is why
the latest is served as the anchor of the chain, not in place of it.

**What a statement establishes, and what it does not.**

| | Establishes | Does not establish |
|---|---|---|
| A `checkpoint` statement, verified under a key the verifier trusts | the key's holder was given this checkpoint and signed it as statement `index` of its chain for the trail, and states that it did so at `witnessedAt` | that the checkpoint names a real record; that it extends the one before; that `witnessedAt` is true; anything against a witness that colludes, or whose key is stolen |
| The same, held against a trail copy | lines 1 to its sequence are the lines that existed when the witness signed, if the witness is independent of the operator | anything after that sequence; that this is the project's only trail; that the records are true, or that every decision was recorded |
| A chain verified up to the head fetched from the witness | the verifier holds every statement of the chain that head ends: none was dropped, reordered or altered | that the witness will serve them tomorrow; that it signed no second chain for the trail, for another audience |
| A `conflict` statement | a submitter the witness allowed for the trail offered another record for a sequence the witness held | which of the two is the trail's; who that submitter was, beyond the witness's own binding |

### 4. Endpoints and storage

**Configuration.** A `witness` member of the engine configuration, at the next `engineVersion`.
That is `"6"` unless ADR-0007's `services` takes it first: the engine reads `"1"` to `"5"`
(`docs/design/engine-config.md`). Its members:

- `log`, an absolute path: the witness log (below);
- `submitters`, optional: the `{issuer, subject}` pairs allowed to submit; absent, any subject the
  configured issuer's tokens name;
- `trailsPerSubmitter`, from 1 to 100000, default 100, and `submissionsPerMinute`, from 1 to 6000,
  default 60, on the precedent of the MCP server's bounds.

The engine refuses to start with `witness` and without `identity`, since submission is
authenticated. With `witness`, `platforms` may be empty, so a party can run a witness and nothing
else; today an engine with no platform is refused (`go/engine.go:1118`). The witness runs in the
signer, which holds the seed and stays standard-library-only (ADR-0001); its endpoints are the
signer's.

**`POST /witness/checkpoints`: submit.**

- **Who.** A bearer token from the configured issuer (`identity`), and a subject in `submitters`
  when that is given. The first accepted submission for a trail **binds the trail** to its issuer
  and subject. A later submission for it from anyone else is `403`. The binding is the witness's
  own record and is never in a statement. Rebinding is an act of the witness's operator, not an
  endpoint.
- **The body.** `application/jsonl`: one or more checkpoint lines as `audit checkpoint --since`
  prints them, each canonical and ended by a newline, all of one trail, with sequences strictly
  increasing. At most 1 MiB, the engine's request bound (`maxRequestBody`, `go/serve.go:515`),
  which is about 6,000 lines. Each line at most 4096 bytes, the runtime's `MaxCheckpointBytes`.
  These are the bytes Desk ADR-0010 §2 sends to an HTTPS holder.
- **Only the last line is signed.** A checkpoint covers every record before it through the chain,
  so the earlier lines add no coverage. They are compared with what the witness holds, for
  conflicts, and are otherwise discarded.
- **The answers.** Submissions for one trail are taken one at a time.
  - **A line conflicts**: the witness holds a `checkpoint` statement at its sequence with another
    `recordDigest`. `409`, `{"error", "reason": "conflict", "statements": [<held>, <conflict>]}`,
    each statement given as a JSON string holding its exact line. The conflict statement is
    appended if it is the first for that sequence. Nothing else is appended.
  - **The last line is held**: same trail, sequence and digest as a `checkpoint` statement.
    `200`, with that statement. Nothing is appended. This is the idempotent retry: the same
    checkpoint twice gives the same statement.
  - **The last line is below the latest checkpoint statement's sequence, and not held.** `409`,
    `reason: "below-head"`, with the head statement. Nothing is appended. A deliverer whose cursor
    fell behind learns where the witness is.
  - **Otherwise** the witness signs a `checkpoint` statement at the next index, appends it to its
    log and syncs the log, and only then answers `200` with it, `application/jsonl`. A statement it
    could not make durable is never returned: `503`, nothing signed.
  - `400` for a body out of shape, `401` without a valid token, `413` over the bound, and `429`
    over `submissionsPerMinute`, or for a new trail over `trailsPerSubmitter`.

**`GET /witness/trails/{trail}/head`.** The trail's last statement, `application/jsonl`, exactly
as logged. `404` for a trail the witness holds nothing for. `{trail}` must be 32 lowercase hex, or
`400`.

**`GET /witness/trails/{trail}/statements?from=<index>&limit=<n>`.** The statements from `index`
(default 0), at most `n` (1 to 1000, default 1000), in index order, exactly as logged. A verifier
asks again from the next index until it reaches the head's.

**Both reads are open,** like `/registry` and `/publickey`: a verifier holds no token. Knowing a
trail's identity is what lets one read it, and no endpoint lists trails. The reference bounds no
read. A party that exposes a witness puts it behind the TLS-terminating front `engine-config.md`
already requires for any other host, and bounds reads there.

**What the witness stores.**

- **The witness log**: one canonical statement per line, newline-ended, append-only, never
  rewritten. It follows the registry's discipline (§3, §4.1): a last line found unterminated is
  ended before the next is written, and a log missing after start is a log the witness cannot
  read, refused rather than taken for an empty one. At start the witness rebuilds each trail's
  head from it.
- **The bindings**: one line per trail, `{trail, issuer, subject}`, beside the log. Never served.
- **Retention**: every statement, for as long as the witness serves the trail. Never pruned in
  part, since a gap breaks the chain. A trail removed whole is answered `410` (question 4).

**How the witness is itself checked.** `gateway witness verify --log <file>`, with the witness's
public key, over a copy of its log. It checks every signature, each trail's index contiguity and
links, that checkpoint sequences increase, and that each conflict names a sequence an earlier
statement holds. The verdict is in its JSON, as for `gateway verify` (§5a.2). That shows a log is
internally consistent, not that it is the log the witness served. A statement someone kept, which
the log lacks or contradicts, shows that.

### 5. Trust and privacy

**What the witness learns,** per trail: its identity; the sequences submitted, so how many lines
the trail had; the record digests at those sequences; when; and the authenticated submitter. Not a
record's contents, pack, inputs or outcome. A record digest covers a random `run` id, so it is not
trivially guessable, and it is not confidential either (ADR-0047, "Privacy"). Anyone who knows a
trail's identity learns the same from the reads, except the submitter.

**What it establishes against an operator,** given a trail copy and the trail's whole chain: no
record up to the latest statement's sequence was edited, removed, inserted or moved since the
witness signed the first statement covering it; a copy cut short below that sequence fails; and a
rewrite from any sequence at or below an earlier statement's fails at that statement, even when a
later checkpoint of the rewrite was signed.

**What it does not establish:**

- **Anything against a witness that colludes, or whose key is stolen.** It can sign any checkpoint
  at any stated time, and a second chain for a trail for another audience. A statement someone kept
  that the served chain lacks exposes the second chain to whoever holds both. One witness gives no
  non-collusion (RFC 0012, clause 7).
- **Anything about an operator who never submits.** Its records stay unwitnessed, and the verifier
  sees that. `--require-checkpoint-through` makes the gap a failure.
- **Anything about records after the last statement,** or about a trail rewritten before its first
  submission.
- **That the trail is the project's only one.** An operator can start another trail. The verifier
  must hold the trail identities it expects (ADR-0047, "What a verifier must hold independently").
- **That the witness keeps what it signed.** A witness that loses or withholds its latest
  statements serves an older head. For a trail it holds nothing for, it answers `404`, which reads
  like a trail never submitted. This cannot be prevented, only shown: the submitter receives every
  statement signed for it, and one with a higher index than the head the witness serves proves the
  witness forgot (RFC 0012, clauses 2 and 5).
- **When anything happened.** `witnessedAt` is the witness's clock: an upper bound on when it held
  the checkpoint, as it states. Like a stamp's time, but without the policy, accuracy and
  certificate chain an RFC 3161 token carries. It says nothing of when a record was made. A
  record's `at` stays the operator's word.

**Rollback, as the verifier sees it,** given the chain fetched from the witness and a trail copy:

- a copy shorter than the latest statement's sequence: `checkpoint-beyond-trail`;
- another record at a statement's sequence: `checkpoint-record-mismatch`;
- a copy of another trail: `checkpoint-trail-mismatch`;
- a copy that matches every statement: the records up to the latest are the ones the witness saw.

Which statements to supply is the reader's policy (RFC 0012, clause 6, recency). All of them up to
the head refuses an older copy presented as current. The statements up to an earlier index audit
an older copy on purpose.

**The clock.** A statement's time is never earlier than the previous one's for the trail: the
witness takes the later of its clock and that time. A verifier compares nothing to a clock.

### 6. How the runtime's verifier reads it

`jpack audit verify` gains:

- `--witness <file>`, repeatable: statements, one per line, as the witness serves them. A file of
  up to 16 MiB, the bound of a held file (`MaxHeldBytes`), which is about 27,500 statements;
- `--witness-key <file>`, repeatable: a witness's public key, obtained out of band. `/publickey`
  is a convenience only (§5);
- `--require-countersigned-through <sequence>`.

**It checks each statement, offline, and fails closed.**

- A statement of another `witnessVersion` or `kind`, or out of shape: `witness-malformed`.
- A statement that verifies under no key supplied, or whose `keyId` is not that of the key it
  verifies under: `witness-signature-invalid`. It is never skipped, whatever key it names
  (RFC 0012, clause 1).
- A gap in `index` from the lowest supplied, a `prevSignature` that is not the previous
  statement's signature, a checkpoint sequence that does not increase, or a conflict naming no
  sequence held before it: `witness-chain-broken`.

Every verified `checkpoint` statement's checkpoint then joins the held checkpoints, and is checked
against the trail exactly as `--expect`'s are.

**What `witnessed` then means.** As now: the chained records up to the highest held checkpoint that
matched with no failed check at or before it, whether a holder's file or a witness statement
supplied it. `--require-checkpoint-through` keeps its meaning. A new coverage member says how far a
witness's signature reaches:

- `countersigned`: `not-checked` without `--witness-key`; `through` the highest sequence a
  verified `checkpoint` statement covers, with no failed check at or before it; or `none`.
- `--require-countersigned-through` fails (`countersigned-coverage-missing`, exit 1) while the
  records up to that sequence are not all countersigned. It is the "whose evidence" floor of
  RFC 0012 clause 3, where `--require-checkpoint-through` is the "how much".
- A report section, `witness`: the statements read and verified, the keys supplied, the lowest and
  highest index, the latest checkpoint statement's sequence and `witnessedAt`, and the sequence of
  each conflict statement. A conflict fails nothing by itself, and is reported with a fixed
  sentence.

The fixed sentences, proposed:

- Establishes: "Lines 1 to N are the lines that existed when a witness under a key supplied signed
  its statement for checkpoint N, which it states it did at T, if that witness is independent of
  the trail's operator."
- Does not establish: "Lines after N are covered by no statement of a witness under a key
  supplied."
- Does not establish: "That the witness holds no later statement for this trail than those
  supplied: only its head, fetched from it, shows how far it holds, and a witness that lost or
  withholds statements serves an older one."
- Does not establish: "Anything against a witness that is not independent of the operator: one
  that colludes can sign what it is asked, at any time it states, and a second history for another
  audience; a key supplied is trusted because the verifier chose it."
- Does not establish: "When any record was made: the time a witness states is its own clock's, for
  when it held the checkpoint."

The runtime fetches nothing. The reader fetches the chain (Desk, a script, `curl`), as it brings
its own revocation lists for stamps.

### 7. Delivery, after acceptance

One pull request each, in this order.

| # | Repository | What | Needs |
|---|---|---|---|
| 1 | gateway | `SPEC.md` gains the witness statement (format, coverage, chain, what it establishes) and §6 rows for the three endpoints; `corpus/witness/` vectors, read by `gateway conform` and verify-ts | this record accepted; a cross-vendor review (public-surface, documented-claim, conformance, security) |
| 2 | gateway | The witness log and statement signing in the core module, and `gateway witness verify` | 1 |
| 3 | gateway | The engine's `witness` member at the next `engineVersion`, the three endpoints, the submitter binding and bounds, and `SECURITY.md`'s scope line for them | 2; questions 2, 3, 4 and 6 |
| 4 | runtime | `audit verify --witness`, `--witness-key` and `--require-countersigned-through`, the `countersigned` coverage, its findings and sentences, and a guide section | 1 (the format and vectors), not the service; question 8 |
| 5 | desk | A new Desk ADR for a witness as a holder: ADR-0010 §2's HTTPS channel to the witness's form, the cursor moved by a statement that verifies under the pinned key, the statements kept, and the panel passing `--witness` | 3 and 4 released; question 5 |
| 6 | desk | Its implementation, as ADR-0010's delivery PR 10 | 5; Desk's pins moved |

Runner needs nothing. Its chain of runs is handed over through Desk (Desk ADR-0010 §5), and the
runtime prints that chain's checkpoints in the same form.

### Consequences

- Good, because a verifier can ask a party other than the operator how far a trail was witnessed,
  and hold an older or rewritten copy to the answer. A stamp cannot tell it that a later stamp
  exists.
- Good, because the witness signs the checkpoint's exact bytes, and every receipt, seal and
  registry verifies as before. A released verifier never reads a statement.
- Good, because a statement is evidence in any hands, the operator's included, so a witness that
  forgets can be shown to have.
- Good, because the runtime reads a statement with one Ed25519 check over a canonical form of
  strings and integers, as it already builds one for record signatures
  (`internal/audit/sign.go:246`).
- Bad, because the witness is the first surface meant to be reached from other hosts by other
  parties. Multi-tenancy, rate bounds and a TLS front become part of running one, where
  `SECURITY.md` lists them as out of scope for the reference.
- Bad, because the witness learns each trail's identity, its length at each submission and its
  record digests, and anyone who learns a trail's identity can read them.
- Bad, because a verifier fetches a trail's whole chain, which grows by one statement, about 600
  bytes, per submission.
- Bad, because nothing here helps against a witness that colludes. One key is one party.
- Bad, because retention is the witness's promise. Nothing makes it checkable beyond the statements
  others kept.
- Bad, because a second signed format sits beside the receipt, with vectors of its own.
- Revisit when a reader wants statements from two witnesses; when the record digest must be hidden
  from the witness (a salt, ADR-0047 "Privacy"); when the gateway's own registry is to be
  witnessed (RFC 0010 §4; RFC 0012, unresolved question 4); or when the specification takes up the
  witness contract.

### How this sits with earlier records

- **Runtime ADR-0047 §3.** This is its design. It refines "serves the latest one it holds" to the
  chain whose head is the latest (determination 3).
- **[ADR-0012](0012-hold-a-write-to-a-signed-record.md).** It names "when the gateway witnesses a
  trail" as a time to revisit. Nothing in `requireSignedRecord` changes here.
- **[ADR-0011](0011-hold-a-write-to-its-decision.md) and ADR-0012** gave `engineVersion` 4 and
  5, and [ADR-0007](0007-the-engine-serves-the-adapters-it-ships.md)'s `services` takes the next
  one when it is built. `witness` takes the next one free when it is built.
- **[ADR-0003](0003-a-fifth-process-speaks-mcp.md).** Its witness question, a plugin observing
  calls the engine did not make, is untouched.
- **Desk ADR-0010.** Its §2 HTTPS channel moves the cursor on any 2xx. For a witness, the new Desk
  ADR moves it on a verified statement, and states what a witness statement establishes in the
  manner of ADR-0010 §7's table.
- **RFC 0012 (draft).** Its scope note places a witness record format, for a currency registry, in
  the runtime, and proposes no change to the gateway. This record is for the runtime's decision
  trail, under ADR-0047 §3, which places the witness in a gateway. It answers the RFC's candidate
  clauses as follows.

| Clause | Here |
|---|---|
| Attribution | by a signature under a key the reader supplies; a statement that verifies under none fails, and is never skipped |
| Delivery | the verifier fetches from the witness; the per-trail chain makes an omission inside it visible; an absent trail reads like one never submitted |
| Enforcement | `--require-checkpoint-through` (how much) and `--require-countersigned-through` (whose) |
| Coverage | a statement constrains the lines up to its sequence, and nothing after |
| Retention | the witness's undertaking (question 4); not checkable beyond the statements others kept |
| Recency | the reader's choice of which statements to supply |
| Non-collusion | none, with one witness; stated |

## Questions for the maintainer

1. **A statement of its own, or receipt version 4?** A third kind inside version 3 is not on
   offer (F1).
   **Recommendation:** a statement of its own (F3), with its own version member and prefix, beside
   the seal. A receipt says a source returned bytes or a target answered; a witness signs what a
   client supplies.
2. **Who may submit?**
   **Recommendation:** a bearer token from the witness's configured issuer, with an optional
   allowlist of subjects; each trail bound to its first submitter; rebinding an act of the
   witness's operator. Not open submission: anyone who learns a trail's identity could submit
   first and lock its operator out.
3. **Who may read?**
   **Recommendation:** anyone who names the trail, as `/registry` is open, with no listing of
   trails. The trail's identity is 128 random bits, known already to whoever holds the trail or one
   of its checkpoints. Reads behind a token would make every verifier a customer of the witness.
4. **What does the witness retain, and for how long?**
   **Recommendation:** every statement for as long as it serves the trail; never pruned in part;
   a trail removed whole only by the witness's operator, and answered `410`. A party running a
   witness publishes its retention period. The reference keeps everything.
5. **Are Desk's HTTPS hand-over and the witness one endpoint or two?**
   **Recommendation:** one wire form, two kinds of holder. Desk POSTs the same `application/jsonl`
   checkpoint lines to either. For a plain HTTPS holder a 2xx moves the cursor, as ADR-0010 says.
   For a witness, the cursor moves on a statement that verifies under the witness's pinned key and
   names the last line sent.
6. **Does the witness sign with the gateway's existing key?**
   **Recommendation:** yes, the existing seed, under the witness's own prefix, as the seal is. A
   party that wants the two roles apart runs a second gateway with its own seed. A second key in
   one signer is a custody path `SECURITY.md` does not describe.
7. **Does a submission sign only its last line, or every line?**
   **Recommendation:** only the last. It covers the others through the chain, and a chain grows by
   one statement per submission instead of one per record. The cost is that a conflict is caught
   at submission only at sequences the witness signed; the verifier still catches every rewrite at
   or below a signed one.
8. **How does the runtime report it?**
   **Recommendation:** a verified statement's checkpoint joins the held checkpoints, so
   `witnessed` and `--require-checkpoint-through` keep their meaning, and a separate
   `countersigned` coverage and `--require-countersigned-through` say how far a witness's signature
   reaches.

## More information

- `SPEC.md` §1.1, §1.2, §1.2a, §1.4, §3, §4.1, §5, §5a and §6;
  `corpus/v3/stores/v3-malformed-kind.json`; [engine-config.md](../design/engine-config.md);
  [SECURITY.md](../../SECURITY.md); `go/serve.go` (`maxRequestBody`, the open endpoints) and
  `go/engine.go` (an engine with no platform), at `9a95e7f`.
- The runtime at `v0.26.0`: ADR-0047, sections 1, 2a, 3 and "Privacy";
  `docs/building-with-packs.md`, "Checking a trail, and handing over a checkpoint", "Handing every
  new checkpoint to a holder" and "Stamping checkpoints with a time-stamping authority";
  `internal/audit/checkpoint.go`, `internal/audit/verify.go`, `internal/audit/stamp.go`,
  `internal/audit/sign.go` and `internal/result/audit.go`.
- Desk ADR-0010, sections 2, 5 and 7, and "Delivery, after acceptance".
- The specification repository: RFC 0010 §4 and "Compatibility"; RFC 0012, its candidate clauses
  and unresolved question 4. Both are drafts.
- Issue #199.
- Material-decision categories, when accepted: public-surface, documented-claim, conformance,
  security.
