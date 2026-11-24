---
status: accepted (with conditions)
date: 2026-11-23
deciders: maintainer
---

# A refused request charged to a scope becomes a signed entry in that scope's own refusal journal, written after the answer; a third sink delivery version carries action receipts, seals and refusal entries

> **0059 is a placeholder, assigned at merge.** Its engine version is 48 (`refusalJournalVersion`).
>
> **Amendment, 2026-11-23 (the maintainer).** A `refusal` body gains two optional members inside its
> signed body (section 3): `tool`, once the route has resolved the request's tool to one its
> source's configuration names, and `descriptorDigest`, that tool's digest in the operation's
> pinned snapshot, only beside `tool`. A refusal before resolution names neither, so a caller's
> own unconfigured text never reaches an entry in the clear. Both readers refuse an entry naming
> `descriptorDigest` without `tool`; the corpus holds `v3-journal-refusal-tool-holds` and
> `v3-journal-refusal-digest-without-tool`. The record version, the name and the commitment are
> unchanged.
>
> **Summary.**
>
> - **Chosen:** one refusal journal for each scope, on ADR-0056's machinery. Its name is
>   `refusal-` and 24 letters derived from the scope's key, so it fits the name rule of
>   `gateway.journal_records` and needs no migration. On the filesystem kind it is
>   `<root>/journals/<name>.jsonl`; on the PostgreSQL kind, the rows of `gateway.journal_records`
>   under that name. Its entries use ADR-0056's envelope, prefix, line bound, signer and load rule
>   unchanged. It has two body kinds: `refusal` and `tally`.
> - **Journaled:** a refusal of an authenticated request is journaled only when ADR-0057 had already
>   charged the request to a scope and taken that scope's hold, and only in that scope's journal. Refusals before the charge are
>   not journaled. Unauthenticated refusals stay counted (`unauthenticatedRefusals`). A limit
>   refusal, and an entry that is dropped, are counted in the scope's `tally`, at most one a minute.
> - **The entry:** time, reason code, caller, the delegation member, scope, and a commitment to the
>   request bytes. The commitment's salt comes from a per-scope key that the store holds outside the
>   journal. No export carries that key, and it never reaches the sink. A journal reader cannot test
>   a guess against the commitment. The operator can open it.
> - **Never on the answer path:** the answer is written first, byte for byte as today. The entry is
>   then handed to the scope's own bounded queue, and nothing waits for it. One gateway-wide writer
>   signs, appends and forwards the entries off every answer path, with at most one signing in flight.
>   A full queue, a full journal or a failed write drops the record and counts it. Nothing blocks,
>   delays or changes an answer.
> - **Bounded per scope:** only requests ADR-0057 charged are journaled, so a scope's entries are
>   bounded by its `requestsPerMinute`, `burst` and `inFlight`, plus one tally a minute. The member
>   is refused at load unless every scope has a request rate. Each scope's journal also has a byte
>   cap, `maxBytesPerScope`, 64 MiB when left out.
> - **Delivery version `"3"`:** `receiptSink.deliveryVersion: "3"` sends one envelope,
>   `{deliveryVersion, kind, digest, …}`, for each acquisition receipt, action receipt, seal and
>   refusal entry. Receipts and seals keep ADR-0049's acknowledgment before the answer, and an
>   `/act` receipt now has it too. A refusal entry is forwarded after its answer, and its delivery
>   never holds an answer. Without the member, a sink receives exactly what it receives today.
> - **SPEC.md:** "the refusal is recorded nowhere" now holds for the caller's side alone. The
>   operator's journal records the refusal.

## Acceptance

The maintainer accepted this record with conditions. Open questions 1 to 8 are ruled as each one
recommends ("Open questions, as ruled", below). The conditions, and where each is folded in:

| Condition | What it rules | Where |
|---|---|---|
| Timing | the bounded residual is accepted, with no cover traffic. Under a key service one signing can take up to ADR-0050's 5 seconds, and a quota shared with the journal can make signings fail, not only slow | section 10, "What remains"; the release notes |
| Compatibility | a release that does not know refusal journals refuses them by name. A separate pull request on `main` makes `gateway verify` and the export reader refuse journal names they do not know | section 12 |
| C1 | delegation step 0's refusals, made in `present` inside authentication, come before the charge and are not journaled | section 4 |
| C2 | `receipt-version` comes before step 8a, so it is journaled for a caller of one scope alone, as `dry-run` is | section 4 |
| C3 | an entry is made only for a scope whose hold the charge actually took, not for every scope it was called with | section 4 |
| C4 | delivery `"3"`'s acknowledgment digest has a domain prefix of its own, and an action receipt travels under a member of its own | section 9 |
| C5 | on the PostgreSQL kind with several instances, which instance forwards which entries; the cursor moves by a monotone compare-and-set under the journal's lock | section 9 |
| C6 | one caller at its own rate can fill a journal, so room is kept for tallies after the refusal entries stop, and what happens at the cap is stated exactly | sections 5 and 11 |
| C7 | the advisory lock takes PostgreSQL's two-`int4` form with a class constant, apart from the gateway's one-`bigint` locks | section 7 |
| C8 | the role `gateway journal open` runs as, and `K_scope` kept where the run-time role cannot rewrite it | section 3 |
| C9 | deleting a key does not make every copy of the entries unopenable | section 8 |
| C10 | the answer is flushed explicitly before the hand-off | section 5 |
| C11 | a sink on `"3"` can decline refusal entries by a switch | section 9 |

## Context and problem statement

Gateway #539 asks for a new `deliveryVersion` that forwards action receipts and seals to the receipt
sink. Under ADR-0049 a sink is sent acquisition receipts (`deliveryVersion` `"1"`), and from engine
version 37 seals (`"2"`, `receiptSink.seals`). It is never sent `/act`'s receipts
(`go/receipt_sink.go:57`, `go/seal_sink.go:43`; SPEC.md §6a, "What is not forwarded"). The second
item in scope is a refusal journal. SPEC.md §6 says of `writeRequesters`, at `SPEC.md:3115`: "The
refusal is recorded nowhere, as no refusal of the action ladder is." The same holds for every other
route. An operator cannot tell which authenticated callers were refused, at which step, or how often.

ADR-0056 builds a reusable journal: signed, chained entries in the store. Its section 8 names the
refusal journal as its first expected reuse, and leaves this record to say how a serving gateway
writes one. ADR-0057 bounds each scope's requests and counts the unauthenticated refusals. Its
acceptance says a later refusal journal relies on that count, and its open question 7 leaves
per-scope refusal counts to this record.

The maintainer fixed these points, and this record does not reopen them:

1. Entries are signed and kept beside the sessions, never in a session chain. Each holds the time,
   the reason code, the caller's identity, the delegation member, the scope, and a commitment to the
   request. It never holds the request's content.
2. Only authenticated callers' refusals are journaled. Unauthenticated refusals are counted
   (ADR-0057's `unauthenticatedRefusals`), not journaled.
3. The journal is bounded per scope by ADR-0057's limits.
4. The caller's response is unchanged, byte for byte.
5. SPEC.md's "a refusal is recorded nowhere" changes for the operator side only.
6. One new sink delivery version carries action receipts, seals and refusal entries.
7. The journal is built on ADR-0056 where it fits. This record says where it does not.

## Decision drivers

1. **No cross-scope oracle.** A caller learns nothing of another scope's refusals, not even whether
   one happened. That holds for the journal, the sink, `/posture`, `/registry`, the limits, and
   timing it can observe, as far as section 10 establishes it. Section 10 also names what remains.
2. **Answers unchanged.** No answer's bytes, status, headers or latency depend on the journal: on its
   state, its failures or its existence.
3. **Bounded.** A scope's entries, its queue's memory and its journal's bytes all have a bound. A
   bound that is reached drops a record and counts it. It never blocks an answer.
4. **Fail closed at load.** A configuration whose journal could not be bounded is refused. A
   journal is never left unbounded without a word.
5. **No format change for what exists.** Receipts, seals, the registry, the operator journal's
   envelope and the corpus are unchanged. A sink not moved to `"3"` sees exactly today's bytes.
6. **Reuse ADR-0056:** its placement, envelope, signing and findings. Where this record departs from
   it, it says so and why.
7. **The operator can remove a scope** with its refusals, and the removal leaves a trace.

## Considered options

**Where the entries live.**

- **P1.** One journal, `refusal`, for every scope, with `scope` in each entry.
- **P2.** One journal for each scope, named from the scope's key.
- **P3.** A new table keyed by journal and scope. This needs a migration.

**Which refusals are journaled.**

- **J1.** Every refusal of an authenticated caller.
- **J2.** Every refusal of a request ADR-0057 had charged to a scope, in that scope's journal.
- **J3.** Only the refusals of `/act`'s ladder.

**The commitment's salt.**

- **S1.** A random salt for each entry, discarded.
- **S2.** A random salt for each entry, kept in the entry.
- **S3.** A salt derived from a per-scope key the store holds outside the journal, and a nonce held
  in the entry.
- **S4.** The same as S3, with one key for the whole store.

**When and how an entry is written.**

- **W1.** Synchronously, before the answer.
- **W2.** After the answer, through a non-blocking hand-off to a per-scope queue, by one writer off
  every answer path. Records are dropped and counted when a bound is reached.
- **W3.** An unsigned record written durably on the answer path, then signed later.
- **W4.** W2, with constant-rate cover: the writer signs and appends at a fixed rate whether or not
  any record is pending.

**The sink.**

- **V1.** Extend `"2"` to action receipts and refusal entries.
- **V2.** A new `"3"`: one envelope for every kind, each delivery naming its kind.
- **V3.** A second endpoint for refusal entries.

## Decision outcome

Chosen: **P2, J2, S3, W2 and V2.**

- **P2** keeps one scope's ordinals, chain, drops and removal free of every other scope. It also fits
  ADR-0056's table without a migration.
- **J2** is the only rule that ADR-0057's limits bound. It is also the only one that never writes a
  record into a scope the caller does not reach.
- **S3** gives a commitment that no reader of the journal or the sink can test a guess against, and
  that the operator can open. A key for each scope opens one scope alone, and deleting a scope's key
  leaves the store's own entries of that scope unopenable (section 8 says what it does not reach).
- **W2** is the only form under which no answer waits on, or changes with, the journal.
- **V2** leaves sinks on `"1"` and `"2"` untouched. Its digest member is named so that an older sink
  cannot acknowledge it by accident.

### Why not the others

- **P1.**
  - A shared chain's `ordinal` and `previous` count every scope's entries, so one scope's entries
    show how many refusals the others had between them. Any reader of one scope's entries would hold
    that count: a later projection by scope (#588) or an auditor of one scope.
  - `remove-scope` could not take one scope's entries out of a shared chain without breaking it,
    because the run-time role cannot rewrite rows and nothing can re-sign the chain.
  - Under several instances, every scope's writers would serialize on one chain's lock.
- **P3.** It is not needed: the name rule `^[a-z-]{1,32}$` admits a derived name (section 1), so
  ADR-0056 amendment A's table serves as it is.
- **J1.**
  - A refusal that comes before the charge has no established scope (ADR-0057 decision 2: an
    unknown source, a source of an unreached scope, a malformed body from a caller of several
    scopes).
  - Writing it under the scope the request named would let a caller write entries into, and spend
    the bound of, a scope it does not reach.
  - Such refusals are bounded by no scope's limits.
- **J3.** It leaves out `/acquire`'s and `/seal`'s refusals and the delegation refusals, which an
  operator needs as much.
- **S1.** No one can ever open the commitment, so it binds nothing anyone can check.
- **S2.** A salt kept beside its commitment makes the commitment an equality oracle to every reader
  of the journal, an export or the sink. A request with few likely values, such as a small
  `arguments` object or a session label, is then its content to anyone who can guess it.
- **S4.**
  - A key handed to one scope's auditor, or kept with a later projection of one scope, would open
    every scope's commitments.
  - A removed scope's commitments would stay openable.
- **W1.** The maintainer's point 4 excludes it. Every answer would carry a signing and an append,
  and a refusal's latency would show the journal's state.
- **W3.**
  - A durable write on the answer path is a wait on the store's disk or database, which every
    scope's answers share.
  - It needs an unsigned record format of its own, beside the signed one.
- **W4.**
  - It is the one form that would remove the shared-resource residual of section 10. The signer, the
    disk and the sink would see the same load whatever the refusals.
  - The cost is a signing, an append and a delivery at every tick for every journal, forever: at one
    tick a second and 20 scopes, about 1.7 million signatures and deliveries a day.
  - It also caps each scope's journal at the tick rate.
  - It is open question 1.
- **V1.** A sink on `"2"` would begin receiving kinds it does not read, and the maintainer fixed that
  sinks on the current version are unaffected.
- **V3.** The issue asks for one sink, and a second endpoint would be a second trust and
  availability dependency.

### 1. Where each journal sits, and its name

- **The name.** A scope's refusal journal is named `refusal-` followed by 24 letters. Take the first
  12 bytes of SHA-256 over `"judgment-pack-gateway/refusal-journal-name/1:"` and the scope's key, and
  write each half-byte as a letter from `a` (0) to `p` (15).
  - The scope's key is the scope identifier, compared byte for byte, or `"unscoped"` for the sources
    of none (ADR-0057's key).
  - The name is 32 characters. It passes `isJournalName` (`go/operator_journal.go:58-68` on
    `operator-command-journal`) and migration 0010's CHECK.
  - The start refuses a configuration where two configured scopes give one name, naming neither
    scope: `refusalJournal: two scopes give one journal name`. With 96 bits this does not happen in
    practice, but it is checked, not assumed.
  - `gateway journal name --scope <key>` prints the name, so an operator can pass it to
    `--require-journal`.
- **The places**, as ADR-0056 section 1 sets them:

  | Kind | Place | Written by |
  |---|---|---|
  | Filesystem | `<root>/journals/<name>.jsonl`, `0600` in `0700`, an append and then a sync | the serving gateway's writer (section 5), under the journal's own lock |
  | PostgreSQL | the rows of `gateway.journal_records` under `<name>` | each serving instance's writer, in one transaction per entry under a lock on that journal (section 7) |
  | Export | `store/journals/<name>.jsonl` | `gateway export`. `gateway export --scope` writes no journal (ADR-0056, acceptance 5) |

- **Where this departs from ADR-0056 section 1.**
  - **Not under the registry's hold.** The operator journal appends under the registry's hold because
    its entries bind registry bytes (`registryFrom`, `seals`). A refusal entry binds nothing in the
    store. Taking the registry's hold would put the journal on the path of every `/seal` of every
    scope, so each refusal journal takes a lock of its own: a `flock` on its file on the filesystem
    kind, and a transaction-scoped advisory lock keyed by its name on the PostgreSQL kind.
  - **No staged file.** There is no store change for an entry to be atomic with, so no
    `<name>.pending` exists.
  - **A torn last piece.** At start, the writer truncates its own journal's last piece if no `0x0A`
    ends it, before its first append. Nothing else writes the file, and ADR-0056 section 6 already
    says such a piece is no entry. Appending after it would make a forged line.

### 2. The envelope, the signature domain and the canonical bytes

- **Unchanged from ADR-0056 section 2.** The envelope is `journal` (the name above),
  `journalVersion: "1"`, `ordinal`, `previous`, `at`, `keyId`, `alg` (optional), `body` and
  `signature`.
- **The signature** is made by the configured signer, the key in force. It is Ed25519, or ES256
  where `alg` is present, over `"judgment-pack-gateway/journal-entry/1:"` followed by `canon`
  (SPEC.md §1.1) of the entry without `signature`.
- **The line** is that canonical form, at most 4096 bytes, with its `0x0A` not counted.
- **No new prefix.** `journal` and `body.kind` are inside the signed bytes, so a refusal entry is
  never read as an operator entry, and the reverse. The prefix is no receipt's, seal's or record's,
  so ADR-0053 decision 2's table gains nothing beyond ADR-0056's row.
- **`at`** is the writer's clock when it signs, as ADR-0056 defines it. The refusal's own time is
  `answeredAt` in the body. The difference between the two is the writer's lag, which only the
  operator reads (section 10).

### 3. The bodies

**`refusal`**, one for each journaled refusal. It has exactly these members:

| Member | Form | Statement |
|---|---|---|
| `kind` | `"refusal"` | |
| `scope` | a scope identifier, or `"unscoped"` | the scope the request was charged to (ADR-0057 decision 2). Its name by section 1 is the journal's |
| `route` | `"/acquire"`, `"/act"` or `"/seal"` | |
| `reason` | a code from section 4's closed list for the route | the step that refused |
| `refusal` | optional: a refusal code of SPEC.md §11.5 | present exactly where `reason` is `delegation` or `grant` |
| `outOfScope` | optional: one of §11.5 step 11's reasons | present exactly where `refusal` is `out-of-scope` |
| `tool` | optional: a non-empty string | the tool the route resolved, present exactly where the refusal came after the route held the request's tool to one its source's configuration names: on `/act`, once step 9 holds it to the write binding's; on `/acquire`, once a delegated call's tool is one the source names (amendment of 2026-11-23) |
| `descriptorDigest` | optional: a digest (§1.2a) | that tool's descriptor digest in the operation's pinned snapshot, taken from the source's versions and from nowhere else; present only beside `tool`, and only where the operation pins one. An entry naming it without `tool` is not of its form (amendment of 2026-11-23) |
| `status` | an integer from 400 to 499 | the answer's status |
| `answeredAt` | `YYYY-MM-DDThh:mm:ss.sssZ` | the gateway's clock when the answer was written |
| `caller` | `{issuer, subject, tokenDigest}`, of §1.2a's form | the identity the request was authenticated as. Under a delegation it is the chain's `sub`, with the credential's digest, as §11.7 sets it on a receipt |
| `delegation` | optional: §11.7's member without `admittedAt` | present exactly where the request was presented under a delegation credential whose chain held §11.4's steps 0 to 7. A chain that did not hold names no `delegation`, since nothing in it was verified |
| `nonce` | 64 lowercase hexadecimal characters | 32 bytes drawn at random for the entry |
| `request` | a digest (§1.2a) | the commitment below |

**The commitment.**

```
salt    = HMAC-SHA-256(K_scope, "judgment-pack-gateway/refusal-salt/1:" || nonce bytes)
request = "sha256:" + hex(SHA-256(salt || "refusal-request:" || route || 0x0A || body bytes))
```

- **The value committed to** is the route and the request body bytes the gateway had read when it
  refused. That is no bytes where it had read none, and never more than the route's body cap. It is
  raw bytes, not `canon`, because a refused body may not parse. It follows §1.2a's form,
  `salt || label || value`, with a label of its own.
- **`K_scope`** is the scope's commitment key: 32 random bytes, drawn when the gateway starts for the
  scope (as built, 2026-11-24; the decision first said when the journal's first entry is written).
  - **Filesystem kind:** `<root>/journals/<name>.key`, `0600`, made once and never overwritten
    (as built, 2026-11-24: staged, synced and linked into place; see "As built").
  - **PostgreSQL kind:** a row of `gateway.secrets`, named `refusal-key.` and the lowercase
    hexadecimal SHA-256 of the journal's name, made by the same create-once put before the journal's
    first entry is inserted. Two instances that race make one key: the second put is refused, and
    that instance reads the key the first one made.
  - **Who can rewrite it (condition C8).** The run-time role holds SELECT, INSERT, UPDATE and DELETE
    on `gateway.documents` (`go/store_pg/grants.sql`), so a key kept there, as this record first had
    it, could be replaced by the serving login. It is kept in `gateway.secrets` instead, on which that
    role holds SELECT and INSERT alone: it can make the key once and read it, and can neither replace
    nor remove it. This adds no migration and no grant. The owner role removes it, in
    `store remove-scope` (section 8). On the filesystem kind the serving gateway's user owns `<root>`
    and can rewrite the key file as it can rewrite any file of the store, so there the key is trusted
    as the store's payloads are (SECURITY.md).
  - **What a rewritten key can do.** A key that was replaced or lost makes `open` answer `no match`
    for the journal's earlier entries. It cannot make `open` answer `match` for bytes that are not
    the request's, which would take a second preimage of SHA-256. So `match` proves the bytes, and
    `no match` from a store whose key could have been rewritten proves only that this key does not
    open the entry.
  - **Where it is never:** it is never in an entry or an export, never sent to the sink, never
    written on stderr, and never read by a verifier.
- **No equality between entries.** Each entry has its own nonce, so two refused requests with
  identical bytes get unrelated commitments, even under one key.
- **A missing key.** A writer that finds a journal holding entries but no key draws no new one: a
  new key would leave the old entries unopenable without saying so. It counts each record as
  `write-failed`, and names the journal on stderr once.
- **Opening.** `gateway journal open --journal <name> --ordinal <n> --route <route> --body <file>`,
  run by the operator against the store, answers `match` or `no match`.
  - `--reveal-salt` prints that one entry's salt, so an auditor can check that one commitment and no
    other, as with a receipt's salt.
  - The command reads `K_scope` and writes nothing.
  - **The role it runs as (condition C8).** It opens the store of the configuration it is given
    (`--config`). On the PostgreSQL kind that is the configuration's login, the run-time role: it
    reads `gateway.journal_records` and `gateway.secrets`, which that role may SELECT, takes no lock
    and writes nothing. On the filesystem kind it runs as the user that owns `<root>`.

**`tally`**: at most one each minute for each journal, from each instance, written only when one of
its counts is not zero. It has exactly these members:

| Member | Form | Statement |
|---|---|---|
| `kind` | `"tally"` | |
| `scope` | as above | |
| `from`, `to` | `YYYY-MM-DDThh:mm:ssZ` | the span the counts cover, since this writer's previous tally or its start |
| `limit` | an object of non-negative integers, its members among `scope-rate`, `scope-in-flight`, `caller-rate`, `caller-in-flight` and `callers` | ADR-0057 limit refusals of this scope, by `limit`. They are counted and never journaled one by one. `gateway-in-flight` is not among them: it comes before the token and is an unauthenticated refusal |
| `dropped` | an object of non-negative integers, its members among `queue-full`, `write-failed` and `journal-full` | this scope's records that were not written, by cause (section 5) |
| `full` | optional: `true` | the journal has reached its byte cap, and this is its last entry |

An object holds only its counts that are not zero. A `tally` whose counts are all zero is not
written.

### 4. Which refusals are journaled

**The rule.** A refusal is journaled when all three of these hold:

- the request was authenticated;
- ADR-0057 had charged it to a scope, at the step its decision 2 table names, before the refusal,
  and the charge took a hold of that scope. A charge passes over a scope the limiter holds no state
  for (`charge`, `go/limits.go`), and no entry is made for a scope it passed over (condition C3):
  the journal follows the holds the request took, never the scopes it named;
- the refusal is one this section lists.

It is journaled once, in that scope's journal, and nowhere else. A charge needs `limits` (section 6).

**Journaled**, each code from a closed list:

| Route | `reason` codes |
|---|---|
| `/acquire` | `session` (not a flat token, sealed, held by another instance, held by the store, the registry unreadable); `source`; `scope`; `trail`; `body` (malformed, or past the bound, after the charge); `publisher-policy`; `grant`; `delegation` |
| `/act` | its `refusedAt`, for every step after step 3a or step 8a: `session`, `platform`, `tool`, `write-requesters`, `arguments`, `action-key` (`action-key-closed` among them), `decision`, `cites`, `approvals`, `record`, `consistency`, `policy-bind`, `policy-signed`, `policy-packs`, `policy-reviewed`, `policy-outcome`, `policy-handoff`, `receipt-version`, `dry-run` and `scope-identifier` (step 8), these three for a caller of one scope, `delegation`, `grant` |
| `/seal` | `session` (no such session, sealed, held by another instance, held by the store); `scope`; `body` |

- **The build holds the list.** It holds every refusal answered after the charge to exactly one code,
  with a test that walks each route's refusals. If a refusal fits no code, the build stops and this
  record is amended. There is no catch-all code.
- **Delegation refusals.** SPEC.md §11.5's steps 1 to 12, and the grant's refusals (§10, rule 3), are
  `delegation` or `grant`, with `refusal` and, for `out-of-scope`, `outOfScope`. A delegated request
  reaches `"unscoped"` alone, so it is charged right after authentication, and each of these comes
  after the charge.
  - Step 0 does not (condition C1). The credential's presentation is held in `present`
    (`go/delegation_credential.go`), inside `authenticateCall` (`go/serve.go`), before
    `chargeRequest` is reached, so its refusals are in the table below.
  - A chain sent in the body beside a credential it is not bound to (`presented`, `go/serve.go`) is
    refused after the charge. It is journaled as `delegation` with `refusal` `credential-mismatch`,
    and, being answered `401`, it is also in `unauthenticatedRefusals`.
- **`receipt-version`, `dry-run` and step 8's `scope-identifier`** are journaled for a caller of one
  scope, because it was charged at step 3a. They are not journaled for a caller of several, because
  step 8a has not yet charged it. `receipt-version` is held in `actKeyed` (`go/act.go`) before the
  scope identifier is read, and so before step 8a (condition C2). The rule follows the charge, not
  the reason, and that is what keeps it inside the limits.

**Not journaled, with the reason for each:**

| Refusal | Why not |
|---|---|
| `401`, and the `429` `gateway-in-flight` | unauthenticated. These are counted in `unauthenticatedRefusals` (ADR-0057 decision 5), as the maintainer fixed |
| a delegation credential refused at step 0 in `present` (`credential-mismatch`, `401`: not live, expired, presented under the other scheme, or a proof that does not hold) | it is held inside authentication (`authenticateCall`, `go/serve.go`), before `chargeRequest` (condition C1). It is counted in `unauthenticatedRefusals`, since every `401` is (`writeJSON`, `go/serve.go`) |
| a refusal after a charge that took no hold of the scope | no hold was taken, so no limit bounds an entry for it (condition C3) |
| `404` for a method | it comes before the token is read |
| `/act`'s `requester`, `scope-identifier` before the body, and `storage` | they come before step 3a. `requester` means no identity is configured, and `storage` is the store's kind, not the caller |
| a refusal before the charge for a caller of several scopes (an unknown source, a source of an unreached scope, a malformed body, no scope where one is needed) | no scope is established, and writing under the named scope would let a caller write into a scope it does not reach (J1) |
| an ADR-0057 limit refusal (`429` `limit_reached`) | it takes nothing (ADR-0057 decision 2), so one entry per refusal would be bounded by no limit. It is counted in the refusing scope's `tally` instead, which answers ADR-0057 open question 7 |
| `/verify`'s `403` for its reach | it comes before its charge (ADR-0057 decision 2). `/verify` has no other refusal: its other answers are the store's errors |
| a source's own answer: `source failed`, a throttled `429` or `503`, `410` `source_reference_expired`, `403` `source_access_refused` | these are the source's outcome, not the gateway's decision on the caller, and their text may carry the source's words |
| `503` `receipt_not_forwarded` | it is the sink's state. The receipt or seal is in the store and is held (ADR-0049) |
| `503` admission closed for maintenance | it is the operator's own act and says nothing of the caller |
| `500` and other errors | they are not refusals |
| the MCP front's refused forwards | they reach the engine through `/acquire` (ADR-0057, "What is not established") and are journaled there, if at all. The build confirms this path |

### 5. The hand-off, the writer, and what happens when a bound is reached

- **After the answer.** The handler writes its answer exactly as today, and the answer is then
  flushed explicitly (`http.Flusher`) before the hand-off begins (condition C10), so no work of the
  hand-off stands between the answer's bytes and the caller.
  - Where the journal is configured, the answer of a request that holds a scope is kept until its
    handler returns. It is then written with an explicit `Content-Length`, the length the server
    would have set itself, and flushed. A flush without it would send the answer chunked.
  - So the status, the header fields and the body are the same bytes as without the journal. Only
    the order of the header lines on the wire can differ, since an explicit `Content-Length` is
    written among the handler's fields; HTTP gives that order no meaning (RFC 9110, section 5.3).

  Then, before the request returns and so before its limiter slots are released (ADR-0057
  decision 2), the gateway does three things:
  - it draws the nonce and computes the commitment from the body bytes it holds;
  - it builds the record, at most 2048 bytes and with no body bytes in it;
  - it offers the record to its scope's queue with a non-blocking send.

  This post-answer work therefore stays inside the caller's own scope's in-flight cap.
- **Each scope's queue** holds at most 256 records and is the scope's own. It is built at start, in
  the immutable map that holds ADR-0057's per-scope state. An offer to a full queue is not taken,
  and the scope's `queue-full` count rises by one, an atomic increment. Nothing waits.
- **One writer for the gateway**, a single goroutine on each instance.
  - It takes records from the scopes' queues in turn, one record from each queue that holds one.
    While k scopes hold records, each gets at least one record in k.
  - For each record it reads its journal's end, signs, appends and syncs: on the PostgreSQL kind it
    inserts and commits. It signs one entry at a time, so the journal adds at most one signing in
    flight to the signer, whatever the number of refusals in any scope.
  - It signs outside the gateway's lock. It takes no lock that an answer takes: not the gateway's
    lock, not the registry's hold, not a limiter's state and not a session's admission.
  - On the PostgreSQL kind it uses a connection of its own, outside the pool that answers use.
- **The byte cap, and the room kept for tallies (condition C6).** A journal's bytes are the sum of
  its lines' lengths, each with its `0x0A`. With `C` its `maxBytesPerScope`:
  - `C` defaults to 64 MiB (67108864), and its range is 1 MiB to 1 GiB.
  - The last `C / 16` bytes (4 MiB at the default, 64 KiB at the least) are kept for `tally` entries.
  - A `refusal` entry is written only where the journal's bytes after it are at most `C - C/16`. The
    first one that is not is not written and counts as `journal-full`, and so does every later
    refusal record of the scope. From then on the scope's refusals are counted, not journaled.
  - A `tally` is written where at least 4097 bytes would remain under `C` after it. Where fewer
    would, the writer writes the closing `tally`, with `full: true`, in its place. It fits, since no
    line is longer than 4096 bytes. The writer then writes nothing more to that journal.
  - So, once the refusal entries stop, the tallies still land: at the default at least 1022 of them,
    each a line of at most 4096 bytes, which is at least 17 hours at one a minute.
  - Every record after the closing tally counts as `journal-full`, in the stderr line of each minute
    and at stop (below).
  - The cap is reached again only in a new store (section 8).
- **A failed write.** A signing error, an I/O error or a refused insert drops the record and
  counts it as `write-failed`. The writer then reads the journal's end again before its next entry.
- **A key that went backwards.** A writer whose key in force comes earlier in the key walk than the
  key of the journal's last entry does not write. It counts the record as `write-failed`. This can
  happen on the PostgreSQL kind while instances move between keys, and writing would make
  `journal-order`.
- **Nothing reaches an answer.**
  - A journal failure is never answered and never turned into a `500`.
  - It writes no stderr line per refusal. At most one line a minute, gateway-wide, gives the counts
    of records dropped in that minute and how many journals they were in, and it names no scope:
    `refusal journal: <n> records were not written in the last minute, in <k> journals; each
    journal's tally holds its counts`.
  - At stop, the writer has 5 seconds to empty the queues. It then writes the remaining counts as
    one stderr line of that form.
- **Durability against latency.** The journal trades durability for latency, and the answer always
  wins.
  - A record still in a queue when the process stops abruptly is lost. No tally counts it, since the
    counts died with the process.
  - So the journal is a signed record of the refusals it holds, together with the drops its tallies
    count. It is not proof that no other refusal happened. Section 11 states this.

### 6. Configuration and the engine version

- **The member.** From engine configuration version `48`
  (`refusalJournalVersion`), a top-level `refusalJournal` member: `{"maxBytesPerScope": <integer>}`,
  where the member inside is optional and `{}` is valid. Without the top-level member nothing is
  journaled, and every answer, start line, posture report and store is as today.
- **The load-time refusals.** Each names the member and quotes no value. The gateway will not start:
  - under an earlier version:
    `refusalJournal is a version-<n> member; engineVersion <m> has no refusalJournal`;
  - without `identity`: no caller is authenticated, so the journal would hold nothing, and a member
    that holds nothing would be a label posing as a bound;
  - without `limits`, or where some configured scope has no effective `requestsPerMinute`, whether
    from its own entry or from `default`: `refusalJournal needs a request rate for every scope
    (limits)`. This is how the maintainer's point 3 is held rather than assumed;
  - with `maxBytesPerScope` out of range, not an integer, or written with a fraction or an exponent;
  - with any other member;
  - where two scopes give one journal name (section 1).
- **The start line.** Where the member is configured, the start writes one stderr line:
  `refusal journal: <n> scopes are journaled, each bounded by its request rate`.
- **Several instances.** Each instance writes the scope's one journal (section 7), and counts and
  tallies its own records. N instances admit up to N times each limit (ADR-0057 decision 6), so up
  to N times the entries.

### 7. The PostgreSQL kind

- **Rows of `gateway.journal_records`,** as ADR-0056 section 8 foresaw: the derived name passes the
  table's CHECK. **No migration and no grant are added.** The run-time role's SELECT and INSERT on
  the table are what the serving gateway writes with.
- **One transaction per entry.** The writer, as the run-time login:
  1. takes `pg_advisory_xact_lock(int4, int4)`, PostgreSQL's two-key form (condition C7): the class
     constant `pgRefusalJournalLockClass` is the first key, and the first four bytes of SHA-256 over
     the journal's name, read as a signed integer, the second.
     - The gateway's other advisory locks take the one-`bigint` form (`pgLogAppendLock`,
       `go/store_pg.go`; `pgStartLeaseLock`, `go/store_pg_lease.go`; `pgMigrationLock`).
       PostgreSQL keeps the two forms' keys apart, so no journal's lock is ever one of those.
     - The build checks the class against every other two-key lock the gateway takes, of which there
       are none today.
     - Two journals whose names give one second key share a lock. That serializes their writers and
       is otherwise harmless;
  2. reads the journal's last row;
  3. signs;
  4. inserts at the next ordinal;
  5. commits.

  So the instances writing one scope's journal take turns, each entry costs one signature, and no
  instance retries a signature after losing a race. This answers ADR-0056 section 8's question.
  Instances writing different scopes' journals never share the lock.
- **The lock does not need UPDATE.** `SELECT … FOR UPDATE` would need UPDATE on the table, which the
  run-time role does not hold and must not (ADR-0056 amendment A).
- **A refused insert,** on the primary key or the chain's foreign key, rolls back. The record counts
  as `write-failed`, and the writer reads the end again. A journal removed whole (section 8) begins
  again at ordinal 0.
- **Signing inside the transaction.** The writer holds a transaction open across one key-service
  signing, up to 5 seconds (ADR-0050). That is the writer's own connection and the journal's own
  lock, so no answer waits on it.
- **`/act`** is still `501` on this kind (`go/serve.go:2848`), so `/act` refusals are journaled on
  the filesystem kind alone until `/act` is served here.

### 8. Who reads it: operators, export, verify; retention and `remove-scope`

- **No route serves a journal.** Not `/registry`, not `/posture`, not `/verify`'s answer, nor any
  other. Only whoever holds the store reads a journal: the operator, `gateway export`,
  `gateway verify` and `gateway journal open`. This is the line between the "operator side" of
  point 5 and the caller.
- **`gateway verify`, step 9 (ADR-0056 section 6)** runs on each refusal journal as it does on any
  journal. It reports `journal-entry-forged`, `journal-order` and `journal-from`, and
  `journal-missing` under `--require-journal <name>`. A refusal journal has no rule against the
  store, so it never reports `journal-entry-mismatch` or `journal-entry-missing` (ADR-0056 section 8,
  item 3). The structural checks of `journal-entry-forged` gain these cases:
  - a `body` that is not exactly a `refusal` or a `tally`;
  - a `reason` outside its route's list;
  - `refusal` or `outOfScope` present against its rule;
  - a `scope` whose name by section 1 is not the journal's name;
  - an operator body in a refusal journal, or a refusal body in `operator`.

  A journal whose name is neither `operator` nor `refusal-` and 24 letters from `a` to `p` is
  `journal-entry-forged` at its first entry. An unknown journal is never passed over.
- **`--scope`.** In a verdict by scope, a refusal journal's finding is reported only in the verdict
  of the scope it names, and other scopes' verdicts are silent on it. A verdict of scope A therefore
  says nothing of B's journal. This departs from ADR-0056 section 6, where a journal's finding stands
  in every scope's verdict as the registry's walk does: that fits the operator journal, whose
  entries name the whole store, and not a journal that holds one scope.
- **`gateway export`** writes each refusal journal as `store/journals/<name>.jsonl`. It writes no key
  and no forwarding cursor (section 9).
  - `gateway export --scope` writes no journal, as ADR-0056 acceptance 5 rules.
  - A per-scope journal would make carrying it safe for its content. It is still not carried: the
    writer's lag (`at` against `answeredAt`) and the `queue-full` counts move with other scopes' load
    (section 10), so they are not one scope's alone. A projection is #588's to decide with that in
    view.
- **Retention.**
  - A refusal entry names no session, so `retain` (ADR-0048) removes none, and its operator entry
    names none.
  - A refusal journal lives as long as its store. `store rotate` begins the new store with no refusal
    journal, and the old store keeps its own, which is verified and deleted with it (ADR-0056
    section 3).
  - The byte cap bounds each journal meanwhile.
  - There is no trim by age. A chain cannot lose its head without becoming `journal-order`, and a
    base marker is not in this record (open question 4).
- **`remove-scope` and `store remove-scope`** remove the scope's refusal journal whole, with its key
  and its forwarding cursor.
  - On the filesystem kind this happens in the command's own step 5, beside the removed files.
  - On the PostgreSQL kind it happens in the owner's transaction, under the journal's advisory lock,
    so a serving writer never interleaves with it.
  - Deleting the key leaves the store's own entries unopenable from then on (condition C9). It does
    not reach a copy that holds the key. A raw copy of the store, and on the PostgreSQL kind a backup
    of the database or its write-ahead log, keeps `K_scope`, and with it opens the entries it holds
    and those an export or the sink holds. The operator removes such copies as it removes the
    scope's payloads from them.
  - **The trace is an amendment of ADR-0056 section 4.** The operator journal's `remove-scope` body
    gains two members, `refusalJournalBytes` and `refusalJournalDigest`: the length and SHA-256 of
    the bytes removed, which on the PostgreSQL kind are the bytes an export would have written. They
    are present exactly when the call removed a refusal journal. Without them, a removal of one
    scope's refusal record would leave no trace. The maintainer accepted this amendment of ADR-0056
    (open question 3).

### 9. Delivery version `"3"`

- **The member.** `receiptSink.deliveryVersion`, the string `"3"`, from engine version
  `48`. It is refused by name under an earlier one:
  `receiptSink: deliveryVersion is a version-<n> member; engineVersion <m> has no deliveryVersion`.
  - Absent, the sink is sent `"1"`, and `"2"` under `seals: true`, exactly as today, byte for byte.
  - `"1"` and `"2"` are not values the member takes: those versions are chosen by its absence and by
    `seals`, as today.
  - Under `"3"`, `seals` is refused if given, since seals are always forwarded:
    `receiptSink: seals is implied by deliveryVersion "3"`.
- **The envelope.** One `POST` to the same url for each record, `Content-Type: application/json`,
  carrying the canonical JSON of exactly:
  - `deliveryVersion`: `"3"`;
  - `kind`: one of `"acquisition-receipt"`, `"action-receipt"`, `"seal"` and `"refusal-entry"`;
  - `digest`: `sha256:` and the lowercase hexadecimal SHA-256 over
    `"judgment-pack-gateway/sink-delivery/3:"`, the `kind`, `0x0A`, and the record's line without its
    `0x0A` (condition C4). That line is the receipt's under `receipts/`, the seal's in the registry,
    or the entry's in its journal;
  - for `acquisition-receipt`: `receipt`, `payloadDigest`, and `payload` as ADR-0049 decision 2
    gives it;
  - for `action-receipt`: `actionReceipt`, a member of its own, so that no reader of an acquisition's
    `receipt` takes it for one (condition C4);
  - for `seal`: `seal`;
  - for `refusal-entry`: `journal` and `entry`.
- **Acknowledged.** The acknowledgment is `{"acknowledged":"<digest>"}`, with ADR-0049 decision 3's
  bounds, and the retries and deadlines are its decision 8's. The sink deduplicates by `digest`.
- **Why `digest` and not `receiptDigest`.** A sink of `"1"` that ignored `deliveryVersion` and read
  `receiptDigest` would otherwise acknowledge an action receipt as an acquisition one without a
  word. Here it finds no member it knows, its acknowledgment names no digest the gateway sent, and
  every acquisition is refused `503` `receipt_not_forwarded`. A mismatch is a refusal, never a
  silent pass.
  - The domain prefix makes sure of it (condition C4): no `"3"` digest is ever a `"1"`
    `receiptDigest` (`receiptDigestOf`, `go/receipt_sink.go`, SHA-256 over the receipt's line
    alone), so an acknowledgment computed the `"1"` way names no digest the gateway sent.
  - A test holds it: a sink that acknowledges a `"3"` delivery with the `"1"` digest of its receipt
    leaves the acquisition refused `503` `receipt_not_forwarded`.
- **Action receipts** follow ADR-0049's rules for acquisition receipts:
  - The receipt `/act` mints is held for the sink, under the gateway's lock that stamped it. It is
    delivered after that lock is released, while the session's admission is held, and `/act`
    answers only once it and every earlier receipt of the session are acknowledged.
  - Per-session order is by `callIndex`, across both kinds. A held receipt of either kind is
    delivered again before the session's next acquisition proceeds, before the next action runs its
    executor, and before the seal.
  - While a receipt of either kind is held, all three are refused with the fixed `503`.
  - **The difference: the write has happened.** Not acknowledged, `/act` answers `503`, code
    `receipt_not_forwarded`, with exactly this sentence:
    `action receipt not forwarded: the receipt sink did not acknowledge this action's receipt; the
    action was carried out and its receipt is in the store; nothing was answered, and the receipt
    is held to be delivered again before the session's next acquisition, action or seal; the same
    actionKey answers it once it is acknowledged`.
    The action key's retained evidence (§1.2b) answers the retry once the receipt is acknowledged,
    so the write is never repeated.
  - A dry-run receipt (§1.2c) is in no store and no session, and is not forwarded.
  - After an interruption, `seal-open --config` and `sealOpenAtStart` deliver every stored receipt
    of the session, action receipts included, before they seal it.
- **Seals** are ADR-0049's amendment under the new envelope: marked, appended, and acknowledged
  before `/seal` answers. They are appended only once every receipt they count is acknowledged, now
  action receipts too. A seal is refused while one of its receipts is held.
- **Refusal entries are never on an answer path.**
  - The writer forwards each entry after it is appended, in ordinal order for each journal, one
    delivery in flight gateway-wide, through an HTTP transport of its own, so it never takes a
    connection a receipt's delivery would use.
  - The forwarder sends the journal's lines as they are, and does not verify their chain; the sink
    verifies it.
  - A delivery that is not acknowledged is sent again later, oldest first, at most once every 5
    seconds for each journal. It never holds a request, an answer, another journal's forwarding, or
    the writer's appends.
  - **The cursor.** Progress is kept as each journal's forwarding cursor: the highest ordinal
    acknowledged, with that entry's digest.
    - On the filesystem kind it is `<root>/journals/<name>.forwarded`, staged, synced and renamed.
    - On the PostgreSQL kind it is a document of no scope, `refusal-forwarded.` and the
      SHA-256 of the name.
    - No verifier reads it, and no export carries it.
    - After a stop or a crash, forwarding resumes from the cursor, and the sink deduplicates what
      it already holds.
    - **Several instances on the PostgreSQL kind (condition C5).** Every instance's writer forwards
      every journal from the one cursor, whichever instance appended the entries: it delivers the
      entries after the cursor, oldest first. The delivery is made outside the journal's lock. The
      cursor then moves under that lock, by a compare-and-set that is monotone: it is replaced only
      where it still holds the ordinal the instance read before it delivered, and only by a greater
      ordinal. Where another instance moved it first, the greater value stays and the instance reads
      again. So no ordinal is passed over, two instances may each send one entry, and the sink
      deduplicates them by `digest`.
  - **A sink that declines refusal entries (condition C11).** `receiptSink.refusalEntries: false`,
    valid under `"3"` alone, forwards no refusal entry. Receipts and seals are delivered as above,
    the journals are kept in the store, and no cursor is written. Without `deliveryVersion: "3"` the
    member is refused by name. Absent, it is `true`.
  - A journal whose entries are not acknowledged grows as it would without a sink, up to its cap.
- **What the sink receives for each scope.** There is one sink for every scope (ADR-0049,
  consequences). It receives every scope's acquisition and action receipts, seals and refusal
  entries, each entry naming its scope and journal. It receives no commitment key, so it can open no
  commitment, and no `tally` is withheld from it. A per-scope sink is not in this record.
- **What older sinks see.** A configuration without the member sends exactly today's bytes; a test
  holds the bodies against the previous release, byte for byte. A sink moved to `"3"` before it
  reads `"3"` refuses every acquisition, as above.
- **Upgrade order.**
  1. Give the sink `"3"`, keeping `"1"` and `"2"`.
  2. Run the gateway binary of this release.
  3. Raise the configuration's version, set `deliveryVersion: "3"`, and restart. A pending seal is
     then delivered under `"3"`.
- **Rollback.** Remove `deliveryVersion` and lower the version. A pending seal is delivered under the
  configured form, since its marker names only a session. Action receipts are then not forwarded, as
  today. Refusal journals stay in the store, unforwarded, and their cursors are passed over.

### 10. No cross-scope oracle: the argument

The adversary is a caller that reaches scope A and not scope B. The question is whether anything it
can observe depends on B's refusals. The table takes each thing it can observe in turn.

| What the caller observes | Why it does not depend on B's refusals | Held by |
|---|---|---|
| Its own answers: status, headers, body | The answer is written before the entry is made (section 5), and nothing on the answer path reads the journal, the queues, the writer or the cursors. Every refusal is answered byte for byte as without the member | golden answers with and without the member, for each code of section 4; mutant 1 |
| Its own answer's latency, from the gateway's own work | The hand-off is a non-blocking send to A's own queue, made after A's answer. The writer takes no lock an answer takes (section 5). B's queue is a different object, and a full one refuses B's offer, never A's | A blocked writer (signer gated by the test) while A and B are answered; B's queue full while A's offer is taken; asserted by order, not timing; mutants 2 and 4 |
| `/posture` | The `refusal-journal` line (below) is computed from the configuration and the caller's reached scopes alone. It holds no count, size or state of any journal. `unauthenticatedRefusals` is ADR-0057's, unchanged | A's report the same bytes whether B's journal is empty, full or failing; mutant 8 |
| `/registry` | No entry goes to the registry (ADR-0056 J1). The registry's bytes are unchanged by any refusal | the registry before and after a run of refusals |
| The limits (`429`, `Retry-After`) | The writer takes no token and no slot of any scope or of the gateway-wide cap. Entries are made after the charge, from requests already counted. A limit refusal is counted in the refusing scope's tally by an atomic increment, after ADR-0057 chose its answer from the refusing state alone | the limiter's state unchanged across the writer's work; mutant 7 |
| The journal, an export, `gateway verify` | Callers read none of them (section 8). For the operator: A's journal's ordinals, chain and tallies count A's entries alone (P2), and a verdict by scope is silent on other journals | the scope-mismatch vector; the verdict-by-scope test; mutants 6 and 13 |
| The sink | The sink is the operator's and callers do not read it. It never holds a commitment key, and refusal deliveries never hold an answer | a sink that never acknowledges refusal entries while A's acquisitions answer; mutant 14 |
| Writing into another scope | An entry goes only to the scope the request was charged to, which ADR-0057 charges only where the caller reaches it. A caller of A cannot add entries to B's journal, fill B's queue or spend B's cap | a caller of A naming B's source: B's queue, journal and tally unchanged; mutant 3 |

**What remains: shared resources.**

- **The shared points.** B's journal work still reaches resources every scope shares: the signer
  (one signing at a time under a key service, ADR-0050), the store's disk or database, the sink
  endpoint, and the CPU.
- **The bounds.**
  - Added load: at most one journal signing and one refusal delivery in flight at any instant,
    gateway-wide (sections 5 and 9).
  - Signings: per scope, at most one for each request ADR-0057 charged, plus one tally a minute.
  - An answer's wait: an answer's signing waits behind at most one journal signing.
- **The footprint is the same.** A journaled refusal costs the shared points what one admitted
  request costs them: one signing, one append and one delivery. A shift in shared latency therefore
  tells A at most that some request of some scope was charged, and was served or refused. It could
  be A's own scope's other callers, an unscoped caller or another scope. That is the signal ADR-0057
  decision 4 already accepts for admitted requests ("bounded, not removed").
- **Under a key service (the maintainer's timing ruling).** One signing can take up to ADR-0050's
  5 seconds, so the one journal signing that an answer's signing can wait behind can add up to
  5 seconds to that answer. A key service's quota shared with the journal can also make signings
  fail, not only slow: an answer whose signing the quota refuses, because journal signings spent it,
  is a failed answer, not a late one. The operator sizes the quota for the journal's signings
  (Consequences). The maintainer accepted this residual, bounded as stated, with no cover traffic
  (open question 1).
- **What is not removed.** A caller that knows by other means that no other request is running, and
  that B has no admitted traffic, could take a shift in shared latency as a sign that B is being
  refused. Removing that takes constant-rate cover traffic (W4), which this record does not choose
  (open question 1).
- **The operator side.** The writer's lag and the `queue-full` counts in A's journal move with B's
  load. That is a cross-scope signal to the operator alone, and it is why `export --scope` carries no
  journal (section 8).

**`/posture`.** A new protection line, `refusal-journal`, is given only where the member is
configured:

- `enforced` where the caller reaches some source. Its reason is fixed: `refusals of authenticated
  requests charged to this caller's scopes are signed into the operator's refusal journal after
  they are answered; nothing of the journal is served`;
- `not-applicable` where it reaches none.

No count is given, so the line is the same bytes for every caller that reaches a source. `gateway
posture`, run by the operator, gives the same line.

### 11. What this does not establish

- That every refusal is journaled. Records dropped at a bound are counted, and records lost in an
  abrupt stop are not.
- That an entry is true beyond the key holder's word, as for any journal (ADR-0056, consequences).
- That the shared-resource residual of section 10 cannot carry a signal under the side knowledge it
  names.
- That the closed lists of section 4 match the code. The build's walk of each route's refusals is
  what holds them, and it stops on a refusal that fits none.
- The MCP front's path through `/acquire`, which is taken from ADR-0057 and not confirmed here.
- That a journal holds its scope's refusals for the store's whole life (condition C6). One caller at
  its own rate can fill its scope's refusal room: at `requestsPerMinute` 60 and entries near 1 KiB,
  60 MiB fills in about 17 hours. From then on that scope's refusals are counted in its tallies and
  not journaled, until a new store. The effect stays within the scope: no other scope's journal,
  room or tally moves with it.

### Consequences

- **Good:** an operator can read back, signed and per scope, which authenticated callers were
  refused, at which step, under which delegation and when, and can open a commitment to a request
  it is shown. A sink receives `/act`'s receipts and every seal under one envelope.
- **Good:** no answer changes, and no reader that callers have changes. Without the members, nothing
  changes at all.
- **Good:** no migration, no grant and no new envelope. The refusal journal is ADR-0056's contract
  with a name, two bodies and a writer.
- **Bad:** the journal is best effort. A refusal can be dropped, and the record of it counted, or
  lost in a crash.
- **Bad:** a refused request that was charged now costs one signing, where it cost none before.
  Under a key service the operator sizes the quota for it.
- **Bad:** the store holds a commitment key for each scope. A raw copy of the store, as opposed to an
  export, carries it, and the operator guards it as the store's payloads are guarded (SECURITY.md).
- **Bad:** the shared-resource residual of section 10 is bounded, not removed.
- **Bad:** a verifier of the operator-journal release that does not know refusal bodies reports a
  store holding a refusal journal as `journal-entry-forged` (section 12). A verifier of v0.38.0 or
  earlier passes `journals/` over.
- **Revisit when** shared counting lands (#593), when `/act` is served on the PostgreSQL kind, when
  #588 projects journals by scope, or when an operator needs a per-scope sink.

### 12. Compatibility

- **Older verifiers.**
  - A verifier of v0.38.0 or earlier passes `journals/` over (ADR-0056 section 7), so it reports
    nothing of a refusal journal.
  - A verifier of the operator-journal release reads every journal, and holds a body to the operator
    kinds alone. It reports a refusal journal as `journal-entry-forged`: a refusal, never a pass.
    The release notes say so, and say to verify with this release.
- **Older readers of an export.** They refuse `store/journals/refusal-….jsonl` as a file an export
  does not write (`exportPathWritten`), as ADR-0056 section 7 sets out for the operator journal.
- **A release that does not know refusal journals refuses them by name** (the maintainer's ruling).
  A verifier or an export reader that meets a journal name it does not know reports a refusal that
  names it, never a journal passed over. A separate pull request on `main` makes `gateway verify`
  and the export reader of the current line refuse journal names they do not know; it is not part
  of this record's build.
- **The engine.**
  - A configuration of an earlier version, or without the members, journals nothing and sends
    today's deliveries.
  - Rolling back the binary leaves the refusal journals in the store. An older start does not read
    them.
  - On the PostgreSQL kind no schema change is made, so no older binary is refused for this record's
    sake.

### 13. SPEC.md sentences

- **§6, `writeRequesters`, `SPEC.md:3115`.** "The refusal is recorded nowhere, as no refusal of the
  action ladder is." becomes:

  > Nothing of the refusal reaches the caller beyond this answer, and nothing a caller can read
  > records it. Where the configuration keeps a refusal journal (§3f), the operator's journal of the
  > request's scope records it, after the answer, as every refusal of the action ladder after the
  > limit step is.

- **§3f** gains "The refusal journals": sections 1 to 3 and the rule of section 4, word for word.
- **§4 step 9** gains section 8's cases of `journal-entry-forged`.
- **§6** gains the `refusal-journal` line of `/posture`, and `/act`'s action-receipt sentence.
- **§6a** gains "Delivery version 3": section 9. "What is not forwarded" gains "except under
  delivery version `"3"`" for an action's receipt and for a seal.
- **§1.3's layout** gains `<root>/journals/refusal-<24 letters>.jsonl`, `.key` and `.forwarded`.
- **§4.1** gains: a `.key` or `.forwarded` file is no journal and is not read.

## More information

### Build plan: three pull requests

**As built.** R2 comes first, and carries R3's verify-ts and corpus vectors. R1, and R3's
forwarding, follow it. Where R2 departs from the text above:

- **K_scope is drawn at start**, for every journaled scope, not at the journal's first entry. The
  salt is computed at the hand-off, on the answer's side, so the key must already be held; drawing
  it there would put a store write on an answer's path.
- **`journal-from` of a refusal journal** is `{observation, journal, entries}`: the operator
  journal's `registryFrom` and `removalFrom` have no meaning in it.
- **`remove-scope` of a scope that holds no records** removes nothing but the scope's refusal
  journal, its key and its cursor, where the journal holds entries (2026-11-24, below). R2 first
  left the journal too.
- **A refusal no handler codes** (outside section 4's lists, such as `/act`'s `storage`) is
  answered as before and not journaled.
- **2026-11-23, the verdict by scope.** Both readers keep a refusal journal's finding or observation
  only in the verdict of the scope whose journal it is, by section 1's name of `--scope`'s
  identifier (`keeps` in `go/scope_cut.go` and in `verify-ts/src/verify.ts`); a finding of any
  other journal is kept as before. `v3-cut-a-refusal-journals-of-others` is mutant 6.
- **2026-11-23, a writer that `remove-scope` left behind.** On the filesystem kind the writer, under
  the journal's lock, compares the file it holds with the journal's path. Where the path is gone or
  is another file, it reads the key again, and opens the path only where the key is the one the
  queued entries were made under; otherwise that scope's entries are dropped, counted as
  `write-failed`, until the next start. On the PostgreSQL kind each append's transaction reads the
  key row under the lock and drops the entry, counted the same way, where the row is gone or holds
  another key. Neither kind writes into a journal that no key opens.
- **2026-11-24, the filesystem writer holds a journal for one round.** This replaces the held file
  of the line above. On the filesystem kind the writer holds no journal file between entries: each
  entry opens the journal, takes its lock, checks that the path is still the file it opened and that
  the key file holds the key the entry was made under, appends, syncs, lets the lock go and closes
  the file. Only a journal the writer has not found, at start or since, is made: under `O_EXCL`, and
  while the key it holds is at its path. Once found, a missing `.jsonl` is a removal, whole or cut
  off before the `.key` went, and the scope's entries are dropped, counted as `write-failed`, until
  the next start; so are they where the key is gone or another. A key that cannot be read for
  another cause drops that one entry, counted the same way. The writer reads the journal again where
  the file is another than the one it read, or its length is not the end it holds. A round that
  made the file and wrote nothing to it takes the empty file away. A `remove-scope` cut off
  between the `.jsonl` and the `.key` therefore never has the journal made again under the old key
  while the gateway runs. Across a restart, too: before any key is read, the start completes the
  removal of each configured scope whose last `remove-scope` entry in the operator journal names a
  refusal journal that is the bytes it names (2026-11-24, below), as a second `remove-scope` run would, and
  says so on stderr. The first entry after it is made under a key drawn then. The PostgreSQL kind
  is unchanged.
- **2026-11-24, the key is drawn at start, and a key file is no journal.** `K_scope` is drawn, or
  read where it is already held, when the gateway starts for each scope the configuration names,
  as the K_scope paragraph above now says, not when the first entry is written. A `.key`
  beside no `.jsonl` is therefore the state of a scope that has refused nothing yet, and verify
  names nothing for it. A `.jsonl` beside no `.key` is judged whole, as an export's is, since no
  verdict reads the key; the writer names that loss (`write-failed`), and so does reading an entry
  back. No export carries a key (section 8): the export check names one put beside an export's
  journals `unlisted`, as any file its manifest does not list. verify-ts reads a store directory
  and has no export check, so a key there is named by the Go reader alone.
- **2026-11-24, the one case where another scope's name reaches a verdict by scope.** A verdict by
  scope reads its own scope's refusal journal alone, and passes over another scope's journal it
  cannot read. `journals/` is still judged by name and type whole (SPEC.md §4 step 9): a directory,
  a link or any other file that is not a regular file at another scope's journal name is named
  `journal-unknown` in every verdict, by scope too. Nothing of that scope's journal is read for it.
  A store so altered has been tampered with, as one holding a planted file of an unknown name has,
  and that already fails every verdict.
- **2026-11-24, an entry's place in its journal.** Entries of one journal follow the writer's queue
  order, not the order answers reach clients. Each answer is written and flushed before its entry
  is handed off, so that no answer waits on the journal (section 5), and a later request's entry can
  be queued before an earlier one's. An entry's `answeredAt` is the gateway's clock when its answer
  was written, and the ordinals and `previous` links give the order the entries were written in.
- **2026-11-24, a forwarding cursor's files in `journals/`.** On the filesystem kind a cursor is
  written by staging it beside its path and renaming it into place, so a process ended between
  the two leaves `<name>.forwarded.<pid>.<12 lowercase hex>.tmp`. Both readers know, for a refusal
  journal's exact name alone, `<name>.forwarded` and that staging form: a regular file of either
  name is passed over and never opened, and any other file is `journal-unknown`, as SPEC.md §4
  step 9 has it. A near miss (another stem, upper-case hex, another length, no process identifier,
  no `.tmp`) is `journal-unknown` too. No export carries either file. The forwarder's start
  removes, before its first pass, the staging files of its own journals' exact names, regular
  files alone, and never follows a link.
- **2026-11-24, the journals as the forwarder's source.** The owner's `refusalEntrySource`
  (`go/refusal_entry_source.go`) names the configured scopes' journals and reads their entries
  outside every lock: on the filesystem kind the journal's file, lines that end in a line feed
  alone, so a torn tail is never sent; on the PostgreSQL kind the rows, on a connection of its own,
  neither a slot of the pool answers use nor the writer's. The cursor moves under the lock the
  journal's appends take: on the filesystem kind the file's `flock`, for that one move as for one
  append round, once the path is still the file locked (none where the platform has no `flock`, as
  for the writer); on the PostgreSQL kind the journal's advisory lock, in a read transaction on that
  connection. The cursor's compare-and-set is still the document of no scope, on the pool (until the
  cursor moved onto that connection, 2026-11-24, below). Under the
  lock the journal must still hold, at its place, the entry the cursor is to name; where it does
  not, or where the journal has no file, the cursor is not moved. The owner moves it only after the
  sink acknowledged an entry read from the journal, so a journal with no file by then was removed
  since the read, and `remove-scope` takes the cursor with it under the same lock: a cursor written
  after it would name an entry no journal holds and stop the scope's next journal at a diverged
  cursor. A journal not yet made holds no entry, and nothing of it is forwarded.
- **2026-11-24, only a durable entry is forwarded.** On the filesystem kind the source reads a
  journal's file no further than its size taken under the file's `flock`, which is let go before
  the bytes are read. The writer syncs each line before it lets the lock go, so a line still in the
  page cache is never forwarded: a power loss could otherwise put another entry at its ordinal, and
  the sink would hold two signed entries at one ordinal that the store does not show. Where the
  platform has no `flock`, the bound is the size at the read. On the PostgreSQL kind a row is read
  only once its transaction has committed.
- **2026-11-24, a line whose write or sync fails is cut back.** On the filesystem kind the writer
  takes the journal's file back to the end before that line, and syncs it, still under the round's
  lock, so the size the lock shows never counts a line that may not be durable. The entry is dropped
  and counted (`write-failed`), and the next entry is written at its ordinal. Where the cut or its
  sync fails too, the scope is lost until the next start, which judges the file, and no later entry
  is written after it.
- **2026-11-24, `remove-scope` of a scope that holds no record removes its refusal journal.** A scope
  whose callers were only ever refused holds a journal and no session. On both kinds, where the
  journal holds entries, `remove-scope` and `store remove-scope` remove it, its key and its cursor,
  under the same lock as the record path (the file's `flock`; the advisory lock in the owner's
  transaction). The operator entry is the `remove-scope` body naming no removal record:
  `removalBytes` 0, `removalDigest` of no bytes, at `removalFrom` the removal file's length, beside
  `refusalJournalBytes` and `refusalJournalDigest`. ADR-0056's body form is unchanged. On the
  filesystem kind the entry is appended and synced before the journal goes, with nothing staged,
  since no record is appended; a run cut off after it is completed as a record path's is. The
  command says what it removed. A key beside no entry stays, and a scope holding neither is left as
  before, with the same output. Both commands refuse `--scope unscoped` before anything is read:
  it is the key of the sources of none (`limitScopeKey`), and the no-record path would take their
  live journal, key and cursor, which nothing can restore.
- **2026-11-24, the journal goes last, so a key beside none is a draw.** On the filesystem kind the
  removal takes the key, then the cursor, syncs the directory, then removes the journal, so the
  order holds on every filesystem. A run cut off between them leaves the
  journal, the bytes its entry names, which the next run or start completes. A journal that is gone
  is a removal completed, so a key or cursor beside none is never a removal's leftover: a key the
  start drew since stays across restarts, with no line on stderr. The start and a second run
  complete a removal only where the journal is the bytes the entry names.
- **2026-11-24, a key is drawn whole or not at all.** On the filesystem kind `K_scope` is written to
  `<root>/.<name>.key.<pid>.<12 lowercase hex>.tmp`, in the store's root and outside `journals/`, so
  neither reader's name rules change. It is synced there and then linked to `journals/<name>.key`. The
  link never overwrites a key; where one is there it is read. A start ended mid-draw leaves the
  staged file and no short `.key`. The next start removes, before any key is read, the staged files
  of its own journals' exact names, regular files only, and never follows a link. Where the link
  fails because the store cannot link that file (`EXDEV`, with `journals/` on another filesystem;
  `EPERM`, `ENOTSUP` or `EOPNOTSUPP`), the staged file is removed and the key is made in place
  under `O_EXCL`, written and synced, as before; any other link failure refuses the draw. A draw in
  place ended part way can leave a `.key` that does not decode as a key (32 bytes in hexadecimal,
  a line feed after them or none): beside an absent or empty `.jsonl` no entry was made under it,
  so the start removes it, draws the key again and says so in one stderr line. A whole key, with its
  line feed or without, is kept. A `.key` that does not decode beside a journal holding entries
  still refuses the start.
- **2026-11-24, the PostgreSQL cursor on the source's own connection (#611).** A forwarding pass
  takes no slot of the pool. The cursor's first read is a read transaction on the source's own
  connection, as the entries' read is. Under the lock, the source takes the journal's advisory lock
  in a write transaction on that connection, finds the entry there again, and then reads the cursor
  and makes its compare-and-set as statements of that same transaction: the revision rule is the
  document space's own (`pgDocumentsOn`, one code path for the pool's documents and a transaction's).
  So no `remove-scope` comes between the lock and the put. Before, the put waited for a slot of the
  pool with the lock's transaction open; a wait past the idle bound ended the session and let the
  lock go, and a `remove-scope` then could take the journal and its cursor before the put made the
  cursor again, naming an entry no journal holds. No transaction spans a delivery: the owner reads
  and delivers outside every transaction and lock, and the locked transaction only checks the entry
  and moves the cursor. On the filesystem kind nothing changes.

Each runs its touched tests alone, and CI does the full run. At most ten mutants run in each, each
in a scratch copy and each made to fail a named test. A security-focused review (Opus) is made on
the second and third.

**R1. Delivery version `"3"`, without the journal.**

- **Files:** `go/receipt_sink.go`, `go/seal_sink.go`, `go/act.go` and `go/serve.go` (the `/act`
  hold and answer), `go/seal_open.go`, `go/seal_open_pg.go`, `go/engine.go` and
  `docs/design/engine-config.md`.
- **Tests:**
  - each kind's envelope and its digest;
  - an `/act` receipt acknowledged before its answer;
  - an `/act` that is not acknowledged: answered `503` with the sentence, the write not repeated on
    a retry with the same key, and answered once acknowledged;
  - a seal refused while an action receipt of its session is held;
  - an older sink: the bodies for a configuration without the member, byte for byte against the
    previous release;
  - a sink of `"1"` given `"3"` acknowledges nothing;
  - each load-time refusal.
- **Mutants:**
  - (9) `/act` answering before the acknowledgment;
  - (10) `"3"` bodies sent without the member;
  - (11) a seal appended while an action receipt is held;
  - (12) `digest` named `receiptDigest`, caught by the older-sink test.

**R2. The refusal journal, filesystem and PostgreSQL.**

- **Files:** `go/refusal_journal.go` (the name, bodies, commitment, queues, writer, tally and cap),
  `go/refusal_journal_pg.go`, the hooks in `go/serve.go` and `go/limits_serve.go`, `go/posture.go`,
  `go/verify.go`, `go/export.go`, `go/remove_scope.go`, `go/store_remove_scope.go`,
  `go/operator_journal.go` (the `remove-scope` members, if accepted), `go/engine.go`, and
  `gateway journal name` and `gateway journal open`.
- **Tests:**
  - every code of section 4 journaled with its answer byte for byte unchanged;
  - every refusal of the not-journaled table leaving every journal unchanged;
  - the walk of each route's refusals against the closed lists;
  - the cross-scope tests of section 10;
  - the queue full, the cap with its closing tally, a failed write, a key that went backwards, and a
    missing key;
  - the commitment: equal bodies give unequal commitments, `open` matches, and the key is absent
    from the export, the sink and stderr;
  - the PostgreSQL kind: two instances writing one journal under the lock with no fork and one
    signature per entry, and a removal under the lock;
  - `remove-scope` removing the journal, the key and the cursor, with its operator entry.
- **Mutants:**
  - (1) the entry written before the answer;
  - (2) a blocking offer to a full queue;
  - (3) the entry written to the scope the request named, not the one charged;
  - (4) one queue for every scope;
  - (5) the salt taken from the nonce alone;
  - (7) a limit refusal journaled one by one;
  - (8) the posture line counting entries;
  - (13) the scope-mismatch check left out of verify.

**R3. Forwarding refusal entries, verify-ts and the corpus.**

- **Files:** the writer's forwarding and cursor, `verify-ts/src/verify.ts` (the refusal kinds, the
  name rule and the forged cases), and `gateway conform`.
- **Corpus vectors**, in `corpus/v3/stores`, run by both verifiers and by `gateway conform`:
  - `v3-journal-refusal-holds`;
  - `v3-journal-refusal-tally-full`;
  - `v3-journal-refusal-forged`;
  - `v3-journal-refusal-scope-mismatch`;
  - `v3-journal-refusal-kind-crossed`;
  - `v3-journal-refusal-order-middle`;
  - `v3-journal-refusal-torn-tail`;
  - `v3-journal-refusal-missing`, under `--require-journal`.
- **Tests:**
  - a sink that never acknowledges refusal entries while acquisitions answer;
  - resume from the cursor;
  - one delivery in flight.
- **Mutants:**
  - (6) the verdict by scope reporting another scope's journal;
  - (14) a refusal delivery awaited on the answer path;
  - (15) the cursor advanced before the acknowledgment.

### The security review's focus list

1. Every path from a refusal to an answer: nothing of the journal is read, awaited or written before
   the answer is flushed.
2. Attribution: an entry goes only to the scope the request was charged to, on every route and for
   both kinds of caller, delegated and reservation senders among them.
3. The queues, the writer and its PostgreSQL connection, the advisory lock's key, and the sink
   transport: none of them is shared with an answer path.
4. The commitment key: where it is created, its file mode and document name, and that it is absent
   from entries, exports, the sink, stderr and errors. Also `open --reveal-salt`.
5. `/posture`: the line's bytes are independent of any journal's state.
6. The closed lists: no refusal text, body byte or session label in any entry.
7. Bounds: the load-time refusal without a rate, the queue, the cap, the tally's rate, and the drop
   counts on every failure path.
8. Delivery `"3"`: held action receipts and seals in order, the `503` sentences, the
   `digest`-named acknowledgment, and today's bytes without the member.
9. `remove-scope` on both kinds: the journal, the key and the cursor removed, and the operator
   entry's members.
10. Verify: unknown journal names, crossed kinds, the scope-to-name check, and the verdict by scope.

### Related

Gateway #539 and the refusal-journal item; #543 and ADR-0056 (sections 1, 2, 3, 6 and 8; acceptance
5; amendment A); ADR-0057 (decisions 2 to 6; open question 7; acceptance 2); ADR-0049 and its
amendment; ADR-0050; ADR-0053; ADR-0054; ADR-0041; ADR-0042; ADR-0035; ADR-0048. SPEC.md §1.2a,
§1.2b, §1.2c, §3f (planned), §4, §6, §6a, §10 and §11.4 to §11.8. Issue #588 (projection by scope)
and #593 (shared counting).

This record amends ADR-0056 section 4 by the two `remove-scope` members (open question 3, ruled as
recommended). It supersedes nothing.

## Open questions, as ruled

The maintainer ruled each question as it recommends.

1. **The shared-resource residual: accept it, bounded as section 10 states (recommended), or add
   constant-rate cover (W4).**
   - Cover removes the signal from the signer, the disk and the sink.
   - It costs a signing, an append and a delivery at every tick for every journal, and caps each
     journal at the tick rate.
   - The recommendation follows ADR-0057's accepted "bounded, not removed". The maintainer should
     say whether the refusal journal must meet a stricter bar than the limits.
   - **Ruled:** the residual is accepted, bounded as section 10 states, with no cover traffic.
2. **Refusals before the charge from callers of several scopes: not journaled (recommended), or
   kept in a gateway-level journal of no scope.** The callers concerned reach several scopes, the
   installation's caller among them. Such a journal would be bounded by `beforeScope` alone.
   **Ruled:** not journaled.
3. **The trace of a removed refusal journal: amend ADR-0056 section 4 with `refusalJournalBytes`
   and `refusalJournalDigest` on `remove-scope` (recommended), or a new operator body kind.** A new
   kind leaves the accepted `remove-scope` form untouched, at the cost of a second entry per call.
   **Ruled:** the amendment.
4. **No trim by age (recommended), or a base marker that lets a journal drop its head.** The byte
   cap and store rotation bound a journal today. **Ruled:** no trim by age.
5. **`maxBytesPerScope`: configurable with a 64 MiB default (recommended), or fixed.**
   **Ruled:** configurable, 64 MiB when left out.
6. **The queue's size: fixed at 256 (recommended), or tied to the scope's `burst`.**
   **Ruled:** fixed at 256.
7. **Source outcomes, such as `source_access_refused`: not journaled (recommended), or journaled
   under codes of their own.** They are the source's answers, and an operator may want them for
   audit. **Ruled:** not journaled.
8. **`/posture`: the fixed `refusal-journal` line (recommended), or no line at all.**
   **Ruled:** the fixed line.

## What the release notes must say

- From engine version `48` (`refusalJournalVersion`), a top-level
  `refusalJournal` member keeps a signed refusal journal for each scope:
  - on the filesystem kind, `journals/refusal-<24 letters>.jsonl`;
  - on the PostgreSQL kind, the rows of `gateway.journal_records`, with no migration;
  - in an export, `store/journals/`.

  Without the member nothing changes.
- **What is journaled:** a refusal of an authenticated request, once ADR-0057 has charged it to a
  scope, in that scope's journal alone. Unauthenticated refusals stay a count in `/posture`. Limit
  refusals, and records that could not be written, are counted in the scope's `tally`, at most once
  a minute.
- **What an entry holds:** the time, the route and reason code, the caller, the delegation member,
  the scope, and a commitment to the request bytes. It never holds the bytes. The commitment opens
  only with the scope's key, which the store holds and no export or sink receives.
  `gateway journal open` checks a request against an entry.
- **Answers are unchanged, byte for byte.** The entry is written after the answer, and a journal
  failure never delays or changes one.
- **The journal is best effort.** A record dropped at a bound is counted. One lost in an abrupt stop
  is not.
- **What the member needs:** `identity`, and `limits` with a request rate for every scope. Each
  journal is capped at `maxBytesPerScope`, 64 MiB when left out. Its last sixteenth is kept for
  tallies: once a scope's refusal entries stop at the cap, its counts still land, until a closing
  tally marks the journal full. One caller at its own rate can fill its scope's room.
- **No route serves a journal.** `/posture` gains a fixed `refusal-journal` line with no counts.
- **Removal:** `remove-scope` removes the scope's journal and key, and its operator journal entry
  records what it removed.
- **Delivery version `"3"`.** `receiptSink.deliveryVersion: "3"` sends acquisition receipts, action
  receipts, seals and refusal entries in one envelope, `{deliveryVersion, kind, digest, …}`,
  acknowledged by `digest`:
  - `/act` now answers only once its receipt is acknowledged, or answers `503`
    `receipt_not_forwarded` with the action carried out and the receipt held;
  - refusal entries are forwarded after their answers and never hold one;
  - a sink not moved to `"3"` receives exactly what it receives today;
  - upgrade the sink first, then the gateway, then the configuration.
- **Older verifiers.**
  - A verifier of the operator-journal release reports a store holding a refusal journal as
    `journal-entry-forged`. Verify with this release.
  - A verifier of v0.38.0 or earlier passes the journal over and reports nothing of it.
  - An older export reader refuses an export that holds one.
- **The cost:** a refused request that was charged now costs one signing, off the answer path. Size
  a key service's quota for it.
- **The bound:** one scope's refusals can still shift the latency of shared points, such as the
  signer, the store and the sink, by at most one journal signing and one delivery in flight. The
  journal bounds that effect; it does not remove it. Under a key service one signing can take up to
  5 seconds, and a quota shared with the journal can make an answer's signing fail, not only slow:
  size the quota for the journal's signings.
