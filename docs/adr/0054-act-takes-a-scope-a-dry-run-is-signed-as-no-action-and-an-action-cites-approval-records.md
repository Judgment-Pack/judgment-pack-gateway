---
status: accepted
date: 2026-11-22
deciders: maintainer
---

# `/act` takes a scope, a dry-run is signed as no action, and an action cites approval records

## Context and problem statement

`/act` has three gaps (#506; the specification side is judgment-pack-spec #391).

- **No scope.** A write source and an action receipt are of no scope identifier (SPEC.md §6,
  "Caller scope identifiers"). A platform fixed to a scope identifier allows no write, and the
  configuration refuses one that sets `write: true` (ADR-0026, decision 9). ADR-0026 names this
  record's condition as a reason to revisit: "when `/act` … needs to reach a scoped platform".
- **No dry-run.** A caller cannot learn whether a write would pass the session, the requesters, the
  decision policy and its arguments without sending it. A refused `/act` sends nothing, but a request
  that passes is sent.
- **No approval citation.** An action receipt names the decision record and the receipts it relied
  on (§1.2a, `decision` and `cites`). It cannot name the record, kept outside the gateway, that
  approved the write: either a single approval of this action, or a **standing promotion record**
  that authorizes an automation to make writes of a class over time. RFC 0014 leaves approval
  evidence open (its unresolved question 1), and §1.2a says a receipt "does not say the identity
  approved it".

Three meanings of "scope" are already in the format, and this record keeps them apart. The **scope
identifier** is §1.2a's `scope`, ADR-0026's label for the party a source serves. A **delegation's
scope** is the source, tool, effect and limits of a link (§11.5, step 11). An **action key's first
scope** is the authority, key, issuer and subject of the first holder (§1.2b, `keyScope`). This
record adds a scope identifier to `/act`. It changes neither of the other two.

## Decision drivers

1. **Nothing changes for a request that uses none of this.** A configuration that fixes no write
   source to a scope identifier, and a request with no `scope`, `dryRun` or `approvals`, behave as
   they do in v0.38.0: the same refusals, in the same order, with the same bodies; a receipt the same
   bytes, Ed25519 or ES256; journal entries the same bytes.
2. **One scope learns nothing of another** (ADR-0041). No refusal, answer or timing of a request in
   one scope depends on the sessions, keys, records or configuration of a scope the caller does not
   reach.
3. **A dry-run is never an action.** No verifier accepts it as one: neither a verifier of this
   release nor one already released (v0.38.0, Go and TypeScript). No citation resolves to it.
4. **A dry-run is never a probe of the write target.** It does not start the executor, it does not
   run the read-back, and it does not use the platform's credentials. It returns nothing the target
   said.
5. **A citation is a claim.** The gateway records what the requester names and says so. It does not
   check an external record that it cannot read.
6. **Refusals come before anything durable.** A scope refusal comes before a session is admitted,
   before a label is recorded, and before an action key is locked, read, reserved, or given a first
   scope.
7. **The format before the surface.** Both verifiers and the corpus read every new form before the
   gateway mints it (§6: "the format was specified before the surface").

## Considered options

For the scope:

- **A.** Reuse the top-level `scope` and `scopeSalt` that §1.2a already admits on either kind, and
  give `/act` a `scope` request member read as `/acquire` reads it. *(chosen)*
- **B.** Add a new member, `action.scope`, inside the action.
- **C.** Bind the scope to the action key's first scope or to a delegation, with no request member.

For the dry-run:

- **D.** A `dryRun: true` member on `/act`, answered with a **dry-run receipt**: a signed form of its
  own, with its own version member and signing prefix. It is not a receipt of a session, and it is
  neither chained nor retained. *(chosen)*
- **E.** A version 3 action receipt that carries `action.dryRun: true`, in the session chain.
- **F.** A version 3 receipt with a new `kind`, `"dry-run"`, in the session chain.
- **G.** A separate path, `POST /act/dry-run`.
- **H.** An unsigned preview.

For the citation:

- **I.** `action.approvals`, an array of `{kind, id, digest}` that the requester supplies. The gateway
  checks only its form, and `kind` is `"single"` or `"standing"`. *(chosen)*
- **J.** The same, with no `kind`.
- **K.** The gateway resolves each citation against an approval-record directory, as it resolves the
  decision record.
- **L.** A decision-policy member that requires a citation of a given kind.

## Decision outcome

Chosen: A, D and I. A reuses what the format and both verifiers already hold: an action receipt with
a scope verifies under v0.38.0 today. D is the only dry-run option that an already released verifier
refuses as an action, wherever the dry-run receipt is put. I records the requester's claim of what
kind of record it cites, so that a reader of receipts alone can sort single approvals from standing
ones, and a verifier can report a single approval cited twice.

### 1. The scope on `/act`

**The receipt member.** An action through a write source fixed to a scope identifier carries the
top-level `scope`, the identifier, and `scopeSalt`, its session's salt (ADR-0042). These are §1.2a's
members, with §1.2a's forms, under the signature. The format change is a single sentence: §1.2a's
"this gateway mints it on acquisitions alone, since a platform fixed to a scope identifier allows no
write" becomes "on an acquisition and on an action of a source fixed to a scope identifier". No new
member is added, and no member moves.

Option B was not taken. It would put one fact in two places. A seal's `scopeDigest` holds a session's
receipts to the top-level member (§4 step 3, `seal-scope-mismatch`), and no released verifier would
read `action.scope`. Option C was not taken because neither existing scope names the party a write
serves (see the context section).

**The request member.** `/act` takes `scope`, a string, as `/acquire` takes it. It is compared with
the write source's scope identifier byte for byte, and held to the identifiers the caller's token
reaches (ADR-0037). It is read only where the configuration fixes some write source to a scope
identifier. Elsewhere it is refused as a member `/act` does not read, as it is today, so driver 1
holds. `keyScope` keeps its meaning: it is the authority-keyed first scope, not a scope identifier.

**Who may name it.** A sender that names a `reservation` (§11.8) has no chain and reaches no scope
identifier (§6: "never a scope identifier"); one that names `scope` is refused at the scope step. A
request under a delegation is held to its chain's scope binding, the RFC 0030 amendment of 2026-11-22
that binds a delegation chain to exactly one scope identifier (§2; SPEC.md §11.1). A delegated `/act`
may name a scope only when its chain is bound to that same scope identifier, the issuing host's
`scopeIds` lists it, and the subject's own caller entry grants it. Otherwise it is refused at the scope
step with step 8's sentence, before the session, the platform and any admission read. A chain bound to
no scope, or to another, never names one, and a chain bound to one names it. Delegation and scope
identifiers stay disjoint apart from that binding.

*Status.* Built for v0.40.0 with the binding. Until then every delegated request that named `scope`
was refused at the scope step. Step 10 holds a delegated request as it holds every caller: a write
source of another scope is refused with step 8's sentence. A scoped delegated action's read-back is
acquired with the action's scope in its admitted session, and the request check is not made for it.

**The configuration** (engine configuration version `43`). From that
version a platform may set `scope` beside `write: true`. Such a platform is refused at load unless
both of the following hold:

- `identity.callerScopes` is an object, so that callers are checked against scopes. A scope on a write
  that every caller may name is a label posing as a boundary. `/acquire` allows `"unchecked"`. A write
  does not.
- The platform names its own `decisionRecords` directory. It must not be the gateway's directory, the
  directory of another scope's platform, or a directory beneath or above either. It is held to the
  ownership and permission check at start that the gateway's directory is held to. An `/act` of that
  scope finds its decision record there and nowhere else. Two reasons settle this. First, the gateway
  has one decision-record directory, and today an `/act` can learn whether a record with a digest it
  names is there, whoever's record it is. Second, a write in one scope must not rest on a decision
  made for another. Unscoped writes keep the gateway's directory. `gateway verify --decision-records`
  takes a directory that holds them all, since its walk is recursive.
  *2026-11-22:* `/verify`, the engine's own verdict, reads the scope's own `decisionRecords`
  directory for a scoped action's record, and no other scope's directory or the gateway's.

Below that version both members are refused by name, as today. `writeRequesters` holds as before, and
the requester must pass both it and the caller-scope check. The MCP front still serves no write tool.

**The ladder.** The steps below are numbered in the order they are answered. Each new step is marked
*new*. Every other step is unchanged.

| # | `refusedAt` | Status | What is refused |
|---|---|---|---|
| 1 | `requester` | 401 | no identity configured (unchanged) |
| 2 | `scope-identifier` | 403 | before the body is read. Where no write source is fixed to a scope identifier, this is unchanged (a caller that does not reach the sources of none, with today's body). Otherwise a caller that reaches no write source is refused, with a sentence that names no scope |
| 3 | `storage` | 501 | unchanged |
| 4 | (none) | 400 | a member `/act` does not read. From the new version, the set includes `scope`, `dryRun` and `approvals` |
| 5 | `dry-run` | 400 | *new*; see decision 2 |
| 6 | `delegation`, `action-key` | as today | credential presented; `reservation` authenticated |
| 7 | `receipt-version` | 400 | unchanged |
| 8 | `scope-identifier` | 400 | *new*. `scope` is not a string; is named by a reservation sender; under a delegation, fails the chain's scope binding (spec RFC 0030 §2: a bound chain names its own identifier, which the issuing host's `scopeIds` lists, and an unbound chain names none); or is an identifier the caller does not reach. The error is `/acquire`'s sentence, `scope: the request's scope does not match the source's` |
| 9 | `session` | 400 | the label is looked up in the namespace of the request's scope, or none's when the request names none (ADR-0051). The session must be open, as today |
| 10 | `platform` or `scope-identifier` | 400 | a platform that is unknown or not a write. A caller that does not reach every source gets step 8's sentence at `scope-identifier` instead of `platform … allows no writes`, so it does not learn which platform names other scopes use (§6, `/acquire`). A write source whose scope identifier is not the request's, or that has one where the request names none, or none where the request names one, gets step 8's answer. The current refusal of every scoped write source here is removed from the new version |
| 11–14 | `tool`, `write-requesters`, `arguments`, `action-key` (form) | as today | unchanged |
| 15 | `decision`, `cites` | 400 | unchanged, with one difference. A scoped action resolves a citation only to a receipt of its own scope, and a receipt of another scope or of none is answered as one this engine does not hold. An action of scope S that cites scope T would carry T's session ids and signatures into S's export, and §4 could not resolve them there |
| 16 | `approvals` | 400 | *new*; see decision 3 |
| 17 | `decision` | 400 | the record is found in the scope's directory. The policy is applied as today |
| 18 | `action-key` | as today | lock, first scope, reservation, retained evidence, close (§1.2b, §11.8) |
| 19 | `platform`, `grant`, `session`, `delegation` | as today | publisher policy, grant, then session admission. The session must be of the action's scope: a session of another scope, a scoped session for an action of none, or a session of none for a scoped action is refused with ADR-0036's sentence, which names neither scope. Then the receipt sink, the marker, the counting admission and the executor |

Steps 8 and 10 come before step 18, so no scope refusal locks, reads, reserves or records anything of a
key (driver 6). Step 8 comes before step 9, so a label is never looked up in a namespace the caller
does not reach. A caller that names a scope it does not reach, together with the label of a sealed
session of that scope, is told the scope sentence and is never told "sealed".

**The key's namespace.** A key reserved by a scoped action lives in a namespace derived from the
authority, the scope identifier, the issuer, the subject and the key. Its first-scope record is in
that namespace too. A key of no scope keeps today's derivation byte for byte. A request in scope S
therefore never reads a reservation, first-scope record or close of scope T. In S, a key that T used is
a key never seen, and `action-key-scope-conflict` speaks only within one scope (driver 2). Nothing is
weakened by this. Within a scope every rule of §1.2b and §11.8 holds as written. Across scopes there
was no write before, so there was no protection to lose. The scope is not added to the approved
content, because the platform, which is already in that content, fixes it. The bound is stated: the
same key in two scopes names two actions. An operator whose two scopes' platforms reach one target
relies on the target's idempotency argument, as for two gateways.

**The read-back** of an uncertain scoped action runs that platform's `<platform>/live` in the
request's session, which is of the same scope. Its receipt carries `scope` and `scopeSalt`. For this
case the new version removes ADR-0026's refusal of a read-back of a scoped live source. A verifier of
this release adds one check to §1.2b's resolution: a read-back resolves its action only where both
carry the same `scope`, or neither carries one. Anything else is `action-reconciliation-unresolved`.
v0.38.0 does not make this check, and the gateway never mints such a pair.

**Removal.** `gateway remove-scope` also removes the scope's action-journal namespace, after its
sessions. It refuses, naming the key, while any key there is pending: dispatched without an answer,
or uncertain and not reconciled. A scope re-created under the same identifier starts with no keys.
The release notes say so.

### 2. The dry-run

**How it is asked.** `/act` takes `"dryRun": true`. Only the JSON value `true` is read. Any other
value, `dryRun` beside `keyScope`, `reconcile` or `reservation`, and `dryRun` under an engine that
mints version 2 receipts, are refused `400` at `dry-run` with `{"error", "refusedAt": "dry-run"}`.
`keyScope` and `reconcile` are refused because they are journal operations, and `reconcile` runs a
read-back. A reservation sender is refused because it never dispatches, so it has nothing to preview.
A gateway that does not read the member refuses the whole body before reading it (§6: "a write taken
from a member this engine does not read is one nobody asked for"), so a dry-run sent to an older
gateway is never a write.

Option G, a separate path, was weighed. It would let a proxy allow previews and block writes. It was
not taken because two handlers would drift, and the worth of a dry-run is that it runs the write's own
ladder. Option H was not taken because an unsigned preview cannot be shown to an approver as the
gateway's word.

**What it checks.** It runs the ladder of decision 1 through step 17, and through the publisher policy
and the named-grant check of step 19, with the write's refusals at each step and the same bodies. In
place of session admission it makes the same checks with no effect: the signer's gate is open, and the
session is not sealed, is not held by another instance, and is of the request's scope. The session's
directory is not made and the session is not held. On the filesystem kind, "held by another instance" is read as a session directory this process did not make. On a kind whose store is shared between instances, it is read from the session's lease, read-only, once `/act` is served there (2026-11-22; `/act` answers 501 on those kinds today). Under `engineVersion` 14 and later it requires
`actionKey`, as the write does. The key is applied to the idempotency argument, so the previewed
request is the one that would be sent, and nothing else is done with it.

Under a delegation, the run's actor alone may ask. The grant's state is read, and §11.5 steps 0 to 12
are made with the admission read at `"count": false`, which is the read the gateway already makes when
its own part of step 11 fails. The host counts nothing and the delegation's budget is unchanged.

**What it does not do.** It does not lock, read, reserve, close or give a first scope to an action key.
It does not record a label, make a session directory, hold a session, deliver to the receipt sink, make
a dispatch marker, use the grant or make its owner read, start the executor, run a read-back, or
consume any count. It writes nothing to the store or the registry. Its receipt is in no session and is
not retained. It is signed by the gateway's signer, so under a key service each dry-run is one signing
call.

A dry-run can therefore pass where the write would then be refused at step 18: a conflicting, closed,
taken or settled key. It establishes nothing about the key.

**The dry-run receipt** is SPEC.md §1.2c (new). It is a canonical JSON object signed over
`"judgment-pack-gateway/dry-run/1:"` followed by `canon` of the object without its `signature`:

| Member | Form |
|---|---|
| `dryRunVersion` | the string `"1"`: the member that marks it, inside the signing input |
| `authority`, `keyId`, `servedAt`, `signature`, `alg` (optional) | as in §1.2a; ES256 exactly as a receipt |
| `source` | `<platform>/write` |
| `scope` | optional, §1.2a's form; present exactly when the write source is fixed to a scope identifier |
| `delegation` | optional, §11.7's form; present exactly under a delegation, `admittedAt` being *t* of the non-counting read |
| `action` | `{requester, decision, cites, tool, request, policy?, approvals?}`: §1.2a's members, with `approvals` from decision 3; no `adapter`, `observedAt` or `delivery`, since no target answered |

It has no `receiptVersion`, `kind`, `sessionId`, `callIndex`, `prevSignature`, `resultDigest`,
`argumentsCommitment`, `witness`, `scopeSalt` or `artifact`. `action.request` is a fresh salted
commitment (`"request:"`) to `{tool, arguments}`.

**The response** is `200` with exactly `{"dryRun": <the dry-run receipt>, "request": {"tool",
"arguments"}, "salts": {"request"}}`. `request` is the object the executor would be handed, with the
gateway's idempotency argument set. A client that reads `receipt` from a `200` finds none. The caller
can show the request and its salt to an approver, who checks them against the signed commitment.
Neither the gateway nor a verifier links the dry-run to a later action: the action's commitment has
another salt, and an auditor who holds both salts compares them.

**The verifier rule** applies in Go and in verify-ts:

- **As a receipt, anywhere.** A dry-run receipt has no `receiptVersion`, so it is `malformed` at §1.4
  order 1 under every receipt verifier, v0.38.0's included: a file of a store, a receipt handed to
  verify-ts's receipt API, or a cited action. A verifier of this release says why, in the reason
  `a dry-run receipt is not a receipt of a session`. Its signature is under another prefix, so a
  dry-run receipt given a `receiptVersion` of `"3"` and a `kind` of `"action"` is `signature-mismatch`
  as well. A `cites` entry or a `reconciliation.action` names a session and an index, which a dry-run
  receipt has none of, so nothing resolves to it.
- **As itself.** `gateway verify-dry-run --public-key <key> [--public-key-alg ES256] <file>`, and
  verify-ts's `verifyDryRun(bytes, key)`, return `{ok, findings, dryRun: true}`. The finding is
  `malformed` for a form error (a missing member, `adapter`, `observedAt` or `delivery` present, or a
  member of §1.2a's forms out of form), `key-mismatch` for a `keyId` that is not the pinned key's, or
  `signature-mismatch`. `dryRun: true` is in every report, so no report of a dry-run receipt reads as
  an action's. Neither command reads a store.

Option E was not taken: v0.38.0 tolerates a member it does not know and would return `ok` for the
dry-run as an action (driver 3). Option F was not taken: v0.38.0 would refuse a new `kind`, but a
dry-run in the chain would make every store that holds one `malformed` under v0.38.0, which breaks
rollback. It would also spend session indexes on previews, and each preview would collide with the
index of the action that follows it.

### 3. The approval citation

**Members.** `action.approvals` is an array of 1 to 8 entries. It is present exactly when the request
names some, and an action that names none is the receipt it is today. Each entry is exactly
`{kind, id, digest}`:

- `kind` is `"single"`, a record that approves this one action, or `"standing"`, a standing promotion
  record that authorizes an automation for writes of a class over time.
- `id` is the record's identifier as its system names it, in the scope identifier's form (§1.2a: 1 to
  128 bytes of UTF-8, with no code point that display policy 1 refuses, and no tab or line feed),
  compared byte for byte.
- `digest` is §1.2a's digest, `"sha256:"` and 64 lowercase hexadecimal characters, of the record's
  exact bytes as its issuer keeps them. The gateway canonicalizes nothing, since the record's format
  is out of scope and may not be JSON. Another algorithm is a later form, and today it is `malformed`.

Two entries with the same `id` are refused. Entries are signed in the order given. The request member
is `approvals`, in the same form, read from the new engine version and refused at `approvals` when out
of form or empty.

**Why the kind is named** (I over J). The two kinds are reviewed differently, and a reader of receipts
alone cannot tell them apart without fetching records whose format this record leaves open. With the
kind, an auditor finds every action that an automation took under a standing record by `id` and
`kind`. A verifier can also report what a single approval should never show, which is a second use.
A verifier of this release adds the observation `approval-cited-again` (§4, "Observations") on each
action receipt of a store that cites a `single` entry, by `id` and `digest`, that another action
receipt of the store also cites. It is not a finding. Only one store is seen.

The kind is the requester's word, like the rest of the citation. A requester can label a single
approval `standing` to avoid the observation, and the receipt then records that it said so, under its
identity.

**How the gateway learns them.** From the request, and it checks only their form. It reads no record,
fetches nothing, and compares them with nothing: the decision record, the policy and the action key's
content are not compared. Option K, resolution against an operator-held directory, would establish
that a file with that digest was present before the write, as `decision` does. It is deferred because
approval systems keep their records elsewhere, and a directory would need a synchronization path that
this record does not design. Option L is deferred for the same reason: it would require only a claim,
so it needs K to mean much.

**The approved content.** `approvals` enters the approved content of §1.2b, but only when it is
present. A reservation made by a request that names none records `identityVersion` `"2"` and is
unchanged byte for byte. One made by a request that names some records `"3"`, which is version 2's
content plus `approvals`. A request whose approvals differ from those of its key's reservation is
refused as `action-key-conflict`, so the receipt of a dispatch names exactly the approvals of the
request that dispatched it. An older gateway refuses a version 3 reservation as `action-journal-invalid`
(§1.2b), which fails closed.

**What a verifier can conclude.** On a receipt that verifies under the gateway's key, it can conclude
that the requester the receipt names claimed, before the write was sent, that these records of these
kinds and digests authorized it. A v0.38.0 verifier tolerates the member, returns its earlier verdict,
and reports nothing of it. No verifier can conclude that a record exists, says what it is claimed to
say, was made by anyone in particular, was in force at `servedAt`, covered this scope or this write, or
was not withdrawn. A party that holds the record re-digests its bytes and judges it by its own format,
against `servedAt`.

### 4. Compatibility

- **Receipts.** An action of no scope that names no approvals is byte for byte the receipt it is
  today, under Ed25519 and under ES256. Every acquisition, seal and registry line is unchanged.
- **Verifiers already released.** An action receipt with `scope` and `scopeSalt` verifies under v0.38.0,
  Go and TypeScript, which hold both members on either kind and hold the session to the seal. An action
  receipt with `approvals` verifies `ok` under v0.38.0, which does not report the approvals. A dry-run
  receipt is `malformed` wherever v0.38.0 meets it as a receipt. v0.38.0 has no dry-run command.
  v0.38.0 makes neither the read-back scope check nor the observation.
- **Journals.** Reservations of no scope and no approvals are unchanged. Scoped namespaces are new
  names that an earlier release never opens, since it refuses a scoped write platform at load.
- **Rollback.** A configuration of the new version is refused by name by an earlier release. Before a
  rollback, settle every key that a request with approvals reserved: an earlier release answers it
  `action-journal-invalid`. A store that holds scoped action receipts verifies under the earlier
  release.
- **Engine configuration.** `43`, for the scoped write platform, the
  platform's `decisionRecords`, and the request members `scope`, `dryRun` and `approvals`. Below it
  everything is refused as today.

### 5. The specification side (#391)

The action receipt's form is the gateway's (SPEC.md §1.2a). The specification repository's dialect
companion §10 and RFC 0014 refer to it and do not define it, and its conformance surface is the
gateway's corpus (RFC 0014, "Conformance"). The specification pull request changes only text:

- `spec/dialect.md` §10 gains one paragraph. It says an action receipt may name its write source's
  scope identifier and the approval records its requester cites (gateway §1.2a, `scope`,
  `action.approvals`). It says a citation is the requester's claim, so "not that a person approved the
  write" stands. It says a dry-run (gateway §1.2c) holds a request to the same policy, sends nothing,
  is not an action receipt, and establishes nothing about a later write.
- `rfcs/0018-dialect.md` holds the same §10 text. It gains that paragraph as a dated amendment, and its
  accepted body is left as it is.
- `rfcs/0014-lineage-record-and-action-binding.md` gains an amendment: §4 names the three members;
  §7's table gains rows for the dry-run receipt (gateway §1.2c, `corpus/dry-run`) and for
  `action.approvals` (§1.2a, `corpus/v3`); "Conformance" names the new corpus cases; unresolved
  question 1 is narrowed, not closed (an action can cite a record, and what would evidence approval is
  still open); and "What identity does not establish" adds that a citation evidences nothing either.
- Any other document that lists an action receipt's members, such as `docs/concepts/roles-in-a-record.md`
  if it does, is brought in line.
- **Vectors.** No vectors go in the specification repository. The verifier vectors for each new member
  and each form refusal are the gateway corpus cases of the build plan. The `/act` refusals are the
  gateway's tests, not vectors, because no verifier reads a request.
- **The release number.** The release is v0.6.1, and `specVersion` stays 0.6.0. No Core schema, no
  Core text (`spec/judgment-pack-core.md`) and no released conformance case or row changes. The change
  is to companion and RFC text, which VERSIONING.md lets a patch release carry. The release needs one
  prerequisite. `tools/build_release.py` (lines 88 to 96 and 984 to 988) refuses a patch tag for a
  `specVersion` that has no normative record, and only `releases/v0.5.0.normative.json` exists. So
  `releases/v0.6.0.normative.json`, derived from tag `v0.6.0`, and its pinned SHA-256 must land before
  the v0.6.1 tag.

### 6. Security

- **A citation is a claim, not a proof** (decision 3). The receipt says this in the format text, and
  §1.2a's "does not say the identity approved it" is kept, with the citation named in it.
- **Disclosure.** `id` is in the clear in every receipt. An identifier that names a person or a
  subject discloses it, so systems should mint opaque ones. `digest` is unsalted. Anyone who holds a
  candidate record can test it against the digest, so a record with little entropy (an approver and a
  time, say) can be guessed. A record format should carry a random nonce. The same holds of
  `decision.recordDigest` today.
- **No cross-scope oracle.** Step 8 comes before the session lookup. Step 10 gives one sentence for a
  platform that is unknown, a platform the caller cannot reach, and a scope mismatch. Keys are
  namespaced by scope. Citations resolve within the scope. Each scope has its own decision-record
  directory. ADR-0036's session sentence names no scope. Together these answer a request in scope S
  from S's state and the configuration of what the caller reaches, and from nothing else. A dry-run
  adds no answer that the write's own refusals do not give.
- **A dry-run is not a probe of the write target** (decision 2). Its only reads beyond the gateway,
  under a delegation, are the issuing host's non-counting admission read and the custody's grant state.
  Neither is the target. Its time does not depend on the target.
- **A dry-run is a policy oracle for permitted writers.** A requester can learn which arguments a
  decision policy admits without making a write. It could learn this today only by being refused or
  by writing. This is bounded to callers that pass `writeRequesters` and the caller-scope check, who
  may write anyway. Each dry-run walks the decision-record directory and signs once, so under a key
  service it costs one signing call. Under a key service that every scope shares, a permitted writer
  of one scope could spend the signing quota of all of them. The per-scope limits of the rate and
  connection record (gateway #507) therefore count every `/act` request, dry-runs included, and that
  record's design states it. Until those limits are built, a dry-run is no more limited than `/act`
  is.
- **A citation is no existence oracle.** An unscoped action may cite a scoped receipt, as today,
  since a citation needs the receipt's 128-hex signature: a caller who can name it already holds it.
- **Fail closed everywhere.** A lost `dryRun` member is refused by an older gateway, never sent. An
  older verifier refuses a dry-run receipt. An older gateway refuses a reservation with approvals. A
  scoped write without checked caller scopes is refused at load.

### Consequences

- **Good:** a party's writes are held to its scope identifier like its reads, with a seal over both.
  Every existing configuration, receipt and journal is unchanged.
- **Good:** a preview runs the write's own checks and is signed, and an older verifier can never take
  it for an action.
- **Good:** an action can name the approval it rests on, single or standing, under the signature, with
  no format imposed on the approval system.
- **Bad:** a scoped write platform needs checked caller scopes and its own decision-record directory:
  two more things for an operator to configure.
- **Bad:** the same key in two scopes names two actions.
- **Bad:** a dry-run says nothing about the key, so a passing preview can be followed by a refused
  write.
- **Bad:** a new signed form, a new prefix and two new verifier entry points. Each must be carried in
  Go and in verify-ts.
- **Revisit when:** a delegation is to reach more than one scope identifier; approvals are to be resolved or
  required (K, L); a single approval is to be refused on reuse rather than observed; or dry-runs are to
  be retained or rate-limited.

### What the release notes must say

- From engine version `43`, a platform may set `scope` with
  `write: true`. It then needs `identity.callerScopes` as an object and its own `decisionRecords`.
  `/act` then takes `scope` as `/acquire` does, and its receipts carry `scope` and `scopeSalt`.
- A scoped action's key is a different key from the same key in another scope or in none. A
  re-created scope starts with no keys. `remove-scope` removes the scope's journal and refuses while a
  key there is pending.
- A scoped action cites only receipts of its own scope.
- `/act` takes `"dryRun": true` and answers `{dryRun, request, salts}`, with no `receipt`. The dry-run
  receipt is signed under `judgment-pack-gateway/dry-run/1:` and is in no session and no store. It is
  checked with `gateway verify-dry-run` or verify-ts's `verifyDryRun`. Every receipt verifier,
  including v0.38.0, calls it `malformed`. It says nothing about the action key. Under a key service
  each dry-run is one signing call.
- `/act` takes `approvals`, which the receipt carries as `action.approvals`. Each entry is the
  requester's claim, checked for form only. v0.38.0 verifies such a receipt `ok` and shows no
  approvals.
- A key reserved with approvals is refused `action-journal-invalid` by an earlier release. Settle such
  keys before a rollback.
- The new observation is `approval-cited-again`. The new read-back finding is
  `action-reconciliation-unresolved`, for a scope that differs between the read-back and its action.
- `/act` has new `refusedAt` values, `dry-run` and `approvals`, and a body-level `scope-identifier`
  that answers `400`. The pre-body `scope-identifier` keeps its `403`.
- The specification side is judgment-pack-spec v0.6.1, and `specVersion` is 0.6.0, unchanged.

### What is not established

- That a cited record exists, is genuine, or was in force at the time. No check is made (decision 3).
- That a dry-run's outcome holds at the write. The session, the key, the record, the policy, the
  budget and the grant can all change in between.
- That a dry-run receipt and a later action are the same request, unless an auditor compares the two
  commitments with both salts.
- Reuse of a single approval across stores, or across gateways.
- Whether the decision-record walk's cost per dry-run needs a bound beyond #507's per-scope limits.
  It is not measured, as for `/act` today.

### Build plan

The changes go in four pull requests. Each runs its touched tests only. CI does the full run. A
security-focused review is done on G2 and G3. At most ten mutants are run in total, each on a
safeguard and in a scratch copy, and every one must make a named test fail.

1. **Spec PR (#391, judgment-pack-spec).** Contains the text of decision 5 and a CHANGELOG entry. A
   separate release-prep PR adds `releases/v0.6.0.normative.json` and its pin. No mutants.
2. **G1, the format (gateway).** SPEC.md §1.2a (the `scope` sentence, `action.approvals`, the
   read-back scope check), §1.2c (the dry-run receipt), §4 (`approval-cited-again`), and §6 (the text
   of `/act`, which stays inert until G2 and G3). Both verifiers. `gateway verify-dry-run` and
   `verifyDryRun`.
   - Corpus `corpus/v3/stores`: `v3-action-scope-valid` and `v3-action-scope-seal-mismatch`. The
     approvals cases: `v3-action-approvals-valid`, `-kind-other`, `-digest-uppercase`,
     `-id-control-character`, `-empty`, `-nine-entries`, `-id-twice`, `-member-extra` and
     `-appended-after-signing`. Then `v3-action-single-approval-cited-again` (the observation) and
     `v3-readback-scope-differs`.
   - New family `corpus/dry-run`: `valid`, `p256-valid`, `adapter-present`, `member-missing`,
     `relabelled-as-receipt`, `in-a-store`, `key-mismatch` and `signed-under-the-receipt-prefix`.
     Each case also records v0.38.0's verdict.
   - Mutants: (1) the dry-run's prefix equal to the receipt's, which `relabelled-as-receipt` catches;
     (2) the `approvals` kind enumeration dropped, which `-kind-other` catches.
3. **G2, `/act` scope (gateway).** The engine version. The scoped write platform, `callerScopes` and
   `decisionRecords` at load. Steps 2, 8, 10, 15, 17 and 19. The key namespace, the read-back and
   `remove-scope`.
   - Tests: each refusal and its order against a key that would otherwise be reserved, with the
     journal unchanged after a scope refusal; a scope the caller does not reach, named with a sealed
     session of that scope, answered with the scope sentence; two scopes with one key, and each
     reserving; an unscoped configuration's `/act` answers compared byte for byte with v0.38.0's.
   - Mutants: (3) the reach check of step 8 removed; (4) the scope dropped from the key namespace;
     (5) step 15 resolving another scope's citation; (6) step 17 using the gateway's directory for a
     scoped write; (7) the `callerScopes` load check removed.
4. **G3, dry-run and approvals on `/act` (gateway).** Step 5, the non-counting path, step 16, and
   identity version 3.
   - Tests: a dry-run leaves the journal, the store, the labels, the sink and the session state
     unchanged; an executor whose name resolves to nothing is never started; a fake issuing host sees
     `count: false`; a delegated dry-run from a reservation sender is refused; a v2 reservation
     replayed with approvals is a conflict; a request with no approvals has its journal bytes compared
     with v0.38.0's.
   - Mutants: (8) the dry-run reaching step 18; (9) the dry-run's admission read at `count: true`;
     (10) approvals left out of the approved content.

### Options not taken

Covered above: B and C (decision 1); E, F, G and H (decision 2); J, K and L (decision 3). One more
option was not taken: a per-scope decision-record directory left optional. It would leave the
cross-scope record oracle open for every operator who does not set it.

This record supersedes nothing. It amends ADR-0026 (decision 9: a scoped write source and its
read-back), ADR-0036 (an action is of its session's scope), ADR-0037 (the `/act` rule) and ADR-0049
(dry-run receipts are not forwarded, like every `/act` receipt).

## More information

SPEC.md §1.2a (`scope`, `action`), §1.2b, §1.4, §4, §6 (`/act`, "Caller scope identifiers", "Who may
ask for a write", "Removing one scope identifier's records"), §11.5, §11.7, §11.8; `go/act.go`
(`actKeyed`, `admitAction`), `go/serve.go` (`/act`), `go/action_execution.go` (`actionNamespace`),
`go/verify_v3.go`, `verify-ts/src/structure.ts`; ADR-0011, ADR-0026, ADR-0036, ADR-0037, ADR-0041,
ADR-0042, ADR-0049, ADR-0051, ADR-0053; judgment-pack-spec `VERSIONING.md`, `spec/dialect.md` §10,
RFC 0014, RFC 0018, RFC 0030 §4.

## Acceptance

Accepted by the maintainer's reviewer on 2026-11-22, with these settled:

- The citation's `kind` values are `"single"` and `"standing"`.
- A single approval cited again is reported by the verifier (`approval-cited-again`) and not refused
  by the gateway; the issuing host checks reuse.
- Resolution against an operator-held directory (option K), and a policy that requires an approval
  (option L), are deferred to a later record.
- RFC 0018 §10 gains the paragraph as a dated amendment; it is not frozen.
- An unscoped action may still cite a scoped receipt (decision 6, "A citation is no existence oracle").
- Two conditions are folded in: a delegated scoped write is lifted by the RFC 0030 scope binding in
  v0.40.0 (decision 1, "Who may name it"); and #507's per-scope limits count dry-runs (decision 6).
