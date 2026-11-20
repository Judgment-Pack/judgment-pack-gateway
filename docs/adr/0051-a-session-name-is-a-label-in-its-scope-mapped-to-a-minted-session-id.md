---
status: accepted
date: 2026-11-19
deciders: maintainer
---

# A session name is a label in its scope, mapped to a session id the gateway mints

## Context and problem statement

Session names share one namespace across every scope identifier. A session id is what the
caller sends as `session`. It names a directory of the filesystem store
(`receipts/<sessionId>`, SPEC.md §3a), and a row of `gateway.series` keyed by name alone on the
PostgreSQL kind (`go/store_pg/migrations/0001_contract_spaces.sql`).

So a name one scope identifier uses is refused to another (`refusalOtherScope`,
`go/open_sessions.go`), while an unused name is accepted, and a caller of scope B learns that a
name is in use by some other scope. The time `/seal` takes tells the two apart as well.
ADR-0041 (decision 4) recorded this and deferred it until per-scope seals and verification
landed. They have (#478, ADR-0042).

Two more things follow from the shared namespace:
- The open `/registry` serves every seal, and each seal carries `sessionId`. So the name a
  caller chose is readable by anyone who can reach the gateway.
- A scheduled job, or any caller that names its sessions by something meaningful, has to
  choose names unique across every scope it does not know about.

The maintainer decided the direction on 2026-11-19 (#550). This record settles how it is
built.

Chosen by the maintainer on 2026-11-19 (direction, #550; label lifetime, point 5).

## Decision drivers

- What a caller of B is answered, and how long the answer takes, depends on B's state alone.
  No refusal, answer or read depends on whether another scope uses a label.
- No signed format changes. Receipts, seals, the registry line and the verifiers keep
  `sessionId` as today, unique across the gateway.
- A session belongs to its scope, not to a user. A scheduled job calls as it does today, with
  a workload token or as the installation's caller. Nothing needs a user identity.
- Existing clients keep working. Every name valid today is a valid label.
- Both store kinds, several PostgreSQL instances on one database included, agree on the
  mapping without a new lock.
- Removal, retention, export and store rotation keep their guarantees, and the mapping goes
  with the session it names.

## Considered options

- **(a) A label in the scope's namespace, mapped to a session id the gateway mints.** The
  gateway keeps `(scope, label) → sessionId` in the store.
- **(b) A session id derived from the scope and the label**, for example a keyed digest of
  both. This needs no stored mapping. But the key becomes a secret every instance and every
  verifier-side tool must share. A label can't be reused after its session is removed without
  deriving the same id again. And a lost key orphans every label.
- **(c) Keep the shared namespace and require unguessable names** (ADR-0041's guidance). This
  leaves the refusal and the timing difference, and puts the whole burden on callers.

## Decision outcome

Chosen option: **(a)**. It is the only option that removes the disclosure without a shared
secret, and it keeps every signed form as it is.

### 1. The mapping

- **Labels.** A label has the form a session id has today: `^[A-Za-z0-9._-]{1,128}$`, with `.`
  and `..` refused. So every existing client's names stay valid. A label is never a path
  component (below), so the form is kept for interoperability, not for path safety.
- **Session ids.** On a label's first use in its scope, the gateway mints a session id: 32
  lowercase hexadecimal characters from 128 random bits (`crypto/rand`). It is of the session
  id form, so the store, the registry and the verifiers read it as any other. If a minted id
  is already a session of the store (probability 2⁻¹²⁸ per pair), it is minted again.
- **The namespace.** A label's namespace is the scope the session is of, as ADR-0036 fixes it:
  the scope identifier of the source, or the `scope` the request names where the source is of
  several, or **none**. A session of no scope identifier has a namespace of its own, `none`.
  So a source fixed to no scope, `"unchecked"`, and a gateway without `identity` label their
  sessions there.
- **Callers that reach several scopes.** The installation's caller, and a caller whose token
  reaches several scopes, label in the scope of each request. The same label in two scopes is
  two sessions. A caller is never answered from a namespace it does not reach.

### 2. Where the mapping is kept

- **Filesystem kind.** One file per label at `<root>/labels/<hex>.json`.
  - `<hex>` is SHA-256 over `"judgment-pack-gateway/session-label/1:" + canon({"label": L,
    "scope": S})`, where S is the scope identifier or `null`.
  - The file holds the canonical `{"label", "scope", "sessionId"}`.
  - It is created exclusively (`O_EXCL`), synced, and its directory synced where the platform
    syncs one (as `store rotate` does), **before** the session's first receipt is written. A
    crash after that leaves a mapping with no receipts. The next request with the label
    reuses its id, and nothing is lost.
  - The verifiers do not read `labels/`. SPEC.md §3a lists it as a store member a verifier
    passes over, as it lists `artifact-removals.jsonl`'s place.
- **PostgreSQL kind.** Migration 0009 (0007 is the rotation mark, #546, and 0008 the key
  history, #560) adds `gateway.session_labels`:
  - `scope` (as `series.scope`: `'none'` or `'scope:' || identifier`), `label`, and `series`;
  - primary key `(scope, label)`, `series` unique;
  - row-level security by `gateway.scope`, as every scoped table has.
  - The run-time role is granted `INSERT` and `SELECT`. `DELETE` is the migration login's,
    for removal and retention.
  - First use is `INSERT … ON CONFLICT (scope, label) DO NOTHING RETURNING series`, then a
    `SELECT` where the row exists. Two instances racing on one label agree on one id, without
    the start lease or a lock of their own.
- **What is never exposed.** `/registry` serves seals, and seals carry the minted id. No
  label and no scope identifier reaches it. The receipt still carries `scope` in plain text
  and the seal its salted `scopeDigest`, as today.

### 3. The surface

- **`/acquire`** takes `session` as a label. It answers as today: the receipt it returns
  carries the minted `sessionId`, and that is how a caller learns it for verification, export
  and citation. Nothing new is added to the answer. A label whose session is sealed is
  refused with the answer a sealed session gets today. A label names one session for its
  life (below).
- **`/seal`** takes `session` as a label and `scope` as ADR-0041 reads it. It looks the label
  up in the namespace of the scope named, or in `none` where no scope is named.
  - A label not in that namespace is answered `no such session: <label>`, with no read of the
    registry or of another scope's state. That removes the one cross-scope answer ADR-0041
    kept (`session is sealed in the registry`) and its timing.
  - A label mapped to a sealed session is answered as today.
  - The seal record answered carries the minted `sessionId`.
- **`/act`** takes `session` as a label, in the namespace of the action's scope (today, none:
  `/act` writes are of no scope). `cites[].sessionId` stays a session id: it names signed
  receipts, which carry ids.
- **The MCP front** keeps `randomSessionName()` per transport session and sends it as the
  label. In the caller form a transport session that calls tools of two scopes now opens two
  sessions under one label, one in each namespace, where today it is refused. The caller-form
  seal tool gains an optional `scope` argument, checked against the caller's reach and
  forwarded as `/seal`'s `scope`. The fixed front names its own scope, as today.
- **Operator commands** take session ids, as today: `seal-open --session`, `remove-artifact
  --receipt`, `export`, `verify`. One new command maps the other way:
  `gateway sessions --config <c> --scope <s|none> [--label <l>]` prints `label sessionId` lines
  for the scope. It reads the store with the gateway running or stopped, and writes nothing.

### 4. The upgrade

- The behaviour is engine configuration version 39 (`labelsVersion`), a version of its own:
  35 to 38 are taken (the receipt sink 35, the key service 36, receipt-sink seals 37,
  retention 38).
- At an older version nothing changes, and the name a caller sends is the session id.
- At the new version, the start refuses while any session is open, and names
  `gateway seal-open --all`. Sealed sessions keep their ids and need no mapping, since nothing
  is acquired into them again. So no existing session is ever addressed by both a name and a
  label.
- On the PostgreSQL kind, every instance moves together: stop all, seal-open, start all on the
  new version. An instance at the older version is refused beside one at the new version, by
  name, as an instance on another key version is (ADR-0050). The instances on one database
  are admitted beside one another by the rows of `gateway.start_lease`: each start records
  its instance in its row, and `admitBeside` (`go/store_pg_lease.go`) compares each live
  row's `key_id` and `authority` with its own and refuses with `errInstanceMismatch`.
  Migration 0009 adds the column `labels boolean NOT NULL DEFAULT false` to that table. An
  instance whose configuration is at version 39 or later records `true` in its row, and
  one at an older version `false`. `admitBeside` compares `labels` as it compares `key_id`,
  so an instance with labels on beside one with labels off is refused by name
  (`errInstanceMismatch`), by the same path, whichever of the two starts second. A binary
  that ships no migration 0009 does not serve a database migrated to it: it refuses a
  schema newer than itself, as it does today.
- Going back to an older version needs the same: every session sealed first. The older
  engine then reads the store as before and passes over `labels/` and `session_labels`.

### 5. Removal, retention, export and rotation

- **`remove-scope`** and **`gateway store remove-scope`** remove the scope's label entries
  with its sessions, after the session-removal records are durable and the receipts gone.
  A crash between the two leaves labels naming removed sessions. A label naming a session
  recorded as removed is refused as a sealed one is, and the rerun the removal already asks
  for removes the labels.
- **`gateway retain`** and **`gateway store retain`** (ADR-0048) remove a session's label
  entry with the session, in the same order.
- After removal a label is free again. Its next use mints a new id, so it starts a new
  session and can't reach the removed one.
- **`export`** does not carry labels. They are not signed, verification does not need them,
  and they are the caller's own words. An export cut by `--scope` lists session ids, as
  today. An operator who needs a label's session reads it with `gateway sessions`.
- **`store rotate`** (ADR-0048, S2) seals what is open. The new store starts with no labels,
  so a label used before the rotation starts a new session after it. The old store's labels
  stay with the old store and go when it is deleted whole.
- **The receipt sink** (ADR-0049) is unchanged. It is sent receipts, and later seals, which
  carry ids.

### 6. What stays the same

- The receipt, the seal, the registry line, `scopeDigest`, the verifiers and the corpus's
  signed vectors.
- The ADR-0036 rule that a session's receipts are of one scope. With the new version it holds
  by construction: a label in one scope's namespace can't name a session of another, so
  `refusalOtherScope` is no longer reached from `/acquire`.

### Consequences

- Good, because a caller of B gets the same answers, in the same reads, whether or not another
  scope uses a label. That closes ADR-0041's last disclosure, by refusal and by time.
- Good, because the names callers choose no longer reach the open `/registry`.
- Good, because a scheduled job can name its sessions by job and run without knowing other
  scopes' names, under the same token it calls with today.
- Bad, because the store holds one more thing that must be kept, removed and rotated with
  sessions: a `labels/` directory, or a table and a migration.
- Bad, because a caller that wants to verify or cite must read the minted id from the receipt.
  It can no longer assume the id is the name it sent.
- Bad, because the upgrade needs every session sealed first, which is a stop on the
  PostgreSQL kind's several instances.
- Bad, because a label names one session for its life: a job reusing one label after a seal
  is refused, and must label each run.
- Callers of one scope, for example a user and a scheduled job, share one label namespace.
  So one of them can learn, by a refusal, that a label is in use within its own scope. This
  is by design: the namespace is the scope, and a scope's callers reach the same sessions.
- Revisit when a caller needs a label to name "the current session" across seals. That would
  be a pointer moved by `/seal`, with its own rules for which session a label then means.

## More information

- Issue #550. ADR-0036 (a session is of one scope), ADR-0037 (caller scope identifiers),
  ADR-0041 (decision 4, deferred here), ADR-0042 (per-scope seals and verification), ADR-0048
  (retention and store rotation), ADR-0049 (the receipt sink), ADR-0050 (key versions across
  instances).
- SPEC.md §3a (the store layout: `labels/` named as passed over), §6 (`/acquire`, `/seal`,
  `/act`: `session` read as a label from the new engine version). No signed form changes.
  Vectors: a store holding `labels/` verifies as the same store without it.
- Code to touch at the build: `go/store.go` (`sessionPattern`, the label form),
  `go/open_sessions.go` (the lookup before the claim), `go/serve.go` (`acquireWithScope`,
  `sealFor`), `go/act.go`, `go/mcp.go` (the seal tool), `go/remove_scope.go`,
  `go/store_remove_scope.go`, `go/retain.go`, `go/store_retain.go`,
  `go/store_pg/migrations/0009_session_labels.sql` (with the `labels` column of
  `gateway.start_lease`), `go/store_pg_lease.go` (`admitBeside`), `go/engine.go`.
