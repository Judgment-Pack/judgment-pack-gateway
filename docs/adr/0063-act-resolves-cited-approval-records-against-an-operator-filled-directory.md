---
status: proposed, 2026-11-24 (option K decided by the maintainer on gateway #581; the directory, the refusal, the scope rule, the byte-identity rule and the unchanged key settled before the build; the mark's form, the segment rule and the bound chosen here)
date: 2026-11-24
deciders: maintainer
---

# /act resolves cited approval records against an operator-filled directory, and the receipt marks the citations it resolved

> **Summary.**
>
> - **Chosen (ADR-0054's option K, as the maintainer decided it on gateway #581):** a member of
>   engine configuration version `52` (`approvalRecordsVersion`), `approvalRecords`, names an
>   approval-record directory: the gateway's, and a scoped write platform's own. The operator fills
>   it. Nothing is synchronized or fetched.
> - **A record** is the file `<dir>/<kind>/<id>`, and its digest is the SHA-256 of the file's bytes.
>   Resolution looks at three names and hashes one file, at most 1 MiB of it. It walks nothing.
> - **Every citation must resolve** before the decision record is looked for and before anything of
>   the key is touched. One that does not is refused `400` at `approvals` with one fixed sentence.
> - **The receipt marks it:** `action.approvalsResolved: true`, under the signature, beside
>   `approvals`, on an action whose citations all resolved.
> - **Without the member,** and below version 52, nothing changes, byte for byte. A citation is then
>   the requester's claim, as ADR-0054 has it. The action key and its identity never change.
> - Option L (a policy that requires a resolved citation) is gateway #622, not this record.

## Context

ADR-0054 decision 3 lets an action cite approval records as `action.approvals`, each
`{kind, id, digest}`, and checks only their form. A citation is the requester's claim. ADR-0054
deferred option K because approval systems keep their records elsewhere, and a directory would need
a synchronization path. The maintainer decided on #581 that the operator fills the directory, by
whatever means it chooses, and that the gateway only reads it. Decision records are the model:
`decision` already resolves its record in a directory per scope (ADR-0054 decision 1).

## Decision

### 1. The member

`approvalRecords` is an absolute path of plain spelling, at the top level and on a platform. It is a
version-52 member. Below 52 either one is refused by name:
`approvalRecords is a version-52 member; engineVersion <m> has no approvalRecords`, with
`platform <name>:` before it for a platform's.

Resolution is turned on by naming the directory, not by the version. At 52 a configuration without
the member is read exactly as at 51, and every citation stays a claim. A gateway that refused every
citation at 52 would make the upgrade itself a refusal of writes that worked the day before.

### 2. Placement, ownership and the scope rule

The directories are placed as `decisionRecords` are:

- A platform's `approvalRecords` is allowed only on a write fixed to a scope identifier. Elsewhere it
  is refused by name, because an unscoped write resolves in the gateway's.
- Where the gateway names one, every write fixed to a scope identifier must name its own. Otherwise
  one scope's citations would stay claims while the gateway's are resolved, and the operator would
  not see it.
- A scoped write's directory is never the gateway's, never another scope's, and never beneath or
  above either (`approvalRecordsApart`). The load compares spellings; the start compares what each
  resolves to, as `decisionRecordsApart` does. Platforms of one scope may share one.
- At start each directory must be there, a directory and not a link, because the gateway never makes
  it and resolution follows no link. It is then held to `holdDecisionRecords`: it, everything
  beneath it and every directory on the way to it are owned by root, the signer or its owner, and
  writable by nobody else.

A scoped action resolves in its platform's directory alone (`approvalRecordsFor`), and an unscoped
action in the gateway's alone. No action looks in another scope's directory. Its answer is therefore
the same, byte for byte, whether or not another scope holds the record (ADR-0041).

### 3. Resolution

At step 16a, after `approvals` is held to its form, each citation is held to the segment rule:

- `kind` and `id` are each one path segment: not empty, not `.` or `..`, and with no `/`, `\`, NUL or
  other control character.
- Every code point is below U+0300.

No code point below U+0300 decomposes, combines or is reordered under NFC. Such a segment is
therefore in NFC, and no other spelling of it names the same file on a filesystem that normalizes
names. Telling an NFC segment with higher code points from a non-NFC one needs the Unicode
normalization tables, which the module does not carry (it has no dependency). So every code point at
or above U+0300 is refused, whether or not the segment is in NFC: ids outside that range are
refused, and gateway #624 records the choices for accepting every NFC segment. A citation outside
the rule is
refused `400` at `approvals` with a sentence that states the rule and names the citation's index.
That sentence is decided by the request alone, before any file is looked at.

Then each record is resolved:

1. `Lstat` of the directory and of `<dir>/<kind>`: each must be a directory, not a link.
2. `Lstat` of `<dir>/<kind>/<id>`: a regular file, not a link. The directory's listing must hold
   `<kind>`, and `<dir>/<kind>`'s listing must hold `<id>`, each byte for byte, because a look by
   name succeeds by another case of the name on a filesystem that folds case. A citation of `CHG-1`
   is then not resolved by a record stored as `chg-1`.
3. The record is opened with `O_NOFOLLOW` and `O_NONBLOCK`. The descriptor's `fstat` must show a
   regular file, and it must be the file of step 2 (`os.SameFile`: the same device and inode).
4. At most 1 MiB + 1 byte is read. More than 1 MiB does not resolve, and the read stops there, so no
   file is read whole to learn that it is too long.
5. `"sha256:"` and the hex SHA-256 of the bytes read must equal the citation's `digest`.

A record that is missing, listed under another spelling of its name, not a regular file, a link at any level, longer than the bound, replaced
between steps 2 and 3, or of another digest does not resolve. Each is answered with the one sentence:

> a cited approval record does not resolve: every citation names a record this gateway holds, by its
> kind, its id and the digest of its bytes, before anything is sent

It names neither the directory nor a path. It does not say which check failed or which citation it
was. Every citation of the action must resolve, not only one. The refusal comes before the decision
record is looked for and before the key is locked, so it leaves no dispatch, no attempt, no
reservation and no receipt. A request on a key whose record has since been removed is refused in the
same way before its retained answer is read, as a removed decision record already refuses one.

On Windows, `O_NOFOLLOW` is not a flag. The open is plain, and the `Lstat` of step 2 refuses a link.
The engine configuration does not run there (`engine_other.go`), so no Windows gateway resolves a
citation.

### 4. The mark: one action-level member

`action.approvalsResolved` is `true` where every citation of the action resolved, and absent
otherwise. It is signed with every other member. The alternative was a `resolved: true` on each
`approvals[]` entry. The action-level member was chosen for three reasons:

- **It says what is true.** Resolution is all or nothing: an action with one citation that does not
  resolve is refused. A mark on each entry could express a partial resolution that the gateway never
  signs, and verifiers would have to classify it.
- **Older verifiers read it.** An `approvals[]` entry is exactly `{kind, id, digest}`, so a v0.40.0
  verifier would call every receipt with a fourth member `malformed`. An action receipt's `action`
  tolerates a member it does not know, so a v0.40.0 verifier returns the verdict it returned before.
- **It keeps the key.** `approvals` stays the request's own member, the one the key's approved
  content and identity version 3 are computed over (decision 6).

The mark is `malformed` (§1.4 order 1) when it is present and not the JSON value `true`, and when it
is present on an action with no `approvals`.

**What the mark proves.** A verifier holds no approval-record directory and resolves nothing again.
A receipt that verifies and carries the mark establishes that the signing gateway found a regular
file with each digest under its directory, at `<kind>/<id>`, before the write was sent. That
directory is the one for the action's scope. It does not establish what the record says, that its
issuer wrote it, or that it is there now. A receipt without the mark establishes what ADR-0054 says
of a claim.

### 5. A dry-run

A dry-run runs the write's ladder through the decision record, so it resolves the citations as the
write does. A citation that does not resolve refuses it with the same sentence. One whose citations
resolve carries `approvalsResolved: true` in its dry-run receipt's `action`, which `verify-dry-run`
accepts.

### 6. The action key and identity

Resolution is the gateway's fact, not the request's. The approved content of §1.2b and identity
version 3 are computed over the request's `approvals`, which resolution does not change. A key
reserved without the directory and replayed with it, or the reverse, is answered from its reservation
and is never `action-key-conflict`.

## Consequences

- **Good:** a receipt can tell a checked citation from a claimed one. Option L (#622) can then
  require a checked one.
- **Good:** no synchronization path is designed or run. The operator owns the directory's freshness.
- **Bad:** one more directory per scope for an operator who wants resolution. A scoped write must
  name one once the gateway names one.
- **Bad:** ids with a code point at or above U+0300 cannot be resolved, even in NFC.
- **Bad:** each resolution lists the directory and the kind's directory, read in pieces and
  stopping at the name, so its cost grows with the number of records of a kind.

## What is not established

- The intermediate level `<dir>/<kind>` is looked at with `Lstat` and then opened through. Someone
  who can write in the directory could swap it for a link and back between the look and the open.
  The start's ownership check limits that to root, the signer and the directory's owner. Opening
  each level relative to the one above would close it; the standard library has no portable call
  for that.
- The directory's ownership is checked at start, not on each request, as for decision records.

## Tests

`go/approval_records_test.go` and `go/approval_records_unix_test.go`: one citation and eight of both
kinds resolve; each way of not resolving gives the one answer, byte for byte, with no dispatch,
reservation or store change, and so does one bad citation among eight; each rejected segment; a
symlinked record and a symlinked kind directory; a record replaced, between the look and the read,
by a file of the same bytes; scope isolation with byte-identical answers; the bound and one over; no
directory answers as before; the member refused by name below 52, and a configuration without it
read alike at 51 and 52; the key replayed across the switch; a dry-run; placement and the start
check. Corpus vectors `v3-action-approvals-resolved`, `-claimed-only`, `-resolved-false`,
`-resolved-string` and `-resolved-without-approvals` are read by `gateway conform` and by verify-ts.
