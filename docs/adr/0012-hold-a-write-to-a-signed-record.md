---
status: proposed
date: 2026-10-02
deciders: maintainer
---

# A decision policy may require its record to be signed by a runtime key it names; the signature is read from the sidecar beside the record, and a key-rotation line is never followed

## Context and problem statement

A decision policy ([ADR-0011](0011-hold-a-write-to-its-decision.md)) holds a write to a record
under the decision-record directory, and what makes a file there a record is its shape. A record
written by hand, with the outcome, pack, `reviewed` and facts the policy asks for, passes the
strictest policy (issue #195). The policy holds a write to whatever record a writer of that
directory put there: an agent with access to the files, a storage layer, another process.

The runtime now signs each record of a chained audit trail (runtime ADR-0047 §2b). It appends
one line per record to `signatures.jsonl` beside the trail, signing the record's `trail`, its
`sequence` and the SHA-256 of its exact line bytes with an Ed25519 key the project configures.
The runtime's guide, `docs/building-with-packs.md`, "Record signatures, exactly", writes the
rule down for another implementation: the sidecar's lines, the bytes signed, how one record is
checked without its trail, key rotation, and a test vector. ADR-0047 names this repository's
part: a policy member, `requireSignedRecord`, with the runtime keys the policy trusts (issue
#198).

## Decision drivers

- A writer who cannot use a key the policy trusts cannot write a record the policy admits.
- The signature is checked over the bytes step 7 matched, never over a re-encoding.
- The rule is the runtime's written one, implemented here from the text and its vector, not
  from the runtime's code.
- What the operator must do when the runtime's key changes is simple to state and to check.
- A policy without the member, and every receipt made before this record, mean what they meant.

## Considered options

- **The keys a policy trusts**: Ed25519 public keys, or keyIds. A keyId names a key and cannot
  verify a signature; public keys.
- **Keys over time**:
  - **A.** Follow the sidecar's `key-rotation` lines from the first key the policy names, as the
    runtime's own verifier does with its keys in order.
  - **B.** Trust exactly the keys the policy names, whatever the sidecar says of rotations.
- **Where the signature is**: the sidecar beside a file the record is found in; any sidecar
  under the decision-record directory; a sidecar path in the configuration.
- **Where the step is**: after `record`, before anything in the record is compared; or last,
  after the policy's other checks.
- **Revocation from a sequence**, as the runtime's verifier takes one: declined here (below).

## Decision outcome

Chosen: public keys; **B**; the sidecar beside the record; the step after `record`. B needs one
line of the sidecar and one signature, reads nothing else of the sidecar, and leaves what the
gateway trusts in the operator's configuration. A asks the gateway to read the whole sidecar in
order and to settle the parts of the runtime's one-record rule its text leaves open (below), and
it lets a sidecar line change which key the gateway trusts.

Determinations:

1. **The member.** A decision policy may carry `requireSignedRecord`: a non-empty array of
   Ed25519 public keys, each 64 lowercase hexadecimal characters, as `jpack audit key public`
   prints one, none given twice. A key that is not the canonical encoding of a point (RFC 8032
   §5.1.3) is refused: a `y` of `p` or more, which the standard library's verifier reads modulo
   `p` as another key than the one written, or an `x` of 0 with its sign bit set. So is a key
   that encodes no point of the curve, since no signature verifies under it, and one of small
   order, since the standard library's verifier admits a signature under such a key that no
   secret made: the all-zero key, a plausible placeholder, is one. The member moves `engineVersion` to `"5"` under the rule that a
   member change moves the version ([engine-config.md](../design/engine-config.md)); a file of an
   earlier version is refused by name with it. `connect` keeps a policy as written and never
   lowers a version. The receipt's `action.policy` digest is over the policy as configured, so
   it covers the member and its keys in their order: the same keys in another order is another
   digest, though the checks are the same.
2. **The step, `policy-signed`.** For a tool whose policy sets the member, after `record` and
   before `consistency`, a refusal naming its step and executing nothing
   ([executor.md](../design/executor.md)):
   - the record must carry `trail`, 32 lowercase hex, and `sequence`, an integer from 1 to
     2⁵³−2: a record no chain numbers carries nothing a signature can name;
   - the record's bytes are its exact bytes: for a tool whose policy sets the member, step 7
     takes a line of a `.jsonl` file as the bytes before its `0x0A`, a `0x0D` among them, and
     does not remove one trailing `0x0D` as `SPEC.md` §4 step 6 does for the verifier and for
     every other policy. A record converted to CRLF is other bytes than the runtime signed, and
     is not found under the digest it signed;
   - a file named exactly `signatures.jsonl` must lie in the directory of a file the record was
     found in, a line of it or the file whole, found by the walk that finds the record: a regular
     file, never a link. The walk reads each file, the record and the sidecar alike, as the entry
     it found: through directories held one at a time from its root, each directory and the file
     judged not a link and the thing opened the entry's own, before the open and after it. A link
     put in place of either, or of a directory above them, after the walk judged it refuses the
     read, and the action with it;
   - one of its readable lines must be a record signature whose `trail` and `sequence` are the
     record's and whose `record` is `decision.recordDigest`, the SHA-256 of the exact bytes step
     7 matched; whose `keyId` is the keyId of a key the policy names; and whose signature
     verifies under that key over `judgment-pack-runtime/record-signature/1:` and the canonical
     form of `{"record", "sequence", "trail"}`.

   One such line admits the record, whatever other lines say. The refusal says which way it
   failed (no trail and sequence, no sidecar beside the record, no readable line naming it, a
   signature that does not verify under a trusted key, keys the policy does not trust) and never a
   value of the record's. The step comes first because whose record it is precedes what it says,
   and so a hand-written record learns nothing of which of the policy's checks it would fail.
3. **Keys over time.** A key signs here because the policy names it, and no `key-rotation` line
   is read. For an operator who rotates the runtime's key, that means:
   - **before the project names the next key,** add its public key to the policy: records the
     next key signs are refused until the policy names it;
   - **once no record the old key signed is still to be acted on,** remove the old key. Until
     then the gateway trusts it for every record, those signed after the rotation by a copy of it
     included, since it does not read the rotation. Removing it is this gateway's revocation, and
     it applies to every record and every trail at once: a revocation from a sequence on, which the
     runtime's verifier takes per trail, has no place in a policy that holds records of any trail;
   - **each change is a new policy,** with a new digest on the receipts made under it.
4. **What it establishes, and what it does not.** With the member, a record the policy admits was
   signed, in its exact bytes, by whoever holds one of the keys it names. So a writer of the
   decision-record directory who cannot use one of those keys cannot satisfy the policy with a
   record written by hand (#195), or with a signed record altered by a byte. It establishes
   nothing against the holder of a named key, the operator among them, who can sign any record
   with it. It does not establish that the trail is complete, when the record was written, or
   that the signing key was not copied; the runtime's checkpoints held by someone else, not this
   step, speak to those. Without the member, a policy holds a write to whatever record a writer of
   the directory put there, as before.
5. **The written rule, read for one record.** The runtime's guide says a reader checking one
   record without its trail applies its step 2 to the record signature for that record. This
   gateway reads that as follows, where the text leaves it open:
   - the record's `trail` and `sequence` are read from the record's own members, and the
     clauses of step 2 that need the trail (that line `S` exists, is chained and is not named
     damaged by a discontinuity) are not checked, since the trail is not read;
   - step 1's order is not applied: any readable line for the record that verifies admits it;
   - a line of at most 4096 bytes, its newline not counted, is read;
   - `sequence` is read only in an integer's spelling, as the canonical parser reads one, so a
     line spelling it `3.0` is unreadable;
   - a string member is read as its JSON value, so a line that spells one with an escape is
     readable.

### Consequences

- Good, because a record written by hand, or a signed record altered by a byte, no longer passes
  a policy that requires a signed record; the runtime's own vector, read by this rule, verifies.
- Good, because what the gateway trusts is in the operator's configuration and under the policy's
  digest, and nothing in the decision-record directory can widen it.
- Good, because a policy without the member, and every receipt made before, mean what they meant;
  the receipt's form and the verifier are unchanged.
- Bad, because an operator who rotates the runtime's key must change the policy too, and records
  the next key signs are refused until they do.
- Bad, because a key the policy still names is trusted for records signed after the runtime
  rotated away from it; only removing it from the policy stops that, and that refuses every
  record it signed.
- Bad, because a record copied away from its trail is admitted only where a sidecar holding its
  signature lies beside the copy.
- Bad, because the walk now reads every `signatures.jsonl` under the decision-record directory
  for a tool that requires a signed record, and a sidecar grows with its trail; the walk was
  unbounded already ([SECURITY.md](../../SECURITY.md)).
- Bad, because nothing here helps against the holder of a key, and the runtime's operator holds
  it.
- Bad, because a record whose trail was converted to CRLF is not found for a tool that
  requires a signed record, where the verifier and every other policy find it with its `0x0D`
  removed; such a record is not the bytes the runtime signed.
- Revisit when a policy needs a revocation from a sequence on, when the gateway witnesses a trail
  (runtime ADR-0047 §3), or when the runtime's sidecar or record-signature version moves.

### How this sits with earlier records

- Of [ADR-0011](0011-hold-a-write-to-its-decision.md), determination 1 in part, the closed set
  of a policy's members, which gains `requireSignedRecord`, a version-5 member (a policy without
  it is a version-4 member as before); and determination 2 in part, the steps after step 7, which
  gain `policy-signed` after `record`. The rest of ADR-0011 stands: what `decision` establishes
  with a policy is still exactly the policy's checks.
- [ADR-0007](0007-the-engine-serves-the-adapters-it-ships.md)'s `services` still takes the next
  version when it is built.

## More information

- `SPEC.md` §1.2a (`policy`, and what `decision` establishes);
  [the executor](../design/executor.md), step 9; [the engine's configuration](../design/engine-config.md).
- `go/record_signature.go`, `go/decision_policy.go`, `go/act.go`; the tests in
  `go/act_signed_test.go`, the runtime's vector among them.
- The runtime: ADR-0047 §2b, and `docs/building-with-packs.md`, "Signing the trail" and "Record
  signatures, exactly".
- Issues #198 and #195.
- Material-decision categories: public-surface, documented-claim, security.
