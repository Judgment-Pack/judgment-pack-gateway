---
status: accepted
date: 2026-09-30
deciders: maintainer
---

# A write is held to its decision by a policy the operator configures, before it is sent; the receipt names the policy, and the verifier compares what an action claims of its record

## Context and problem statement

`POST /act` holds that the decision record a request names exists under the decision-record
directory with the stated digest, and that the receipts it cites are in the engine's store under
its key. It reads nothing inside the record. The verifier does the same after the fact
([receipt-v3.md](../design/receipt-v3.md), open question 5, and issue #186).

A clean-room integrator reproduced, against the real handler, that `/act` executes a write and
signs a receipt citing a record that requested a handoff; that decided `deny` while the write
sets `status: approved`; that was decided on the facts of revision 3 of a quote while the write
targets revision 4; that was decided under another pack than the request names; that cites other
receipts than the request does; and that the runtime marked `"reviewed": false`. A reader who
sees `decision` on a signed action receipt can take it to mean that the decision permitted the
write. The receipt does not say that, and nothing held it.

The integrator's requirements: checks before the write is sent, since a check after it is too
late to stop a refund; the allowed outcome set by the operator's configuration and never by the
request; the write's arguments bound to the record's facts; and an authenticated record of which
policy the write passed.

## Decision drivers

- A write the operator has said must follow a decision is refused, with nothing sent, when the
  decision does not say what the write assumes.
- What a write is held to is the operator's to say, in the configuration, per tool; the request
  is the party being checked and says nothing of it.
- A tool the operator holds to nothing behaves exactly as before.
- The receipt says what was checked, under the signature, and no more than was checked.
- The verifier keeps grading a store it did not produce, from the store and the records alone.
- The cost the open question names stands: reading the record couples this repository to the
  runtime's record format and version.

## Considered options

- **A. Compare in the verifier only**: the record's pack digest and citations against the
  receipt's, after the fact.
- **B. Hold the write in the executor** to a policy the operator configures per tool: the
  record's outcome, its handoff, its pack, whether it was judged under reviewed law, and the
  equality of named arguments with named facts; the request's own claims held to the record too.
- **C. Say in `SPEC.md`** what `decision` does and does not establish, and read nothing.
- Take the allowed outcome from the request. Declined: the request is what is being checked.
- Leave the binding of the object written to a precondition on the target (a revision or an ETag
  compared on write). Not declined, and not enough: it closes the interval between a check and a
  commit where a target offers one, and says nothing of whether the decision was about that
  object at all.

## Decision outcome

Chosen: A, B and C together. B is the only one that stops a write before it is sent; A is what a
verifier holding the store and the records can check of any action receipt, whether its tool was
held or not; C is what a reader needs to know of a receipt either way.

Determinations:

1. **A decision policy, per write tool, the operator's.** A platform entry of the engine's
   configuration may carry `decisionPolicy`, an object keyed by write tool name. Each policy is a
   closed object: `outcomes`, required, a non-empty array of outcome ids; `packs`, optional, a
   non-empty array of pack digests; `reviewed`, optional, a boolean; `bind`, optional, an array of
   `{"argument": <JSON pointer into the request's arguments>, "fact": <JSON pointer into the
   record's inputs.facts>}`. The configuration refuses an unknown member, a member of another type,
   an entry named twice in a list, a pointer that is not an RFC 6901 pointer, a policy for a tool
   the platform's write binding does not name, and a policy on a platform without `write: true`.
   The member moves `engineVersion` to `"4"` under the rule that a member change moves the
   version ([engine-config.md](../design/engine-config.md)); a file of an earlier version is
   refused by name with it. `connect` keeps a policy on an entry it replaces, since it has no flag
   for one, and refuses a replacement the policy would no longer fit; it never lowers a file's
   version.
2. **The executor holds a write to its policy before anything is sent.** For a tool with a
   policy, after the record is found (step 7), three steps follow, each a refusal naming its step
   and executing nothing ([executor.md](../design/executor.md)): the record must be a **runtime
   evaluation record** (determination 6), or the request is refused at `record`; the record's
   `pack.digest` must equal the request's `decision.packDigest`, and the record's `cites` must
   equal the request's as a set, or it is refused at `consistency` — a record with no `cites`
   matches no action, since every action cites; and the record must meet the policy, in this
   order: its disposition is an `outcome` whose `outcomeId` the policy lists
   (`policy-outcome`), its handoff state is `none` (`policy-handoff`), its pack is one the policy
   lists when it lists any (`policy-packs`), it carries `"reviewed": true` when the policy asks
   for it (`policy-reviewed`), and for each binding both pointers resolve and the two values are
   equal as JSON values with their types (`policy-bind`). Equal means the same bytes in the
   canonical form of `SPEC.md` §1.1: the string `"4"` never equals the number `4`, member order
   does not matter, and a fact outside the canonical domain equals no argument, since arguments
   are held to it. A refusal names the check and never a value of the record's. The bytes judged
   are the bytes whose digest matched. For a tool with no policy, `/act` reads nothing in the
   record and is unchanged.
3. **The receipt names the policy.** An action receipt for a tool with a policy carries
   `action.policy`: `"sha256:"` and the SHA-256 of the canonical form of the tool's policy object
   as configured, which for that object is its RFC 8785 form too — its member names are fixed
   ASCII and it holds no number. It is absent for a tool with none. It is signed with every other
   member, so the receipt says which policy the write passed, beside the decision digest and the
   request commitment it already carries. `SPEC.md` §1.2a gains it, optional; a verifier holds it
   to its form and to nothing else, since it holds no configuration to recompute it against.
4. **The verifier compares what it can.** When an action receipt's record is found and is a
   runtime evaluation record, the verifier compares the record's `pack.digest` with
   `decision.packDigest` and the record's `cites` with the receipt's as a set, and reports
   `decision-pack-mismatch` and `decision-cites-mismatch`, each beside the receipt's `ok`
   (`SPEC.md` §4 step 8). A record it does not understand is not compared: the report says so of
   the receipt in a new member, `observations`, as `decision-record-not-compared`, and fails
   nothing. The report had no place for a statement that fails nothing, and this is the smallest
   that fits its shape: an array of entries like a receipt's finding, absent when empty, never a
   part of `ok`, and not read by the corpus runner. Four vectors hold the new statuses and the
   member, and one holds a record that is not compared; the second implementation, `verify-ts`,
   answers to them.
5. **What `decision` establishes, stated beside it** (`SPEC.md` §1.2a). Without a policy: that a
   record with the stated digest exists and that the cited receipts verify — not that the record
   permitted the write, that its outcome is the one the write assumes, that its inputs are the
   object written, or that the target was unchanged since. With a policy: exactly the policy's
   checks, and no more. A precondition on the target is still the only thing that closes the
   interval between the check and the commit, and that is the target's or the plugin's to
   supply; `bind` stops a substituted object, not a concurrent edit.
6. **A runtime evaluation record** is what the runtime's audit trail writes of one pack
   evaluated on one facts document (runtime ADR-0018): one JSON object — read as `SPEC.md` §1.1
   reads a document, a member name twice at any depth, a string that is not UTF-8 or holds a lone
   surrogate each making it none, but with a number of any form admitted, since the runtime writes
   facts as their caller spelled them — whose `recordVersion` is `"1"`, whose `kind` is
   `"evaluation"`, and whose `pack` carries a digest. It is a regular file whole or a line of a
   `.jsonl` file, never a `.jsonl` file whole. A graph composite is not one: it carries no pack
   and no inputs to bind, and whether a write may be held to a composite is left to a later
   decision.
7. **The engine's configuration version.** [ADR-0007](0007-the-engine-serves-the-adapters-it-ships.md)
   determination 1 named `"4"` as the version its `services` member would move the file to, under
   the same rule. `services` is not built; `decisionPolicy` moves the file to `"4"` first, and
   `services` takes the next version when it is built. This replaces that number and nothing
   else of ADR-0007.

### Consequences

- Good, because a write through a tool held to a policy cannot be sent on a decision that
  requested a handoff, decided another outcome, was made under another pack, was judged under
  draft law, or was made about another object than the one written, as far as the policy binds
  it — the cases the integrator reproduced are refused before the executor starts.
- Good, because the receipt says which policy the write passed, under the signature, and a
  request cannot choose the policy it is held to.
- Good, because a verifier holding the store and the records catches an action whose claims its
  runtime record does not bear out, whether or not its tool was held.
- Good, because a tool with no policy, and every receipt made before this record, mean exactly
  what they meant.
- Bad, because the engine and the verifier now read another project's record format. A new
  `recordVersion` is a change here: a tool held to a policy refuses every record of it, and the
  verifier stops comparing them, until this repository reads it.
- Bad, because a write cannot yet be held to a graph composite, and a tool held to a policy
  refuses one.
- Bad, because a fact spelled `4.0` does not bind to an argument `4`; a fact outside the
  canonical domain binds to nothing. The refusal is the safe side of it, and the runtime records a
  fact as its caller spelled it.
- Bad, because `reviewed` without `packs` holds a write to whatever reviewed-set lock is current,
  not to particular reviewed bytes: an edited pack, locked again, yields records with
  `"reviewed": true` and a new pack digest, and such a policy admits them. `packs` is the member that
  names the reviewed bytes (gateway issue #196).
- Bad, because the digest names the policy as configured: a policy with `"reviewed": false` and
  one without the member make the same checks and have two digests; and a reader needs the
  configuration to know what a digest stands for, since the receipt does not carry the policy.
- Bad, because the verifier's comparison can be sidestepped by a record it does not understand:
  an opaque file, a composite, a record without a pack digest. It says so of the receipt and does
  not fail it. The executor, under a policy, refuses such a record before the write.
- Bad, because the verifier's report grows a member. A consumer that reads `ok` and `findings`
  is unaffected; one that holds the report to exactly those two members has to allow it.
- Bad, because a refusal names the check and not the value, so a requester who wants to know
  which outcome was recorded reads the record.
- Bad, because `bind` compares at the moment of the check. A write to an object that changed
  between the check and the commit is not caught here; only the target can refuse it.
- Revisit when the runtime's record version moves; when a write needs to be held to a composite;
  when a target offers a conditional write the executor could use; or when evidence of approval
  ([receipt-v3.md](../design/receipt-v3.md), open question 6) is decided.

### How this sits with earlier records

- [ADR-0001](0001-one-engine-four-processes.md) determination 7 stands: a receipt never asserts
  that an action was right or that it was authorized. `action.policy` says which checks, of a
  record and a request, the engine made and found to hold before it sent the write. That the
  write was right is not among them, and a token still proves only who asked.
- "A pack authorizes nothing" stands: the policy is the operator's configuration, not the pack's,
  and the record is evidence the policy is checked against.
- Of [ADR-0007](0007-the-engine-serves-the-adapters-it-ships.md), the version number of
  determination 1 (determination 7 above), and nothing else.

## More information

- `SPEC.md` §1.2a (`action.policy`, and what `decision` establishes) and §4 step 8.
- [The executor](../design/executor.md), [the engine's configuration](../design/engine-config.md),
  and [receipt version 3](../design/receipt-v3.md), open question 5.
- `go/decision_policy.go`, `go/act.go`, `go/verify.go`; the vectors
  `corpus/v3/stores/v3-action-policy*.json`, `v3-decision-*-mismatch.json` and
  `v3-decision-record-not-compared.json`.
- Issue #186.
- Material-decision categories: public-surface, documented-claim, conformance, security. The
  cross-vendor review is recorded on the pull request that carries this record.
