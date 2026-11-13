---
status: proposed
date: 2026-11-13
deciders: maintainer
---

# Payloads a gateway does not keep: a source that keeps no payload, and a recorded removal

## Context and problem statement

A gateway keeps the bytes of every result it attests, under `<root>/artifacts/<hex>`, and has
no way to remove them; verification fails a receipt whose bytes are gone, `artifact-missing`
(SPEC.md §1.4, order 7). An operator whose sources return results it should not hold beyond
the call, or should stop holding after a time, has two choices today: keep the bytes, or
delete them by hand and have every receipt that named them fail (issue #422). The ask is a
receipt that stays checkable without the gateway holding the payload, in two forms: a source
that keeps no payload at all, and a removal of a kept payload that the store records. A
member under the receipt's signature, a record a verifier reads, and an operator command that
deletes bytes are specification changes, so this is a decision and not only a member.

## Decision drivers

- A receipt, a store and a configuration that use neither form keep their bytes, and verify
  exactly as before; every frozen vector is unchanged.
- The two new states pass, and say so, in a way a reader can tell from a receipt whose bytes
  were checked; a receipt whose bytes are gone with no record still fails as it does now.
- Neither form may hide a changed payload: bytes that are there are always re-digested, and
  bytes supplied by a reader are re-digested too.
- A record of a removal is one only the gateway's key can make, and one that cannot be moved
  to another receipt.
- A verifier written before the change fails where this one passes, and is stated.
- No new dependency in `go/`.

## Considered options

1. **A signed receipt member for the first form, and a signed record in the store for the
   second, both read by the artifact step (chosen).**
2. **One receipt member for both**: a removal re-mints the receipt with the member. Refused: a
   receipt is never replaced (the store contract), and a re-minted receipt breaks the chain
   of every receipt after it in the session.
3. **Removal records in the registry**, as seal lines. Refused: a verifier written before the
   change would read an unknown kind of line in the walk, and every receipt of the store
   would change verdict, not only the removed ones; the registry is the seals' anchor, and a
   removal anchors nothing.
4. **A store-writer-made record, unsigned.** Refused: one who can write to the store could
   then make any receipt whose bytes it deleted pass.
5. **A new passing status** (`artifact-not-retained` as a ladder status in place of `ok`).
   Refused: every reader that acts on `ok` per receipt would read the new status as a
   failure, and the ladder's statuses are failures; an observation beside `ok` is how the
   verifier already says something of a receipt without failing it (SPEC.md §4,
   "Observations").

## Decision outcome

Chosen option 1, in these determinations:

1. **The receipt member.** A version 3 acquisition receipt may carry the top-level member
   `artifact` with the one value `"not-retained"`, under the signature (SPEC.md §1.2a). Any
   other value, or the member on an action, is `malformed`. Version 2 does not define it.
2. **The configuration.** A platform may set `artifact: "not-retained"` from engine
   configuration version 22 (`docs/design/engine-config.md`); absent means kept. Its history
   and live sources then return the result, digest it, write nothing under `artifacts/`,
   and mint the member. The value mirrors the receipt's, so one word names the state in
   both places. Refused beside `write: true`, since `/act` and its recovery read an action's
   result back, and before version 22 by name. Allowed beside `mcp`, `scope` and a
   delegation, which change nothing of what is kept. `connect --replace` keeps it.
3. **The removal record.** `gateway remove-artifact` appends, to
   `<root>/artifact-removals.jsonl`, a record naming the receipt by `sessionId`, `callIndex`,
   `receiptSignature` and `resultDigest`, with `removedAt`, `removedBy` and `keyId`, signed
   by the key in force under its own context prefix
   (`judgment-pack-gateway/artifact-removal/1:`), and then removes the bytes. The receipt's
   signature in the record binds it to one receipt; the key binds it to the gateway.
   `removedBy` is a label of the form of a scope identifier, required, and checked against
   nothing: the command has no authenticated operator to name.
4. **What loads.** A record loads when it holds exactly its nine members, each of its form,
   under a key the walk reached, its signature verifying. It names a receipt when the four
   naming members are the receipt's and its key is the receipt's or a later one, so a key
   retired before a receipt was minted cannot record its removal. A line that does not load
   is nothing the verifier reports, as a torn line of an interrupted append is not.
5. **The artifact step.** Bytes read at `<root>/artifacts/<hex>` are re-digested, whatever
   the receipt carries and whatever records name it. Where nothing is there, a receipt with
   the member or named by a record passes order 7; one with neither is `artifact-missing`.
   Something there that yields no bytes is `artifact-missing`, as it was. Bytes a reader
   supplies with `--artifacts <dir>` are re-digested for a receipt that passed order 7 with
   none in the store; another digest is `artifact-mismatch`. Supplied bytes are never read
   for a kept receipt with no record.
6. **Distinct outcomes.** Five states, five outcomes: bytes there and matching, `ok` with no
   observation; never kept and no bytes checked, `ok` with `artifact-not-retained`; removed
   under a record that loads and no bytes checked, `ok` with `artifact-removed`; gone with no
   record, `artifact-missing`; wrong bytes, in the store or supplied, `artifact-mismatch`.
   Bytes checked and matching are `ok` with no observation in every state: the bytes were
   checked, as for a kept receipt. The observations are additive members of the report, as
   the existing ones are; no status is renamed and no passing status added.
7. **The command's refusals.** It runs with the gateway stopped and its registry held, as
   `gateway seal-open` does. It refuses a receipt that does not have ladder status `ok`
   (so bytes changed before a removal are not removed), an action, a receipt that carries the
   member, a receipt whose `scope` `--scope` does not give byte for byte (one sentence,
   naming no identifier, as `/acquire`), and a receipt whose digest another receipt in the
   store needs: one not named in the same run, not carrying the member and named by no
   record, or a descriptor statement or snapshot. It appends the record before it removes
   the bytes, so a stop between leaves bytes that are checked; a second run completes it and
   appends no second record.
8. **Every ordering, stated.** Bytes changed then removal asked: refused, the receipt
   `artifact-mismatch`. Removed then other bytes put back: `artifact-mismatch`. Removed then
   the same bytes put back: `ok`, no observation. A record for a receipt whose bytes are
   there: the bytes are checked. A record copied to another receipt, or signed by a key the
   walk did not reach: loads or names nothing, `artifact-missing`. Two receipts of one digest,
   one removed: refused unless both are named or the other needs no bytes.
9. **Citations and sealing.** A receipt with either outcome has ladder status `ok`, so `/act`
   resolves a citation of it and `gateway seal-open` seals its session; an action reads no
   cited payload. An action's own result is always kept.
10. **A verifier written before the change** — `v0.26.0`, in Go and in TypeScript, read from
    its source at that tag and run over the new vectors — tolerates the member, reads no
    removal record and refuses `--artifacts` as a usage error: it reports `artifact-missing`
    for both new passing states and agrees elsewhere, but for a member not of its form on a
    receipt whose bytes are there, which it passes.

### Consequences

- Good: an operator can run a source whose results it does not hold, and stop holding a kept
  result, without losing a receipt's check; a reader holding the bytes can have them checked.
- Good: a receipt without the member, and a store without the file, read as before.
- Bad: a reader that verifies a store without the bytes learns that the call was made and
  what it returned the digest of, not what it returned. A consumer that needs the bytes must
  keep them (SPEC.md §5a.4).
- Bad: one who can write to the store can delete the removal file, which turns removed
  receipts into `artifact-missing` failures; that is a denial, as deleting the bytes was, not
  a pass.
- Neutral: `removedBy` is a label, not an identity; who ran the command is the operator's to
  record elsewhere.

## More information

- SPEC.md §1.2a (`artifact`), §1.3a, §1.4, §4 ("Observations", "Supplied bytes"), §4.1, §5,
  §5a.4, §6 ("Payloads a gateway does not keep"), §7.
- `docs/design/engine-config.md`, `artifact`; `docs/design/store-contract.md`.
- Vectors: `corpus/v3/stores/v3-artifact-*.json` (`corpus/README.md`).
