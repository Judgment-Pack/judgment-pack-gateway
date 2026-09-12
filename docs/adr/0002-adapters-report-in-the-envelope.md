---
status: accepted
date: 2026-09-12
deciders: maintainer
---

# Adapters report their acquisition inside the result envelope

## Context and problem statement

[ADR-0001](0001-one-engine-four-processes.md) keeps the source contract of SPEC.md §6 as the
only channel between the signer and an adapter: canonical arguments on stdin, one JSON
result on stdout, and says the contract grows only when an adapter needs a richer channel.
Receipt version 3 (SPEC.md §1.2a) records an acquisition — which system, which statement,
which snapshot, through which adapter — and for every shape but `"command"` those members
are things only the adapter knows. The question is how they reach the signer without a second
channel, and which of them the signer takes on the adapter's word.

## Decision drivers

- One request, one result: the contract ADR-0001 chose, and the one every existing source
  already satisfies.
- The signer decides what is signed. An adapter must not be able to choose its own `shape`,
  have the `statement` member stored in the clear, or assert digests of items the signer
  itself holds.
- Byte-lineage, not truth: the record may be the adapter's testimony, but the receipt must
  say so, and a compromised adapter must remain unable to sign.

## Considered options

- **A. An envelope inside the result.** A source declared with `--source-shape` writes
  `{acquisition, result, page?}`; the gateway attests `result` and records `acquisition`.
- **B. A second channel** — a third descriptor, a sidecar file, a header line — carrying the
  acquisition beside the result. A new contract for every adapter and for the spawn code, for
  no isolation gained.
- **C. Configuration only.** The gateway fills the record from what it configured (the
  binding, the endpoint) and records nothing per call. Loses the snapshot, the statement and
  the schema, which are the members that make a receipt answer "which query, which version".

## Decision outcome

Chosen option: **A**. SPEC.md §6 "Adapter sources" states the envelope and §1.2a "Where the
members come from" states the division:

1. The gateway records the eight members as the adapter reported them — `adapter`,
   `endpoint`, `snapshot`, `peerIdentity`, `schema`, `upstreamToken`, `observedAt`, and the
   statement — after holding each to its stated type and form.
2. Three members are the gateway's alone: `shape` is what the operator declared with
   `--source-shape`; `statement` is the gateway's salted commitment to the text the adapter
   reported, its salt returned as `salts.statement`; `pageItems` is computed by the gateway
   over the items of the result it attests, when the envelope says `page: true`.
3. Any departure from the envelope is a refusal of the whole acquisition, with nothing minted
   and nothing retained. A version 2 gateway refuses an adapter source outright.
4. A bare command's output is never read as an envelope: the shape is declared by the
   operator, so no source can promote itself by writing the right members.

### Consequences

- Good, because every adapter is a source: the spawn, the environment rule, the process
  group and the output bound of `serve` apply unchanged, and the boundary tests of
  ADR-0001 keep meaning what they say.
- Good, because the receipt states its own epistemics: an adapter-shape record is the
  adapter's testimony under the signature, and SECURITY.md says what that adapter can do
  (misreport) and cannot (sign — provided the operator gave it an identity that cannot read
  the seed, which nothing in this change enforces; an adapter run as the signer can read the
  seed, as any source can, and the engine configuration is where that refusal belongs).
- Bad, because only `statement` is committed: an adapter that repeats its query in
  `endpoint`, `snapshot` or the result has put it in the receipt or the artifact in the
  clear, and the text says so rather than promising otherwise.
- Bad, because the adapter binary the gateway spawned is not itself named in the receipt:
  `adapter` is what the adapter reports (a connector image, for the `airbyte` shape), and
  the spawned program is attributable only through the source name and the engine release
  that shipped it. Naming both would be a format change with vectors, recorded here as the
  open question.
- Bad, because a page's items are re-digested by the gateway in the signer's process; the
  output bound (`--source-max-output`) is what keeps that work finite.
- Revisit when an adapter needs a streamed page sequence or a long-lived session, as ADR-0001
  already says; or when the open question above is answered in SPEC.md.

## More information

SPEC.md §1.2a and §6; `go/serve.go` (`parseEnvelope`, `adapterAcquisition`); the tests under
"adapter sources" in `go/teeth_test.go`.
