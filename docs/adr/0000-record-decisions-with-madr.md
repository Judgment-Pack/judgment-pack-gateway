---
status: accepted
date: 2026-09-12
deciders: maintainer
---

# Record gateway decisions with MADR-format ADRs, and place this repository under the interim review regime

## Context and problem statement

This repository has carried its cross-cutting decisions in three places that are not its own:
the research line's records in `judgment-pack-evaluator-experiments` (its ADR-0002 opens the
trustworthy-input-acquisition line this gateway deploys), the specification's draft RFCs 0010 to
0012 (signing identity, currency anchor, witness contract), and `SPEC.md` itself, which is
normative for the format but is not where a decision about *the repository* belongs. Decisions
that are neither format nor research — what this repository ships, how its modules relate, what
its release contains — have had no home, and the first such decision ([0001](0001-one-engine-four-processes.md))
is large enough that leaving it in a pull-request body would lose it.

## Decision drivers

- A stance like "the signer is never linked to an adapter" is owned by no single diff and must
  be findable without reading `git log`.
- `SPEC.md` must stay a specification of the format, not a changelog of repository choices.
- The specification repository's review regime already governs material decisions in the
  runtime; a repository that mints the trust root should be under at least the same discipline.

## Considered options

- Markdown ADRs (MADR) under `docs/adr/`, as the runtime does.
- Fold repository decisions into `SPEC.md` as informative sections.
- Keep relying on pull-request bodies and the records of neighbouring repositories.

## Decision outcome

Chosen option: MADR-format ADRs under `docs/adr/`, on the runtime's conventions, because the
decisions are already made and the record should stay cheap enough to write. The boundary
between records is the same one the runtime draws:

- **This repository → ADRs.** What the gateway ships, how its modules relate, what its release
  contains. Recorded after the fact, immutable once accepted.
- **`SPEC.md` → the format.** What a receipt is and how it verifies. A change there follows
  [CONTRIBUTING.md](../../CONTRIBUTING.md) and moves the frozen corpus with it.
- **The specification repository → RFCs.** Anything that needs agreement across independent
  implementations or touches the Judgment Pack Specification.

**Review.** Every material decision in this repository follows the interim review regime the
specification repository records in its `GOVERNANCE.md` and designed in its RFC 0009, on the
same terms the runtime adopted: a recorded adversarial review by a model from a different vendor
than any model that assisted the drafting, a written disposition per finding, the reviewed commit
named, and a `Material-decision impact:` line on every pull request. [README.md](README.md)
states the regime for this repository; this record is what places the repository under it. The
pull request that introduces this record is the first one reviewed under it.

### Consequences

- Good, because a reader asking why the adapters live in this repository, or why the signer runs
  alone, finds one file.
- Good, because the review obligation now attaches to the repository that holds the trust root,
  rather than being inherited informally from neighbours.
- Bad, because it is a second place to keep honest beside `SPEC.md`; an accepted record that no
  longer holds must be superseded, never edited or ignored.
- Revisit when the repository gains a contributor community that needs comment-before-commit,
  at which point some decisions may warrant an RFC process of their own.

## More information

Status lifecycle: `proposed` → `accepted` → (`deprecated` | `superseded by NNNN`). See
[README.md](README.md) for how to add a record and for the review regime in full.
