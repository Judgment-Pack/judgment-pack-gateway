# Architecture decision records

This directory records the cross-cutting decisions behind this repository — what the gateway
ships, how its modules relate, what its release contains — the ones no single commit or pull
request captures well.

These are **ADRs**, not the format. The split follows what a change would alter:

- **This repository → ADRs.** Repository decisions, recorded after they are effectively made.
  Lightweight; no comment-before-commit process.
- **`SPEC.md` → the format.** Normative for what a receipt is and how it verifies. A change
  there follows [CONTRIBUTING.md](../../CONTRIBUTING.md#changing-specmd) and moves the frozen
  corpus with it; it is never made by editing an ADR.
- **The specification repository → RFCs.** Cross-implementation proposals, and anything that
  touches the Judgment Pack Specification, in `judgment-pack-spec` under `rfcs/`.

[SPEC.md](../../SPEC.md) describes the format **as it is now**; ADRs record **why and when** the
repository became what it is. `docs/design/` holds design notes for work not yet decided or not
yet built; a design note graduates into an ADR when the decision is made, and into `SPEC.md`
when it changes what a verifier accepts.

## Adding a record

1. Copy [template.md](template.md) to `NNNN-short-title.md` using the next free number.
2. Write it, set `status: proposed`, and open it in the pull request that makes the decision.
3. On merge, set `status: accepted`. ADRs are immutable once accepted: a later change is a
   **new** ADR that supersedes the old one (which is then marked `superseded by NNNN`), never
   an edit.

**Partial supersession.** A later ADR may supersede a **named determination** of an earlier
record without superseding the record: the earlier record keeps its own status and its text is
not edited, and the index row for it carries the annotation naming what was superseded and by
which record.

## Review of material decisions

A **material** decision in this repository follows the interim review regime recorded in the
specification repository's
[`GOVERNANCE.md`](https://github.com/Judgment-Pack/judgment-pack-spec/blob/main/GOVERNANCE.md#interim-review-regime)
and designed in
[RFC 0009](https://github.com/Judgment-Pack/judgment-pack-spec/blob/main/rfcs/0009-interim-review-regime.md).
A decision is material when it changes a public surface, a documented claim, what the frozen
corpus accepts, the security posture, or a dependency boundary. The trigger is the decision, not
the paperwork: a material decision made without an ADR is still material, and skipping the ADR
does not skip the review.

Such a decision requires a recorded adversarial review by a model from a **different vendor**
than any model that assisted the drafting, with a written maintainer disposition for each
finding, on the pull request that makes the decision. The record states the commit SHA that was
reviewed. A material change after the reviewed SHA requires a fresh review, with one exception
mirrored from the regime: a change that implements a dispositioned finding of a review already
recorded on the same pull request is covered by that finding's disposition. *Vendor* means the
organization that controls the model's weights and training — the developer, not the API host
and not a reseller. *Assisted the drafting* means generated or revised text that survives in the
merged artifact, or planning, analysis, structure, or design choices supplied by a model and
relied on to produce it; paraphrase does not launder assistance. Applying an accepted finding in
one's own words does not make the reviewer a drafter, and adopting reviewer-generated text
verbatim under an accepted finding does not retroactively invalidate the review that produced it,
but the record says where each such adoption happened. ADRs are written after the decision and
are immutable once accepted, so the review attaches to the pull request, not to the ADR text.

The review obligation applies to the pull request that introduces this section and every later
pull request that makes a material decision, including one that supersedes an existing ADR.
Beginning with the introducing pull request, every pull request — material or not — carries the
declaration below. "Later" is determined by commit ancestry from the commit introducing this
section, not by a calendar date.

Every pull request in this repository states its impact in the description, on one line:

```
Material-decision impact: none
Material-decision impact: <category>[, <category>...]; review: <link to the review record on this PR>
```

Categories: `public-surface`, `documented-claim`, `conformance`, `security`, `dependency`.
`none` appears alone; otherwise list every category that applies, comma-separated, followed by
`review:` and a permanent link (or links) to review records covering every listed decision. A
test-only or behavior-preserving change is `none` unless it changes what `gateway conform`
accepts, which is `conformance`. Any change to what is signed, to canonicalization, or to the
verifier's findings is `conformance` and `security` together, whatever the diff looks like.
Adding, removing, or replacing a dependency in either module is `dependency`. `none` is a claim,
not a formality: it is the author classifying their own change, and it is wrong whenever the
change turns out to be material.

Materiality is classified by the maintainer, who is also the author — the weak point of this
arrangement, stated rather than papered over. What the declaration does is make silence a policy
violation: when the rule is followed, the classification is explicit, dated, recorded on the pull
request with the reviewed SHA, and contestable there. Model review substitutes for review breadth
while the project has a single maintainer; it is not decision authority, and following it confers
no conformance status on anything.

## Index

| #                                                   | Decision                                                                                             | Status   |
| --------------------------------------------------- | ---------------------------------------------------------------------------------------------------- | -------- |
| [0000](0000-record-decisions-with-madr.md)          | Record gateway decisions with MADR-format ADRs, and place this repository under the interim review regime | accepted |
| [0001](0001-one-engine-four-processes.md)           | One engine, four processes: ship adapters and the runtime with the gateway, out of process, in one repository | accepted |
| [0002](0002-adapters-report-in-the-envelope.md)     | Adapters report their acquisition inside the result envelope; the gateway keeps shape, statement commitment and page items its own | accepted |
