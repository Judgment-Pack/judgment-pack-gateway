---
status: accepted
date: 2026-10-26
deciders: maintainer
---

# A release takes the CI evidence main recorded at the tagged commit, or refuses; it does not run CI again

## Context and problem statement

[ADR-0008](0008-a-release-carries-the-programs-as-archives.md) determined that the tagged commit
passes CI as that commit defines it, by the release workflow calling `ci.yml` (determination 2).
A tag is pushed on a commit `main` already holds, and `main`'s CI has already run every job and
leg of that same `ci.yml` at that commit: the release ran all of it a second time, about eight
minutes of four jobs at `v0.22.0-alpha.1`, before it built anything. The same commit alone does
not prove the same run, though: a run of another trigger, an older green attempt behind a newer
failed one, another toolchain or runner image, a skipped leg, or a native leg stood in for by
Linux would each be evidence of something else (issue #323).

## Decision drivers

- Determination 2's guarantee is kept: every job and leg of the commit's own `ci.yml`, as that
  commit defines them, Linux, macOS and Windows each by its own leg.
- Evidence that is missing, partial, stale, of a newer failed or running attempt, of other inputs,
  or unreadable never becomes a success; the release stops and says why.
- Every check that concerns the release itself stays at the release: the tag, the notes, the
  reviewer rule, the packing, the native archive runs, the attestation, the draft, the approval and
  the published files.
- One gate for every repository that adopts it, tested where it is written: the development kit's.

## Considered options

- Keep calling `ci.yml` at the tag.
- Read `main`'s CI result for the commit from its commit status or check runs.
- Take the evidence `main`'s run recorded at the commit with the development kit's release
  evidence gate, configured per repository, and refuse otherwise.

## Decision outcome

Chosen option: the kit's release evidence gate, because it keeps determination 2's coverage while
holding the evidence to the exact commit, workflow, trigger, attempt, jobs, inputs and toolchains,
and refuses everything else; a status or check run can be set under any name by anyone who can
write to the repository, and is never read.

1. **A push to `main` records evidence in every job and leg of `ci.yml`**
   (`scripts/dev/release_evidence.py capture`): the commit, its input identities, the runner and
   the toolchain, and for `check` the result of every setup step and check. A pull request records
   none.
2. **The `CI at the tag` job takes that evidence or refuses** (`release_evidence.py verify`,
   `.github/ci-evidence.json`, [docs/releasing.md](../releasing.md#the-ci-evidence-the-release-takes)):
   the newest run of `ci.yml` at the tagged commit, by a push to `main`, completed and successful,
   at most 48 hours old, every job and leg present and successful on its hosted runner, the inputs
   the commit holds, and each leg's toolchain: the Go `release.yml` names on every leg, and on Linux
   the runner image and toolchains the release's runner resolves. The decision record is kept with
   the run. `ci.yml` is not called.
3. **A refusal stops the release.** Nothing re-runs or dispatches CI by itself; the fresh route
   (re-run all jobs of `main`'s run at the commit, then the release's failed jobs) is a
   maintainer's, once.
4. **The native legs run the release's toolchain.** Each leg of the `go` matrix sets up the Go
   `release.yml` names, exactly, instead of the newest `1.26` patch its image caches, so that its
   evidence can be held to a pin; the legs' names, which branch protection requires, are unchanged.

This supersedes determination 2 of ADR-0008 in one part: how the tagged commit is shown to pass
CI. That it must, as the commit defines it, stands.

### Consequences

- Good, because the release no longer spends about eight minutes and four runners repeating what
  `main` ran at the same commit, and says, in its record, which run and attempt it relied on.
- Good, because a newer runner image or toolchain since `main`'s run, or a leg that did not run,
  is a refusal by name rather than a different run passing.
- Bad, because a release must follow its commit's CI within 48 hours, or take the fresh route.
- Bad, because the kit's gate admits `vX.Y.Z` alone: a prerelease tag is refused (`tag-syntax`)
  until the kit admits one. A prerelease is not released by this workflow meanwhile.
- Bad, because what the gate cannot see stays unseen: the dependencies `pip` resolves for the setup
  step's `jsonschema`, and the macOS and Windows image versions, which are recorded and not
  compared.
- Revisit when the kit's gate admits prereleases, or when a check of `ci.yml` comes to depend on
  the tag (it then belongs in the release workflow, not in the evidence).

## More information

- Issue #323; the development kit's issue #37 and its `docs/ci-evidence.md`.
- [`release.yml`](../../.github/workflows/release.yml), [`ci.yml`](../../.github/workflows/ci.yml),
  [`.github/ci-evidence.json`](../../.github/ci-evidence.json),
  [`.github/test_ci_evidence.py`](../../.github/test_ci_evidence.py).
