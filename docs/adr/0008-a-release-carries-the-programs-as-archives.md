---
status: accepted
date: 2026-09-29
deciders: maintainer
---

# A release carries the programs as archives, built from a tag by a workflow; the image is not yet published

## Context and problem statement

[ADR-0001](0001-one-engine-four-processes.md) determined that "the release is the engine": one
image carrying the gateway, the adapters, the pinned runtime and the catalog. That image is built
by CI from every commit and has never been published
([design/engine-image.md](../design/engine-image.md#provenance)).

Meanwhile the repository has been released five times, `v0.1.0` to `v0.4.0`, by hand. Each of
those releases is a tag and a page of notes. None carries a built program, a checksum or a
statement of where a build came from. The consumers that exist build from source at a commit they
pin, and two such pins came to name commits that lived on a branch and never on `main`: a pin had
nothing better to name.

What should a release of this repository carry now, who makes it, and what holds it to the state
that was reviewed?

## Decision drivers

- A consumer can pin a tag, and the commit it names, and know that state passed everything CI asks.
- A built program can be held to the workflow and the commit that built it, without trusting the
  machine of whoever released it.
- Nothing becomes a release without a maintainer having approved it.
- The core stays one binary that links the standard library alone, and the signer is never linked
  to an adapter ([ADR-0001](0001-one-engine-four-processes.md), determinations 1 and 2).
- A program that links another's code carries that code's licence.
- The image's design is not reopened to get there.

## Considered options

- Keep releasing by hand: a tag and notes.
- Publish the engine image first, as ADR-0001's third determination describes the release.
- Publish the programs as archives, built from a tag by a workflow, and publish the image later.

Within the third, two smaller choices: notes generated from commit titles, or notes a person
writes; and a release workflow that carries its own copy of the checks, or one that calls CI.

## Decision outcome

Chosen option: the programs as archives, built from a tag by a workflow, because it gives a
consumer something to pin and to verify now, and asks nothing new of the image's design. Publishing
the image first would have put the larger question (a digest, a bill of materials for both modules,
the runtime pin, a registry) in front of the smaller one.

What is decided:

1. **A release is made from a tag a person pushes on a commit `main` holds.** The workflow works on
   that commit by its digest, and holds the tag to it when the run begins, before the draft is
   made, and before it is published. A tag is `vX.Y.Z` or `vX.Y.Z-<prerelease>` as SemVer 2.0.0
   writes them; build metadata is refused. A tag with a prerelease is published as a prerelease and
   is never marked latest.
2. **The tagged commit passes CI as that commit defines it.** The release workflow calls `ci.yml`
   and carries no second copy of the checks.
3. **A release carries six archives**, for Linux, macOS and Windows on `amd64` and `arm64`, each
   architecture at its lowest level: the gateway, every program under `adapters/cmd`, `SPEC.md`,
   the corpus, the catalog, and the licences. It carries their checksums and a build-provenance
   attestation for each.
4. **Nothing is a release until a maintainer approves it** at the `production` environment. The
   workflow refuses to run in a repository where that environment has no reviewer rule.
5. **Notes are written by a person**, in `docs/releases/<tag>.md`, and reviewed in the pull request
   that prepares the release.
6. **The gateway says which release it is**: `gateway version`, and the same value as the MCP
   server's `serverInfo.version`. The release build writes the tag into the executable. The
   adapters are not stamped.
7. **`THIRD_PARTY_NOTICES` is written from the module cache** and held to it by CI.
8. **Two things are the maintainer's practice and are checked by nothing.** A tag is signed; the
   workflow admits an unsigned one. Release immutability is turned on for the repository; the
   workflow does not read the setting.

This is a material change to the public surface (a subcommand, and the value `initialize`
reports for a released build), to documented claims, and to the security posture (what a consumer
can verify, and what stands between a tag and a release). It changes nothing in `SPEC.md`, in what
is signed, or in what the corpus accepts.

**Determination 3 of ADR-0001 is superseded in one part, and in no other.** That determination
opens "The release is the engine. One image carries the gateway binary, the adapter binaries, the
pinned runtime binary, and the catalog." From this record on, a release of this repository is what
is decided above: archives of the programs, without the runtime and without an image. What is
superseded is that account of what a release is. The rest of determination 3 stands as written:
what the image carries, the one configuration file, `connect`, and what `verify` reads. So do the
record's other determinations. The image remains the form the engine is designed to run in, and
remains unpublished; when it is published, the archives' `checksums.txt` is where its digest is
to be named, as [design/engine-image.md](../design/engine-image.md#provenance) already says.
ADR-0001 is not edited; its row in the index names this supersession.

### Consequences

- A consumer can pin a tag and verify a download against the workflow and the tag that built it.
- GoReleaser becomes a tool of the release, pinned by version in the workflow. It is not a
  dependency of either module, and the core's rule is untouched.
- The release toolchain is named exactly in the workflow and is moved by hand.
- Two of the six archives, `darwin/amd64` and `windows/arm64`, are built and read and never run.
  The adapters' tests run on Linux only, and of the adapter executables in an archive, three are
  started by the archive smoke tests and the rest by none.
- The archives and their attestation exist before the approval: the archives as an artifact of the
  run, the attestation in a public log. The approval gates the release, not their existence.
- While the project has one maintainer, the person who pushes the tag is the person who approves.
- A tag is not protected until its release is published, and is protected then only where release
  immutability is turned on. The workflow's three checks of the tag stand in for that before
  publication, and an administrator can still change the environment's rule between them.
- The checks lock nothing. A draft can be changed while it waits, by whoever may write to the
  repository, so the workflow holds the draft's title, notes and files to the ones the run
  packaged after the approval and before it publishes. A moment remains between the two. What a
  consumer verifies does not depend on it: an archive the workflow did not build has no
  attestation.
- The reading of the archives is a check of the workflow's own packaging. It is not a defence
  against an archive made to be read differently by different programs. It accepts the form the
  packer writes for what the repository gives it today, and may have to follow when a file is
  added under another kind of name or the packer is upgraded.
- No claim is made that a build can be reproduced bit for bit by someone else.
- A release made before this record, `v0.1.0` to `v0.4.0`, stays as it is: notes only.

## More information

- [docs/releasing.md](../releasing.md): how a release is made and how a download is verified.
- [`release.yml`](../../.github/workflows/release.yml) and [`.goreleaser.yml`](../../.goreleaser.yml).
- The runtime's release workflow is the model this one was adapted from.
