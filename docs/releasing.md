# Releasing the gateway

Only maintainers release this repository. A release is a tag a person pushes on a commit already on
`main`; [`release.yml`](../.github/workflows/release.yml) builds everything else from that commit and
publishes no release until a maintainer approves it.
[ADR-0008](adr/0008-a-release-carries-the-programs-as-archives.md) records the decision.

## What a release is

A tag names a reviewed state of the repository ([CONTRIBUTING.md](../CONTRIBUTING.md#tags)). A
release adds the built programs for that state:

- six archives, for Linux, macOS and Windows on `amd64` and `arm64`. Each holds `gateway`, every
  program under `adapters/cmd`, `SPEC.md`, the corpus, the catalog, `LICENSE`, `README.md`,
  `SECURITY.md` and `THIRD_PARTY_NOTICES`, and nothing else;
- `checksums.txt`, the SHA-256 of each archive;
- a build-provenance attestation for each archive, signed by GitHub for this workflow at the tagged
  commit;
- the notes a person wrote, from `docs/releases/<tag>.md`.

What a release is not:

- **Not the engine image.** CI builds the image from every commit and never pushes it
  ([design/engine-image.md](design/engine-image.md#provenance)).
- **Not the n8n node.** It is published by its own workflow on its own tags
  (`n8n-nodes-judgment-pack@<version>`).
- **Not a format version.** `receiptVersion` names what a verifier accepts and moves on its own.
- **Not a registered application.** A public release carries no publisher's Google registration
  ([design/publisher-google-oauth.md](design/publisher-google-oauth.md)); CI refuses a tree that
  holds one.

Only `gateway` carries the release's version (`gateway version`, and the MCP server's
`serverInfo.version`). The adapters are not stamped: an adapter is known by the archive it came in.

Releases up to `v0.4.0` were made by hand and carry notes only.

## What is tested where

| | Linux | macOS | Windows |
| --- | --- | --- | --- |
| The gateway's tests and the corpus (CI) | yes | yes | yes |
| The adapters' tests (CI) | yes | no | vetted, not run |
| The released archive, run: `gateway version`, `gateway conform` on the corpus it carries | `amd64` and `arm64` | `arm64` | `amd64` |
| The released archive, run: three adapters start and print their usage line | `amd64` and `arm64` | `arm64` | no |
| The released archive, read and not run: it holds files and nothing else, each under its plain name and once; its documents, corpus and catalog are the commit's, byte for byte; each program is one program, built from the package of its name, for the archive's platform, at the lowest level of its architecture, and is the bytes the packer built; no file is there that a release does not hold; the archive reads to its end | `amd64` and `arm64` | `amd64` and `arm64` | `amd64` and `arm64` |

What the reading of the archives is for: a mistake in the packaging, such as a pattern that
passes a file over, a program built from the wrong package, or an archive cut short. It accepts
a member only in the form the packer writes one, and reads an archive as Python's standard
library does. It is not a defence against an archive made to be read differently by different
programs: whoever could put one where the check looks could change the check.

A program is held to the bytes the packer wrote when it built it, by the packer's own account
(`dist/artifacts.json`). Those bytes are held to nothing but their build record: the check does
not say the packer built a program well.

The form is the packer's for what this repository gives it today: short names in plain letters,
files of ordinary size, modes as the checkout has them. A file added under a long name or one
not in plain letters, a mode changed, or an upgrade of the packer may be written in a form the
check refuses. Such a refusal is looked into: it may be the check that has to follow.

The `darwin/amd64` and `windows/arm64` archives are built, read and checksummed and are not run
by anything. Of the adapter executables in an archive, three are started by the archive smoke
tests (`adapter-airbyte`, `adapter-http`, `adapter-mcp`) and the rest by none, on any platform.
(CI, whose run at the tagged commit the release takes as evidence, starts others, but built from
source or in the image it builds, and not from an archive.) No check here reaches a platform account: an adapter that starts has not
been shown to connect.

## Once, before the first release

1. Create the `production` environment with a required reviewer. The workflow reads the rule before
   it builds anything and refuses a repository without it: an environment a workflow names without
   its existing is created with no rule at all.

   ```bash
   gh api -X PUT repos/Judgment-Pack/judgment-pack-gateway/environments/production \
     -F 'reviewers[][type]=User' -F "reviewers[][id]=$(gh api user --jq .id)"
   ```

   What the workflow reads is that a reviewer rule exists. It does not read who the reviewers
   are, and it cannot keep an administrator from changing the rule later. While the project has
   one maintainer, the person who pushed the tag is the person who approves: the gate is then a
   pause in which the draft is read, not a second person.

2. Turn on release immutability for the repository (Settings → General → Releases). It locks the
   tag and the assets from the moment a release is published, and not before: until then the
   workflow itself holds the tag to the commit the run was started for. The workflow does not read
   this setting. Where it is off, a published release's tag and assets can still be changed by
   whoever may write to the repository.

## Prepare the release

1. Open a pull request that adds `docs/releases/<tag>.md`: what changed since the last release, what
   an operator must do, and what the release does not establish. It is reviewed like any other
   change, and it is the text the release page will carry.
2. Validate locally, from a clean checkout of the branch:

   ```bash
   (cd go && gofmt -l . && go vet ./... && go test ./... && go build -buildvcs=false -o gateway . && ./gateway conform)
   (cd adapters && gofmt -l . && GOWORK=off go vet ./... && GOWORK=off go test ./...)
   python3 build/third_party_notices.py --check
   goreleaser check
   goreleaser release --snapshot --clean --skip=publish
   ```

   `gofmt -l` prints the files it would change and exits zero either way: read its output. Use the
   GoReleaser version and the Go toolchain the workflow names: `THIRD_PARTY_NOTICES` carries the
   toolchain's own licence, so it is written and checked with the toolchain that links the
   release. A snapshot build calls itself a snapshot
   (`gateway version` prints `gateway v<last tag>-SNAPSHOT-<commit>`); unpack one archive and run
   `./gateway conform --corpus corpus` in it.
3. Merge the pull request, and let main's CI run at the merge commit complete: that run is the
   evidence the release takes ([below](#the-ci-evidence-the-release-takes)), for 48 hours from
   its start.

## Tag

Tag the merge commit on `main`, signed, and push only that tag:

```bash
git fetch origin
git tag -s <tag> -m "gateway <tag>" "$(git rev-parse origin/main)"
git push origin <tag>
```

If no signing key is configured, stop and settle the signing policy; do not replace a signed tag
with an unsigned one. Signing is the maintainer's practice and the workflow does not check it: an
unsigned tag is admitted like a signed one. A tag is never moved or reused. A fix is a new version.

A tag is `vX.Y.Z`, or `vX.Y.Z-<prerelease>` as SemVer 2.0.0 writes it. Build metadata (`+...`) is
refused. The workflow publishes a tag with a hyphen as a prerelease, never marked latest, and the
release evidence gate it runs next ([below](#the-ci-evidence-the-release-takes)) admits one because
`.github/ci-evidence.json` sets `tag.prerelease` to `true`. This repository uses the two pre-release
forms the development kit's policy defines: `vX.Y.Z-rc.N` is a candidate of the complete milestone,
graduated to `vX.Y.Z` with no code change when nothing is found, and `vX.Y.Z-alpha.N` is a scoped cut
for a named consumer that never graduates.

## What the workflow does

Every job works on the commit the run was started for, by its digest, and not on the tag's name.

1. **Admits the tag.** It is a version as above; it names the commit the run was started for; that
   commit is on `main`; its notes exist; the `production` environment has a reviewer rule.
2. **Takes the CI evidence `main` produced at that commit, or refuses** (`CI at the tag`). The
   checks are the commit's own [`ci.yml`](../.github/workflows/ci.yml)'s, every job and leg of it,
   so the release carries no second copy of them; they include the three that concern a release:
   the third-party notices are what the linked modules say, every program under `adapters/cmd` is
   named in the release build, and the tree carries no publisher registration. They are not run
   again: the release reads what the push to `main` recorded at the tagged commit itself, as the
   next section says. A check `main` has gained since that commit is not asked.
3. **Packages without publishing.** One reviewed toolchain, named exactly in the workflow; no cgo,
   no workspace, no recorded paths; `amd64` at `v1` and `arm64` at `v8.0`. The tag is written into
   `gateway`. File timestamps are set to the commit's. All six archives are then opened and read
   by `build/release_archives.py`, as the table above states. CI runs that script against sound
   archives and against archives spoiled one way at a time.
4. **Runs the archives of four targets**, each on a runner of its own platform, as the table above
   states.
5. **Attests and drafts.** Only after every smoke test passes, and only if the tag still names the
   commit, are the archives attested and a draft release created, with the notes from the commit.
   The job records the draft's release id for the publish job.
6. **Waits at the `production` gate.** Review the draft on the Releases page: the notes and the
   seven assets. Approve the pending deployment on the run.
7. **Holds the draft to the run, and publishes it by its id.** A draft can be changed while it
   waits, by whoever may write to the repository. So on the far side of the gate the tag is held to
   the commit once more, and the run's own files are held to their checksums. The release the run
   drafted is then read through the releases API by its id, without downloading anything: it must
   still be a draft under the tag, with the title the workflow gave it and the notes the commit
   holds (compared without the newlines either ends in), and the digest the API reports for each
   of its assets must be the digest of the run's file of that name, no asset more or fewer. Any
   difference refuses. The publish call follows that last read at once, addressed to the same
   release id, not to the tag.
8. **Reads the published release again.** Immediately after publication the job reads the
   published release's asset digests through the API once more, and fails the step `The published
   release holds what this run packaged`, printing both digest sets, if they differ from the run's
   files.

An approval given more than thirty days after the run finds the run's
archives gone, and the job fails: release a new version.

### The CI evidence the release takes

`ci.yml` runs on every push to `main`, and there each job and each leg of the `go` matrix records
its evidence as an artifact of the run: the commit, the identity of its inputs, the runner and the
toolchain it ran with, and for `check` the result of every setup step and check of `dev.json`.
The `CI at the tag` job reads it with the development kit's release evidence gate
([`scripts/dev/release_evidence.py`](../scripts/dev/release_evidence.py), vendored from the kit
whose `docs/ci-evidence.md` is its contract), configured by
[`.github/ci-evidence.json`](../.github/ci-evidence.json), and runs no check of its own. It takes
the evidence only when all of this holds, and refuses otherwise:

- the run is `ci.yml` (by its path and its name), in this repository, at the tagged commit itself,
  started by a push to `main`; a pull request's run, a merge commit GitHub made for one, another
  branch, another workflow, a commit status or a commit with the same tree is not it;
- it is the newest run at the commit: no newer attempt of a run on `main` at the commit failed,
  was cancelled or is still running, and the gate never looks past one for an older green run;
- it completed and succeeded, and started at most 48 hours before the gate reads it;
- every job and leg succeeded on a GitHub-hosted runner with its labels: `check`,
  `ubuntu-latest · Go 1.26`, `macos-latest · Go 1.26` and `windows-latest · Go 1.26`, the three
  operating systems each by its own leg; none was skipped, and `check` passed every setup step and
  every check, with no skip;
- each job's evidence names the commit and the inputs the release's checkout holds; the Go of each
  leg and of `check` is the one `release.yml` names (`1.26.5`); the Linux runner image and its
  operating system release, and the Go, Node, Python and Docker of `check` and the Linux leg, are
  what the release's own runner resolves now, setting the toolchains up as `ci.yml` does; the
  macOS leg ran on macOS `ARM64` and the Windows leg on Windows `X64`;
- the tag is an annotated tag that names the commit, before and after the evidence is read.

What it reuses and what it still does at the release:

| | On a push to `main` | At the release, before | At the release, now |
| --- | --- | --- | --- |
| `ubuntu-latest · Go 1.26`, `macos-latest · Go 1.26`, `windows-latest · Go 1.26`: the core's Go steps, natively | run, evidence recorded | run again | taken from each leg's evidence, never one leg for another |
| `check`: the setup steps and every check of `dev.json`, the adapters, the release contents, the plugins, the second implementation, the image, the witness scenario, the agreement of the two paths | run, evidence recorded | run again | taken from its evidence |
| The tag, `main`, the notes, the `production` reviewer rule; the notices with the release's toolchain, the packing, the checksums and the six archives read; the archives run on four platforms; the tag again and no release under it; the attestation; the draft; the approval; the draft and the published release held to the run's files | not run | run | run, unchanged and in the same order |

No check of `ci.yml` depends on the tag, so nothing the gate takes is tag-sensitive. What a run
depends on beyond the commit, and how the gate holds it:

- the pin files: the workflow files, `dev.json`, `jpdev.json`, the runner scripts, every `go.mod`
  and `go.sum`, the lock files of the plugins and of the second implementation, the Python
  requirements of the setup step, `.goreleaser.yml`, the Dockerfile with its digest-pinned images,
  `.dockerignore` and the two programs it copies one by one (`build/setcap.go`, `build/mkhomes.go`),
  the image check's builder image (`scripts/checks/image-root-unwritable.sh`), the witness
  scenario's pinned runtime (`scripts/checks/witness-scenario.sh`), and the images the agreement of
  the two paths starts: its world database (`adapters/agreement/agreement_test.go`) and the
  catalog's server images (`catalog/postgres.json`). The commit holds them, and the evidence
  records each by its git object id. The trees the Dockerfile copies whole (`go/`, `adapters/`,
  `catalog/`, `corpus/`) are the commit's too, and are not recorded file by file.
  `.github/test_ci_evidence.py` finds the pin files in the tree (every reference by digest outside
  the documents and the data it names, every module, lock and requirements file, the manifest, the
  packer's configuration and every file `ci.yml` names) and fails until each is recorded;
- the Go toolchain: named exactly in `release.yml`, set up by every leg and by `check`, and pinned
  per platform in the configuration (`.github/test_ci_evidence.py` holds the three equal);
- Node `22` and Python `3.12` as `dev.json` names them, and Docker: whatever the hosted image
  resolves, so the Linux image and these tools must be what the release's runner resolves now. A
  newer image or toolchain since `main`'s run is a refusal, and the fresh route below. While GitHub
  rolls a new image out, the two Linux jobs and the release's runner can land on different
  versions of it, and the route may have to wait until they do not;
- the macOS and Windows images: recorded in the evidence, and not compared; their platform and
  their Go are;
- a known bound, pinned by nothing: the dependencies of the setup step's `jsonschema==4.23.0`,
  which `pip` resolves when the step runs. The gate cannot see them, and the checks that use them
  (the schema checks, which validate test fixtures; nothing released links them) are reused all
  the same. A hash-locked requirements file installed with `--require-hashes` would close it.

Capture runs on a push to `main` wherever the workflow runs: in a fork with Actions on, a push to
the fork's own `main` fails each job's capture with `context-repository`, since the configuration
names this repository. That says nothing of this repository's evidence, which the gate reads by this
repository's ids alone.

The decision, `reuse` or `refuse` with its code, is the last line of the step `Reuse main's
exact-commit CI evidence, or refuse`, and the whole record (the run and attempt, the input
identities, each job's result, labels, runtime and checks) is in that step's log and kept as the
run's `release-evidence-<attempt>` artifact.

Measured from the API, job start to completion, before this:

| Release | `CI at the tag` | From the end of admission to the start of packaging |
| --- | --- | --- |
| `v0.21.0` (run 39175719664) | the eleven jobs `ci.yml` had then, the longest 190 s, 1,037 s in all | 194 s |
| `v0.22.0-alpha.1` (run 40343693612) | `check` 483 s, `windows-latest` 266 s, `macos-latest` 223 s, `ubuntu-latest` 128 s: 1,100 s in all | 488 s |

The gate's own cost is measured at the next release, not promised here. The development kit's
gate job, which sets up no toolchain, took 16 s at its `v0.10.0` (run 40390217399); this one also
sets up Go (9 s in `main`'s `check` job), Node and Python. A refusal adds the fresh route: a full CI
run and a re-run.

### The window that remains

The API cannot publish a release on condition that its assets are the ones just read, so one
window remains: between the last read of the draft's asset digests and the publish call, a few
moments of the same step. Whoever can write to the repository's releases can act in it: a
repository writer, which in this organisation is a maintainer, the same people the `production`
gate asks to approve. Nothing in the workflow closes that window. A file replaced in it is
published, and the read after publication then fails the run by name; with release immutability
on, the published release can no longer be changed, so the replacement stays visible as a failed
release and is not quietly corrected.

No maintainer token and no repository secret is used.

### What exists before the approval

The gate is on the release. Three things exist before it and are not secret:

- the archives, as an artifact of the workflow run, which anyone who can read the repository's
  runs can download for thirty days;
- the attestation of those archives, which is recorded in a public transparency log when it is
  made. An attestation says which workflow built an archive, from which commit. It does not say a
  maintainer approved it: only a published release says that;
- the draft, which those who can write to the repository can see.

### If a run fails

Fix the cause on `main` and release a new version. Re-running is for a failure that was the
runner's, not the commit's: re-run the failed jobs, not all jobs.

What to do with a draft depends on which job failed:

| The job that failed | The draft | What to do |
| --- | --- | --- |
| `CI at the tag` | none was made | read the refusal: the step's last line, or the `release-evidence-<attempt>` artifact. Take the fresh route once: re-run **all** jobs of `main`'s CI run at the tagged commit (`gh run rerun <run id> --repo Judgment-Pack/judgment-pack-gateway`; a re-run of the failed jobs alone leaves the others' evidence in an earlier attempt and refuses), which also works after `main` has moved on and is the route for a run older than 48 hours or a newer runner image; when that run has completed, re-run the release run's failed jobs. `run-unfinished` means `main`'s run at the commit was still running: wait for it, then re-run the failed jobs. A second refusal, or evidence that cannot be made at that commit: fix the cause on `main` and release a new version. Nothing re-runs or dispatches CI by itself |
| Any other job before `Attest and draft release` | none was made | re-run the failed jobs |
| `Attest and draft release` | may exist, and may lack assets | read it, delete it by hand, then re-run the failed jobs. The job refuses to run while a release under the tag exists, draft or published, and refuses when it cannot find out |
| `Publish release`, before publication | needs looking at: it may be as it was made, changed, incomplete or gone | read why the job failed, and look at the Releases page. **Keep** a draft that is as it was made, and re-run the failed jobs: that job only publishes the release id the run drafted. Do not publish a draft that was changed or is incomplete. Where the draft cannot be published, release a new version |
| `Publish release`, at `The published release holds what this run packaged`, with the message "the published release does not hold what this run packaged" and two digest sets | published, holding files this run did not package, or not published after the call | someone who can write to the repository changed the release in the window above. Treat it as an incident: tell the maintainers, point no one at the release, and release a new version from a new tag. Do not re-run |
| `Publish release`, at the same step, with the message "the published release could not be verified" and no digest sets | published; a read after the call failed (an API or network error, or an empty answer), so nothing is known of its files | the release is unverified, not found changed: make no diagnosis. Read the same release id again and compare its asset digests with the run's: `gh api repos/Judgment-Pack/judgment-pack-gateway/releases/<id>/assets --jq '.[] | "\(.name) \(.digest)"'` (the id is in the job's log and the draft job's `release-id` output), against `checksums.txt` of the run's `release-dist` artifact and the `sha256` of each archive and of `checksums.txt` itself. If they match, the release is good. If they differ, treat it as the incident in the row above. Do not re-run the publish step |

A draft is deleted with `gh release delete <tag> --repo Judgment-Pack/judgment-pack-gateway`,
which leaves the tag. A published release is never deleted to make room for another.

## Verifying a download

```bash
sha256sum --check --ignore-missing checksums.txt
gh attestation verify <archive> \
  --repo Judgment-Pack/judgment-pack-gateway \
  --signer-workflow Judgment-Pack/judgment-pack-gateway/.github/workflows/release.yml \
  --source-ref refs/tags/<tag> \
  --source-digest <commit>
```

The first command holds the archive to `checksums.txt`, which is only as good as where that file
came from. The second holds the archive to an attestation made in this repository, by this
workflow, in a run started for that tag, from that commit; each flag is one of those, and with
`--repo` alone the command holds it to the repository and nothing more. `<commit>` is the full
digest of the commit the tag names, as the release page and `git rev-parse '<tag>^{commit}'` give
it. None of it says that a maintainer approved the release: that is what its being published
says. On macOS, `shasum -a 256 --check --ignore-missing checksums.txt`.
`gh attestation verify` prints nothing when its output is not a terminal; add `--format json` in a
script.

A consumer that builds from source instead pins the tag and the commit it names, and builds with
`-trimpath -buildvcs=false`, as Desk's bundle does.
