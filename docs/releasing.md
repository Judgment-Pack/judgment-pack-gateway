# Releasing the gateway

Only maintainers release this repository. A release is a tag a person pushes on a commit already on
`main`; [`release.yml`](../.github/workflows/release.yml) builds everything else from that tag and
publishes nothing until a maintainer approves it.

## What a release is

A tag names a reviewed state of the repository ([CONTRIBUTING.md](../CONTRIBUTING.md#tags)). A
release adds the built programs for that state:

- six archives, for Linux, macOS and Windows on `amd64` and `arm64`. Each holds `gateway`, the nine
  programs under `adapters/cmd`, `SPEC.md`, the corpus, the catalog, `LICENSE`, `README.md`,
  `SECURITY.md` and `THIRD_PARTY_NOTICES`;
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

Releases up to `v0.4.0` were made by hand and carry notes only.

## What is tested where

| | Linux | macOS | Windows |
| --- | --- | --- | --- |
| The gateway's tests and the corpus (CI) | yes | yes | yes |
| The adapters' tests (CI) | yes | no | vetted, not run |
| The released archive: `gateway version`, `gateway conform` on the corpus it carries, every program present | `amd64` and `arm64` | `arm64` | `amd64` |
| The released archive: three adapters start and print their usage line | `amd64` and `arm64` | `arm64` | no |

The `darwin/amd64` and `windows/arm64` archives are built and checksummed and are not run by
anything. No check here reaches a platform account: an adapter that starts has not been shown to
connect.

## Once, before the first release

1. Create the `production` environment with a required reviewer. The workflow reads the rule before
   it builds anything and refuses a repository without it: an environment a workflow names without
   its existing is created with no rule at all.

   ```bash
   gh api -X PUT repos/Judgment-Pack/judgment-pack-gateway/environments/production \
     -F 'reviewers[][type]=User' -F "reviewers[][id]=$(gh api user --jq .id)"
   ```

2. Turn on release immutability for the repository (Settings → General → Releases), so that
   publishing locks the tag and the assets.

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
   GoReleaser version the workflow names. A snapshot build calls itself a snapshot
   (`gateway version` prints `gateway v<last tag>-SNAPSHOT-<commit>`); unpack one archive and run
   `./gateway conform --corpus corpus` in it.
3. Merge the pull request.

## Tag

Tag the merge commit on `main`, signed, and push only that tag:

```bash
git fetch origin
git tag -s <tag> -m "gateway <tag>" "$(git rev-parse origin/main)"
git push origin <tag>
```

If no signing key is configured, stop and settle the signing policy; do not replace a signed tag
with an unsigned one. A tag is never moved or reused. A fix is a new version.

A tag with a hyphen (`v0.5.0-rc.1`) is a prerelease: it is published as one and is never marked
latest. The first release made by this workflow should be a release candidate, since no run of the
workflow precedes it.

## What the workflow does

1. **Admits the tag.** It is an exact SemVer version; its commit is on `main`; its notes exist; the
   `production` environment requires a reviewer.
2. **Runs CI at the tag.** The release calls [`ci.yml`](../.github/workflows/ci.yml) itself, so the
   tagged state is held to every check a commit is held to, including the three that concern a
   release: the third-party notices are what the linked modules say, every program under
   `adapters/cmd` has a release build, and the tree carries no publisher registration.
3. **Packages without publishing.** One reviewed toolchain, named exactly in the workflow; no cgo,
   no workspace, no recorded paths. The tag is written into `gateway`, which is how
   `gateway version` and the MCP server's `serverInfo` come to name it. File timestamps are set to
   the tagged commit's. The archives are then opened and their corpus and catalog compared with the
   tag's, byte for byte.
4. **Runs each archive where it says it runs**, as the table above states.
5. **Attests and drafts.** Only after every smoke test passes are the archives attested and a draft
   release created, with the notes from the tag.
6. **Waits at the `production` gate.** Review the draft on the Releases page: the notes, the seven
   assets, the checksums. Approve the pending deployment on the run, and the draft is published.

No maintainer token and no repository secret is used.

If a run fails, fix the cause on `main` and release a new version. Re-running a failed job is for a
failure that was the runner's, not the tag's.

## Verifying a download

```bash
sha256sum --check --ignore-missing checksums.txt
gh attestation verify <archive> --repo Judgment-Pack/judgment-pack-gateway
```

The first command holds the archive to `checksums.txt`; the second holds it to this repository's
release workflow at the tagged commit. On macOS, `shasum -a 256 --check --ignore-missing
checksums.txt`. `gh attestation verify` prints nothing when its output is not a terminal; add
`--format json` in a script.

A consumer that builds from source instead pins the tag and the commit it names, and builds with
`-trimpath -buildvcs=false`, as Desk's bundle does.
