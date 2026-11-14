---
status: proposed
date: 2026-11-13
deciders: maintainer
---

# The engine image carries a static bubblewrap, the release publishes the image by digest past its gate, and a start may refuse a source sandbox it cannot enforce

## Context and problem statement

No release published the engine image (issue #378). CI built it from every commit and never
pushed it, so a deployment had to build its own and pin a digest nobody else could check
against a release. The image also carried `adapter-sandbox` and no bubblewrap (issue #385). A
restricted source in a container was therefore confined by Landlock, reported `partial`, or not
at all. Where neither backend could be had, the engine started and served, and only
`gateway posture --config` or the first acquisition, refused with `sandbox-not-enforced`, showed
it. The operator learned this from a failed call rather than at start.

## Decision drivers

- Nothing the registry serves under a name exists before a maintainer approves the release at
  the `production` gate. A tag in a registry can be moved; a run's artifact cannot.
- The image is named the way the archives are: its digest in the same `checksums.txt`, under
  the same attestation, and stated in the release notes.
- CI runs the build and the push the release runs, not a model of them.
- The launcher must pass the helper's own check (`trustedFile` in `adapters/internal/sandbox`):
  root's along its path, writable by nobody else, with any program interpreter and library
  search path held the same way. The fewer files it brings, the less there is to hold.
- The image stays minimal, every file in it is accounted for, and each licence travels with
  what it covers.
- A configuration of an earlier version starts as it did. `go/` stays standard library only.

## Considered options

Publishing:

1. Build and push in the package job, before the gate (the usual build-and-push action).
2. Build in the package job into an OCI archive, make the index's bytes a release asset, and
   push that archive by digest in the publish job, after the gate and before the release is
   published.
3. Build in the publish job, after the gate.

The launcher:

1. Alpine's or Debian's bubblewrap package, with its dynamic loader and libraries copied in.
2. bubblewrap built from its released source as one static executable, with musl and libcap.
3. No launcher. Document a derived image (the state before this record).

Refusal at start:

1. Every configuration of version 13 or later measures at start and refuses.
2. A new optional member at version 23, `measureSandboxAtStart`, off unless set.
3. No refusal at start: posture reports, and each launch refuses (the state before).

## Decision outcome

**Publishing: option 2.** The package job runs `build/engine-image.sh build` from the tagged
commit for `linux/amd64` and `linux/arm64`, the same script CI runs
(`scripts/checks/image-platforms.sh`). The bytes of the image index become
`judgment-pack-gateway_<version>_engine-image.index.json` beside the archives. Their SHA-256 is
the image digest: a line of `checksums.txt`, attested with the archives, plus a second
attestation naming `ghcr.io/judgment-pack/judgment-pack-gateway` so that
`gh attestation verify oci://…` finds it. The notes gain an "Engine image" section, written by
the workflow, that gives the tag and the digest. Before the archive leaves the package job,
each platform's image in it is pushed to a registry on the runner's loopback, pulled by its
manifest's digest, created and exported without being run, and its filesystem held by
`.github/image_checks.py` (`build/engine-image.sh check`, which CI runs on the same build). Past
the gate, the publish job holds the draft to the run's files first, so that a draft found
changed refuses with nothing pushed. It then compares the archive's index with the asset byte
for byte and pushes every manifest by its digest under the version as its tag, `0.28.0` for
`v0.28.0`, the convention of the runtime pin the `Dockerfile` names. It reads the tag back and
refuses a tag that names another digest, holds the draft again, and publishes the release. No
`latest` is pushed, since a deployment pins by digest.

Option 1 puts a public, movable name in the registry before approval. Option 3 leaves the
approved draft unable to name the digest it will publish.

**The launcher: option 2.** A launcher stage on the pinned Alpine base fetches the bubblewrap
0.13.1 release tarball by its SHA-256. It links bubblewrap statically with musl and libcap, and
links a static one-line `/bin/true` for bubblewrap's start check. The build is refused if
either program names a program interpreter, or if the Alpine repository would link any version
other than the one the notices name. `/usr/bin/bwrap` is the first of the helper's fixed
locations. Both programs are root's, mode 0755, with no set-user-id bit and no capability, and
`.github/image_checks.py` holds them so. They need user namespaces as the source's user, which
the container runtime gives or refuses. Option 1 brings a loader and shared libraries for the
helper to follow. Option 3 is what #385 asked to end.

**Licences.** In `/usr/share/engine/bubblewrap/`:

- bubblewrap's `COPYING` (LGPL-2.0-or-later), with the exact source tarball it was built from;
- musl's `COPYRIGHT` (MIT);
- libcap's `License` (BSD-3-Clause or GPL-2.0-only, taken under BSD-3-Clause);
- a README that names the versions linked.

The two library texts are kept in `build/notices/`, copied from their upstream repositories at
those versions, so that a build fetches nothing but the source. The compiler's runtime library
is under the GCC Runtime Library Exception, which asks for no notice. The gateway's own
`LICENSE` and `THIRD_PARTY_NOTICES` are in `/usr/share/engine/`, since the image is now
published as the archives are. `THIRD_PARTY_NOTICES` stays generated from Go modules alone.

**Refusal at start: option 2.** With the member on, `serve --config` probes each source's
sandbox as its user, each under a launch's own twelve seconds, after the user switch is known
to work and before anything is made. It refuses to start where a launch would be refused: a
probe with no report, a restricted mode measured as not enforced, or a source with no wrapper.
Each such source is named. Partial, enforced and `danger-full-access` start. The completed
probe is the one each later launch is bound to. Option 1 would stop engines that start today,
some of which serve what needs no source. An earlier version refuses the member by name.

### Consequences

- Good, because an operator can pin the published image by a digest that `checksums.txt` and
  an attestation name, and a release cannot be published with an image other than the one it
  built.
- Good, because a container that allows user namespaces gets bubblewrap's `enforced` boundary
  with no derived image, and an operator who wants a host without one refused at start can have
  that.
- Bad, because Docker's default seccomp profile refuses a new user namespace, and on some
  Docker versions Landlock's calls too. Enforcement there takes `seccomp=unconfined` or a
  profile of the operator's own (the quickstart). Loosening the profile is the operator's
  trade-off.
- Bad, because the bubblewrap in the image moves only when the `Dockerfile` moves its pin.
  bubblewrap's releases are tracked by hand.
- Bad, because a push that succeeds before the second draft check or the publish call fails
  leaves a tag for an unpublished release: a draft changed in the moments of the push, or a
  failed call. It names the digest the run built and attested, and a rerun pushes the same
  digest. A draft found changed at the gate leaves nothing in the registry.
- Bad, because the first push creates the package private. A maintainer makes it public once.
- Bad, because the arm64 image is built (its compile stages under the builder's emulator), its
  index entry checked and its filesystem judged, but not run in CI.
- Not done: the software bill of materials that the engine image's design note promised. The
  index's `org.opencontainers.image.revision` names the commit, whose `Dockerfile` names the
  runtime pin and every base by digest.
- Revisit when the registry offers immutable tags, when Docker's default profile admits user
  namespaces for an unprivileged container, or when an SBOM is to be published.

## More information

- `Dockerfile`, `build/engine-image.sh`, `build/engine_image.py`,
  `.github/workflows/release.yml`.
- `go/sandbox_at_start.go`, `scripts/checks/image-sandbox-start.sh`.
- [docs/design/engine-image.md](../design/engine-image.md), "The source sandbox" and
  "Provenance".
- [docs/design/engine-config.md](../design/engine-config.md), "Measuring the sandbox at the
  start (engine version 23)".
- [docs/engine-quickstart.md](../engine-quickstart.md).
- [docs/releasing.md](../releasing.md).
