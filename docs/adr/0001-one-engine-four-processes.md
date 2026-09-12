---
status: proposed
date: 2026-09-12
deciders: maintainer
---

# One engine, four processes: ship adapters and the runtime with the gateway, out of process, in one repository

## Context and problem statement

The gateway attests whatever bytes a configured subprocess returns. That is the whole of its
integration surface: `--source NAME=CMD`, canonical arguments on stdin, one JSON result on
stdout ([SPEC.md §6](../../SPEC.md)). Every source that exists today is a script someone wrote
by hand — the synthetic `my_source` in the README, the screening and decision-desk sources in
the demo repository — and that is the evidence for the problem: an operator who wants attested
facts from a warehouse, a document store or a ticket system has to write the connector first,
and nobody outside this project has.

The lineage plan this record opens asks for more than a source slot. It needs adapters that
reach the catalogs that already exist — connector images speaking the Airbyte protocol for bulk
and historical reads, the MCP servers vendors now publish for live reads and for writes — page
receipts over a corpus, an executor for writes a person has approved, the runtime in the same
distribution so a decision record can cite its receipts, and a caller identity on receipts from
the customer's own identity provider. The question this record settles is **where that code
lives and how it runs**, because the answer decides whether the security claim in
[SECURITY.md](../../SECURITY.md) survives: *the key is the trust root, and its disclosure forges
everything*.

[CONTRIBUTING.md](../../CONTRIBUTING.md) said the repository "stays one Go binary and its
specification". That sentence was written when a source was a script the operator supplied.
This record narrows what it protects — the core — and widens the repository around it.

## Decision drivers

- **Third-party verifiability rests on key isolation.** A receipt is worth something only
  because nothing but the signer can produce one. Code that talks to the outside world must not
  be able to reach the seed.
- **One download.** The open-source user should run one thing, configure platforms rather than
  processes, and never wire an adapter by hand. Hand wiring is why sources stayed bespoke.
- **The core stays standard-library-only**, with the frozen corpus as arbiter and a clean-room
  second implementation possible from `SPEC.md` alone ([corpus/README.md](../../corpus/README.md)).
- **Catalogs are consumed, never vendored.** Connector images and MCP servers are pulled at run
  time, pinned by digest; none of their code enters this tree, so their licences do not either.
- **Cadence.** The receipt format moves rarely and with vectors; catalogs move monthly.

## Considered options

- **A. A separate adapters repository**, bundled into the gateway's release. Right on
  isolation, but the seam is invisible to a user only if the release does the bundling, and
  once outside code is pulled at run time rather than vendored, a second repository isolates
  nothing that a second module does not.
- **B. One process.** Link connector libraries into the gateway binary, the way an integration
  platform does. A compromised connector then signs, and SECURITY.md's trust-root statement
  becomes false.
- **C. One repository, two modules, one release, four processes.** The core module stays as it
  is; an adapters module beside it holds everything that reaches outside; the release ships both
  plus the runtime as one image; at run time the signer, each adapter, the runtime and the
  verifier are separate processes.
- **D. Status quo.** Operators keep writing source scripts. Rejected by the evidence above.

## Decision outcome

Chosen option: **C**, because it is the only shape that keeps the key isolated *and* gives the
user one thing to run. The determinations this record settles:

1. **Two modules that never meet.** `go/` (module `gateway`) is the core: canonicalization,
   signing, sealing, verification, `conform`, `serve`. It imports the standard library and
   nothing else. `adapters/` (module `adapters`) holds the adapters, the action executor, the
   catalog of platform binding files, and the sources of any plugin contributed to an outside
   platform. Neither module imports the other, and neither `go.mod` carries a directive that
   would let it: `go/boundary_test.go` and `adapters/boundary_test.go` fail `go test` on the
   first crossing, and CI refuses the directives. The adapters module *may* take dependencies
   the core never will; standard-library-only is preferred there too, and each addition is a
   `dependency` decision under the review regime ([README.md](README.md)).

2. **No new channel.** The gateway spawns an adapter exactly as it spawns any source today:
   the source contract of SPEC.md §6, unchanged. An adapter reads canonical arguments on stdin,
   does its work, and writes one JSON result on stdout. It obtains a platform's credentials from
   its own environment or files named in the engine configuration, never from the gateway
   process; the gateway holds the seed and passes it to nothing. The runtime (`jpack`) runs as
   its own process, pinned by release digest, and holds neither seed nor credentials. The
   verifier needs no key at all.

3. **The release is the engine.** One image carries the gateway binary, the adapter binaries,
   the pinned runtime binary, and the catalog. One configuration file names platforms,
   credential locations, the identity provider, and the store — never a process
   ([docs/design/engine-config.md](../design/engine-config.md)). A `connect` command turns a
   catalog binding into a configuration entry and tests it. `verify` grows to read the decision
   records beside the receipts. What the image contains and how its processes relate is in
   [docs/design/engine-image.md](../design/engine-image.md).

4. **Two adapter shapes, chosen by the operation, not two paths per platform.** `airbyte`
   runs a connector image and reads its record stream: bulk and historical reads, paged, the
   state bookmark recorded as the snapshot and the discovered stream schema recorded by digest.
   `mcp` is a client of an MCP server: live reads, and writes as tool calls. `http` is the
   generic fallback for either. A platform is a binding file naming which catalog entry serves
   which operation, pinned by digest, with its licence stated. Adding a platform is adding a
   file. A record reached through two shapes must derive to byte-identical facts, and a golden
   record per platform is checked both ways.

5. **The first three platforms**, one per shape, so the next phase has a target: a warehouse
   (Postgres, through Airbyte's `source-postgres` for history and an MCP Postgres server for
   live reads), a document store (an S3-compatible object store, through `source-s3` and a
   direct object read), and a ticket system (Jira, through Atlassian's remote MCP server for
   live reads and writes and `source-jira` for history, with GitHub Issues as the runnable
   stand-in for the demo). The binding files decide the pins; this record decides the targets.

6. **The receipt format grows, in `SPEC.md`, not here.** What an acquisition receipt needs to
   say — which system, which query, which snapshot, through which adapter, for which caller —
   and what an action receipt says are designed in
   [docs/design/receipt-v3.md](../design/receipt-v3.md). Nothing in that note is normative
   until it lands in `SPEC.md` with corpus vectors, under CONTRIBUTING's rule that the
   specification leads and the binary follows.

7. **What this record does not change.** The ceiling stays byte-lineage: a receipt never
   asserts that its contents are true or that an action was authorized. An action receipt
   records that an executor was asked, by whom, citing which decision, and what the target
   answered. `SPEC.md`, the corpus, and the honest bounds in the README are untouched by this
   record.

### Consequences

- Good, because the user downloads one thing and configures platforms, while the trust-root
  statement in SECURITY.md stays true by construction.
- Good, because coverage comes from catalogs other people maintain, and the vendors' own MCP
  servers cover the systems no community connector reaches well.
- Good, because the boundary is tested, not asserted: a crossing fails on a developer's machine
  before a pull request exists.
- Bad, because the repository is no longer dependency-free as a whole; only the core is, and
  the contribution guide has to say so.
- Bad, because the engine depends at run time on a container runtime to execute connector
  images, an operational dependency this repository never had.
- Bad, because a second module in one repository invites the shortcut this record forbids; the
  guard is the only thing standing between "in the box" and "in the process".
- Revisit when an adapter needs a richer channel than one request and one result over
  stdin/stdout — a streamed page sequence, a long-lived MCP session — and decide then whether
  the source contract grows or a second contract stands beside it; when pinning the runtime in
  the image starts lagging its releases; or when a second implementation of the engine exists
  and the boundary needs stating as a contract rather than a test.

## More information

[SPEC.md §6](../../SPEC.md) for the source contract this record keeps. [SECURITY.md](../../SECURITY.md)
for the trust boundary it protects. The runtime's ADR-0013 for the precedent of shipping a
release as an OCI image. Design notes: [receipt-v3.md](../design/receipt-v3.md),
[engine-config.md](../design/engine-config.md), [engine-image.md](../design/engine-image.md).
