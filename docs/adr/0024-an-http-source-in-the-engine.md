---
status: accepted
date: 2026-11-11
deciders: maintainer
---

# A catalog binding's `live` operation may be of the `http` shape, run by `adapter-http` as the platform's user and receipted as the plain form receipts it

## Context and problem statement

`serve --config` derives its sources from catalog bindings, and a binding naming the `http`
shape was refused by name ("the http shape is not shipped by this release"). `--source` cannot be
combined with `--config`, and `/act` cites only receipts from the engine's own store. So reading
an HTTP API in the engine, and acting elsewhere on what was read, took a hand-written MCP server
in front of the API: another program between the credential and the request, written for the
occasion, and a receipt that named that program and not the API (gateway #384). The plain form
already has the program for this, `adapter-http`, run with `--source-shape NAME=http`, and the
receipt for it (SPEC.md §1.2a, shape `http`). What was missing was the slot in the engine.

## Decision drivers

- One HTTP client: the engine runs the plain form's `adapter-http`, and the receipt is the plain
  form's, member for member; no second client and no new wire or receipt form.
- The engine's separation holds unchanged: the request is made by an adapter process as the
  platform's OS user, with that platform's credentials file, under the source sandbox; the signer
  never reads the credential.
- The engine form is at least as strict as the plain form: what the binding fixes, a request
  cannot steer, and nothing a platform names beside the binding is accepted and left unused.
- An older gateway refuses what it cannot run, by name, before any source is derived.
- Read-only: an `http` source is never a write tool and `/act` never dispatches to it.

## Considered options

1. A new member of the engine configuration naming an HTTP source per platform, under a new
   engine version.
2. A binding's `live` operation of the `http` shape, the slot the binding format already names
   and refused, run by `adapter-http` as the engine runs `adapter-mcp`.
3. `--source` beside `--config`.

## Decision outcome

Chosen option: 2, because the design already reserved it — the binding parser knew the shape and
refused it, and the design note said it was served by `adapter-http` "and not yet by any binding
operation" — and because a binding is pinned by digest in the catalog, so the endpoint, the paths
and the headers are fixed where every other platform's reach is fixed and reviewed. Option 1
would put the reach of a source in the operator's configuration beside the binding that is meant
to state it, and needs a version every existing configuration would carry for nothing. Option 3
would bring the plain form's sources, run as the signer's own user unless told otherwise, into
the form whose claim is that no source runs so.

The decisions within it:

1. **The operation.** `live` of shape `http` has exactly `shape`, `licence`, `endpoint`, `paths`
   and, optionally, `methods`, `headers`, `checkPath`, and exactly one of `bearer` and
   `credentialHeader` (`docs/design/engine-config.md`, "An HTTP API as a platform's live
   operation"). The endpoint is held to SPEC.md §1.2a's endpoint form, stricter than the adapter,
   which also takes `localhost`; no placeholder; and in its path, as in a path, no percent sign, dot
   segment or empty segment (one closing `/` aside, which the adapter drops), since the adapter
   sends the endpoint's path decoded and escaped again. A path is what the adapter accepts and,
   besides, printable ASCII without a comma, a percent sign or a brace: the engine passes the paths
   comma-joined, so a comma would widen the allowlist; the adapter sends a path escaped, so a
   percent sign would not be what the operator wrote; a brace reads as a placeholder no parameter
   fills; and the paths, comma-joined after `--paths=`, make one word under 128 KiB, since Linux
   refuses to start a program given one of 128 KiB or more. A credential member is required, since
   the platform names a live credentials file as for every operation; a credential header may not be
   `Proxy-Authorization`, which a proxy reads, nor one the adapter writes. A check path is one of
   the paths with `GET` among the methods, as a probe is one of the tools: a check asks for nothing
   an acquisition could not. No `caFile`, `maxOutput` or `timeout`: the endpoint chains to the
   system's roots, as a remote MCP server's does, and the adapter's own bounds (1 MiB, twenty
   seconds) lie inside the engine's on every source (1 MiB, thirty seconds).
2. **Alone, and in bindingVersion 1.** An `http` live operation is its binding's only operation:
   its platform reads by it and acts through another platform's `write`, and `/act` reads a write
   platform's live source as an MCP server's. No owner taxonomy (ADR-0021) is defined for an
   operation whose acquisitions name no tool, so a bindingVersion 2 or 3 binding naming the shape is
   refused — an empty `toolTaxonomies` must not stand in for a declaration — and the current
   admission's owner-declaration requirement, which is of MCP operations, does not reach it, as it
   does not reach `history`. `write` and `history` of the `http` shape stay refused.
3. **Who makes the request, as whom, with which credential.** `adapter-http`, a program of the
   adapters module the signer is never linked with, started by the signer for each acquisition as
   every engine source is started: as the platform's OS user (never root, the signer's own, the MCP
   server's or another platform's), with `no_new_privs`, under the source sandbox as an adapter from
   engine version 13, in the platform's environment. It reads the platform's live credentials file
   — owned by that user, mode `0600`, the path walked and resolved by the signer — and sends the one
   member the binding names to the endpoint the binding fixes, nothing else of the file, and nowhere
   else: it follows no redirect, and no request names the host. The signer reads the envelope from
   the adapter's stdout and signs; it never reads the credential. The plain form may run the same
   adapter as the signer's own user; the engine cannot.
4. **What a platform may name beside it.** Refused at start and at `connect`: a `grant`, since an
   `http` acquisition names no tool, so a delegation's own scope check (SPEC.md §11.5) would refuse
   every one under the grant as `out-of-scope` — reason `source` when no scope entry names the
   source, `tool` when one does — and the grant would admit nothing; an `endpoint`, since the
   binding fixes it and the receipt names the URL sent to; and, by the rules that already hold for a
   binding without a write operation, a live MCP operation or a placeholder, `write: true` — and
   with it `decisionPolicy` and `writeRequesters` — `parameters`, `descriptors`,
   `operationDescriptors` and `descriptorStatements`. The platform's `environment` stays, for a
   proxy, say.
5. **Admission.** `/acquire` of the source is authenticated as every source's is. Since the platform
   names no grant, a delegated acquisition, with a delegation credential presented or not, is
   refused `grant-unknown` (SPEC.md §10, rule 3) before the scope check, the custody, the issuing
   host or the adapter is reached. The MCP server lists no tool of the platform, since it has none;
   `/act` takes no write for it, since it derives no write source, and takes a write on another
   platform that cites its acquisition, as it takes one citing any.
6. **`connect` and `posture`.** `connect` runs `adapter-http --check`, with the check path, as the
   platform's user; the endpoint the report names must be the binding's, a probe must be reported
   exactly when a check path was given and must have answered 2xx; nothing is captured, and the
   entry written carries no new member. `posture` counts the source among the sources it judges.
7. **Versions.** No engine version and no binding version is added. An older gateway must refuse a
   configuration that pins an `http` binding, and it does: every release since the engine
   configuration first shipped refuses an operation of the `http` shape by name when it loads the
   binding, for every binding version, before any source is derived; the configuration's members
   are unchanged and the binding's bytes are pinned by digest. A bindingVersion bump would make an
   older gateway refuse on a version it already refuses on by shape, and would put the shape under
   a version no other binding uses. A configuration that pins no `http` binding derives exactly the
   sources it did. Nothing a verifier accepts changes: the receipt is the plain form's `http`
   acquisition, already in SPEC.md §1.2a.

### Consequences

- Good, because an HTTP API is read in the engine by the program and under the receipt the plain
  form already has, and an action elsewhere can cite what was read, with no program written for
  the occasion between the credential and the request.
- Good, because the request is made by the platform's own user with its own credential, which is
  stricter than the plain form's default.
- Bad, because an endpoint that takes no credential cannot be named: every engine operation has a
  credentials file, and the binding must name a member of it.
- Bad, because an endpoint under a private certificate authority cannot be named except through
  the platform's environment, and an answer above one mebibyte cannot be read: the engine keeps its
  bounds on every source.
- Bad, because a delegated caller cannot read an `http` source, since no scope admits a call that
  names no tool.
- Revisit when an owner taxonomy for a non-MCP read is defined (which would let a delegation name
  one, and a bindingVersion 2 binding carry one), when a credential-less or private-CA endpoint is
  needed in the engine, or when an `http` operation is wanted beside `history` or `write` in one
  binding.

## More information

- Gateway #384; `docs/design/engine-config.md`, "An HTTP API as a platform's live operation";
  SPEC.md §1.2a (shape `http`), §6 ("Adapter sources", "In the engine"), §11.5; SECURITY.md,
  "Security boundary"; `adapters/README.md`, "adapter-http".
- Code: `go/http_binding.go` (the operation, its command line, the platform refusals, the check
  report), `go/engine.go` (`parseOperation`, `parseBinding`, `deriveSources`,
  `resolveEngineConfig`, `describedOperation`), `go/taxonomy.go`, `go/operation_descriptors.go`,
  `go/connect.go`.
- Tests: `go/http_binding_test.go`, `go/http_binding_e2e_test.go`.
