# adapters

The gateway's second module: the programs that reach outside catalogs and hand the
signer bytes over the source contract of [SPEC.md §6](../SPEC.md), in the envelope
[ADR-0002](../docs/adr/0002-adapters-report-in-the-envelope.md) settled. An adapter is
spawned by `gateway serve` as its own process, holds one platform's credentials, and
is never linked into the signer: `boundary_test.go` fails `go test ./...` on the first
import of the core module.

```
cd adapters && gofmt -l . && go vet ./... && go test ./...
go build -o adapter-airbyte ./cmd/adapter-airbyte
```

## Write an adapter

An adapter of your own — a wrapper around a private API, or around a system of your own — is a
source like the ones below: a program `gateway serve` starts for each acquisition of a source
declared with `--source-shape NAME=airbyte|mcp|http`. It reads one request on stdin, the
acquisition's `arguments` in their canonical form, and either writes one envelope on stdout and
exits 0, or refuses: it writes nothing on stdout, says why on stderr, and exits with another
status. The gateway starts it as it starts any source: the command resolved once, the environment
the operator declares with `--source-env` and `PATH` and nothing else, a process group of its own,
at most `--source-timeout` seconds (thirty by default) and at most `--source-max-output` bytes on
stdout (one mebibyte by default). A refusal reaches the caller as the first 200 bytes of what the
adapter wrote on stderr, each byte outside printable ASCII replaced by `?`, so say the reason in
one short line and keep a credential out of it.

### The envelope

The envelope is the one object [SPEC.md §6](../SPEC.md) states under "Adapter sources". This is
one, [`one-row.json`](../schema/vectors/adapter-envelope/valid/one-row.json) among the schema's
vectors:

```json
{
  "acquisition": {
    "adapter": {"name": "adapter-example", "version": "1.0.0", "digest": "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"},
    "endpoint": "api.example",
    "statement": "select id, status from decisions where id = 101",
    "snapshot": null,
    "peerIdentity": null,
    "schema": "sha256:fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
    "upstreamToken": null,
    "observedAt": "2026-10-25T12:00:00Z"
  },
  "result": {"id": 101, "status": "approved"}
}
```

- `result` is what the gateway attests: the receipt's `resultDigest` is over its canonical form, it
  is retained as the artifact, and the acquire response returns it. Any JSON value, in the canonical
  domain of SPEC.md §1.1: a number is an integer of the safe range written in digits, never `1.0`
  or `1e2`.
- `page`, when present, is `true`, and `result` is then an array of items; the receipt carries the
  digest of each.
- `acquisition` has exactly eight members: `adapter`, an object of exactly `name`, `version` and
  `digest` (`sha256:` and 64 lowercase hexadecimal characters) naming what fetched; `endpoint`,
  `snapshot`, `peerIdentity` and `upstreamToken`, each a string or `null`; `statement`, the query,
  path or tool call as text, or `null`, which the gateway commits to under a salt of its own and
  does not keep in the clear; `schema`, `null` or the digest of the schema the result was read
  under; and `observedAt`, when the result was read, as `YYYY-MM-DDThh:mm:ssZ` in UTC and whole
  seconds. Every member is present, `null` where the adapter knows nothing.
- An adapter of the `mcp` shape that reached a remote server over Streamable HTTP adds `transport`,
  `"http"`, and `server`, the `name` and `version` the server gave itself, together; its `endpoint`
  is then the server's URL and its `peerIdentity` the TLS peer's
  ([ADR-0015](../docs/adr/0015-a-remote-mcp-server-as-a-source-and-executor.md)). No other shape
  carries them.
- Nothing else, at any level: not `shape`, which is the operator's, not `pageItems`, which the
  gateway computes, and no member of your own.

The envelope is published as a JSON Schema,
[`schema/adapter-envelope.v1.json`](../schema/adapter-envelope.v1.json) (draft 2020-12), with
valid and invalid vectors beside it under `schema/vectors/adapter-envelope/`. Every valid vector
is accepted by the schema and by the gateway, and every invalid one refused by both: the `go-test`
and `adapter-envelope-schema` checks hold the two to the same files. A schema reads parsed JSON,
so four things are the gateway's alone, and its description names them: the reading of the text
(a fraction or an exponent, a member named twice, text that is not UTF-8); `transport` and
`server` from a source declared with another shape than `mcp`; the source's output bound and
timeout; and a result nested deeper than the response can carry. A new member or a changed form
is a new version of the file.

### Check it: `gateway adapter-conform`

`gateway adapter-conform` runs your adapter as `serve` would run it as a source, hands it each
request of a directory of cases, and reports what `serve` would make of each answer, with nothing
retained and nothing minted: no store, no seed, no session.

```
gateway adapter-conform --shape http --vectors ./cases 'my-adapter --endpoint https://api.example'
gateway adapter-conform --shape mcp --vectors ./cases --env HOME -- my-adapter --config /etc/my-adapter.json
gateway adapter-conform --shape http 'my-adapter --endpoint https://api.example' < request.json
```

The adapter's command is one argument, split on white space as `--source` splits it, or the words
after `--` as given. `--shape` is required: it is the shape you will declare with `--source-shape`.
`--env KEY` hands the adapter that variable from this process's environment and `--env KEY=VALUE`
that value, as `--source-env` does, and nothing else reaches it but `PATH`; `--timeout SECONDS` and
`--max-output BYTES` are the source's `--source-timeout` and `--source-max-output`. Each case is a
`*.json` file of the directory, taken in the order of their names, of exactly two members:

```json
{"request": {"path": "/read", "body": {"id": 101}}, "expect": "accepted"}
```

`request` is the acquisition's `arguments`. `expect` is `accepted`, or `refused: ` and the class of
the refusal the case expects (below): `refused: source-failed` for a request your adapter must turn
down itself. A refusal of another class than the one named is not the one expected, so an adapter
that answers such a request with a broken envelope, or runs past its timeout, fails the case.
Without `--vectors`, the request on stdin is the one case, expected to be accepted. A case file
that cannot be read stops the run before the adapter is started.

Each case is reported as `accepted`, or as `refused:`, its class and the reason, one line each, the
ones that did not come out as expected marked `UNEXPECTED`, and then the count; `--json` writes the
same report as one canonical JSON object, `{"shape", "cases": [{"case", "expect", "outcome",
"refusal"?, "reason"?, "unexpected"}], "unexpected"}`, `refusal` being the class. The exit status
is 0 when every case came out as expected, 1 when one did not, and 2 when the command line or a
case could not be read.

### What a refusal means

`refused` is the refusal `serve` makes: the acquisition fails, nothing is retained, nothing is
minted, and the caller is told the reason. Its class says whose it was, and the reason begins with
`serve`'s words for it:

- `source-failed`, `source failed: …` — the adapter exited with a status other than 0, and what
  follows is the start of what it wrote on stderr. This is your adapter refusing, the one class a
  case for a request it must turn down expects.
- `timeout`, `source did not finish within its N-second timeout` — the adapter ran past the
  source's timeout, or left a descendant holding its output past it.
- `output-bound`, `source output exceeds N bytes` — stdout ran past the source's output bound.
- `not-started`, `source could not be started: …` — the adapter could not be run.
- `not-json`, `source did not return a canonical JSON value: …` — stdout is not one JSON value in
  the canonical domain: a fraction, an exponent, an integer past the safe range, a member named
  twice, text that is not UTF-8, or anything after the value.
- `not-an-envelope`, `the adapter's result is not an envelope: …` — the value is not an envelope of
  the form above, or carries `transport` and `server` from a source declared with another shape;
  what follows names the member and the rule. An adapter that answers a request with this has a
  defect, and the schema refuses the same envelope.
- `not-returnable`, `the result cannot be returned: …` — the result is nested deeper than the
  response can carry.

Only `source-failed` is your adapter's own; a case may name another class, to hold the adapter to
the source's bounds, for one.

The shipped adapters are held to the same command by the `adapter-conform` check
(`scripts/checks/adapter-conform.sh`, `testdata/adapter-conform`): `adapter-airbyte`,
`adapter-mcp` and `adapter-http` are run to accepted envelopes against stand-ins for a container
runtime, an MCP server over stdio and a remote one over Streamable HTTP, and a provider. The
connection programs reach providers that nothing can stand in for from outside their process, by
design: each envelope source of the connection local plan is run as the plan runs it to a request
it refuses itself before reaching a provider, each such refusal held to the class `source-failed`,
and the envelope its own code writes in its package's tests, against a stand-in provider, is run
through `adapter-conform` and the schema. That is the source's envelope as its code writes it, not
one its released program wrote from a real provider.

## adapter-airbyte

Runs a connector image that speaks the Airbyte protocol — the catalog of several
hundred sources — through the operator's container runtime, and reads **one page of
one stream** per acquisition: the records as the result, and the acquisition as the
adapter recorded it.

```
gateway serve ./store gateway.seed gateway:acme ./registry.jsonl \
  --source history='adapter-airbyte --image airbyte/source-postgres:3.6.1@sha256:… --credentials /run/secrets/warehouse --endpoint warehouse.internal:5432' \
  --source-shape history=airbyte \
  --source-env history=HOME
```

- `--image` must be pinned by digest: what runs is what the receipt names. The name is
  held to the shape of a reference — registry, path and tag components, each beginning
  with a letter or digit — and the runtime's option parsing is ended (`--`) before the
  image on its command line, so nothing handed to it as an image or as a container
  argument is read as an option.
- `--credentials` is the connector's configuration JSON, a file the adapter's identity
  can read and the signer's cannot ([SECURITY.md](../SECURITY.md)). It is mounted
  read-only into the connector's container and never passed through an environment. It is
  at most 1 MiB and an object, held to exact member names with a duplicate refused, so every
  value in it is one the redactor knows.
- `--runtime` is `docker` by default; `podman` works the same. The runtime inherits
  the adapter's environment, which is what the operator declared with `--source-env`:
  a runtime needs its `HOME`, and `PATH` is copied by default.
- `--endpoint` is the host the connector reaches, as the operator names it; the
  connector's own configuration is not read for it.
- `--check` runs the connector's `check` with the credentials instead of a read, and
  reports on stdout what the platform answered — `{"check": {"adapter", "status":
  "succeeded", "message"}}`, the message redacted as every diagnostic is — without reading
  stdin. A connector that answers `FAILED`, reports an error, or answers nothing fails the
  check with its own message, and a connector exits 0 whichever way it answers, so the
  answer is read from the message and never from the exit status. The first status the
  connector emits is its answer — a later one cannot revise it, and a second answer fails
  the check. A check that did not succeed writes `{"check": {"status": "failed", "message"}}`
  on stdout beside its exit status, so a caller reads one shape either way. The report is for
  the operator connecting a platform (`gateway connect`); nothing is minted from it.

The request, as canonical arguments on stdin:

```json
{"stream": "decisions", "namespace": "public", "limit": 1000, "state": "<the previous receipt's snapshot>"}
```

The members are read by their names as written, each once: `STREAM` is not `stream`, and a
request that names a member twice, in one spelling or in two, is refused.

A stream is named by `stream` and, when the connector offers that name in more than one
namespace, by `namespace` — a null namespace and an empty one are distinct, as the
protocol has them, and `"namespace": null` names the stream without one; a name that is
ambiguous without a namespace is refused. `limit` is
the page's floor, not a cut: once it is reached, records are kept until the connector
emits a checkpoint that covers them, so the next page never repeats a record; past
`--max-records` without one, the read is given up on. A stream that ends with records
after its last checkpoint is refused rather than bookmarked there, since a resume would
repeat them and the receipt has no member to say so. `state` is the previous page's
`snapshot`, exactly as its receipt recorded it, and is handed back to the connector in
the form it reads. A record whose data is not an object, and a `RECORD`, `STATE`,
`TRACE` or `CATALOG` message that does not have its stated shape — a checkpoint without
the payload its type needs to be handed back, among them — fail the acquisition; a line
that is not a message at all — a connector's log — is skipped. A message is read by its
members' exact names, with a duplicate member at any depth refused: Go's struct decoding
would let `TYPE` stand in for `type`, or `STREAM` for `stream`, and a second member overwrite
the first, on lines that decide what a record belongs to and whether the platform answered.

What the envelope carries, and so what the receipt records:

| Member | From |
|---|---|
| `adapter` | the pinned image: name, tag, digest |
| `endpoint` | `--endpoint`, or `null` |
| `statement` | the read request — stream, sync mode, cursor, the state resumed from — which the gateway commits to under a salt |
| `snapshot` | the connector's last checkpoint for the stream, compacted and otherwise as emitted, or `null` when it offered none |
| `peerIdentity` | `null`: a connector inside a container does not tell the adapter who it connected to |
| `schema` | the digest of the stream's discovered schema, canonicalized per §1.1 with any non-integer number carried as its decimal text |
| `upstreamToken` | `null`: the connector protocol carries none |
| `observedAt` | when the last record of the page was read |
| `result`, `page: true` | the records, each carried into the canon domain: member names sorted, and a number with a fraction or an exponent, or past ±(2^53−1), carried as a string holding its literal exactly |

**The container.** The credentials are written into a directory only the adapter's
user can enter (`0700`); inside it, the directory mounted read-only at `/secrets` is
readable by any user (`0755`, files `0644`), so a connector running as its image's
non-root user under a rootless runtime — whose identity does not map to the adapter's
— can read its configuration while no other user on the host can reach the parent. The
mount is removed when the acquisition ends, and its modes are set after creation so the
umask the adapter was launched under does not narrow them. Every container is told to
stop by name when the acquisition ends, whether or not its client is still running,
because a runtime client that is killed leaves its container running; a kill the runtime
refuses is followed by an inspect, and only an inspect the runtime answers with "no such
object" or "no such container" followed by the container's own name counts as gone — a container it still knows, or a runtime
that cannot say (a daemon that is down, a host that cannot be resolved), fails the
acquisition and says so first, since the container holds the credentials mount.
`--timeout` (twenty seconds) is the time for reading; the adapter's cleanup wait budget for
stopping the container is seven seconds on top of it (a kill, an inspect and the drain of its
output, and the wait for the client's pipes). The gateway's source timeout — thirty seconds by
default, or the `--source-timeout` given that source — starts before the adapter does: the
gateway resolves the command and starts it, on Unix behind a process-group anchor, before the
adapter's own clock begins. So keep `--timeout` plus that budget under the source's timeout with
further margin for that start and for the adapter's report; the margin is what a connector
reaching the adapter's deadline needs to be reported as a deadline rather than killed
mid-report. At the defaults the twenty and the seven leave three seconds of it.

**Diagnostics.** A connector's error — the first line of its stderr, or a `TRACE`
message, or the runtime's answer about a container that would not stop — is reported to
the gateway, which returns it to whoever called `/acquire`.
Every scalar of the credentials file — each non-empty string and each number, as
written, longest first, in one pass over the original text — is redacted from it before
it leaves the adapter. That is as
good as the connector's habit of quoting its configuration verbatim: a secret it encodes
or splits is not caught, and a one-letter value redacts every letter like it. What the
connector or the runtime writes on stderr is kept up to 64 KiB and redacted before its first
line is cut, so a key spanning lines, or a value longer than a line, is matched whole; when
the buffer overflowed, whatever ends it that is the start of a credential is cut off — after the
whole ones were replaced — since the rest of it may be what was dropped. A message with a duplicate member anywhere in
it, or nested deeper than a decoder reads (10,000 levels), is refused before it is classified,
since a second `type` spelled with an escape, or a member too deep to read, would otherwise
decide what the line is. A credentials file that is refused is not quoted: the refusal names
no member, since a member's name may be another member's value. A check the connector ends without a status reports the
connector's first line of stderr, when it wrote one.

Two honest bounds. The record data are the connector's: a record with a duplicate
member name or invalid UTF-8 fails the acquisition rather than being repaired. And the
page is bounded twice — by `--max-output` here and by the gateway's
`--source-max-output` there; keep the first at or below the second, so a page that is
too large is reported rather than killed mid-write. Neither podman nor Windows paths in
the mount argument are exercised by the tests; the fake runtime reads what was mounted
as the adapter's own user.

Tests run the adapter against a stand-in for the container runtime
(`internal/fakeruntime`), so no runtime is needed to test it; the both-paths agreement below
is the adapters' one test that uses a runtime, gated on `AGREEMENT_RUNTIME` and run by a CI
job of its own;
the adapter's canonicalizer answers to the same frozen vectors as the core's
(`corpus/canon.json`), read from disk and never linked.

## adapter-mcp

### Customer bindings

A customer server uses the same source contract as every MCP adapter, without a
provider-specific connection implementation. A catalog binding with
`"bindingVersion":"2","customer":true` names the server and declares `operation`
and `effect` for every allowed tool in `toolTaxonomies`. `gateway connect` runs
`--check --descriptors-binding=NAME@sha256:HEX` with the owner declaration and
captures a separate snapshot for each enabled operation. Registration calls no
tool; a customer binding accepts no probe. Missing declarations and contradictory
server annotations refuse registration.

The server is one of a digest-pinned `image`, a fixed `url`, or a `command` array.
A command server additionally requires an absolute `workspace` directory and may
name a separate operator policy file with `sandboxPolicy`. Arguments remain array
elements, including spaces; they are never interpreted by a shell. A source
derived from the binding has shape `mcp`, just as a manually declared source with
`--source-shape NAME=mcp` does.

For a manually declared source, pass `--customer-binding` alongside the existing
owner-declaration, approved-platform, approved-binding, approved-operation,
descriptor-snapshot and descriptor-pin flags. Capture uses the existing
descriptors-platform, descriptors-binding and descriptors-operation flags with
`--check` instead of the approved snapshot. A local command also requires
`--sandbox-workspace`; `--sandbox-policy` selects the separate policy file and
`--sandbox-source` selects its source override.

Customer captures use `"snapshotVersion":"3"`. Each tool includes `descriptorDigest`,
the SHA-256 of the complete tool descriptor's strict JSON bytes from `tools/list`,
before display filtering. Changes to an unsupported schema, an output schema, a
title, or any other descriptor member therefore refuse the next call, as do
representation changes within those bytes. Version 2 approvals remain readable
for their existing bindings; they cannot substitute for a customer's version 3
approval. Neither an acquisition nor a health check refreshes approval.

Every call checks the exact allowed names, pinned snapshot bytes, binding,
operation, endpoint, server identity and current descriptors before `tools/call`.
The named refusals include `mcp-tool-not-allowed`, `mcp-descriptor-drift`,
`mcp-taxonomy-contradiction`, `mcp-owner-declaration-required` and
`mcp-snapshot-required`. A descriptor refusal leaves approval unchanged.

Receipt version 3 is unchanged. The acquisition's disclosed `statement` additionally
names `binding` and `descriptorSnapshot` when a customer call uses an approved snapshot;
the receipt commits to this statement using its existing salt. `acquisition.snapshot`
continues to mean upstream currency and is not repurposed. The descriptor snapshot
is not yet independently signed; signed provenance is the separate work in #313.

The sandbox policy file has this shape:

```json
{"policyVersion":"1","defaultMode":"workspace-write","sources":{"customer/live":"read-only"}}
```

Absent a policy file, a customer command uses `workspace-write`. The three modes
are `read-only`, `workspace-write` and explicitly selected `danger-full-access`.
Workspace-write permits writes under the source workspace and a private temporary
directory. The policy file must resolve outside that workspace. The policy belongs to the operator; a tool's arguments cannot select it.
The successful check report includes `sandbox` with mode, backend, state and reason.
No backend means `sandbox-not-enforced` and the restricted command is not started.

Linux tries bubblewrap and falls back to Landlock ABI 3 or newer. Landlock is
reported as `partial`: file-content writes, truncation and directory mutations are
restricted, while metadata operations such as chmod remain outside its controls.
macOS uses Seatbelt through sandbox-exec. Windows uses the restricted-token and ACL
backend described below and reports partial enforcement. Other platforms refuse
restricted customer commands. Network access is outside this filesystem policy.
The mode does not establish a tool's declared effect or the truth of its answer.

A client of a [Model Context Protocol](https://modelcontextprotocol.io) server reached over
stdio, or over Streamable HTTP at a URL (the remote form, below) — the servers vendors now
publish for their own systems — that calls **one tool** per acquisition: the tool's whole result as the result, and the acquisition as the adapter
recorded it. It is meant for live reads at decision time; writes belong to the executor,
later. **The adapter cannot tell a read tool from a write tool**: an offered tool of any name
is callable with the configured credentials, and a read tool given a write statement runs
it. Reads-only is therefore the operator's to establish — credentials the platform holds to
read-only, and `--tools` naming only the tools meant to be called — and nothing here
establishes it for them.

```
gateway serve ./store gateway.seed gateway:acme ./registry.jsonl \
  --source live='adapter-mcp --image ghcr.io/example/mcp-postgres:2.1@sha256:… --credentials /run/secrets/warehouse-env --endpoint warehouse.internal:5432 --tools query' \
  --source-shape live=mcp \
  --source-env live=HOME
```

- `--image` runs a pinned server image with stdin attached; what follows `--` are then the
  server's own arguments inside the container, after the image on the runtime's command
  line: `adapter-mcp --image …@sha256:… -- --access-mode=restricted`. A local server
  instead — one installed beside the gateway, or a launcher like `npx` — is given after
  `--`, word by word, with its arguments: `adapter-mcp --credentials … -- npx -y
  @example/mcp-server --flag`. The gateway splits a source on whitespace and parses no
  quotes, which is why neither is a quoted value. Exactly one of the two forms, and the
  `--` is required and the line is split at it before the adapter's flags are parsed: without
  it, flag parsing would stop at the first word and hand every later flag to the server,
  silently, and parsed together a `--` could be consumed as a flag's value.
- `--credentials` is a JSON object of strings that become the server's environment — a
  token, a connection string — and nothing else is added: a container gets them through an
  env file in its private mount; a command gets them beside the adapter's own environment,
  which is what the operator declared and what a launcher like `npx` needs. The file is at
  most 1 MiB and is held to exact member names with a duplicate refused, so every value in it
  is one the redactor knows; for a server the adapter runs, each member is an environment variable name (`[A-Za-z_][A-Za-z0-9_]*`,
  since an env file drops a line that begins with `#` or whitespace) with a string value
  holding no newline, carriage return or NUL, since an env file is read by lines and a
  carriage return before the newline is dropped with it — a value the container would see
  differently from the adapter is refused rather than carried. A refusal names no member, since
  a member's name may be another member's value.
- `--tools` names the only tools a request may call; a request outside it is refused before
  any server starts.
- `--check` starts the server with the credentials, completes the handshake and lists its
  tools, then reports on stdout — `{"check": {"adapter", "server": {"name", "version"},
  "protocolVersion", "tools"}}`, with `"transport": "http"`, `"endpoint"` and, over TLS,
  `"peerIdentity"` after `adapter` for a remote server — calling nothing and reading no stdin. A tool named by
  `--tools` that the server does not offer fails the check, so a binding that names a tool
  the pinned server lacks is found out when the platform is connected, not at the first
  acquisition. A server that starts and lists its tools without a working connection to its
  platform answers the handshake all the same, so `--probe TOOL` names a tool the check calls
  once with no arguments — one of `--tools`, offered by the server — and requires it to answer
  without an error; its result is discarded, and the report says which tool answered. A server
  that catches its own failure and answers it as ordinary text, `isError` false, says so only
  in the text, and `--probe-failure TEXT` names what such an answer begins with — as written, neither side
  trimmed — so that answer fails the check too; the binding that pins the server is where that
  text is known. A text item the check cannot read by its exact members fails the check as
  well, rather than being passed over. What the server said of itself — its name and version, its tools' names — is
  redacted before it is reported, as every diagnostic is. The report carries `"status":
  "succeeded"`; a check that did not succeed writes `{"check": {"status": "failed",
  "message"}}` on stdout beside its exit status, so a caller reads one shape either way. The
  report is for the operator (`gateway connect`); nothing is minted from it. Each string in it
  is at most 512 bytes, the marker of a cut included, and the list of tools at most 64 KiB, with
  what passes it counted in `toolsUnlisted`.
- `--descriptors-platform NAME` with `--descriptors-binding NAME@sha256:HEX`, beside `--check`,
  has the check capture what `connect` keeps for the platform
  ([docs/design/tool-descriptors.md](../docs/design/tool-descriptors.md)): for each allowed tool
  its description and its input schema's original text, and the server's name and version as
  its `initialize` answer gave them. The listing is then pinned, so a cursor given twice or a
  tool offered twice fails the check. A candidate is captured whole or falls back whole, never
  stripped: display policy 1 (Unicode 15.0.0 classes, from `mcp/policy_table.go`, which
  `mcp/gen_policy.go` makes), schema grammar 1 and its limits, and no string holding a value of
  the credentials. The report gains `descriptors`, the snapshot in canonical form, at most
  320 KiB with at most 256 KiB of descriptions and schemas, tools admitted in the server's order
  while both hold; and `fallbacks`, each tool and part not captured with the reason, at most
  64 KiB with the rest counted in `fallbacksUnlisted`.

**The remote form.** `--url` names a server reached over
[Streamable HTTP](https://modelcontextprotocol.io/specification/2025-06-18/basic/transports),
instead of an image or a command, and is exclusive with both: given together, or with words
after `--`, they are refused before anything is read
([ADR-0015](../docs/adr/0015-a-remote-mcp-server-as-a-source-and-executor.md)).

```
gateway serve ./store gateway.seed gateway:acme ./registry.jsonl \
  --source tickets='adapter-mcp --url https://mcp.example.com/api/mcp --credentials /run/secrets/tickets --bearer TICKETS_TOKEN --header X-MCP-Readonly=true --tools get_ticket' \
  --source-shape tickets=mcp
```

- `--url` is held to the one form `SPEC.md` §1.2a states for a remote server's endpoint, which
  the signer and both verifiers hold the receipt's `endpoint` to as well: at most 2048 bytes of
  printable ASCII; `https://`, or `http://` at a loopback address written as one (127.0.0.0/8 in
  dotted decimal, or `[::1]` — a name such as `localhost` is not one, since what it resolves to
  is not in the text), the scheme in lower case; a host that is a name of letters, digits, `-`,
  `.` and `_`, or an IPv6 address in brackets, in the form RFC 3986 names `IPv6address`, with
  no zone; a port, when given, from 1 to
  65535 with no leading zero; no user, so no `@` before the host (one in the path names no
  user, and is taken as written); no query, no fragment; every `%` in the path followed by
  two hexadecimal digits. It is used
  exactly as written, nothing appended. A redirect is never followed: the server's `3xx` fails
  the call, named by its status and never by its location.
- `--bearer MEMBER` names the member of the `--credentials` file sent as
  `Authorization: Bearer`. The file is a JSON object of strings, held as above; nothing else of
  it is sent, and every value in it is redacted from what the adapter reports. The credential is
  never on a command line, and never in an error, a log, the envelope or the report; an answer
  that repeats it, as written or escaped, is refused before anything of it is read.
  `--credentials` without `--bearer` is refused — a credentials file with no use is a mistake —
  and a server that takes no credential is given neither.
- `--header NAME=VALUE` is sent on every request as written and may be given more than once.
  `Authorization`, `Proxy-Authorization` and `Cookie` are refused (a credential's place is the
  credentials file), and so are the protocol's (`Mcp-Session-Id`, `Mcp-Protocol-Version`,
  `Last-Event-ID`) and the ones the client and the transport write (`Content-Type`, `Accept`,
  `Content-Length`, `Host`, `Transfer-Encoding`, `Connection`, `Accept-Encoding`). A read-only
  header the server honours — Azure DevOps' `X-MCP-Readonly`, say — is the operator's to send,
  and is the server's promise: nothing in the record claims it.
- `--ca-file` is a PEM file whose certificates are the only roots trusted for the server,
  instead of the system's, as `adapter-http` has it.
- One session per invocation: `initialize` — held to the same rules as over stdio — then
  `notifications/initialized`, the tool list, the one `tools/call` (or, for `--check`, the list
  and the probe), and the session ended with a `DELETE`. The session id the server issues
  (`Mcp-Session-Id`) is the client's: sent on every later request, and recorded nowhere. An
  answer may be JSON or an event stream; each is read no further than a limit of its kind, and an
  answer one byte past its limit is refused with a sentence naming the kind of answer and the bound.
  A JSON body is read whole, to the limit and one byte more, before any of it is parsed. An event
  stream is held to the limit as a whole, every byte counted, comments and notifications included;
  its events are parsed as they arrive, and the response to the request ends the reading, so what
  follows it is not read. An answer with a `Content-Encoding` other than `identity` is refused before
  any of it is read, and no encoding is asked for. The limits:
  a tool call's is `--max-output` and 64 KiB (the JSON-RPC envelope, an event stream's framing, and
  a server's comments and notifications ahead of the response), `initialize`'s is 1 MiB and each
  page of the tool list's is 8 MiB, neither bounded by `--max-output`. A tool's result is then held
  to `--max-output` as over stdio. A
  request the server makes of the client is answered as over stdio. A body that is not a JSON-RPC
  message, of another content type, a response to another request, or a status outside `2xx` —
  the server's refusal, named by its status — fails the call; a JSON-RPC error is reported in
  the server's words, redacted.
- `--tools`, `--check`, `--probe`, `--probe-failure`, the descriptors capture, `--error-results`,
  `--max-output` and the result's reading are the stdio form's, unchanged. `--endpoint` is
  refused beside `--url`, which is the endpoint the receipt records, and `--runtime` is not used.
  `--timeout` bounds the call, and ending the session takes up to five seconds more.

What a remote acquisition establishes: that an endpoint at that URL, presenting that TLS
identity, answered that tool call with those arguments with those bytes, at that time, under the
operator's credential, where one is configured (the record itself does not say whether one was
sent) — byte lineage from that endpoint, and nothing about whether
the bytes are true. What it does not: that the tool read rather than wrote (the adapter cannot
tell, and `--tools` is the only thing that keeps a source to reads); that the server is honest or
is the vendor's; that the name and version it gave itself are its own; or anything the session
carried beyond the one call.

The request, as canonical arguments on stdin:

```json
{"tool": "query", "arguments": {"sql": "select id, status from decisions where id > 100"}}
```

`tool` and `arguments` are read by their names as written, each once: `TOOL` is not `tool`.
What `arguments` holds is the tool's, and its names are held to nothing here.

What the envelope carries, and so what the receipt records:

| Member | From |
|---|---|
| `adapter` | the pinned image: name, tag, digest; for a command, the command as configured, the version the server reports of itself (redacted, as a diagnostic is), and the digest of the executable; for a remote server, this adapter: `adapter-mcp`, its version, and the digest of its own executable |
| `endpoint` | `--endpoint`, or `null`; for a remote server, the URL as configured |
| `statement` | the call — tool and arguments — which the gateway commits to under a salt |
| `snapshot` | `null`: the protocol offers no bookmark |
| `peerIdentity` | `null`: a server over stdio establishes no transport identity; for a remote server, `tls:sha256:` the digest of the leaf certificate the call's answer came under, `null` over plaintext loopback |
| `schema` | the digest of the tool's declared output schema, canonicalized per §1.1 with any non-integer number carried as its decimal text; `null` when the tool declares none, which most do today — the descriptor's name, title, description and annotations are presentation, not schema |
| `upstreamToken` | `null` |
| `observedAt` | when the tool's answer was read |
| `result` | the tool's whole result — content, structured content — carried into the canon domain; no `page` |
| `transport` | for a remote server only: `"http"`; absent over stdio, whose envelope is what it was before the remote form |
| `server` | for a remote server only: `{"name", "version"}` as its `initialize` answer gave them, redacted as a diagnostic is; absent over stdio |

The handshake is `initialize` — refused unless the server answers with a protocol version
this client speaks (2025-06-18, 2025-03-26 or 2024-11-05), a tools capability, and a
`serverInfo` naming the server with a version string — `notifications/initialized`,
`tools/list` (paged to the tool; a page must carry a `tools` array, and a `nextCursor` that
is present must be a non-empty string), `tools/call`. A `ping` from
the server is answered with an empty result; any other request the server makes of the
adapter — for roots, for sampling — is answered "method not found", since this adapter
serves nothing; a notification, and a response to an id this adapter never used, are passed
over. A tool result is held to its shape — a `content` array of typed items, an object for
`structuredContent`, a boolean for `isError` — by exact member names; one that answers
`isError` fails the acquisition with its text, redacted; a text item whose `text` is not a
string as the server wrote it — null, or a number — is malformed and fails too. A line on the server's stdout that
is not a JSON-RPC message is a protocol violation and fails the acquisition, as the stdio
transport reserves stdout for messages. Every message, and every tool descriptor, is read by
its members' exact names with a duplicate refused, so `RESULT` cannot stand in for `result`
nor `NAME` for `name`; and what the server says is written into a diagnostic as it said it,
never quoted with an escape that would carry it past the redactor.

**The server.** An image is run and stopped as `adapter-airbyte` runs a connector — given
the wait delay to end on end-of-input, then told to stop by name, its absence established;
stopping takes up to nine seconds. A command is ended by end-of-input and, after the wait
delay, killed; both ends of its pipes are closed with the deadline, so neither a reader nor
a writer holds the adapter past it; and the command stays in the adapter's own process group,
so that under the gateway the source group's kill reaches it and what it started. On Linux the
adapter also adopts the orphans its descendants leave (`PR_SET_CHILD_SUBREAPER`) and kills every
descendant last, found through `/proc`, so a process the server left behind — holding the
credentials in its environment — does not keep them, rescanning until two scans in a row find none alive and
reap none — so a process forked between a listing and the reading of its parent is found once
its parent is gone — and failing the stop — and with it the check or the acquisition — when one
survives. A descendant is found through its
parentage, whatever session or group it made itself — it is the source group's kill, the
fallback, that a new session escapes — as far as the adapter's `/proc` shows them, which
includes child pid namespaces; elsewhere than Linux only the server itself is reached. `--image` is the shape
that keeps the lifecycle under a name. Every diagnostic
that crosses the source boundary — the server's, the runtime's, and this adapter's own about
what the server said, offered tool names included — is redacted and bounded as
`adapter-airbyte`'s are; a connection string's user name, password and query values count
as secrets in their own right, encoded and decoded, and a credential value that is itself
JSON is walked, as tokens, so a value under a member name that repeats is a secret too. A
token inside a format the redactor does not parse is not caught. What a server or a runtime
writes on stderr is kept up to 64 KiB and redacted before its first line is cut, so a credential
longer than a line, or spanning lines, is matched whole, and when the buffer overflowed whatever
ends it that is the start of a credential is cut off — after the whole ones were replaced, since a
credential whose end repeats its start is whole before it is a prefix; a duplicate member name in a message,
which the diagnostic names, is written as it is rather than quoted with an escape.

## adapter-http

One bounded request over TLS to an endpoint the operator fixed — a search provider's JSON
API, a reader service that renders a page or a PDF as text, any resource a URL names — with
a credential this adapter holds: the answer as the result, and the acquisition as the adapter
recorded it. It is the generic shape the envelope contract names, for a platform that has a
plain HTTP API and neither a connector image nor an MCP server of its own. What the receipt
then records is byte lineage from the endpoint's answer — which endpoint, over which TLS
identity, answered what, when — and nothing about whether the answer is true, current, or
the page its author meant.

```
gateway serve ./store gateway.seed gateway:acme ./registry.jsonl --receipt-version 3 \
  --source search='adapter-http --endpoint https://api.tavily.com --paths /search --credentials /run/secrets/tavily --bearer TAVILY_API_KEY' \
  --source-shape search=http \
  --source read='adapter-http --endpoint https://r.jina.ai --paths / --header Accept=application/json --max-output 8388608' \
  --source-shape read=http \
  --source-max-output 8388608
```

- `--endpoint` is the base URL every request is sent under: `https`, or `http` on a loopback
  host only, since a credential sent in the clear is a credential given away. It carries no
  user, no query and no fragment; a base path is allowed and a request's path follows it.
- `--paths` names the only paths a request may name, each exactly as it will be sent under
  the endpoint; a request outside them is refused before any connection is made. `--methods`
  names the methods, `GET` and `POST`, and is `POST` alone by default.
- `--credentials` is a JSON object of strings, a file the adapter's identity can read and the
  signer's cannot ([SECURITY.md](../SECURITY.md)); it is at most 1 MiB and held to exact member
  names with a duplicate refused, so every value in it is one the redactor knows. Exactly one
  member is sent: `--bearer MEMBER` sends it as `Authorization: Bearer`, and
  `--credential-header NAME=MEMBER` sends it under the header NAME, for an endpoint that takes
  its key under a name of its own. A refusal names no member, since a member's name may be
  another member's value. An endpoint that needs no credential is given none of the three.
- `--header NAME=VALUE` is sent on every request as written and may be given more than once;
  an `Accept`, a format selector. `Authorization`, `Proxy-Authorization` and `Cookie` are
  refused here: a credential's place is the credentials file, not a command line a process
  listing shows. So are the headers the adapter writes itself — `Content-Type` (from the
  body), `Content-Length`, `User-Agent`, `Accept-Encoding`, `Host`, `Transfer-Encoding` and
  `Connection` — since a fixed value there would be silently overridden; `Accept` is the one
  header with a default (`application/json`) that a fixed header replaces. The gateway splits
  a source on whitespace and parses no quotes, so a value with a space in it cannot be given
  on a `--source` line.
- `--ca-file` is a PEM file whose certificates are the only roots trusted for the endpoint,
  instead of the system's — for a private endpoint, and for a test.
- `--check` holds the configuration and the credentials to their rules, then reaches the
  endpoint: the TLS handshake alone, which establishes the peer's identity and nothing about
  the credential — on a plaintext loopback endpoint, a TCP connection, which establishes only
  that something answers — or with `--check-path /p` one `GET` of that path with the
  credential, which must answer 2xx. It reports on stdout — `{"check": {"status": "succeeded", "adapter",
  "endpoint", "peerIdentity", "probe"?: {"path", "status"}}}` — reading no stdin; a check that
  did not succeed writes `{"check": {"status": "failed", "message"}}` beside its exit status,
  so a caller reads one shape either way. Nothing is minted from it.
- A redirect is an answer from another resource than the one the operator fixed, and
  following one would carry the credential there: it is reported and never followed. An
  answer outside 2xx is a read that did not happen — nothing is minted, and the first bytes of
  the answer are the diagnostic, redacted on the bytes as answered before anything trims them,
  since an endpoint may quote the credential it refused. **An answer that repeats a credential
  is refused too**, 2xx or not: the credential that was sent, at any length, or any other
  scalar of the credentials file of eight bytes or more, found in the body as sent, in the
  body as it would be carried (a JSON string unescaped), or in a header the result or the
  receipt would carry — the `ETag` among them — fails the acquisition with nothing minted,
  because an artifact and a receipt are signed and in the clear, and an answer rewritten to
  hide it would not be the endpoint's. `--timeout` (twenty seconds) bounds the request. The
  gateway's source timeout — thirty seconds by default, or the `--source-timeout` given that
  source — starts before the adapter does, since the gateway resolves the command and starts it
  first, so keep `--timeout` under the source's timeout with margin for that start and for the
  adapter's report; that margin is what a request reaching the adapter's deadline needs to be
  reported rather than killed; `--max-output` bounds the answer and the envelope (at most 1 TiB, so
  the bounded read's sentinel byte cannot overflow), and an answer past it is refused, never
  cut — the read stops at the bound rather than draining what follows. Keep it at or below the
  gateway's `--source-max-output`: a reader service that renders a long PDF answers megabytes,
  and both bounds are the operator's to raise together. The adapter asks for no content
  encoding and decodes nothing on the way in; an answer the endpoint encoded anyway
  (`Content-Encoding` other than `identity`) is refused rather than carried as something it
  was not.

The request, as canonical arguments on stdin:

```json
{"path": "/search", "method": "POST", "query": {"lang": "en"}, "body": {"query": "federal skilled worker eligibility", "max_results": 5}}
```

`path` is required and names a resource under the endpoint — it begins with `/`, and carries
no query, no fragment, no dot segment and no empty segment; `method` is `POST` when absent;
`query` is an object of strings, encoded onto the URL with its names sorted; `body`, any JSON
value, is sent as `application/json` and refused beside a `GET`. The request is read by its
members' exact names with a duplicate refused and held to the canonical domain first, so the
body sent and the statement committed to are one spelling whoever wrote the request.

What the envelope carries, and so what the receipt records:

| Member | From |
|---|---|
| `adapter` | this adapter: its name, its version, and the digest of its own executable, which is what pins it |
| `endpoint` | the URL the request was sent to, without its query |
| `statement` | the request — method, path, query and body — as sent, which the gateway commits to under a salt: a search query or a page URL is in the receipt as a commitment, and in the clear only where the answer repeats it |
| `snapshot` | the answer's `ETag`, or its `Last-Modified` when there is no `ETag`, or `null`: the endpoint's claim about currency, which for a reader service is the service's and not the page's |
| `peerIdentity` | `tls:sha256:` the digest of the peer's leaf certificate; `null` over plaintext loopback |
| `schema` | `null`: an HTTP answer declares none |
| `upstreamToken` | `null`: no endpoint this adapter speaks to signs its answers |
| `observedAt` | when the answer had been read whole |
| `result` | `{status, headers, bodyEncoding, body}`: the status; of the headers, `cache-control`, `content-length`, `content-type`, `date`, `etag`, `expires` and `last-modified` when present, by their lowercase names, and never a cookie; and the body — an answer the endpoint sent as JSON (`application/json`, `text/json`, or a `+json` type) as a value carried into the canon domain, member names sorted and a number with a fraction or an exponent carried as a string holding its literal, so `"score": 0.98` reads back as `"score": "0.98"`; any other answer as `base64`, byte for byte — so a PDF is carried whole and a consumer re-digests the bytes it decodes |

Three honest bounds. A reader service is the source of the bytes it renders: `peerIdentity`
names the service, `endpoint` names the service, and the page's own origin, title and dates
are what the service reported in the body, established by nothing here — a consumer that
needs the page itself fetches the page itself, as its own source. Every diagnostic the
command writes — a request that would not parse, a configuration refused, a check that
failed, an acquisition that failed — crosses one boundary that redacts it against every
scalar of the credentials file and bounds it, and the answer-repeats-a-credential refusal
holds the same list; but a token inside a format the redactor does not parse, encoded or
split, is caught by neither. And a flag the command does not know is reported with the
usage, bounded but not redacted, since the credentials file is named by the flags that
failed to parse: the command line is the operator's own, and a credential does not belong on
it.

Tests run the adapter against a TLS server in the test process, with its certificate as the
adapter's `--ca-file`, so no network is needed and none is used in CI; the gateway's own
end-to-end test (`go/adapter_http_test.go`) spawns the built adapter as a declared source and
verifies the store that results.

## adapter-document

A document a person attaches in a desk — a PDF, a scanned form, a text export — read for its
text and attested as one versioned record. The contract is
[docs/design/attachments.md](../docs/design/attachments.md) and
[ADR-0004](../docs/adr/0004-documents-are-an-adapter-under-the-command-shape.md); this section
says how the adapter meets it. It is wired as a **bare** source — no `--source-shape` — so the
receipt carries the `command` shape: the gateway names the adapter by the command's first word
and the digest of the file that word resolved to, read before the process started, and every
transport member is `null`. The record carries the rest, as the adapter's testimony.

```
gateway serve ./store gateway.seed gateway:desk ./registry.jsonl --receipt-version 3 \
  --max-request 33554432 --source-timeout documents=40 \
  --source documents='adapter-document --max-bytes 16777216 --max-output 8388608 --timeout 30s' \
  --source-user documents=engine-documents \
  --source-max-output 8388608
```

- **The request** is the canonical arguments on stdin: `{"document": {"name", "mediaType",
  "bytes", "sha256"?}, "options"?: {"ocr": "auto" | "never"}}`. The adapter refuses at the first
  of four checks that fails — past the read bound, 4 × ⌈`--max-bytes` / 3⌉ + 64 KiB
  (`request-over-bound`); arguments outside the contract, `bytes` not its one base64 encoding
  included (`arguments-invalid`); a decoded document past `--max-bytes`
  (`document-over-bound`); a `sha256` that does not match (`digest-mismatch`) — by exiting 1
  with one ASCII line of at most 160 bytes, code first, which the gateway hands the caller as
  `source failed: <line>`. The reading of the request is inside the adapter's deadline, and a
  request still not read in full two seconds past it is refused the same way, under
  `adapter-failed`.
  `/acquire` reads at most 1 MiB by default, allowing about 760 KiB
  of inline document bytes. `gateway serve --max-request BYTES` sets that body bound up to
  64 MiB; size it for base64 plus the surrounding request. The example allows a 32 MiB body
  for a document of up to 16 MiB. A desk or proxy forwarding the request needs a compatible
  body limit of its own. Engine-derived sources retain the default gateway bounds.
- **The record** is built with the types of [attachment/](attachment/), and every record the
  adapter's tests produce — the fixtures' included — is held to `attachment.Check`, the note's
  reference check, before anything else is asserted of it.
- **The PDF reader** ([document/pdf/](document/pdf/)) is written in this module against the
  standard library: cross-reference tables and streams, object streams, Flate, LZW,
  ASCII-hex, ASCII-85 and run-length filters with PNG and TIFF predictors, the standard security
  handler opened with an empty user password (revisions 2 to 6, RC4 and AES), simple fonts
  through the predefined encodings and `Differences`, composite fonts through `Identity-H`,
  `Identity-V` and embedded CMaps, `ToUnicode` maps for both, and the text operators of each
  page in stream order, with spaces and line breaks inferred from glyph positions. A CMap's
  codespace ranges split a string into codes byte by byte, as 9.7.6.2 has it; bytes that fall in
  no range are consumed as the range holding the longest run of them says (9.7.6.3, the shortest
  such range deciding between equals) and are unmapped whatever number they make, since that
  number is no code the CMap gives. A code is its bytes and how many of them it has, so a
  mapping is found among the mappings for codes of that length: `<41>` and `<0041>` are two
  codes. A CMap whose ranges of two lengths hold the same leading bytes says two things about
  how long a code is and is not used at all, as a CMap past a
  bound is not used — a bound met anywhere in it, in a section of it or at the outer parse, since
  a map read no further than a bound is no reading of the map; what reading it cost is charged
  all the same. A CMap that declares no codespace range of its own is read at the lengths of the
  sources it maps, every one of them, the single codes of a `cidchar` or `bfchar` section as much
  as the ends of a range: one length throughout is that length, several are given the codes each
  actually maps, and where those cannot stand beside one another the map says two things about
  how long a code is and is not used either. The two ends of a range are codes of one length, as
  the two ends of a codespace range are, and a pair whose ends are of two lengths gives no range
  at all: read at either end's length it would hold codes of a length neither end gives, and
  which end to read it at is the reader's choice and not the map's. Such a pair maps nothing and
  says nothing of how long a code is; what reading it cost is charged all the same. The ranges
  given a length are drawn about the runs of codes it maps and no wider, so that a length takes
  in no leading byte another length's codes begin with, and are split where a byte carries —
  `<00FF>` to `<0100>` is two ranges, a range holding a byte at a time, and the one range from
  `00` to `01` beside `FF` to `00` holds neither of those codes; where a length maps more runs
  than the reader holds ranges for — the ranges counted as they are drawn, and not set aside
  before a run that may need fewer — they are taken together, from its lowest code to its
  highest, and where the range that takes them together does hold the leading bytes another
  length's codes begin with, the map says two things about how long a code is and is not used at
  all. A map holding no mapping at all is read at two
  bytes. What a CMap establishes is what it holds that a code can be looked up in — a codespace
  range it declared, a range it maps, a single code it maps — and not what the parser was given
  to read: an entry whose destination is no text (an empty string, an odd number of bytes, an
  unpaired surrogate) maps nothing, and neither does a range of codes whose destinations are every
  one of them a surrogate half or past the last scalar value Unicode has; a map of nothing
  establishes nothing. A range whose destinations leave the scalar values part way along
  establishes the codes whose destinations a text can carry and no others, being cut to them: a
  code the cut leaves out is mapped by nothing, and is no source this map gives when the lengths of
  its codes are inferred. A destination written as a number is charged whatever the number is,
  since the reader read it: one below zero and one past 2^31, neither of which is a destination
  this reader holds, are charged as much as a surrogate half or a value past the last scalar value
  — one entry in the single form of a `bfchar` or a `cidchar`, and what a range costs in the range
  form of a `bfrange` or a `cidrange`. What follows from that depends on which CMap it was: a
  composite font whose own **encoding** CMap is unusable has its glyphs unmapped and counted, by
  the rule below, while a font whose **`ToUnicode`** map is unusable keeps the encoding it has — a
  simple font's bytes are codes of one byte whatever a `ToUnicode` map says, so its glyphs are the
  ones its own encoding gives. Dropping the map is no defect of the document and adds no problem of
  its own; what that encoding maps is mapped and not counted, and a code it does not map — a
  `/Differences` naming a glyph no name of the standard sets gives, say — is unmapped and counted
  there as it is anywhere. A composite font whose `/Encoding` is neither `Identity-H`, `Identity-V`, a predefined CMap's
  name nor a CMap stream the reader can use — a stream it cannot use, a stream whose parse
  establishes no encoding at all (no bytes, bytes holding no operator of the syntax, a `begincmap`
  and an `endcmap` with nothing between them, or a stream naming a parent CMap with `/UseCMap`,
  which this reader does not look up), a reference to an object
  the file does not hold, `null`, a number, a dictionary, or no `/Encoding` at all — is not read as
  `Identity-H`: its bytes are split into two-byte codes so that the glyphs can be counted, every
  one of them is unmapped and takes the font's default width, and a `ToUnicode` map is not
  consulted — which codes the page shows is not something the file says. Where a font names a
  predefined CMap the reader does not carry, the codespace ranges its `ToUnicode` map
  **declares** say how many bytes its codes have, or two bytes where the map declares none — a
  range the reader inferred from the mappings a map holds is the reader's reading of it and is
  not borrowed — and every glyph takes the font's default width: the CID a
  code stands for is in the CMap the reader does not have, and a width read at the code's own
  number would be some other glyph's. An object a cross-reference places in an object stream is
  read by the number the stream's own header declares it at. Every place that header gives is
  kept as it stands, a pair the reader cannot use included, so that the place a cross-reference
  entry names is the place the header gave; a number is declared by its place before the offset
  beside it is read, so a pair whose offset the header does not hold, or holds as a token the
  reader cannot read, is a place that holds no object and a number declared there all the same;
  an offset is from the first object's and lies within what the stream holds after it. A token of
  the header past a bound of the parser is no such damage: a bound is not read past, so the
  header is no reading at all — not the places before the bound either — and the bound goes back
  to the reading that asked for the stream, the file's own where a scan of the file was the one
  reading it. Where the header declares one number twice, the entry's place
  decides, and only where the header declares that number at it.

  Where an inline image's data ends is established from the way the image is encoded, and from
  nothing else. The dictionary between `BI` and `ID` is read first, as pairs, at every depth it
  holds: `ID` stands between two complete pairs of the dictionary itself, and any other keyword, a
  key with no value, a value where a key stands, a stray delimiter, a byte that begins no token (a
  `)` closing no string, a `>` that is not half of `>>`, a byte in a hexadecimal string that is
  neither a hexadecimal digit nor white space — all of which elsewhere are skipped so a damaged
  file still yields its objects), or a container that does not close — in the dictionary or in a
  value of it — fails the page, since what follows an unfinished value may be the image's data
  rather than the dictionary. A key bearing on the end given twice with values that disagree fails
  it too — the abbreviations of 8.9.7 standing for the names they abbreviate, a filter written
  alone standing for the same filter in an array of one, a device colour space standing for the
  array of its family alone (a device space takes no parameters), and numbers compared by the value
  the reader holds: an integer as a 64-bit integer, a real as a binary64, and a real written finer
  than a binary64 holds as the nearest binary64 to what was written. Two writings the reader holds
  as one value are one declaration, so `1` and `1.0` are one value, of which the reader keeps the
  integer whichever was written first; two it holds as different values are two, whatever was
  written, so a whole number past 2^53 written as a real, beside that same number written as an
  integer, is one declaration or two as the binary64 falls, and a pair the reader holds as two
  values fails the page and is reported. A colour space stands at the name written alone, at the
  family at the head of an array, and at the positions such an array gives a colour space of its
  own — the base of an `Indexed` space, the alternate of a `Separation` or a `DeviceN` one — each
  of which is read as a colour space under the same rule as the outermost, however deep it lies, so
  `[/Indexed [/DeviceRGB] 1 <000000FFFFFF>]` and `[/Indexed /DeviceRGB 1 <000000FFFFFF>]` are one
  value. Those are the only positions read as colour spaces: what an array holds besides them is
  that family's parameters — a colourant's name, a tint transformation, a hival, a lookup table —
  and is compared as the image wrote it. An array of one element is the device space written
  another way only where that element is a device family's own name, so `[[/DeviceGray]]` is not
  `/DeviceGray` — it has no name at its family position — and beside it says a second thing about
  the image; a name at a nested family's position that is no family of one is left as written too.
  A bare name that is no device colour space is the name of one of the resources in force and
  abbreviates nothing, so `/I` and `/Indexed` name two resources and an image giving both says two
  things; only at the head of an array does `/I` stand for `Indexed`. The device names are the
  other way about: `/DeviceGray`, `/DeviceRGB` and `/DeviceCMYK`, and their abbreviations, name the
  device families themselves wherever they stand (8.6.8) — never a resource of that name, whatever
  the resources in force hold under it — and so does the array of such a family alone. A value
  written `null` is an entry the dictionary does not have (7.3.9): it says nothing of its key, and
  nothing another writing of that key says can disagree with it. That holds at every depth two
  writings are compared to: two dictionaries differing only by a `null` member are the same
  dictionary, however deep the member lies. An array's `null` element is not absent, since an
  array's elements are its positions. One white-space byte separates `ID` from the data, a carriage
  return and a line feed counting as the one end-of-line marker 7.2.3 makes them.

  An image no filter encodes is then measured: every viewer consumes the bytes its width,
  height, bit depth and colour components take, a row at a time and each row whole bytes. The
  depth is one of 1, 2, 4, 8 or 16 written as an integer (an image mask's is 1, or is not written
  at all — a mask that writes `0` has written a depth no sample has, which is not the same as
  leaving it out);
  the colour space is a device space, a space written as an array — `CalGray`, `CalRGB`, `Lab`,
  `ICCBased` by its stream's `/N`, `Indexed`, `Separation`, `DeviceN` by its up to 32 colourants
  — or the name of one of the resources in force, the page's or the form's, which is looked up
  there and read the same way. An `ICCBased` space's `/N` is 1, 3 or 4 written as an integer and
  is no other count (8.6.5.5): a stream declaring 2, 5, 32, `3.0` or no number at all has
  declared a packing no such space has, and an image in it is not measured from it.
  An image whose dictionary says none of this is not measured. The
  16 MiB bound below is a bound on the bytes the samples take, reached through the packing: a row
  one bit a sample wide holds eight times the pixels of a row of the same length at eight bits,
  and an image is past the bound when its bytes are past it and not when its pixels are.

  An image a filter encodes is framed by its **first** filter — the filters after it act on what
  the first decodes to, not on the bytes in the file — and only by one of the filters 8.9.7's
  Table 93 gives an inline image an abbreviation for: ASCIIHexDecode's `>`, ASCII85Decode's `~>`,
  RunLengthDecode's end-of-data, the end of a deflate or LZW stream, DCTDecode's end-of-image,
  CCITTFaxDecode's end-of-block. The encoding must be the encoding it claims: hexadecimal digits
  and white space — the white space of 7.2.3 and not every byte below a space — base-85 in groups
  of five within a four-byte word, a final group of two to four standing for as many bytes less
  one and completed as 7.4.3 completes it, a zlib header with the deflate data and the Adler-32
  checksum of what it decodes to, LZW ending at its end-of-data code. Data that is not the
  encoding at all is the image's own defect and is told from data whose end lies past what the
  reader may read of one image: a deflate stream corrupted in its first block is the one, a
  deflate stream that simply does not end within the window is the other. What a framing decodes
  is charged to `--max-inflate` and dropped, and every one of the seven framings reads the
  deadline as it walks, so that an encoding decoding to nothing is still bounded by the clock. The
  clock is read as the *bytes* go and not as the steps do: a run of JPEG fill bytes is walked one
  at a time, and a decoder handed a whole deflate block in one read has the clock read on that
  read rather than on the cadence, which counts calls.

  For the fax and JPEG framings the reader walks the encoding's own structure and decodes no
  rows and no blocks: an end-of-block is the end of fax data by definition and an end-of-image
  marker the end of a JPEG's, so the image ends there and what follows is the page's content —
  a JPEG whose scan holds no block still ends at its marker. In entropy-coded data `FF 00` is a
  sample byte and a restart marker resumes the data, the fill bytes ITU T.81 allows before one
  belonging to it: only a marker that is neither ends the scan. Outside that data the walk steps
  from marker to marker of the marker set alone — the markers that carry a segment whose first
  two bytes are its length, `C0`–`C7`, `C9`–`CF`, `DA`–`DF`, `E0`–`EF` and `FE`; the markers that
  carry none, `01` and `D0`–`D7`; `D9`, where the image ends; and `FF`, fill before a marker —
  and every other code fails the page, two bytes of anything else being no segment
  length: `FF 00` is the stuffing of a sample byte there as it is inside the scan, the codes
  below `C0` that are neither the temporary marker nor a restart are reserved, a second
  start-of-image begins no segment, and `C8` and `F0`–`FD` are reserved for extensions of the
  format whose segments are whatever an extension made of them, which this reader does not
  establish. A walk that read those two bytes as a length would step over
  the end-of-image the image really has, and over the `EI` and the operators after it, to
  whatever end-of-image lay beyond; the reader fails the page instead. Where such a structural end is
  reached and no `EI` stands there, the page fails; the `EI` check refuses that, and establishes
  nothing by itself.

  The length `/L` states is not a boundary: viewers disagree over it — one honours it where an
  `EI` follows, another decodes the filter and never reads it — so a record that took it would
  carry one viewer's reading rather than the page. Nor is an `EI` found in the data: those two
  bytes are as common in an image's samples as any other two, and a comment, a string or a later
  image after a whole image holds them as readily. An image the reader can neither measure nor
  frame therefore fails the page, and the record says so: that is CCITTFaxDecode with
  `/EndOfBlock false` or with `/EncodedByteAlign true` (where the fill bits before a row make the
  bits of an end-of-line, and telling the two apart means decoding the rows), JBIG2Decode and
  JPXDecode (the specification's inline-image abbreviation list, Table 93, does not include them,
  and this reader does not frame them), `Crypt`, a
  filter this reader does not know **as the first filter**, an encoding that is not the encoding
  it claims, and an unfiltered image whose width, height, bit depth or colour space the file does
  not give. An encoding whose end lies past the 16 MiB the reader may read of one image has met
  that bound and the page fails at it; a decode that meets `--max-inflate` fails with
  `stream-over-bound`, which is the only bound that records one.

  A predictor's last row, where the data ends inside it, is undone as far as the data goes, for
  the PNG predictors at every depth the reader supports and for the TIFF predictor at 8 bits a
  component, which is the only depth it implements. A
  damaged cross-reference is rebuilt by scanning for objects; everything read under the one it
  replaces goes with it — the objects, the object streams they came out of, and the fonts and
  CMaps built from them — since an object number then names other bytes. Every operation that resolves
  more than one of an object's fields is one read: following a chain of references, walking a
  page-tree node, reading one cross-reference section — a table, or a stream with its length, its
  `/W`, its `/Index` and its `/Size`, whether the chain reached it by `startxref`, by `/Prev` or by
  a hybrid file's `/XRefStm` — reading the encryption dictionary, drawing a form, finding a font, sizing a
  colour space, decoding a stream, looking for the page tree's root, reading a page's content and
  building a font each begin one. A read publishes to a
  cache, and records a bound or an undecodable object stream, only under the cross-reference it
  began on, at every depth it reaches, so a read that was under way when the rebuild happened
  leaves nothing of itself behind — the fields it goes on to resolve are fields of an object this
  document no longer has; the bounds that are the file's rather than one cross-reference's — the objects a scan
  of the file may find, the objects read in one document — stand whatever is rebuilt. The scan
  that rebuilds has a scope of its own: whatever read it was called from, its own reads are begun
  again under the cross-reference it is building, so that an object it could not read is marked as
  such and a bound it met is kept — as the file's, since a scan reads the file and not the objects
  of one cross-reference — and the read it was called from is put back afterwards and still
  publishes nothing. The references that read was following are put aside with it, so that the
  depth the scan reports is the depth the scan itself reached. A candidate the scan parses that
  is nested past what the parser admits is such a bound, a trailer dictionary among them; damage
  short of a bound is what the scan is for. A cross-reference section whose own read met the
  rebuild is abandoned where it stands: it declares none of its entries, its trailer carries the
  chain no further, and its failure — a bound of its own fields included — is published no more
  than its entries are, since it is a section of a document this one no longer is. That holds
  from the section's first field: a stream section whose `/Length` is the reference that rebuilt
  declares no entry either. The sections the chain had already queued are dropped with it — a
  `/Prev` or an `/XRefStm` named by the trailer of a section this document no longer has leads
  nowhere it says — while what the scan itself met stands, being the file's. What the scan
  registers, it registers under the trailer it rebuilt: the objects an object stream holds are
  registered once that trailer has said which handler the document is read through, since a
  stream decoded with the key the old trailer named holds no object to register and the file is
  scanned once. The
  encryption dictionary the trailer names is read again under the rebuilt cross-reference, and
  its handler and key with it, before the restarted pages are read. It is read as it stands: that
  dictionary's own strings are never encrypted (7.6.1), whichever read reaches it — the opening
  of a handler, or an ordinary reference from another object's field, resolved while the handler
  being replaced was still installed — and what the reader holds of the objects it has read is
  dropped before a handler is opened, so that the dictionary a handler is opened from is the
  dictionary the file holds and not one deciphered with a key this document does not name — a rebuild met while the page tree's root
  is looked for is a rebuild the reading begins again from the top, the root the catalog now
  names being read under a handler this walk is not the one to establish. Where the rebuilt
  trailer names no encryption at all, what was read through the handler the old one named was
  read through a key this document does not have, and those objects and the fonts and CMaps built
  from them are dropped as they are when a handler is installed. A bound that is the file's own, met while a page was read — a scan of the whole file that ended
  at one — refuses the document as it refuses one met opening it: what the reader has of the
  pages was read while the file was being scanned, and a bound is not read past wherever it is
  met. Extracting the pages ends at the
  page whose reading rebuilt the cross-reference — the generation is read again the moment that
  page's content comes back, before any of it is interpreted — and a walk that met a rebuild ends
  where it stands and is not extracted at all: the pages after it belong to a document
  this one no longer is, and what reading them would cost is not spent on them; a document is rebuilt at most once,
  however its opening goes, so a reading that would need a second rebuild reads the object as one
  that is unavailable — which refuses the document where the object is needed, and falls back to
  the `endstream` after it where what was wanted was a stream's length. A reading
  of the document's pages that began under the old cross-reference is begun again under the new,
  so that a record's pages were all read under one. The bounds met under the cross-reference that
  was replaced, and the object streams it could not decode, go with it: they are defects of a
  document this one no longer is, and an object still past a bound meets it again. What is not
  given back is what reading the file has cost — the inflate budget, the objects counted, the
  font budget — since a file that made the reader read it twice has spent it twice.

  A page-tree node named twice by a tree that holds no cycle is two nodes, and a page named
  twice is two pages; a node under itself is walked once, the root included where the catalog
  names it (a root found by scanning is known by no number, so one that names itself among its
  kids is walked as a kid would be, to the bounds on the walk). It decodes no image and renders
  nothing: a page that draws an image and whose text is empty after normalisation is `needs-ocr`.
  Page text is normalised as it is built, so the text budget is decided on the normalised bytes.
- **Scanned pages** go to the program named with `--ocr` — one word, resolved on the adapter's
  `PATH` and digested, the deadline checked immediately before it is started, and run in the
  adapter's own process group with its stderr discarded — once per document, with the page
  numbers as arguments and the bytes on stdin. Its answer is admitted only within the
  canonicalizer's domain, with exact members and only the pages it was asked for; anything else
  applies nothing (`ocr-failed`). With no program, or `options.ocr` `never`, the pages stay
  `needs-ocr` under `ocr-not-run`. The adapter carries no OCR engine. Launched with
  `--document-processing` and no `--ocr`, as the local plan launches it while a
  processor is configured, the operator's document-processing settings name the
  program and its deadline instead
  ([attachments](../docs/design/attachments.md#document-processing-ocr-under-the-managed-local-plan)).
- **Bounds** are flags, each but `--max-output` reported in the record. Each has a default and a
  ceiling:

  | Flag | Default | Ceiling |
  |---|---|---|
  | `--max-bytes` | 16 MiB | 1 GiB (1,073,741,824 bytes) |
  | `--max-pages` | 500 | 1,000,000 |
  | `--max-text` | 8 MiB | 1 GiB |
  | `--max-inflate` | 64 MiB in total, with 16 MiB for any one stream | 4 GiB |
  | `--ocr-max-output` | 32 MiB | 1 GiB |
  | `--max-output` | 1 MiB, at or below the gateway's `--source-max-output` | 1 TiB |
  | `--timeout` | 25 s, whole milliseconds; leave margin below the gateway's source timeout | 10 minutes |

  A value that is not positive, is past its ceiling, or for `--timeout` is not a whole number of
  milliseconds is a usage error: the adapter exits 2 without reading the request. At the
  ceilings, the read bound derived from `--max-bytes` is 4 × ⌈2^30 / 3⌉ + 64 KiB, 1,431,721,304
  bytes, and `timeoutMs` is 600,000, so every bound the record reports, and the read bound,
  stays within 2^53 − 1. The deadline runs from the adapter's start, before it reads its own
  executable for its identity and before it reads the request: the request is bounded in time as
  well as in bytes. The cutoff is an instant: two seconds past the deadline, and never nearer
  than fifty milliseconds from when the read began. That floor is the cutoff only where the
  deadline and the two seconds after it together fall earlier than fifty milliseconds from the
  read's start — a deadline more than 1,950 milliseconds old when the read begins — and it is
  there because such a deadline would otherwise leave a read of bytes that are there less than
  fifty milliseconds, possibly none at all; a deadline a millisecond old leaves the rest of those
  two seconds and never reaches the floor. A read that **ended** at or before the cutoff is the
  request, and the record then says `timeout`; one that ended after it is not, and is refused
  with `adapter-failed`, since no document has been established and there is nothing to record.
  The instant the read ended is stamped and recorded where the cutoff's arbitration can see it,
  under the same lock, so a read the runtime paused between stamping and handing its bytes over
  is waited for rather than refused: what decides is when the read ended, not when the adapter
  came to look. An arbitration that finds no read has ended is committed only once the clock is
  strictly past the cutoff, so that a read stamped after it is necessarily a late read: the
  refusal says that no read had ended by the cutoff, and not that none had ended by the moment
  the adapter looked. That has one exception, and it is a refusal: the looks such an arbitration
  makes are counted, and 4,096 looks that found no read ended and no reading strictly past the
  cutoff are treated as past it, so a read that then ends exactly at the cutoff is refused. What
  is counted is the looks and not a clock standing still — a clock advancing a nanosecond a look,
  from far enough behind the cutoff, is exhausted by them with the cutoff still ahead of it. The
  adapter never reaches the exception: it reads the system clock, and the cutoff's own timer has
  fired before the adapter looks, so the first reading settles it. Without the exception a clock
  that did not arrive, for a read that never ended, would be waited on for ever. What an
  exhausted arbitration refuses stays refused, and no read is taken after it: a result the read
  hands over in the meantime is not what decides. Nothing there is an elapsed time: what ends the
  wait is a reading of the clock, not an interval. What the cutoff
  does not promise is that a read the operating system has not finished scheduling will be taken.
  `durationMs` runs from the instant the adapter turns to reading the request, so it carries that
  reading as well as the work after it. While the document is opened — its
  cross-reference and trailer read, and a damaged cross-reference rebuilt by scanning — the
  deadline is checked at the intervals in the structure bounds below, and one met there ends the
  run the way one met while the page tree is walked does: `timeout`, `truncated` `true`, and no
  page listed. A reading of the deadline that finds it passed, wherever it is made, stops the
  document: from then on every reading finds it passed, nothing the reader reads is kept — no
  object, object stream or header, font, CMap or index of the file, and no bound or failure it
  meets — no rebuild of the cross-reference begins, and a read the deadline ended is the
  deadline, never an absent object, a malformed field or a bound met after it. In a page's
  content the deadline is checked
  before each of the page's content streams is decoded, between operators, at the interval in the
  structure bounds below, and before each reading of a form the page draws,
  and within one operator that shows a string at the interval below for
  glyphs; work between two checks is not interrupted, so what one check admits runs to its end
  within the structure bounds below. The deadline is read once more when the page's reading
  ends, whatever the page came to: a deadline that has passed by then passed while the page was
  read, and an object a resolve did not find after it — the scan that resolve began, ended by the
  deadline; the font the page was then shown with as unknown; the content stream then unread — is
  not known to be absent, so the page is not listed as it stands, nor as failed, and the run ends
  as one met in the page's content ends it. A deadline is read from the
  clock as well as from the context, so one that has passed while nothing has cancelled the
  context is still a deadline that has passed. An OCR program's outcome is taken once the program
  has exited and its stdout has ended, or once the adapter has ended it; a deadline passed by
  then is `ocr-timeout`, whatever the program wrote, and an outcome that is both past
  `--ocr-max-output` and past the deadline is `ocr-timeout`.
- **Structure bounds** are constants of the reader in [document/pdf/](document/pdf/). Where one is
  met decides what it is. Met while the document is opened or its page tree walked, it is
  `pdf-malformed` — but in the encryption dictionary, which is then a dictionary that cannot be
  read and `pdf-encrypted`. Met in a page's content, its content streams and the forms it draws,
  it fails the page as `pdf-page-failed`; a stream of it that inflates past `--max-inflate`, or
  past the 16 MiB for one stream, is `stream-over-bound` instead. Met while another resource the
  page names is read — a font, its CMap, an XObject — it is no error, as step 5 of the note says
  of every resource: a font keeps fewer widths or mappings, a glyph it can no longer map is
  counted in `unmapped`, and an XObject that is not read is not drawn. A page's `/Resources`
  dictionary itself is not one of those: it is an inheritable attribute of the page tree, read
  while the tree is walked, so a bound or an object stream met reading it is `pdf-malformed` (step
  4), while the same defect in a font that dictionary names is not. A cross-reference the reader
  could not finish reading — a `/Prev` chain past its bound, a section past a bound of its own —
  is `pdf-malformed` with no `encryption` in the record, whatever a trailer it did read named: the
  encryption dictionary is read from a document the reader has opened, and there is none.

  | Bound | Value | Met |
  |---|---|---|
  | indirect objects read in one document | 262,144 | wherever objects are read |
  | bytes read and held for each byte of the file and of each byte its streams inflate to | 160 | wherever objects are read: the bytes a value holds, charged as it is built, so one past the bound is never held whole, and the bytes of the file read to build it, charged as they are read, so a file read once for every object it declares spends the allowance; past it the object is left unread and the ones after it are not parsed |
  | bytes read and held in all | 1 GiB | wherever objects are read: the ratio above bounds a small file, this bounds every file, and a document within `--max-bytes` and `--max-pages` meets it by holding a great deal as well as by overlapping — about 1.9 million one-member dictionaries the extraction parses, or the equivalent: 500 pages of 3,600 each in their resources read whole, 4,000 each are refused. It is not the only bound such a document can meet: one that holds a great deal in a single array or dictionary meets the bound on a container's items first |
  | the bytes of an object read to decide whether it is the page tree or the catalog | 1,024 bytes | rebuilding: the window is read as objects, not searched for a word, and an object it cannot settle is parsed |
  | references resolving to references | 32 | wherever objects are read |
  | indirect objects read inside another object's read, including stream lengths | 32 | wherever objects are read |
  | the bytes searched for an `endstream` a stream's `/Length` does not locate | 4,096 bytes | wherever objects are read: the file's `endstream` offsets are indexed once, one per block of that size, and the index answers past the block |
  | arrays and dictionaries nested in one another | 256 | wherever objects are read, content included |
  | elements of one array, members of one dictionary | 1,048,576 | wherever objects are read, content included |
  | a name token; a string token; a numeric token | 4,096 bytes; 16 MiB; 64 bytes | wherever objects are read, content included |
  | objects one object stream declares | 65,536 | wherever objects are read |
  | cross-reference sections in the `/Prev` and `/XRefStm` chain | 64 | opening |
  | the object numbers one cross-reference section declares | 4,194,304 | opening |
  | cross-reference entries, scanned objects or trailers read between two readings of the deadline | 4,096 | opening: the deadline is read at least this often, and as often among the other things opening and rebuilding do one at a time for each of a structure the file declares -- the elements of a cross-reference stream's `/Index`, the ranges it declares, the members of a trailer merged or copied, the object numbers a cross-reference names gathered, sorted in runs of this many and merged, the places an object stream's header declares read, mapped and registered, and the blocks of the index of stream ends set up and filled |
  | inspections of a byte of the file made searching for object headers between two readings of the deadline | 65,536 | rebuilding: the deadline is read before the search for headers begins and whenever this many byte inspections have been made since the last reading, every inspection counted -- a byte the search for the keyword looks at, the byte after a keyword, each byte a header's backward reading tests, the one that ends a run included -- and a byte inspected twice counted twice; the search looks at most two bytes past what is left of the part, so at most 65,538 inspections lie between two readings, a deadline already passed costs no search, and one that passes during it costs at most that many more |
  | bytes of the file searched for `trailer` or `endstream` between two readings of the deadline | 65,536 | rebuilding, and indexing where streams end: the file is searched in parts of this size, each search looking the keyword's length less one byte past what is left of its part, and what is left carried from one search to the next, so at most 65,544 bytes are searched between two readings |
  | bytes a document's lexer advances over between two readings of the deadline | 16,384 | wherever objects are read, content and CMaps excepted: the cross-reference table and trailer, each object and each object-stream header, read with the deadline read whenever this many bytes have been advanced over since the last reading -- a token's bytes, the whitespace and comments skipped, which are read within a run however long it is, and a byte read again where the parser steps back over a token counted again; a keyword or a number is read whole, so at most 20,480 bytes lie between two readings, and a parse the deadline ends is the deadline and not a defect of the file or a bound. A page's content and its CMaps are read under the page's own readings |
  | objects found while the cross-reference is rebuilt by scanning | 262,144 | wherever objects are read |
  | page-tree depth; page-tree nodes visited | 64; 1,048,576 | the walk |
  | operators interpreted on one page, the forms it draws included | 4,000,000 | content |
  | operators interpreted between two readings of the deadline | 4,096 | content: the deadline is read at least this often |
  | glyphs shown between two readings of the deadline | 4,096 | content: the deadline is read at least this often within one operator that shows a string |
  | forms drawn within forms | 12 | content |
  | the operand stack | 64 | content |
  | bytes the operands of a page hold at one time, the forms it draws included | 64 MiB | content: the allowance is handed to the parser, which spends it as it builds each operand, so one operand past the bound ends the page rather than being built first |
  | graphics states saved and not restored | 256 | content |
  | one inline image's dictionary; its data | 128 objects; 16 MiB | content |
  | a page's content streams, concatenated | 64 MiB | content |
  | the work one page may cost: the bytes its content streams and the forms it draws hold, the decrypted copies made for it, and each entry of a filter list read | 64 MiB; 256 bytes an entry | content: a count of the work, not of the time it takes -- a chain of filters that yields nothing may still be slow -- a `/Contents` array may name one stream any number of times, a page may draw one form any number of times, and a filter that yields little charges the inflate bounds that little for each of them; an entry is charged as it is read, whether it is then applied or rejected, and not again when it is applied |
  | characters the glyphs shown on one page map to, the forms it draws included | 4,000,000 | content: an unmapped glyph counts as one, and glyphs past the text budget count |
  | fonts held by reference for a document; font resource names held while one page's content is read | 4,096; 4,096 | a font: past either the font is read again rather than held (no error) |
  | width entries one font's `/W` declares | 262,144 | a font: past it the font keeps no widths |
  | the CID a `/W` entry names; the CIDs one `/W` range spans | below 1,048,576; 65,536 | a font: past either the entry is left out |
  | mappings one CMap holds | 1,048,576 | a CMap: counted in the entries each mapping is charged, below; past it the CMap is not used |
  | codespace ranges one CMap declares | 256 | a CMap: past it the CMap is not used |
  | width entries and CMap mappings of all of a document's fonts together | 4,194,304 | a font: the `/W` or CMap a charge would take past it is not used, and a page shown with a font that kept none of its mappings reports its glyphs as unmapped rather than as an error |
  | the codes one `bfrange` or `cidrange` spans | 65,536 | a CMap: a longer range is cut to that span |
  | the entries one `bfrange` or `cidrange` is charged | 4; one more for each 8 characters of its destination | a CMap: a range whose destination is a number or a string is held as its endpoints and those characters, so it maps as many codes as its span while the two bounds above count what holding it costs. A range whose destination is an array is not a range at all: each of its members maps one code and is charged as a mapped code |
  | the bytes the values one CMap is read through may hold | 96 MiB | a CMap: never more than the entries its document's fonts have left, at the same reckoning; an operand, a destination or an array of them is built within it, and a CMap whose reading meets it is not used |
  | a `bfchar` or `bfrange` destination string | 512 bytes | a CMap: a longer one maps nothing |

  Widths serve the glyph positions from which spaces and line breaks are inferred; they do not
  map a glyph to a character.

  **What the bounds cost.** Two of them are stated in entries, and an operator sizing the
  adapter's process reads them as memory rather than as bytes of the file, since a compressed
  stream declares an entry in far fewer bytes than an entry costs. A cross-reference section may
  declare 4,194,304 object numbers, and the reader holds each as an entry of about 112 bytes,
  measured with a section of 262,144 entries, so a file of a few kilobytes whose cross-reference
  stream declares that many leaves it holding about 470 MB. A document's fonts may hold 4,194,304
  width entries and CMap mappings together, and a `/W` range is held as a width for each CID it
  spans rather than as its endpoints, so a file of a few kilobytes whose fonts share `/W` ranges
  that long leaves it holding about 200 MB — the figure a `/W` of that many entries extrapolates
  to, measured with one font's 262,144 widths, is about 151 MB, and 200 MB is the round number an
  operator sizes with. What the same 4,194,304 font entries cost as CMap mappings the shape of
  the mappings decides, and each shape is charged in entries for what it holds. Measured in one
  CMap for each shape: a code mapped to one character on its own is held at about 112 bytes and
  charged one entry, about 470 MB at the bound, and one mapped to seven characters at about 128
  bytes, about 540 MB, both at 262,144 mappings to the map; a `bfrange` or `cidrange` with a short
  destination is held at about 70 bytes and charged four, about 74 MB, at 65,536 ranges to the
  map; and a mapping of either kind whose destination is 256 characters is held at about 1.1 KB
  and charged a further entry for each eight of them, about 130 MB for ranges and 140 MB for
  single codes, at ten thousand to the map. Each of those is one measured population carried out
  to the bound, and none of them is a ceiling over the others: what a mapping costs for each
  depends on how full the Go map holding it is, so the same single mappings measured a hundred
  thousand to a map come to about 330 MB for one character and about 400 MB for seven. They are
  the order of the memory an operator should size for and not the most a bound can cost. A
  document whose fonts spend the bound keeps no mappings past it: the CMap that would cross it is
  not used at all, the codes it
  would have mapped are left to whatever mapping the font has without it — a simple font still
  maps through its encoding, and a font with none leaves its glyphs unmapped and counted in
  `unmapped` — and no error is recorded, since a font past its bound is not a failure of the page
  (step 5).

  The objects a document holds are bounded against what the reader spends on them rather than
  against the file's length: 160 bytes for each byte of the file and for each byte its streams
  inflate to, and 1 GiB in all, whichever is smaller. At `--max-bytes` 16 MiB with the default
  64 MiB of inflation the ratio would allow 12.5 GiB, so the ceiling is what binds a document of
  that size. It is a bound a document can meet by holding a great deal without overlapping
  anything, and not only by overlapping — about 1.9 million one-member dictionaries the
  extraction parses, or the equivalent — though it is not the only bound such a document can
  meet: one that holds as much in a single array or dictionary is refused at the bound on a
  container's items with a fraction of that charged. The figures are of pages whose dense
  structure lies in their own `/Resources`, which the walk reads whole before a page is
  extracted, so they are what an extraction parses and not what a test resolved for itself: five
  hundred pages of two thousand each, an eight-megabyte file, are charged about 566 MB and read
  whole; five hundred pages of three thousand six hundred each, fourteen megabytes, about
  1,022 MB and read whole; five hundred pages of about three thousand seven hundred and
  ninety each, fifteen megabytes, about 1,074 MB, which is the densest the ceiling admits
  at all — the page tree is walked whole and what is left is too little for the later pages'
  content, so they are listed as failed — and a little more than that, four thousand each among
  them, is `pdf-malformed` with no page listed. The last dictionary either side of that figure is
  the build's rather than the bound's: what a token's buffer is charged follows what Go's
  allocator gives it, and an instrumented build gives it something else, a few per cent either
  way. A reader that admitted the four thousand would be holding some 740 MB of Go maps and
  saying nothing about it. A document adapter
  that refuses at a stated bound is doing its work; what would make such a document cheap is a
  smaller representation for a small dictionary, which is not a change this bound can make. Two costs are charged against it, which
  are not the same cost of the same bytes: what a value **holds**, charged as the value is
  built, and what was **read** to build it, charged as each of a document's lexers advances over
  the file — a comment with no line end, a string with no end read ahead of a value and stepped
  back over, a candidate given up on and a token all count. Each byte counts once for each lexer
  that reads it, and a document starts one lexer for each object it reads; within one lexer a
  byte is charged once however often the parser steps back over it, except that the one-token
  lookahead after an integer reads a string again where the object after it is one. Which
  allowance a reading spends depends on what is being read: the objects of a document, its
  trailer, its cross-reference and the heads it inspects all spend the document's one balance,
  while a page's operands and an inline image's dictionary spend that page's operand allowance
  and a CMap's values spend one of its own — each bounded in its own right, and the memory of
  every token charged wherever it is read. What a page's content streams cost to decode is the
  page's work allowance -- its content streams and the forms it draws as they lie in the file,
  the decrypted copy made of any of them, and each entry of a filter list read -- and what a
  document's streams cost to decode while it is opened or rebuilt is charged against the same
  balance as its objects: the bytes each decoder is handed, before it runs, cross-reference
  streams included, so that a file whose streams share one long tail is charged for reading it
  once for each of them rather than reading it over and over for what it yields; a stream with no
  filter hands nothing to a decoder, and is charged where its bytes are parsed instead — an
  unfiltered object stream's header and objects are lexed and parsed against that same balance —
  with one exception: the rows of an unfiltered cross-reference stream are read as the
  fixed-width fields they are, without a lexer and without a charge, and what bounds them is the
  cross-reference table's own limits above, on the sections chained, the object numbers one
  section declares, and the bytes the file holds. Who answers for
  a decrypted copy is settled by the caller that asked for the decoding and not by the stream's
  own `/Type`: an object stream's decoded data is held by the document's caches for its life and
  is charged to the document, while a copy made for a page is dropped with the page and charged
  to its work. A file whose objects are each followed by a
  comment that runs to its end is read once for every object it declares, holds almost nothing,
  and is bounded by the second of those. The ratio is what dense ordinary
  structure needs — the smallest dictionary a file can spell, `<</A 1>>`, is eight bytes of file
  and a Go map of about 370 bytes held, and a pair of coordinates, `[0 0]`, is five bytes and
  charged about a hundred and thirty, for the fifty-six it holds — and it is what bounds a file
  whose objects hold, or read, the same bytes over and over, where what the reader spends would
  otherwise grow with the square of the file: a file of
  64 KiB whose every object is an unterminated string running to its end holds about 10 MB of
  them, and one whose every object ends in a comment with no line end reads about 10 MB of it.
  The charge is taken as each value is built, so a value past the bound is never held whole, and
  it is measured against what Go retains for each shape
  (`TestBoundsChargeCoversWhatIsRetained`), so the bound is a bound on memory and not on an
  estimate of it. An array is charged the room it grows to and not the elements put in it: Go's
  append leaves room past the length — thirty-three elements are held in a backing array of
  seventy-one slots — so the room is charged before the growth that takes it, at the doubling a
  small slice gets, and reconciled to the room the growth left once it is known, what was
  charged and not taken going back to the balance. The entry figures above are within the bounds
  and within `--max-bytes`, and none of them is a refusal: the process wants room for them. The
  overlapping shapes are not — a file whose objects hold or read the same bytes over and over
  meets this bound, and the document is `pdf-malformed` with no page listed.

  A `/Filter` name whose bytes are not valid UTF-8 is recorded as `null`, the way a `/R` outside
  the canonical range is: the record carries the name the document declared or nothing, not a
  reading of it with each byte the record cannot carry replaced. Which handler the reader opens
  is decided on the name's bytes either way, and a name is at most the 4,096 bytes of a name
  token above.
- **Fixtures** under [document/testdata/](document/testdata/) — normal, scanned, mixed,
  encrypted (RC4, AES, and one that needs a user password), truncated, a broken
  cross-reference, not a PDF, sixty pages, an inflating stream, a text file — each with the
  record it yields; `make_fixtures.go` regenerates them from the generator in
  `internal/pdfgen`, whose output the tests cross-check against poppler's `pdftotext` on a
  machine that has it. The gateway's end-to-end test (`go/adapter_document_test.go`) spawns the
  built adapter as a bare source, acquires a fixture, has a refusal reach the caller, and
  verifies the store.

## adapter-render

Content a desk wants as a document — the report of a decision, a letter, a summary — written
as a Word file and attested as one versioned record that holds the file. The contract is
[docs/design/rendering.md](../docs/design/rendering.md) and
[ADR-0006](../docs/adr/0006-documents-are-rendered-by-an-adapter.md); this section says how the
adapter meets it. It is wired as a **bare** source, as `adapter-document` is, so the receipt
carries the `command` shape. It holds no credential and opens no connection, and starts no
process but the rendering program an operator configured, for a PDF. The desk's local plan
names it as the source `render`, with no rendering program. No engine configuration and no image
names it: an operator adds the source.

```
gateway serve ./store gateway.seed gateway:desk ./registry.jsonl --receipt-version 3 \
  --source render='adapter-render --max-output 6291456' \
  --source-user render=engine-render \
  --source-max-output 6291456
```

- **The request** is the canonical arguments on stdin: `{"format": "docx" | "pdf",
  "document": {"title", "language"?, "blocks"}, "cites"?: {"decision"}}`. A block is a
  heading, a paragraph, a list or a table, and holds runs of literal text that may be bold,
  italic, in a fixed-width typeface, or linked. Every object is closed, nothing nests, and
  nothing is brought in from outside the request. The adapter refuses at the first check that
  fails, by exiting 1 with one ASCII line of at most 160 bytes, code first:
  `request-over-bound`, `arguments-invalid`, `content-invalid`, `content-over-bound`,
  `renderer-not-configured`, `renderer-failed`, `timeout`, `file-over-bound`,
  `record-over-bound`, `adapter-failed`. A rendering is whole or it is refused: the adapter writes no record of
  part of one. A write of the record that fails part-way exits 1, and may leave the
  beginning of a record on stdout, which the gateway does not read. The adapter ignores
  the signal a write to a closed pipe raises, so that such a write is reported too.
- **The Word writer** ([render/docx.go](render/docx.go)) is written in this module against
  the standard library. It writes seven parts in one order, each under one fixed timestamp and
  compressed before it is stored, and takes nothing from the clock or the environment, so the
  same content gives the same bytes from the same build. The text of any language is stored
  as text; the file embeds no typeface, and how a reader lays the text out is the reader's.
- **A PDF** is produced by a program the operator names with `--renderer`, one word. The
  adapter hands it the Word file it wrote for the same content, on stdin, and takes the PDF
  from its stdout, under the lifecycle of [internal/program/](internal/program/), which is
  the OCR program's. The record names the program as configured with the digest of its
  file, and says what it was offered. The adapter does not confine the program and does not
  read the PDF. With no program configured a PDF is refused with `renderer-not-configured`;
  a program that did not answer is `renderer-failed`, or `timeout` where the deadline had
  passed when its outcome was taken. The program is one written for this: a converter named
  by itself is handed `docx` and `pdf` as arguments.
- **A link** is a text and a target of scheme `https`, `http` or `mailto` that names a host
  or one address in its plainest form. The adapter writes the target into the Word file as
  given and never follows it.
- **The record** is held to `render.Check`, the contract's reference check, before the
  adapter writes it: the members closed, and the size and the digest those of the file the
  base64 holds. For a Word file the check also holds the file to be the seven parts laid out
  as the writer lays them out, and the parts to be within the bound the record states. For a
  PDF it holds the file to begin and end as a PDF does, and bounds nothing of what the PDF
  holds. `cites.decision` is copied into the record as the caller's assertion and checked
  for its form only.
- **The bounds** are `--max-request` (1 MiB), `--max-blocks` (2,000), `--max-file` (4 MiB),
  `--max-output` (1 MiB) and `--timeout` (25 s). `--max-file` bounds a Word file's archive
  and what its parts hold uncompressed, since a small archive can hold long parts, and what a
  rendering program may write. The file travels in the
  record as base64, so with every default the largest file that fits is about 766 KiB; the
  example above raises the record's bound, and the gateway's, to carry a file of 4 MiB.
  Arguments that nest deeper than the structure does are refused by one pass over their
  bytes, before anything else is read of them.
- **What the tests hold.** The file's parts are read back with the standard library's ZIP and
  XML readers and held to the text and the structure of the request. Where `pandoc` is
  installed, one test reads the file with it as well, and is skipped where it is not. No test
  here opens the file in Microsoft Word or LibreOffice.

## The both-paths agreement

[ADR-0001](../docs/adr/0001-one-engine-four-processes.md) point 4 promises that a record reached
through both shapes derives to byte-identical facts, and that a golden record per platform is
checked both ways. `agreement/` is that check for the postgres platform: the rule by which each
shape's envelope yields a record's facts (`facts.go`), the envelopes the two adapter binaries
wrote when they fetched the golden records — the World sample database's city with `id = 1`, and
a one-row table holding 2^53 + 1 — under the artifacts `catalog/postgres.json` pins, with two
counterexample captures (`testdata/postgres/`), and the tests that hold them to each other, to the
golden records, to the pins and to the statements the rule names. With `AGREEMENT_RUNTIME=docker`
(or `podman`) the test also starts the World database, fetches both records afresh through the
adapter implementations under a role held to reading, requires two writes through that role to be
refused, fetches the counterexamples again, reads the stream in the connector's xmin mode, and
holds the fresh facts to the fixtures'; the CI job "both paths agree" runs it. The rule, what the first capture found,
and what the check does not establish are in
[docs/design/both-paths-agreement.md](../docs/design/both-paths-agreement.md).

## How the connection programs read a request

`gateway-connections`, `adapter-drive`, `adapter-gmail` and `adapter-sources` read the
body of a request, of whatever provider, by its members' names as written, each once. A
member the operation does not name is refused, and so is one named in another case: Go's
struct decoding would take `QUERY` for `query`, and where a request held both would read
the one that comes last. The refusal is `invalid-request`, and says nothing of the request.

Three things this does not say:

- An operation that answers without reading its body holds the body to nothing. A
  connection service the operator has blocked answers every request so, `status` with its
  blocked state and the rest with `blocked-by-policy`.
- The line `gateway-connections` reads from its parent (`id`, `method`, `params`) is the
  host's and is read as it was, a member it does not know included.
- A document within a request is read by whoever uses it. A Google service account
  credential is JSON within the text of `credential`, and is read by the library that signs
  with it, which takes a name in another case.

## Personal Google Drive connections

Public source and GitHub releases include **no publisher Google registration**.
The checked-in `adapters/cmd/gateway-connections/publisher-google.json` remains
`{}`. An installation operator configures their own Google Desktop app through
the host's setup UI (Desk: **Admin → Connections**), then the account owner grants
access through Google's consent screen. App registration is not account consent.
Do not include personal or organization-owned publisher registrations in public
release artifacts, and do not fetch a publisher default automatically.

The companion retains support for an explicitly configured downstream build,
but that capability is not the public distribution policy. The prior proposal to
ship publisher-registered public bundles is superseded; the mechanism and its
limits are recorded in [the registration design](../docs/design/publisher-google-oauth.md).
Existing operator registrations, account tokens and authorization epochs are not
replaced by an update. Changing a client remains explicit and requires disconnecting
its account first. Operator-disabled connections remain blocked.

`gateway-connections --state-dir /private/connections --principal desktop-owner`
is a bounded JSON-lines control companion over private parent pipes. It implements
`status`, `configure`, `connect`, `poll`, `cancel`, `disconnect`, `search` and
`select`. `connect` asks for the whole of the person's Drive, the scope `drive`,
and for no chooser of Google's. A connection made under `drive.file` is answered
`reconnect-required`. `search` takes `{ "query": "words" }` and returns
at most twenty files that `adapter-drive` would take, with a `selectionContext`;
`select` takes `{ "resourceIds": ["id"], "selectionContext": "context-from-search" }`
of at most four files and returns a grant for each.
`configure` takes a registered Google Desktop application's `clientId` and
`clientSecret`. No reply contains provider access or refresh tokens. The parent
must authenticate its UI before relaying controls. This pipe is not an HTTP API
and must not be exposed to arbitrary remote callers. `--disabled` refuses provider
operations. Organization identity and policy routing are not implemented by this
personal companion.

`adapter-drive --state-dir /private/connections --principal desktop-owner` is a
separate source with `--source-shape drive=http`. It accepts
`{"fileId":"selected-file","grant":"64-lowercase-hex"}`. The grant comes from
`select`, which takes any file's ID, one a search gave or another: a grant says
that the host asked to read the file, and not that a person chose it. It
is scoped to that file and connection, expires after five minutes, and is
consumed once. `JPACK_CONNECTIONS_DIR` can supply the operator's state path when a
source command cannot contain spaces; a request cannot override it. Give this
source a 60-second timeout and 16 MiB output bound. Files are limited to 4 MiB;
Docs, Sheets and Slides export as PDF. The record retains original bytes inline.

See [the connection design](../docs/design/drive-connections.md) for the identity
boundary, Google registration, cancellation and revocation semantics. Private
credential custody currently supports Linux and macOS; other platforms refuse
startup rather than use unchecked file permissions. Signing and provider processes
are separate modules, but running them as the same OS user does not isolate what
that user can read.

## Personal Gmail connections

`gateway-connections --provider gmail --state-dir /private/connections --principal desktop-owner`
uses a separate provider namespace under the same private custody root. It shares
`status`, `configure`, `connect`, `poll`, `cancel`, and `disconnect` with Drive.
Gmail uses fixed read-only scope, and has no `pick`, send, delete or write operation.
`search` accepts `{ "query": "from:person@example.com", "pageToken": "optional" }`
and returns up to ten metadata previews. Search also returns an opaque `selectionContext`. `select` accepts `{ "messageIds": ["hex-id"], "selectionContext": "context-from-search" }`
(up to four) and returns message-bound single-use grants. These controls belong to
the authenticated user-facing picker; search results are not automatically model context.

`adapter-gmail --state-dir /private/connections --principal desktop-owner` accepts
`{ "messageId": "hex-id", "grant": "64-lowercase-hex" }` as a source with
`--source-shape gmail=http` and explicit `--source-env gmail=JPACK_CONNECTIONS_DIR`.
Use a 60-second source timeout and 16 MiB output bound. It emits a bounded 4 MiB
plain-text email export with retained export bytes, message/thread IDs, source
history version, and `provenance.source.format = "text-export-v1"`. The export is
not the raw MIME message. Separate mail attachments are excluded; HTML is converted
to text without scripts or remote resources. UTF-8 and supported legacy charsets
are decoded through Go's x/net package, only in the adapters module.

Enable Gmail API and configure a Desktop OAuth application for `gmail.readonly`.
This grants mailbox-wide read permission at Google; application selection narrows
what is attached to chat, not Google's permission. Google revocation is project-wide,
so disconnecting may require other connections using that Cloud project to sign in
again. Separate provider stores do not change upstream revocation semantics.
See [Gmail design and limits](../docs/design/gmail-connections.md). Live production
consent/retrieval has not been tested without an operator's registration and consent.

### Notion and Obsidian note sources

`gateway-connections --provider notion` performs browser OAuth with automatic
client registration. `--provider obsidian` connects an existing local vault via
`configure {"path":"/absolute/vault"}`. Both expose bounded search and explicit
selection; `adapter-sources --provider notion|obsidian` consumes the resulting
single-use read grant. No write operation is exposed. Notion uses remote MCP;
Obsidian reads local Markdown without a plugin. See
[connected note sources](../docs/design/connected-note-sources.md) for protocol,
custody, snapshot, account scope and limits.

### Discover connection capabilities

`gateway-connections --catalog` prints a versioned JSON catalog of implemented
connection protocols and exits. It needs no account or state directory and makes
no provider requests. Hosts use the advertised authentication, registration,
selection and operation identifiers with their own supported handlers, then ask
for live account status. The catalog does not authorize access or prove a service
is currently available. See [the catalog contract](../docs/design/connection-catalog.md)
for compatibility, limits and the distinction from tool listings and receipts.
`--catalog-v3` prints version 3, and `--catalog-v4` version 4: version 3 with the
research capabilities each adapter can serve, `answer`, `search` and `page`
([research capabilities](../docs/design/connection-catalog.md#research-capabilities-version-4)).

### Selected public web pages

`adapter-web` accepts `{"url":"https://example.com/policy"}` and returns an HTTP
acquisition envelope with a verified attachment record. Configure it as an HTTP
source (`--source web=adapter-web --source-shape web=http --source-timeout web=60`)
and allow 16 MiB source output. It admits public HTTPS only, validates DNS and
redirect destinations before dialing, and fetches at most 4 MiB without cookies,
credentials, proxies, JavaScript, or OCR. HTML becomes a static text snapshot;
plain text/PDF retain original bytes. See [the source contract and limits](../docs/design/public-web-sources.md).
Catalog v2 advertises it under `sources`, separately from account providers.

## Amazon S3 file source

The connection companion's catalog v3 advertises `aws-s3`. Existing hosts using
`connection-v1`, credential forms, prefix queries and `resource-v1` can display it
without provider-specific host code. The S3 source left the v2 catalog unchanged.

In Desk, choose **+ → More connections → Amazon S3**. Supply the commercial AWS
region, a general-purpose bucket and optional key prefix, and credentials with
`s3:ListBucket` for that prefix and `s3:GetObject` for the files. Reading a selected
object version also needs `s3:GetObjectVersion`; SSE-KMS objects may require
`kms:Decrypt` on their key. The connector does not grant these permissions.
Temporary credentials additionally need the session token and RFC 3339 expiration.
Save checks listing access. Browse lists filenames starting with the configured
prefix plus the entered query; it does not search file contents or other buckets.

Select up to four PDF/text files, each at most 4 MiB. Listed archived, oversized,
empty and unsupported objects are disabled. Objects needing extra permissions
can still appear in listing and fail selection/read with a permission message.
The connector does not restore archived objects, accept requester-pays charges,
accept customer encryption keys or follow alternate/custom endpoints. Selected
objects are read conditionally and version-pinned when S3 supplies a version ID,
including `null`. Document bytes are retained, extracted locally (with OCR only when the
operator's document-processing settings enable a processor),
and verified through the existing signed resource record.

Browse contexts expire after five minutes, with the latest eight pages retained
for selection. Grants last five minutes and can be used once. Changing the scope,
credentials, policy or connection invalidates pending selections. Disconnect
removes local credentials; remove or deactivate an IAM key at AWS to revoke it
there. No AWS credentials or registrations are included in builds.

Credential custody is currently supported on Linux/macOS. This adapter uses
explicitly entered credentials; it does not read AWS CLI profiles, environment
credentials or Identity Center caches. Browser-based Identity Center sign-in,
GovCloud/China partitions, directory buckets, access points and custom S3 services
are separate follow-ups. The official Go SigV4 signer and Smithy path encoder are
pinned in `go.mod`, with license/notice files under `third_party/github.com/aws/`.

See [the design and acceptance boundary](../docs/design/s3-file-source.md).
Synthetic TLS and Desk tests are not a claim of live AWS account acceptance.

### Web search connections

`gateway-connections --provider web-search` holds up to six named search
connections, to Tavily or to Google Cloud Search grounding, and
`adapter-sources --provider web-search` reads one of them: a query in, links out,
under the HTTP shape. A daily request budget for each connection is reserved
before the network is reached. Hits are leads to read through `web`, not
documents. Catalog v3 advertises the provider under the protocol `web-search-v1`
and the local source plan names the source. The arguments are held to one table,
which `--describe-research` gives as a versioned request schema: a Tavily search
may also be restricted to domains and, as Tavily dates results, to a span of
time, and any other argument, or a value out of its form, is refused by name
before anything is charged or sent
([ADR-0019](../docs/adr/0019-web-search-holds-its-arguments-to-one-table.md)). See
[configuration, limits and the provider contract](../docs/web-search.md).
A Google grounding hit is a link to Google's redirect endpoint; `web` follows it
to the publisher only under the operator's `google-grounding` redirect policy
(`adapter-web --redirect-policies=google-grounding`, or
`JPACK_WEB_REDIRECT_POLICIES` for the local plan), and otherwise refuses it as
`web-redirect-origin`
([operator redirect policies](../docs/design/public-web-sources.md#operator-redirect-policies)).
Tests with local servers are not a claim that a live account is accepted.

### Databricks connections (API profile)

`gateway-connections --provider databricks` holds up to six named connections,
each to one Databricks workspace's REST API, and `adapter-sources --provider
databricks` reads one of them under the HTTP shape: one SQL statement on the
connection's SQL warehouse, or one page of a Unity Catalog listing. Catalog v3
advertises the provider under the protocol `databricks-v1` (`status`,
`configure`, `test`, `disconnect`; `auth` `client-credentials`), and the local
source plan names the source `databricks` with 60 seconds. The managed MCP
servers are its MCP profile (below).

`configure` takes the connection's `id`, its `revision` (empty to create, the
current one to change it), a `name`, and the setup fields: `workspace-url`,
HTTPS and a host of a workspace's own domain (`*.cloud.databricks.com`,
`*.cloud.databricks.us`, `*.cloud.databricks.mil`, `*.gcp.databricks.com`,
`*.azuredatabricks.net`) with no path, port, user information, query or
trailing dot; `warehouse-id`; `auth`, `token` with `token` (a personal access
token) or `service-principal` with `client-id`, `client-secret` and an optional
`scope` (space-separated, `all-apis` unless given); an optional `catalog` and
`schema`; `wait-seconds` (5 to 50, 30 unless given) and `max-result-bytes`
(65,536 to 15,728,640, 8 MiB unless given), as text:

```json
{"id":"lake","revision":"","name":"Lake","workspace-url":"https://example.cloud.databricks.com","warehouse-id":"0123456789abcdef","auth":"service-principal","client-id":"00000000-0000-4000-8000-000000000000","client-secret":"<OAuth secret>","catalog":"main","schema":"sales"}
```

A blank secret on a change keeps the saved one only where the workspace, the
authentication and the client stay as they were. `status` never returns a
secret; `test {id, revision}` makes one request, for the first catalog of the
listing, which starts no warehouse; `disconnect {id, revision}` removes the
connection, its secret and any minted token from custody, and revokes nothing at
the workspace.

`adapter-sources --provider databricks --principal <principal>` reads, with
`JPACK_CONNECTIONS_DIR` naming the custody root:

```json
{"connection":"lake","revision":"<64-hex>","read":"statement","statement":"SELECT region, sum(amount) AS total FROM orders WHERE year = :year GROUP BY region","parameters":[{"name":"year","value":"2026","type":"INT"}]}
{"connection":"lake","revision":"<64-hex>","read":"catalog","list":"tables","catalog":"main","schema":"sales","pageToken":"<the last page's next_page_token>","maxResults":50}
```

A statement is one `POST /api/2.0/sql/statements` with the connection's
warehouse, its wait, `on_wait_timeout: CANCEL`, `disposition: INLINE`, `format:
JSON_ARRAY`, the catalog and schema (the request's, or the connection's), and
the named parameters as given, as Databricks documents the request in
[Execute a SQL statement](https://docs.databricks.com/api/workspace/statementexecution/executestatement)
(no date shown; read 2026-10-13). A statement that has not finished when the
wait passes is cancelled by the workspace and refused, `statement-timeout: the
statement did not finish within N seconds and was cancelled`; one answered
`PENDING` or `RUNNING` is refused and not polled. `FAILED` and `CANCELED` are
refused with the API's message as given (`statement-failed: …`,
`statement-canceled: …`), every whole credential in it replaced; a message over
4,096 bytes is cut to that bound after the replacement, and is then not
verbatim. An inline result may come in chunks, each fetched by a request of its
own ([the Statement Execution API tutorial](https://docs.databricks.com/aws/en/dev-tools/sql-execution-tutorial),
updated 2026-10-06): a result in more than one chunk, or truncated, is refused
as `result-incomplete`, and the other chunks are not fetched. The members the
connection decides by (`statement_id`, `status.state`, `status.error.message`,
`manifest.truncated`, `manifest.total_chunk_count`, `result.chunk_index` and
the next-chunk members) are read by their exact names: an answer that also
names one of them in another case, or twice, is refused.

Only a listing carries `max_results`; a statement's request carries none. A
listing (`catalogs`, `schemas`, `tables` or `functions`) is one `GET
/api/2.1/unity-catalog/<list>` with `max_results` (the request's, 0 for the
workspace's own page length; at most 50 for tables, 1,000 otherwise) and the
request's `pageToken` as `page_token`; the answer's `next_page_token` is the
caller's to send, and is never followed. Databricks documents the listings and
their paging in [catalogs](https://docs.databricks.com/api/workspace/catalogs/list),
[schemas](https://docs.databricks.com/api/workspace/schemas/list),
[tables](https://docs.databricks.com/api/workspace/tables/list) and
[functions](https://docs.databricks.com/api/workspace/functions/list) (no date
shown; read 2026-10-13): `max_results` left out returns every row, and the end
is the answer without a `next_page_token`.

A request whose statement, parameters, catalog, schema or cursor carries the
connection's credential (the personal access token, the client secret, or a
token held or minted for it) is refused as `credential-in-request` before it is
sent, in words that name the rule and not the value.

Each read is one request, after one token request where a service principal
holds no token more than a minute from its expiry: the client's id and secret
as basic authentication at the workspace's `/oidc/v1/token`, the
client-credentials grant and the scope, as
[OAuth machine-to-machine authentication](https://docs.databricks.com/aws/en/dev-tools/auth/oauth-m2m)
(updated 2026-10-12) states them. The access token is kept in custody with its
expiry and the connection's revision, and removed before another is asked for.
Its lifetime counts from the token request; one that would not outlast the
minute when it arrives is refused as `token-failed`, is not kept, and no other
is asked for. Nothing is retried: a 429 from a read is refused as
`rate-limited`, and one from the token endpoint as `token-failed`, each with the
wait its `Retry-After` header or `RetryInfo` asks for, and the next request is
the caller's. A redirect is refused and not followed; a 401 is
`credentials-required`, a 403 `permission-denied`, another 4xx
`request-refused`, a 5xx `provider-unavailable`, each naming the status and the
API's `error_code`, never its message; a failed token request is
`token-failed`, naming the status and the OAuth error code. An answer over the
connection's bound is `result-too-large`, read no further; an answer that is not
JSON is refused, and so is one that repeats the credential, as written or in
escapes, in a value or a member name.

The result is the API's answer as received, carried into the canon domain, with
its `statement_id`, `status`, `manifest` and `result` (or the listing and its
`next_page_token`). The acquisition names the endpoint (the workspace URL and
the path), the request as the statement the gateway commits to (connection,
revision, read, method, endpoint, and the body or query sent: the warehouse,
the statement and its parameters among them), the `statement_id` as the
snapshot (a listing has the digest of the answer as received), the TLS peer's
certificate, and the time the answer was read. What a read establishes, and
what it does not, is in [the connection catalog](../docs/design/connection-catalog.md#databricks-version-3).
In particular, a statement is sent as given: the warehouse's and Unity
Catalog's grants on the identity are what keep this profile to reads.

Since the Azure DevOps provider's first review round (#255), the screens the
two providers share hold here as there: every request, answer and outgoing
text is held against every credential custody holds for the principal (each
connection's personal access token or client secret, and each token held, not
only the connection a read names); escapes are decoded as deeply as they nest,
to the point where decoding changes nothing, and a text still changing after
32 passes is held to carry one; `configure` refuses a connection whose own
text (its name, workspace, warehouse, client id, scope, catalog, schema,
bounds, servers or tools) spells one; a `FAILED` or `CANCELED` message that
still spells one once its whole ones are replaced is not repeated; every
control answer is held once more as a whole; and compression is neither asked
for nor undone, so the result bound is on the bytes received, and an answer
that names a `Content-Encoding` other than `identity` (in any case) is refused.

The tests answer from an in-process TLS server; a live check runs only where
`JPACK_DATABRICKS_LIVE_WORKSPACE` and its companions name a workspace, and is
otherwise skipped. They are not a claim that a live workspace accepts the
requests or answers as recorded.

### Databricks connections (MCP profile)

A Databricks connection may also enable the workspace's managed MCP servers,
which Databricks now lists as the legacy workspace endpoints of its
[Databricks-provided MCPs](https://docs.databricks.com/aws/en/agents/mcp-tools/built-in-mcp-services)
(updated 2026-10-08): each an endpoint under the workspace, reached over
Streamable HTTP ([authentication and networking](https://docs.databricks.com/aws/en/agents/mcp-tools/authentication-networking),
updated 2026-10-07), and available once a workspace administrator has enabled
**Managed MCP Servers** on the workspace's Previews page; and the MCP services
registered in Unity Catalog that Databricks' Unity Gateway serves, which
Databricks now recommends (below). `configure` takes
`mcp`, the servers the connection enables, each a `server` by its name and
`tools`, the names a read may call on it (none, when the list is empty or left
out):

| `server` | Endpoint under the workspace | Scope the server's page names |
|---|---|---|
| `sql` | `/api/2.0/mcp/sql` | `sql` |
| `genie:<space id>` | `/api/2.0/mcp/genie/<space id>` | `genie` |
| `functions:<catalog>.<schema>.<function>` | `/api/2.0/mcp/functions/<catalog>/<schema>/<function>` | `unity-catalog` |
| `ai-search:<catalog>.<schema>.<index>` | `/api/2.0/mcp/ai-search/<catalog>/<schema>/<index>` | `ai-search` |
| `unity-gateway:<catalog>.<schema>.<service>` | `/ai-gateway/mcp-services/<catalog>.<schema>.<service>` | `ai-gateway` |

The endpoints and scopes are those of Databricks' pages for
[Databricks SQL](https://docs.databricks.com/aws/en/agents/mcp-tools/databricks-sql)
(updated 2026-10-08), the [Genie Agent](https://docs.databricks.com/aws/en/agents/mcp-tools/genie-agent),
[Unity Catalog functions](https://docs.databricks.com/aws/en/agents/mcp-tools/uc-functions)
and [AI Search](https://docs.databricks.com/aws/en/agents/mcp-tools/ai-search)
(each updated 2026-10-07). A space id is 32 lowercase hexadecimal characters,
as the [Genie API](https://docs.databricks.com/api/workspace/genie/startconversation)
writes one (no date shown); each Unity Catalog name is held to the API
profile's name form and written into the path as a path segment,
percent-encoded where it must be. A Unity Catalog functions server is one
function, as the page shows it; AI Search is what Databricks formerly called
vector search, and the former `vector-search` prefix is not taken. A tool's
name is 1 to 128 ASCII letters, digits, `_`, `-` and `.`, the form the
[MCP specification](https://modelcontextprotocol.io/specification/2025-11-25/server/tools#tool-names)
says a name should take. A server's name or a tool that carries the
connection's credential, as written or in JSON escapes, is refused, and so is
a name that holds `*`: a name is a name, never a pattern. A connection enables
at most 16 servers, each with at most 32 tools.

**Unity Gateway services.** `unity-gateway:<catalog>.<schema>.<service>` is an
MCP service registered in Unity Catalog, reached at
`/ai-gateway/mcp-services/<catalog>.<schema>.<service>` under the workspace
([authentication and networking](https://docs.databricks.com/aws/en/agents/mcp-tools/authentication-networking),
[MCP service reference](https://docs.databricks.com/aws/en/ai-gateway/mcp-service-reference),
each updated 2026-10-07). Databricks recommends these for new work: "For new
Genie One and Databricks SQL connections, use the `system.ai` MCPs", and lists
the four endpoints above as legacy workspace endpoints behind the Managed MCP
Servers preview ([Databricks-provided MCPs](https://docs.databricks.com/aws/en/agents/mcp-tools/built-in-mcp-services),
updated 2026-10-08). A service is either one Databricks provides under
`system.ai` (`genie_one_mcp`, `dbsql`, `web_search`, `sandbox`, and connectors
to Slack, GitHub, Atlassian, Google Drive, Calendar and Gmail, and Microsoft
365) or an external MCP server an account registers from a Unity Catalog HTTP
connection ([register an external MCP server](https://docs.databricks.com/aws/en/ai-gateway/register-mcp-service),
updated 2026-10-07). So a service may be an external connector, and it may
write: no page says any service is read-only, Databricks states that the SQL
service "permits reads and writes by default"
([Databricks SQL](https://docs.databricks.com/aws/en/agents/mcp-tools/databricks-sql),
updated 2026-10-08), and the connection claims nothing about it. Only a
service the operator enables by its exact name is reached; the connection
neither discovers nor lists the workspace's services. Its tool calls are made
under the `ai-gateway` OAuth scope ("MCP tool calls use `ai-gateway`"): a
service principal enables one only where its configured `scope` names
`ai-gateway` (`all-apis`, the scope a blank one asks for, is not taken for it),
and `configure` refuses otherwise as `scope-required`. A personal access token
is accepted, which the page puts as "for local testing". Calling a service
takes `EXECUTE` on it and `USE CATALOG` and `USE SCHEMA` on its parent
([govern an MCP](https://docs.databricks.com/aws/en/ai-gateway/govern-mcp-service),
updated 2026-10-08). Everything below holds for a service as for the other
servers.

```json
{"id":"lake","revision":"<64-hex>","name":"Lake","workspace-url":"https://example.cloud.databricks.com","warehouse-id":"0123456789abcdef","auth":"token","token":"","mcp":[{"server":"sql","tools":["execute_sql"]},{"server":"genie:01f0a1b2c3d4e5f60718293a4b5c6d7e","tools":[]},{"server":"functions:main.finance.exchange_rate","tools":["main__finance__exchange_rate"]},{"server":"unity-gateway:system.ai.dbsql","tools":["execute_sql"]}]}
```

The credential is the API profile's, sent as `Authorization: Bearer`: the
personal access token, which the legacy workspace endpoints accept, or the
service principal's access token, minted and held as for the API profile. A
service principal's `scope` must name what each server's page names; whether
`all-apis` covers the MCP servers, no page states.

A read, on `adapter-sources`' stdin:

```json
{"connection":"lake","revision":"<64-hex>","read":"mcp","server":"functions:main.finance.exchange_rate","tool":"main__finance__exchange_rate","arguments":{"currency":"EUR"}}
```

A read is one session with the server: `initialize`, `tools/list` until the
tool is found (its descriptor names its output schema), one `tools/call` with
the arguments as given, and the session's end. The `initialize` answer is read
by the connection itself, by its members' exact names: a `protocolVersion` of
2025-11-25, 2025-06-18 or 2025-03-26, `capabilities` with `tools`, and
`serverInfo` with a `name` and a `version`; so is each `tools/list` page
(`tools`, `nextCursor`, each tool's `name`), at most 32 pages, a cursor given
twice refused. The arguments are an object
(`{}` when left out) in the canonical domain: a whole number within ±2^53, and
no fraction, which is sent as a string. Refused before anything is sent: a
server the connection does not enable (`server-not-enabled`); a tool not on
that server's list (`tool-not-allowed`); and arguments, a tool or a server that
carry the connection's credential, as written or in escapes
(`credential-in-request`). A tool on the list that the server does not offer
is `tool-not-offered`, and nothing is called. Nothing is retried, and no
redirect is followed. An answer other than 2xx is named by its status, in the
API profile's words (401 `credentials-required`, 403 `permission-denied`, 429
`rate-limited`, another 4xx `request-refused`, otherwise
`provider-unavailable`); a JSON-RPC error is `provider-unavailable` with the
server's message; a result whose `isError` is true is `tool-error` with its
text. In each, every whole credential is replaced by `[redacted]` before the
text is cut to 4,096 bytes; a text that still spells a credential or the
session id once its own JSON escapes are decoded is not reported, and the
refusal says so in words of its own. A result larger than the connection's
`max-result-bytes` is `result-too-large`, and each answer is read no further
than that bound and 64 KiB, or 8 MiB where that is larger. Each whole message
the server answers with (`initialize`, each `tools/list` page, the call; a
JSON body, or each event of a stream, a notification or a request of the
server's among them) is screened, envelope and every member, before any
member of it is read or acted on, for the credential, the token in use, every
credential custody holds for the provider and the session id the server
issued, as written or as decoded to the point where decoding changes nothing,
and one that repeats any of them is refused: nothing of the read is kept
(since #256's first review round, which found that a member beside the
result was screened by the client for its own token and session id only). A
server's text is therefore read only where it spells none of them; the
replacement before the cut is the words' own guard. The members a read is decided by (the result's `content`,
`structuredContent` and `isError`, each content item's `type` and `text`, the
descriptor's `name` and `outputSchema`) are read by their exact names, and an
answer that also names one of them in another case is refused. A read has 50
seconds.

The result is the tool's result as `adapter-mcp`'s remote form reads a
source's (`mcp.ToolResult`), in canonical form. The acquisition names the
server's endpoint as configured; the read as the statement the gateway commits
to (connection, revision, `read: "mcp"`, the server, its endpoint, the tool and
the arguments); the digest of the result as received as the snapshot; the TLS
peer the result came from; and the tool's declared output schema, digested, or
`null` where it declares none. The session id is in none of it. The source is
still declared `http`: SPEC.md §1.2a holds `transport` and `server` to shape
`mcp`, so an `adapter-sources` read records the eight members alone, the
transport being in the statement's `read` and the endpoint's path.

`test {id, revision}` makes the API profile's one request, then reaches each
server the connection enables: `initialize` and `tools/list`, 15 seconds each,
and no tool called. It answers `{"ok", "mcp": [{"server", "ok", "offered",
"notOffered", "error"}]}`: the names each server offers (each cut to 128
bytes, every credential replaced), the names on its list it does not offer, or
why it could not be read; `ok` is true when every server was read. The whole
answer is held once more to every secret its reports were held to, each
session id the servers issued among them, which the broker's final screen
does not know: one that would still spell a session id where nothing can be
replaced (as a member's name) is not written, and a refusal of fixed words
is. A connection that enables no server answers as the API profile does.
`status` lists each connection's servers and their tools, and never a
credential. Each
field of a test's answer and each error is held once more against the
credential, the token and the session id before it is written: each whole one
replaced, and a field that would still spell one written as `[redacted]`.

What a read establishes, and what it does not, is in [the connection
catalog](../docs/design/connection-catalog.md#databricks-version-3). In
particular, the identity's grants and the tools list are what keep this
profile to reads: Databricks states that the Genie Agent server does not write
to tables, while the SQL server runs what it is sent under the identity's
permissions, a Unity Catalog function does what its body does, and a Unity
Gateway service is whatever MCP service was registered under that name, an
external connector among them, which may write. The tests
answer from the in-process Streamable HTTP fake; a live check runs only where
`JPACK_DATABRICKS_LIVE_WORKSPACE`, `JPACK_DATABRICKS_LIVE_MCP_SERVER` and
`JPACK_DATABRICKS_LIVE_MCP_TOOL` name a workspace's server, and is otherwise
skipped.

### Azure DevOps connections (API profile)

`gateway-connections --provider azure-devops` holds up to six named
connections, each to one project of one Azure DevOps organization's REST API,
and `adapter-sources --provider azure-devops` reads one of them under the HTTP
shape: work items (a WIQL query, items by id, or the two as one read), Git
repositories (the list, a repository's items, its commits, its pull requests)
and pipelines (the list, a pipeline's runs, one run). Catalog v3 advertises the
provider under the protocol `azure-devops-v1` (`status`, `configure`, `test`,
`disconnect`; `auth` `credentials`, the secret typed into the form and used as
given), and the local source plan names the source `azure-devops` with 60
seconds. The MCP profile, the organization's remote MCP server, is
[below](#azure-devops-connections-mcp-profile).

`configure` takes the connection's `id`, its `revision` (empty to create, the
current one to change it), a `name`, and the setup fields:

- `organization-url`: `https://dev.azure.com/{organization}` or the older
  `https://{organization}.visualstudio.com`, the two forms Microsoft documents
  ("Organization-level REST APIs accept either URL form, regardless of when you
  created the organization",
  [work with organization URLs](https://learn.microsoft.com/en-us/azure/devops/extend/develop/work-with-urls),
  dated 2026-04-03). The organization is held to the
  [naming restrictions](https://learn.microsoft.com/en-us/azure/devops/organizations/settings/naming-restrictions)
  (dated 2025-10-30): letters of the English alphabet, digits and hyphens, a
  letter or a digit first and last, under 50 characters; as a host name, in
  lowercase. Nothing else is taken: no user information, port, path past the
  organization (a single trailing `/` is dropped), query, fragment, escape or
  trailing dot.
- `project`: the project's id, or its name as the same page holds a
  project's ("Must not contain more than 64 Unicode characters"): at most
  64 characters, a bound of its own, no control or surrogate character, none of
  `\ / : * ? " ' < > ; # $ { } , + = [ ] |`, not `_` first nor `.` first or
  last. It is written into each path as a path segment.
- `auth`: `token` with `token`, a personal access token; or `bearer` with
  `access-token`, a Microsoft Entra access token, and `expires-at`, its expiry
  as the token was issued with it (RFC 3339). The connection mints no token:
  obtaining and replacing an access token is the operator's.
- `max-result-bytes`: 65,536 to 15,728,640 (8 MiB unless given), as text.

```json
{"id":"board","revision":"","name":"Board","organization-url":"https://dev.azure.com/example","project":"example-project","auth":"token","token":"<personal access token>"}
{"id":"board","revision":"","name":"Board","organization-url":"https://example.visualstudio.com","project":"example-project","auth":"bearer","access-token":"<Entra access token>","expires-at":"2026-10-13T11:00:00Z"}
```

A blank credential on a change keeps the saved one only where the organization
URL and the authentication stay as they were; a blank access token keeps its
expiry with it, and an expiry given without a token is refused. A connection
whose own text (its id, name, organization URL, project or expiry) spells its
credential, as written or in JSON escapes, is refused as
`credential-in-configuration` and nothing of it is kept. `status` never
returns a credential, and reports a connection whose access token is within a
minute of its expiry as not ready; `test {id, revision}` makes one request, a
query for at most one of the project's work items, and answers only whether it
succeeded; `disconnect {id, revision}` removes the connection and its
credential from custody, and revokes nothing in the organization.

`adapter-sources --provider azure-devops --principal <principal>` reads, with
`JPACK_CONNECTIONS_DIR` naming the custody root:

```json
{"connection":"board","revision":"<64-hex>","read":"workitems.query","query":"SELECT [System.Id] FROM WorkItems WHERE [System.State] = 'Active'","top":50}
{"connection":"board","revision":"<64-hex>","read":"workitems.get","ids":[12,7],"fields":["System.Title","System.State"]}
{"connection":"board","revision":"<64-hex>","read":"workitems.query-and-get","query":"SELECT [System.Id] FROM WorkItems WHERE [System.State] = 'Active'","fields":["System.Title"]}
{"connection":"board","revision":"<64-hex>","read":"repos.commits","repository":"example-repo","path":"/docs","version":"main","top":100,"skip":0}
{"connection":"board","revision":"<64-hex>","read":"pipelines.list","top":100,"cursor":"<the last page's continuationToken>"}
```

Each read takes the members its row names and no others, each of its form;
anything else is `invalid-request`, and nothing is sent. Every request names
`api-version=7.1` and is made under `{organization URL}/{project}/_apis/`:

| `read` | Members | Request |
|---|---|---|
| `workitems.query` | `query` (WIQL, at most 32,000 characters), `top` (1 to 20,000; 200) | `POST wit/wiql?$top=` with `{"query"}` |
| `workitems.get` | `ids` (1 to 200, distinct) or `id`; `fields` (at most 64 reference names) | `GET wit/workitems?ids=&fields=`, or `wit/workitems/{id}?fields=` |
| `workitems.query-and-get` | `query`, `top` (1 to 200; 200), `fields` | the query, then `GET wit/workitems?ids=&fields=` |
| `repos.list` | none | `GET git/repositories` |
| `repos.items` | `repository` (name or id), `path` (`/`), `recursion` (`none`, `oneLevel`, `full`; `oneLevel`), `version`, `versionType` (`branch`, `tag`, `commit`; `branch`) | `GET git/repositories/{repository}/items?scopePath=&recursionLevel=&$format=json` |
| `repos.commits` | `repository`, `top` (1 to 1,000; 100), `skip`, `path`, `version`, `versionType` | `GET git/repositories/{repository}/commits?searchCriteria.$top=&searchCriteria.$skip=` |
| `pullrequests.list` | `repository`, `top`, `skip`, `status` (`active`, `abandoned`, `completed`, `all`) | `GET git/repositories/{repository}/pullrequests?$top=&$skip=` |
| `pipelines.list` | `top` (1 to 1,000; 100), `cursor` | `GET pipelines?$top=&continuationToken=` |
| `pipelines.runs` | `pipeline` | `GET pipelines/{pipeline}/runs` |
| `pipelines.run` | `pipeline`, `run` | `GET pipelines/{pipeline}/runs/{run}` |

The requests are as Microsoft's REST API reference (version 7.1) documents
them: [Wiql - Query By Wiql](https://learn.microsoft.com/en-us/rest/api/azure/devops/wit/wiql/query-by-wiql?view=azure-devops-rest-7.1),
[Work Items - List](https://learn.microsoft.com/en-us/rest/api/azure/devops/wit/work-items/list?view=azure-devops-rest-7.1)
("Maximum 200 ids allowed"),
[Work Items - Get Work Item](https://learn.microsoft.com/en-us/rest/api/azure/devops/wit/work-items/get-work-item?view=azure-devops-rest-7.1),
[Repositories - List](https://learn.microsoft.com/en-us/rest/api/azure/devops/git/repositories/list?view=azure-devops-rest-7.1),
[Items - List](https://learn.microsoft.com/en-us/rest/api/azure/devops/git/items/list?view=azure-devops-rest-7.1),
[Commits - Get Commits](https://learn.microsoft.com/en-us/rest/api/azure/devops/git/commits/get-commits?view=azure-devops-rest-7.1),
[Pull Requests - Get Pull Requests](https://learn.microsoft.com/en-us/rest/api/azure/devops/git/pull-requests/get-pull-requests?view=azure-devops-rest-7.1),
[Pipelines - List](https://learn.microsoft.com/en-us/rest/api/azure/devops/pipelines/pipelines/list?view=azure-devops-rest-7.1),
[Runs - List](https://learn.microsoft.com/en-us/rest/api/azure/devops/pipelines/runs/list?view=azure-devops-rest-7.1) and
[Runs - Get](https://learn.microsoft.com/en-us/rest/api/azure/devops/pipelines/runs/get?view=azure-devops-rest-7.1)
(no date shown on these pages; read 2026-10-13). A query's length and its
`top` are the [work tracking limits](https://learn.microsoft.com/en-us/azure/devops/organizations/settings/work/object-limits)
(dated 2026-09-10): a query of at most 32,000 characters, and results
"truncated at 20,000 items - no error is shown". The pages state no bound on a
page of commits, pull requests or pipelines; 1,000 is the connection's own.

A `workitems.query-and-get` is one acquisition of two requests: the query with
`$top` at the read's bound, and then the work items by the ids its answer
names, in its order and no others, with the fields asked for. A query that
answers more ids than the bound is refused as `ids-bound-exceeded` and the items
are not read; a query that answers none makes no second request; a query of
links (a tree or one hop) is refused as `query-not-flat`; an items answer that
names an item not asked for, or one twice, is refused; and the two answers must
come under one TLS identity. A `workitems.get` of more than 200 ids is refused
as `ids-bound-exceeded` before anything is sent.

Paging is the caller's. The connection takes a page of pipelines to answer
the next continuation token in its `x-ms-continuationtoken` header: the
reference page names only the request's `continuationToken`, and the header is
Microsoft's Python client's (`azure-devops` 7.1.0b4:
[`client.py`](https://github.com/microsoft/azure-devops-python-api/blob/86c9a559fc4ab309df21e674b236a542f9e77f89/azure-devops/azure/devops/client.py),
`_continuation_token_header_key = 'X-MS-ContinuationToken'`, and
[`v7_1/git/git_client_base.py`](https://github.com/microsoft/azure-devops-python-api/blob/86c9a559fc4ab309df21e674b236a542f9e77f89/azure-devops/azure/devops/v7_1/git/git_client_base.py),
`get_policy_configurations`, `response.headers.get('x-ms-continuationtoken')`;
that client's `list_pipelines` sends `continuationToken` and reads no token
back). **This is not verified against a live organization.** The result
carries the header's value as `continuationToken` (or `null`) beside the page,
held to a cursor's form and screened as an answer is, and the caller sends it
back as `cursor`. Commits and pull requests page by `skip` and `top`. No page
is followed by the connection.

Nothing is retried. A 429 is `rate-limited`, and a 503 `provider-unavailable`,
each with the wait its `Retry-After` header asks for (seconds or a date) and
the threshold its `X-RateLimit-Resource` names, "it was not retried", as
[rate and usage limits](https://learn.microsoft.com/en-us/azure/devops/integrate/concepts/rate-limits)
(dated 2025-09-15) describes the headers; a `Retry-After` on a 200, which the
page says a delayed request may carry, changes nothing about that answer, and
the `X-RateLimit-*` headers are not recorded. A 401 is `credentials-required`,
a 403 `permission-denied`, another 4xx `request-refused`, a 5xx
`provider-unavailable`, and another 2xx (an organization may answer 203 with a
sign-in page) `provider-unavailable`, each naming the status and the error type
the body gives in its `typeKey` (read by that exact name, held to an
identifier's form), never the API's message, which may repeat what was sent.
No reference page documents the error body; `typeKey` is the member
Microsoft's Python client reads it by (`azure-devops` 7.1.0b4:
[`_models.py`](https://github.com/microsoft/azure-devops-python-api/blob/86c9a559fc4ab309df21e674b236a542f9e77f89/azure-devops/azure/devops/_models.py),
`WrappedException`, `'type_key': {'key': 'typeKey'}` beside `message` and
`typeName`, deserialized in `client.py`'s `_handle_error`). **This is not
verified against a live organization.** A redirect is refused after one
request and not followed. Compression is neither asked for nor undone, so the
bound is on the bytes as received: an answer over the connection's bound is
`result-too-large`, read no further than a byte past it (and not at all when
its length is announced past it), and an answer whose `Content-Encoding`
names anything but `identity` is refused (each header, each comma-separated
coding, in any case; `identity` names no encoding, and an empty value is not
it), as is one the transport undid; an answer that is not JSON is refused. Each
request has 25 seconds, so the two of a query-and-get end inside the
adapter's 55.

The credential is sent only as the request's `Authorization` header: a
personal access token as HTTP basic authentication with an empty user name,
`Basic ` and the base64 of `:` and the token, as
[use personal access tokens](https://learn.microsoft.com/en-us/azure/devops/organizations/accounts/use-personal-access-tokens-to-authenticate)
(dated 2026-09-21) states it ("The username can be empty"), built from custody
when the request is made and stored nowhere; an access token as `Bearer`, as
[service principals and managed identities](https://learn.microsoft.com/en-us/azure/devops/integrate/get-started/authentication/service-principal-managed-identity)
(dated 2026-09-21) states it. An access token at or within a minute of its
configured expiry is refused as `credentials-expired`, checked immediately
before every request, so a query-and-get whose second request would go within
the minute is refused whole. The token, its basic authentication value and the
access token of every connection custody holds for the principal (not only
the one a request names; during a change, the connection's earlier
credential and its new one) are the secrets held out of every record, error,
status and test answer:

- "As decoded" means a text's JSON escapes decoded again and again, as
  deeply as they nest, to the point where decoding changes nothing; a text
  still changing after 32 passes (one level can cost five bytes), or longer
  than 16 MiB, is held to spell a secret.
- A request whose query, fields, repository, path, version, status or cursor
  spells one, as written or as decoded, is refused as `credential-in-request`
  before it is sent; the body and the URL as they would be sent are screened
  once more. A `test` is held to the same screens as a read: its request
  before it is sent, its answer after.
- Every answer is screened for each, in its bytes and as decoded (every
  string, number and member name, a string's own escapes, and a string that is
  itself JSON), before anything of it is read: one that spells one is refused,
  and nothing of it is kept. A pipelines page's continuation token is screened
  likewise.
- The members the connection decides by (a query answer's `workItems`,
  `queryResultType` and `workItemRelations` and each item's `id`; an items
  answer's `value` and each item's `id`; an error body's `typeKey`) are read by
  their exact names: an answer that also names one of them in another case, or
  twice, is refused.
- A threshold an organization names has every whole secret replaced before it
  is cut to 256 bytes, and is not named at all where it would still spell one;
  `configure` refuses a connection whose own text spells any of them
  (`credential-in-configuration`); every field of a status row is held against
  them; and every error and every control answer (`status`, `configure`,
  `test`, `disconnect`), fixed words included, is held once more as a whole:
  each whole secret replaced, a sentence that would still spell one replaced
  by one that says so, and where that too would spell one, an error with no
  text written.

The result is the API's answer as received, carried into the canon domain (a
number outside it as its literal text): for `pipelines.list`,
`{"pipelines": <the page>, "continuationToken": …}`; for
`workitems.query-and-get`, `{"query": <the query's answer>, "items": <the
items' answer, or null where the query found none>}`, so the ids read are in
the result. The acquisition names:

| Member | Value |
|---|---|
| `endpoint` | the URL of the answer the snapshot digests, as it was requested, its query included (for a query-and-get with items, the second request's URL with its ids) |
| `statement` | `connection`, `revision`, `provider`, `project`, `read`, and the first request as sent: `method`, `endpoint`, `query` (every parameter, `api-version` among them) and, for a query, `body`; a query-and-get adds `fields`, and `then`, the second request as sent (`method`, `endpoint`, and `query`: the ids in the order sent, the fields, `api-version`), or `null` where the query found none |
| `snapshot` | the digest of the answer as received (the items' answer for a query-and-get that read items) |
| `peerIdentity` | `tls:sha256:` of the verified leaf certificate |
| `schema`, `upstreamToken` | `null`: no answer carries a schema, and a work item's `rev` or an ETag is a version, not an integrity token the organization vouches with; revisions stay in the result |

What a read establishes, and what it does not, is in [the connection
catalog](../docs/design/connection-catalog.md#azure-devops-version-3). In
particular, the credential's scopes are what keep this profile to reads: issue
a token with only Work Items (Read), Code (Read) and Build (Read) (`vso.work`,
`vso.code`, `vso.build` in the [scopes](https://learn.microsoft.com/en-us/azure/devops/integrate/get-started/authentication/oauth#available-scopes)).

The tests answer from an in-process TLS server; a live check runs only where
`JPACK_AZURE_DEVOPS_LIVE_ORGANIZATION`, `JPACK_AZURE_DEVOPS_LIVE_PROJECT` and
`JPACK_AZURE_DEVOPS_LIVE_TOKEN` name an organization, and is otherwise skipped.
They are not a claim that a live organization accepts the requests or answers
as recorded; in particular, neither the `x-ms-continuationtoken` header of a
pipelines page nor the `typeKey` of an error body, each taken from Microsoft's
Python client and from no reference page, has been seen from a live
organization.

### Azure DevOps connections (MCP profile)

A connection may also enable its organization's remote MCP server, "a hosted
version of the Azure DevOps MCP Server" that Azure DevOps runs at
`https://mcp.dev.azure.com/{organization}`, reached "by using streamable HTTP
transport" ([set up the remote Azure DevOps MCP Server](https://learn.microsoft.com/en-us/azure/devops/mcp-server/remote-mcp-server),
dated 2026-09-21). `configure` takes `mcp`: at most one server, `remote`, with
`tools`, the names a read may call on it (none, when the list is empty or left
out; at most 32), and `readOnlyHeader`, `send` (the default) or `off`:

```json
{"id":"board","revision":"<64-hex>","name":"Board","organization-url":"https://dev.azure.com/example","project":"example-project","auth":"bearer","access-token":"","expires-at":"","mcp":[{"server":"remote","tools":["wit_work_item","repo_repository","pipelines_run"]}]}
```

- **The endpoint** is built from the configured organization URL, of either
  form, never from a request: `https://mcp.dev.azure.com/` and the
  organization's name ("Use just the organization name (for example,
  `contoso`), not the full Azure DevOps URL",
  [troubleshoot the remote server](https://learn.microsoft.com/en-us/azure/devops/mcp-server/remote-mcp-server-troubleshooting),
  dated 2026-07-31). The server's root URL, which takes the organization in
  each tool call instead, is not used.
- **The credential** is the connection's access token (`auth` `bearer`), sent
  as `Authorization: Bearer` on every request and held to its configured
  expiry immediately before each one, as for the API profile. "Personal access
  tokens (PATs) aren't supported for the remote server" (troubleshoot the
  remote server), so `configure` refuses the profile under `auth` `token` as
  `bearer-required`. The pages document only a user's token: a client
  registered in the tenant is granted the *delegated* permissions it needs on
  the **Azure DevOps MCP** enterprise application
  (`2a72489c-aab2-4b65-b93a-a91edccf33b8`), and "OAuth scopes don't override
  the permissions of the signed-in user. An MCP operation succeeds only when
  both the application scope and the user's Azure DevOps permissions allow it"
  (set up the remote server). No page states that the server takes an
  application-only token from the client-credentials grant, and Microsoft
  Entra's own page says an application authenticating as itself "can't use
  *delegated permissions* because there is no user for your app to act on
  behalf of" ([client credentials flow](https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-client-creds-grant-flow),
  dated 2026-01-30). So the connection mints nothing: the operator obtains a
  user's access token for that application and pastes it with its expiry,
  and replaces it when it expires. Whether the server also takes a token
  issued for Azure DevOps itself (the API profile's), or the REST API this
  one, no page states; `test` reports the two profiles each on its own, and
  an operator whose two tokens differ configures two connections.
- **The read-only header.** Each request carries `X-MCP-Readonly: true`, the
  header the page documents "to restrict the server to read-only operations"
  (the troubleshooting page: "Verify the header value is the string
  `"true"`"). `readOnlyHeader: "off"` sends no such header; the operator sets
  it knowingly. Either way it is the server's promise, kept by the server:
  the record does not name it, and nothing in the connection checks what a
  tool did. The `X-MCP-Toolsets`, `X-MCP-Tools` and `X-MCP-Insiders` headers
  are not sent.
- **The tools** are named as the server's list names them. Most are grouped
  dispatchers that take an `action` argument (`wit_work_item` with `get`,
  `get_batch`, `list_comments`, …), and the page marks each action read-only
  or not; the writes have tools of their own (`wit_work_item_write`,
  `repo_pull_request_write`, `pipelines_write`, …). The list holds tool names,
  not actions: a tool on it may be called with any action it takes. The page
  says "This list might not always reflect the most recent tool updates";
  `test` reports what the server offers.

A read, on `adapter-sources`' stdin:

```json
{"connection":"board","revision":"<64-hex>","read":"mcp","server":"remote","tool":"wit_work_item","arguments":{"action":"get","project":"example-project","id":12}}
```

The arguments are the tool's own: an object (`{}` when left out) in the
canonical domain (a whole number within ±2^53, and no fraction, which is sent
as a string), sent as given; the server's listing gives each tool's input
schema (these are the names the local server's `wit_work_item` takes at
2.10.0). A read is one session with the server, as
the [Databricks MCP profile](#databricks-connections-mcp-profile) makes one,
under the same rules: `initialize` and each `tools/list` page read by the
connection by their members' exact names; one `tools/call`; the session's end,
which is a request like the others and comes before anything of the read is
kept: an end the guard refuses (the token within its minute) leaves nothing.
Refused before anything is sent: a server the connection does not enable
(`server-not-enabled`), a tool not on its list (`tool-not-allowed`), a read
out of its form, an access token at or within a minute of its expiry
(`credentials-expired`), and arguments, a tool or a server that carry a
credential custody holds for the provider, any connection's, as written or as
decoded (`credential-in-request`). A tool on the list the server does not
offer is `tool-not-offered`, and nothing is called. Nothing is retried, no
redirect is followed, and a refusal is named in the Databricks MCP profile's
words for its status (401 `credentials-required`, 403 `permission-denied`,
429 `rate-limited`, another 4xx `request-refused`, otherwise
`provider-unavailable`); a JSON-RPC error is `provider-unavailable` with the
server's message, and a result whose `isError` is true is `tool-error` with
its text, each with every whole credential replaced before it is cut to 4,096
bytes, and not reported at all where it still spells a credential or the
session id once its own escapes are decoded. Each whole message the server
answers with (a JSON body, or each event of a stream, its envelope and every
member, a notification of the server's among them) is screened, before any
member of it is read or acted on, for every credential custody holds for the
provider and the session id the server issued, as written and decoded to the
point where decoding changes nothing; one that repeats any of them is
refused, and nothing of the read is kept, so a server's text is read only
where it spells none. Compression is neither asked for nor undone, and an
answer whose `Content-Encoding` names anything but `identity` is refused
(each header, each comma-separated coding, in any case; `identity` names no
encoding, and an empty value is not it), as is one the transport undid, so
the bounds are on the bytes received: the tool's result is held to `max-result-bytes`
(`result-too-large`), and each answer is read no further than that and
64 KiB, or 8 MiB where that is larger. A read has 50 seconds. Every error is
held once more against the credentials and the session id before it is
written.

The result is the tool's result as `adapter-mcp`'s remote form reads a
source's, in canonical form. The acquisition names:

| Member | Value |
|---|---|
| `endpoint` | the server's URL, `https://mcp.dev.azure.com/{organization}` |
| `statement` | `connection`, `revision`, `provider`, `project` (the connection's; a tool's arguments may name another project the credential can read, and nothing holds them to it), `read: "mcp"`, `server`, `endpoint`, `tool`, `arguments` |
| `snapshot` | the digest of the tool's result as received |
| `peerIdentity` | `tls:sha256:` of the leaf certificate the result came under |
| `schema` | the digest of the tool's declared output schema, or `null` where it declares none |
| `upstreamToken` | `null` |

The session id is in none of it. The source stays declared `http`
(`azure-devops-api-v1`), as the Databricks MCP profile's does: SPEC.md §1.2a
holds `transport` and `server` to shape `mcp`, so the transport is in the
statement's `read` and the endpoint.

`test {id, revision}` makes the API profile's one request, then reaches the
server: `initialize` and `tools/list` (15 seconds), and no tool called. For a
connection that enables the server it answers `{"ok", "api": {"ok",
"error"}, "mcp": [{"server", "ok", "offered", "notOffered", "error"}]}`,
each profile reported on its own; `ok` is true when both were read. A server
whose session's end the guard refused is reported as not read. The whole
answer, the API's error and the fixed member names included, is held once
more to every secret the server's report was held to, its session id among
them (the API's error was written before the session existed, and the
broker's final screen does not know it): each whole one replaced, and an
answer that would still spell one, as a member's name, not written; a
refusal of fixed words is written instead. A connection that enables no
server answers as the API profile does. `status` lists the server, its
tools and its `readOnlyHeader`, never a credential; a
list that would spell a credential custody holds is not reported, and its
connection is not ready.

**What it establishes, and what it does not**, is in [the connection
catalog](../docs/design/connection-catalog.md#azure-devops-version-3): the
bytes from the organization's MCP endpoint under its TLS identity, for that
tool and those arguments, at that time, under the configured token acting
with its user's permissions; not that the tool read rather than wrote, nor
that the answer is true. The read-only header is the server's promise; the
tools list and the token's permissions are the connection's only guard.

The tests answer from the in-process Streamable HTTP fake; a live check runs
only where `JPACK_AZURE_DEVOPS_LIVE_ORGANIZATION`,
`JPACK_AZURE_DEVOPS_LIVE_ACCESS_TOKEN` (with `_EXPIRES_AT`) and
`JPACK_AZURE_DEVOPS_LIVE_MCP_TOOL` (with `_MCP_ARGUMENTS`) name an
organization's server, and is otherwise skipped. Nothing here has been seen
from a live organization: in particular, which token the server takes.

**The local server.** Azure DevOps also publishes the server as an npm
package, `@azure-devops/mcp` (2.10.0, published 2026-09-09), run over `stdio`
on the operator's machine ([enable AI assistance with the Azure DevOps MCP
Server](https://learn.microsoft.com/en-us/azure/devops/mcp-server/mcp-server-overview),
dated 2026-08-12). It is not a catalog connection: the connections run no
third-party server process, and this one is a program the operator chooses,
pins and runs. It is an operator-level source through `adapter-mcp`'s
existing stdio form, a source and not a write-back platform: the catalog
ships no binding of it, as recorded in the
[catalog's Azure DevOps section](../catalog/README.md#azure-devops).

```
gateway serve ./store gateway.seed gateway:acme ./registry.jsonl \
  --source boards='adapter-mcp --credentials /run/secrets/ado-mcp-env --tools wit_work_item,wit_query -- npx -y @azure-devops/mcp@2.10.0 example --authentication env --tenant 00000000-0000-0000-0000-000000000000 -d core work-items' \
  --source-shape boards=mcp \
  --source-env boards=HOME=/var/lib/jpack/ado-mcp-home
```

- The organization is the first argument, by its name, as the server's
  [getting started](https://github.com/microsoft/azure-devops-mcp/blob/43a2b179b02d912399be612e0f7b5121a55eb692/docs/GETTINGSTARTED.md)
  (at the `v2.10.0` tag) gives it: `npx -y @azure-devops/mcp <your-org>`. The
  package is pinned by its version; `npx` resolves it from the registry, and
  the record's `adapter` names the command as configured and the digest of
  `npx`, not of the package or of what it depends on.
- `--authentication env` takes the token from Azure Identity's
  `DefaultAzureCredential`, which a service principal configures with
  `AZURE_TENANT_ID`, `AZURE_CLIENT_ID` and `AZURE_CLIENT_SECRET`
  ([Azure Identity for JavaScript](https://learn.microsoft.com/en-us/javascript/api/overview/azure/identity-readme),
  dated 2026-09-14). Those three are the `--credentials` file, the server's
  environment and nothing else:
  `{"AZURE_TENANT_ID":"…","AZURE_CLIENT_ID":"…","AZURE_CLIENT_SECRET":"…"}`.
  The service principal must be added to the organization with its own access
  level and permissions ([service principals and managed identities](https://learn.microsoft.com/en-us/azure/devops/integrate/get-started/authentication/service-principal-managed-identity),
  dated 2026-09-21). The other methods are `interactive` (the default, a
  browser sign-in), `azcli`, `envvar` (a bearer token in `ADO_MCP_AUTH_TOKEN`)
  and `pat` (`PERSONAL_ACCESS_TOKEN`, the base64 of `<email>:<pat>`), each as
  the getting-started page states it.
- By the server's source at that tag ([`src/index.ts`](https://github.com/microsoft/azure-devops-mcp/blob/43a2b179b02d912399be612e0f7b5121a55eb692/src/index.ts),
  [`src/auth.ts`](https://github.com/microsoft/azure-devops-mcp/blob/43a2b179b02d912399be612e0f7b5121a55eb692/src/auth.ts),
  [`src/org-tenants.ts`](https://github.com/microsoft/azure-devops-mcp/blob/43a2b179b02d912399be612e0f7b5121a55eb692/src/org-tenants.ts)):
  without `--tenant` it asks `https://vssps.dev.azure.com/{organization}` for
  the organization's tenant and caches it in `~/.ado_orgs.cache`; and where a
  tenant is known, it tries the Azure CLI's sign-in first and the environment
  after, so it runs here with a `HOME` of its own where no Azure CLI sign-in
  is found, or it acts as that sign-in instead of the service principal.
- `-d` loads only the named domains (`core`, `work`, `work-items`,
  `repositories`, `wiki`, `pipelines`, `search`, `test-plans`,
  `advanced-security`); the local server has no read-only option at 2.10.0
  (its arguments are the organization, `--domains`, `--authentication` and
  `--tenant`). `--tools` is the allowlist, as for any stdio server; the
  local tools' names are in its [toolset](https://github.com/microsoft/azure-devops-mcp/blob/43a2b179b02d912399be612e0f7b5121a55eb692/docs/TOOLSET.md),
  where the writes again have tools of their own (`wit_work_item_write`, …).
- `adapter-mcp --check` with the same words starts the server, completes the
  handshake and lists its tools, failing where a name in `--tools` is not
  offered; `--probe` names a tool it calls once.

What such a source establishes is `adapter-mcp`'s over stdio: the tool's
answer as that process wrote it, under the command as configured. It does not
establish the organization's TLS identity (the process reaches Azure DevOps
itself, and the record names no transport identity), that the process is the
package the version names, that a tool read rather than wrote (no read-only
mode; the tools list and the service principal's permissions are the guard),
or that the answer is true.

### Bounded website exploration

`adapter-web --discover` accepts exactly `{"url":"https://example.com/"}`.
Declare it as `web-discovery` with HTTP shape and a 60-second source timeout.
The connection catalog and local source plan advertise it separately from `web`,
so existing consumers can keep reading individual pages. No credentials are used.

The breadth-first crawl follows `<a>` and `<area>` links, resolves the first
HTML base URL, removes fragments, and stays on the exact HTTPS origin (not sibling
subdomains). Every request and redirect passes the existing public-DNS/numeric-dial
checks, and no redirect policy applies: `--discover` refuses `--redirect-policies`.
It sends no cookies or authorization and does not execute JavaScript,
enumerate sitemaps, or follow external links. Robots.txt must be readable or return
an ordinary 4xx absence; 401, 403, 429, 5xx, malformed rules, and unsupported media
stop exploration. Redirects of robots.txt also stay on the same origin. Matching
uses `github.com/temoto/robotstxt` (MIT; license in `licenses/robotstxt/`).

Fixed limits, not caller arguments: 10 attempted pages, two link levels, 100
manifest rows, 1,000 candidate links per page, 8 MiB total body bytes including
failed reads, 30 HTTP requests including redirects/robots.txt, and 45 seconds.
Each page retains the existing 4 MiB response limit; robots.txt is limited to
512 KiB. Requests are spaced by at least 500 ms, increased by Crawl-delay. Page
attempts include blocked and failed pages. Depth-three links are listed as skipped.

The signed JSON result has `version:1`, `seed`, `origin`, `pages`, `stopReason`,
`bytes`, `requests`, `externalLinks`, and `limits`. Each page has `url`, `from`,
`depth`, `title`, `status` (`discovered`, `blocked`, `failed`, or `skipped`), and
`reason`. It is a navigation manifest, not extracted evidence or a claim of full
coverage. `discovered` means fetched successfully during discovery. The HTTP
acquisition describes the initial robots observation; the signed result records
subsequent page outcomes. Body counters exclude headers and unconsumed redirect
bodies. Response output is capped at 1 MiB.

A consumer reads selected discovered pages through ordinary `web` acquisitions
using `{"url":"https://example.com/page","site":"https://example.com/"}`.
The optional `site` enforces the exact origin and robots rules again, including
redirects. Each page then has its own verified document and citation; fetching
again may observe newer content. Those later reads have their own limits and
are not counted in the discovery budget. Direct `{"url":...}` reads are unchanged.

### Windows customer-command isolation

The Windows backend uses `CreateRestrictedToken` with `DISABLE_MAX_PRIVILEGE` and
`WRITE_RESTRICTED`, a fresh restricting SID and a low mandatory integrity label.
It grants that SID modify access only on the workspace and the private temporary
directory in workspace-write mode. Read-only grants neither. Full access remains
an explicit bypass of the sandbox, selected by the operator's policy.

A trusted launcher creates a private window station and desktop before starting
the restricted child; it never grants access to the interactive desktop. The host
account must be permitted to create that station. If creation or restricted-child
startup fails, the command fails without retrying at broader permissions.

The workspace must support security descriptors. Existing reparse points and
multiply-linked files are refused before any ACL changes. At most 10,000 existing
objects are held by handle; those handles prevent renames or deletions of existing
objects while the command runs. Concurrent workspace-write uses of the same
workspace are refused across logon sessions, with exclusion acquired before the
ACL snapshot. New objects inherit the workspace grant. A job with
kill-on-close and no breakaway contains the launcher and its descendants. Cleanup
terminates that job and verifies it is empty before restoring held ACLs.

The report is `partial`: network access is unchanged, objects without usable access
controls are not confined, and workspace filesystem operations have the limits
above. The backend does not provide read isolation. The operator must keep policy,
credentials and signing material outside the workspace. An abrupt parent exit can
leave ACL grants or low integrity labels behind; newly created objects retain their
inherited grants and labels even after normal cleanup. No later run reuses the SID.
A cleanup failure returns `sandbox-cleanup-failed`, fails registration or acquisition
even if the child completed successfully, and retains temporary files for recovery. Use a dedicated workspace and inspect its
permissions following an interrupted run.

Native CI tests cover the write boundary, outside-file ACL changes, access to the
parent's handles and token, link refusal, ACL restoration and descendant cleanup.
These checks execute on the Windows runner; cross-compilation alone does not
establish that enforcement works. The implementation follows the documented
[restricted-token access checks](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-createrestrictedtoken)
and [mandatory integrity rules](https://learn.microsoft.com/en-us/windows/win32/secauthz/mandatory-integrity-control).
