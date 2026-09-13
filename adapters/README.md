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
`--timeout` (twenty seconds) is the time for reading; stopping takes up to seven seconds
more (a kill, an inspect and the drain of its output, and the wait for the client's
pipes), and the sum stays under the gateway's thirty, so a slow connector is reported as
a deadline rather than killed mid-report.

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
(`internal/fakeruntime`), so no runtime is needed to test it and none is used in CI;
the adapter's canonicalizer answers to the same frozen vectors as the core's
(`corpus/canon.json`), read from disk and never linked.

## adapter-mcp

A client of a [Model Context Protocol](https://modelcontextprotocol.io) server reached over
stdio — the servers vendors now publish for their own systems — that calls **one tool** per
acquisition: the tool's whole result as the result, and the acquisition as the adapter
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
  is one the redactor knows; each member is an environment variable name (`[A-Za-z_][A-Za-z0-9_]*`,
  since an env file drops a line that begins with `#` or whitespace) with a string value
  holding no newline, carriage return or NUL, since an env file is read by lines and a
  carriage return before the newline is dropped with it — a value the container would see
  differently from the adapter is refused rather than carried. A refusal names no member, since
  a member's name may be another member's value.
- `--tools` names the only tools a request may call; a request outside it is refused before
  any server starts.
- `--check` starts the server with the credentials, completes the handshake and lists its
  tools, then reports on stdout — `{"check": {"adapter", "server": {"name", "version"},
  "protocolVersion", "tools"}}` — calling nothing and reading no stdin. A tool named by
  `--tools` that the server does not offer fails the check, so a binding that names a tool
  the pinned server lacks is found out when the platform is connected, not at the first
  acquisition. A server that starts and lists its tools without a working connection to its
  platform answers the handshake all the same, so `--probe TOOL` names a tool the check calls
  once with no arguments — one of `--tools`, offered by the server — and requires it to answer
  without an error; its result is discarded, and the report says which tool answered. A server
  that catches its own failure and answers it as ordinary text, `isError` false, says so only
  in the text, and `--probe-failure TEXT` names what such an answer begins with, so that
  answer fails the check too; the binding that pins the server is where that text is known. What the server said of itself — its name and version, its tools' names — is
  redacted before it is reported, as every diagnostic is. The report carries `"status":
  "succeeded"`; a check that did not succeed writes `{"check": {"status": "failed",
  "message"}}` on stdout beside its exit status, so a caller reads one shape either way. The
  report is for the operator (`gateway connect`); nothing is minted from it.

The request, as canonical arguments on stdin:

```json
{"tool": "query", "arguments": {"sql": "select id, status from decisions where id > 100"}}
```

What the envelope carries, and so what the receipt records:

| Member | From |
|---|---|
| `adapter` | the pinned image: name, tag, digest; for a command, the command as configured, the version the server reports of itself (redacted, as a diagnostic is), and the digest of the executable |
| `endpoint` | `--endpoint`, or `null` |
| `statement` | the call — tool and arguments — which the gateway commits to under a salt |
| `snapshot` | `null`: the protocol offers no bookmark |
| `peerIdentity` | `null`: a server over stdio establishes no transport identity |
| `schema` | the digest of the tool's declared output schema, canonicalized per §1.1 with any non-integer number carried as its decimal text; `null` when the tool declares none, which most do today — the descriptor's name, title, description and annotations are presentation, not schema |
| `upstreamToken` | `null` |
| `observedAt` | when the tool's answer was read |
| `result` | the tool's whole result — content, structured content — carried into the canon domain; no `page` |

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
`isError` fails the acquisition with its text, redacted. A line on the server's stdout that
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
