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
  `needs-ocr` under `ocr-not-run`. The adapter carries no OCR engine.
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
  page listed. In a page's content the deadline is checked
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
  | cross-reference entries, scanned objects or trailers read between two readings of the deadline | 4,096 | opening: the deadline is read at least this often |
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
  declare 4,194,304 object numbers, and the reader holds each as an entry of about 112 bytes, so
  a file of a few kilobytes whose cross-reference stream declares that many leaves it holding
  about 470 MB. A document's fonts may hold 4,194,304 width entries and CMap
  mappings together, and a `/W` range is held as a width for each CID it spans rather than as its
  endpoints, so a file of a few kilobytes whose fonts share `/W` ranges that long leaves it
  holding about 200 MB — the figure a `/W` of that many entries extrapolates to is about 151 MB,
  and 200 MB is the round number an operator sizes with; the cross-reference above is the most
  any of these entry bounds costs. What the same
  4,194,304 font entries cost as CMap mappings the shape of the mappings decides, and each shape
  is charged what it costs so that no shape costs much more than another: a code mapped to one
  character on its own is held at about 96 bytes and charged one entry, about 400 MB at the
  bound, and one mapped to seven characters at about 112 bytes, about 470 MB; a `bfrange` or
  `cidrange` with a short destination is held at about 70 bytes and charged four, about 70 MB;
  and a mapping of either kind whose destination is 256 characters is held at about 1.1 KB and
  charged a further entry for each eight of them, about 130 MB. A document whose fonts spend the
  bound keeps no mappings past it: the CMap that would cross it is not used at all, the codes it
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
  and a Go map of about 370 bytes held, and a pair of coordinates, `[0 0]`, about a hundred and
  thirty — and it is what bounds a file whose objects hold, or read, the same bytes over and
  over, where what the reader spends would otherwise grow with the square of the file: a file of
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
`status`, `configure`, `connect`, `pick`, `poll`, `cancel`, and `disconnect`.
`configure` takes a registered Google Desktop application's `clientId` and
`clientSecret`. No reply contains provider access or refresh tokens. The parent
must authenticate its UI before relaying controls. This pipe is not an HTTP API
and must not be exposed to arbitrary remote callers. `--disabled` refuses provider
operations. Organization identity and policy routing are not implemented by this
personal companion.

`adapter-drive --state-dir /private/connections --principal desktop-owner` is a
separate source with `--source-shape drive=http`. It accepts
`{"fileId":"selected-file","grant":"64-lowercase-hex"}`. The grant comes from the
picker, is scoped to that file and connection, expires after five minutes, and is
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
without provider-specific host code. The v2 catalog stays unchanged.

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
including `null`. Document bytes are retained, extracted locally with OCR off,
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
