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
  `source failed: <line>`. `/acquire` reads at most 1 MiB by default, allowing about 760 KiB
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
  page in stream order, with spaces and line breaks inferred from glyph positions. A damaged
  cross-reference is rebuilt by scanning for objects. It decodes no image and renders nothing:
  a page that draws an image and whose text is empty after normalisation is `needs-ocr`. Page
  text is normalised as it is built, so the text budget is decided on the normalised bytes.
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
  executable for its identity; `durationMs` runs from the start of reading the request, so the
  record's duration does not carry that reading. While the document is opened — its
  cross-reference and trailer read, and a damaged cross-reference rebuilt by scanning — the
  deadline is checked at the intervals in the structure bounds below, and one met there ends the
  run the way one met while the page tree is walked does: `timeout`, `truncated` `true`, and no
  page listed. In a page's content the deadline is checked
  between operators, at the interval in the structure bounds below, and before each reading of a
  form the page draws, and within one operator that shows a string at the interval below for
  glyphs; work between two checks is not interrupted, so what one check admits runs to its end
  within the structure bounds below. A deadline is read from the
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
  | graphics states saved and not restored | 256 | content |
  | one inline image's dictionary; its data | 128 objects; 16 MiB | content |
  | a page's content streams, concatenated | 64 MiB | content |
  | characters the glyphs shown on one page map to, the forms it draws included | 4,000,000 | content: an unmapped glyph counts as one, and glyphs past the text budget count |
  | fonts held by reference for a document; font resource names held while one page's content is read | 4,096; 4,096 | a font: past either the font is read again rather than held (no error) |
  | width entries one font's `/W` declares | 262,144 | a font: past it the font keeps no widths |
  | the CID a `/W` entry names; the CIDs one `/W` range spans | below 1,048,576; 65,536 | a font: past either the entry is left out |
  | mappings one CMap holds | 1,048,576 | a CMap: past it the CMap is not used |
  | codespace ranges one CMap declares | 256 | a CMap: past it the CMap is not used |
  | width entries and CMap mappings of all of a document's fonts together | 4,194,304 | a font: the `/W` or CMap a charge would take past it is not used |
  | the codes one `bfrange` or `cidrange` spans | 65,536 | a CMap: a longer range is cut to that span |
  | a `bfchar` or `bfrange` destination string | 512 bytes | a CMap: a longer one maps nothing |

  Widths serve the glyph positions from which spaces and line breaks are inferred; they do not
  map a glyph to a character.

  **What the bounds cost.** Two of them are stated in entries, and an operator sizing the
  adapter's process reads them as memory rather than as bytes of the file, since a compressed
  stream declares an entry in far fewer bytes than an entry costs. A cross-reference section may
  declare 4,194,304 object numbers, and the reader holds each as an entry of about 160 bytes, so
  a file of a few kilobytes whose cross-reference stream declares that many leaves it holding
  several hundred megabytes. A document's fonts may hold 4,194,304 width entries and CMap
  mappings together, and a `/W` range is held as a width for each CID it spans rather than as its
  endpoints, so a file of a few kilobytes whose fonts share `/W` ranges that long leaves it
  holding about 200 MB. Both are within the bounds above and within `--max-bytes`; neither is a
  refusal, and the process wants room for them.

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
