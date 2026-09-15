# The engine as an MCP server

[plugins.md](plugins.md) leaves one thing open: a team already running an MCP gateway wants
receipts on the tool calls it routes, and a plugin inside that gateway is a *witness* — it
would hand the engine bytes the engine never acquired, which `SPEC.md` §6 admits from no
caller. This note takes the other path the plugin note named: the engine speaks MCP itself,
so that an MCP client — a gateway federating servers, an agent's host, a desk — calls a
platform's live tools *through* the engine, the engine's own adapter makes the call, the
engine's own key signs, and the receipt comes back with the answer. No change to the
specification, and no plugin to install: the gateway's operator registers a server. What
follows is the design as it must be before code: what the process is, what it holds, how it
is reached, what a call becomes, what a client gets and does not get.

## What it is

`engine-mcp` is a fifth process of the engine, beside the signer, the adapters, the runtime
and the verifier: an MCP server that is a client of the signer's HTTP surface (§6), and
nothing more. It holds no signing key and no platform credential, and it does not open the
store. What keeps it that way is established in three places, each named for what it can and
cannot prove:

- **The image** carries a second copy of the executable, `/usr/local/bin/engine-mcp`, mode
  `0755`, root-owned, with no file capability — the signer's `0700` binary with its
  capabilities is never the one this process runs — and a user `engine-mcp` (uid `65533`,
  its own group and no other, home `/home/engine-mcp`) that no group of the signer's or of a
  platform's admits. The image check holds the copy's mode and attributes, the user's entry
  and groups, that nothing outside that home is the user's or its group's, that no symbolic link
  is under `/home` and every entry under it but the frontend's own home is closed to others, and that the paths a deployment mounts a seed, a
  store, a configuration or a credential at are absent from the image — what an image check
  can prove, and no more: what an operator mounts at deployment the image never sees.
- **The launch** is the operator's. The executable is the gateway's, copied; the
  subcommand selects the role, as for every other command of the binary, and the one
  supported invocation is, in full:

  ```
  # as uid 65533, gid 65533, no supplementary group but its own, no capability in any set,
  # HOME=/home/engine-mcp, working directory /home/engine-mcp
  /usr/local/bin/engine-mcp mcp --config /etc/engine/engine.json --http
  ```

  (`--stdio` in place of `--http` for a host that spawns it.) The process then **checks its
  own reach at start**, under the deployment assumptions the operator's note states — the
  configuration and the signer's mounts are in place before it starts, and are not changed
  while it runs — and refuses to run otherwise: its effective, permitted, inheritable and
  ambient capability sets are empty; its uid and gid are the frontend's (`65533`) and its
  supplementary groups are none but its own — a container runtime lists the primary group
  there, and that membership admits nothing the gid does not; and opening the configured seed path, every configured
  credentials file and the configured store for reading fails with permission denied — a
  path that does not exist, or any other answer than denial, is refused too, since it says
  nothing. What such a check proves is that this process cannot open those paths now: a
  permission or mount changed afterwards is outside it, as is a path the configuration does
  not name (a runtime socket reachable by another path, a subordinate-uid mapping), and the
  operator's deployment note lists those as obligations; an ACL on a path the check opens is
  caught by the open itself.
- **The configuration rule**: the signer's loader already refuses a platform whose user is
  root, the signer's own or another platform's; it now also refuses a platform whose user is
  the frontend's, so no credentials file can ever belong to the user this process runs as.

The process reads the configuration once at start, as metadata: the platforms' names, each
binding's `live.tools`, the signer's `listen` address, the `identity` member and its own
`mcp` member (below). It resolves each binding by its pin as the signer does and refuses to
start on a mismatch. A configuration change is a restart of both processes; the note makes
no claim about two processes reading two snapshots, and a key-set change is the rotation
below. The image starts only `serve`; the operator starts `engine-mcp` beside it, as the
runtime and the verifier are started, which ADR-0001's follow-on records with the process's
role, user and address. Anything past localhost is a TLS terminator's job, in front of both.

## Configuration

`mcp` is a new optional top-level member of the engine's configuration, which under
[engine-config.md](engine-config.md)'s rule moves `engineVersion` to `"2"`; a version-`1`
file without the member still loads, and a version-`1` file with it is refused by name.

```json
"mcp": {
  "listen": "127.0.0.1:8788",
  "resource": "https://engine.example.internal/mcp",
  "origins": ["http://localhost", "http://127.0.0.1"],
  "sessions": 64, "idleSeconds": 1800, "concurrency": 8, "callsPerMinute": 120
}
```

`listen` is a literal loopback address with an explicit port, validated as the signer's
`listen` is; when `mcp` is present the signer's `listen` may not name port zero, since the
frontend finds the signer by that value and nothing else. `resource` is the URL the world
reaches the MCP endpoint by — the protected resource's identifier, below — an absolute
`https` URL without a fragment, required with `--http`; with it, the `identity` member is
required too, and its `issuer` must be an authorization server's identifier as RFC 8414 has
it — an absolute `https` URL with no query and no fragment — which the signer's parser does
not demand and the frontend does. **There is no
unprotected HTTP mode**: `--http` without an `identity` is a refusal to start. `--stdio`
without one is allowed — a host spawning the process on the operator's own machine, the
signer recording `caller: null`. `origins` are the exact origins the HTTP transport admits:
loopback origins when the member is absent; when it is present and empty, no origin at all,
so a request carrying an `Origin` header is refused and a native client without one is
admitted. The four bounds default as shown and take the ranges stated under
Bounds. The endpoint path is `/mcp`; the transport is chosen at launch, never by a request.

## What a call becomes

| MCP request | What the server does |
|---|---|
| `initialize` | speaks protocol `2025-06-18` and no other — the version the engine's own client speaks — and answers it whatever version the client proposed, as the lifecycle allows (a client that cannot speak it disconnects); a JSON-RPC batch, which the earlier version required servers to accept, is an invalid-request error here; answers the engine's authority as the server name and the engine version, capability `tools` only; accepts `notifications/initialized`; answers `ping`; acknowledges notifications without a response |
| `tools/list` | the table below, in one page, no cursor |
| `tools/call` | `POST /acquire` to the signer's `listen` address with `source = "<platform>/live"`, the session (below) and `arguments = {"tool": <tool>, "arguments": <the call's arguments, byte for byte>}`; the answer, below |
| anything else | a JSON-RPC method-not-found; no prompts, no resources, no sampling, no writes |

Messages are read as the pinned protocol has them, by their members' exact names, never
case-folded, with no member named twice — except the `arguments` of a `tools/call` of a
platform tool, whose content is the signer's to judge: an id is a string or a number with no fractional part, in any
spelling (a spelling of at most 64 bytes and an exponent within ±999, since an id is compared
and echoed, never computed with), and never `null`; `params` is an object; a client's
response carries an id and exactly one of a `result` object and an `error` object of an
integer `code` and a string `message`, and no `params`. A message is UTF-8, or it is not a
message: a byte that is not is refused, never repaired. A request that cannot be served is
answered with an error that carries its id; any other input that cannot be accepted — a
notification or a response of the wrong shape, or a message that is neither — is refused as
input: over HTTP a `400` whose body has no `id` member, over stdio JSON-RPC's error with a
`null` id. `initialize` is validated — a `protocolVersion` string,
a `capabilities` object, `clientInfo` with `name` and `version` strings — and happens once per
session; until it has, `tools/list` and `tools/call` are refused. The seal tool's arguments
are the server's own and are read the same way as the envelope.

**The tool table.** One tool per `(platform, live tool)` pair the configuration and bindings
name, held in an explicit table from name to pair, built at start. The name is
`<platform>.<tool>`; a name two pairs would share is a refusal to start, never an overwrite, and
routing is by the table, never by splitting a name. Under protocol `2025-06-18` a tool name is a
string; a platform or tool name with a character some host refuses is a compatibility limit of
that host, which the server cannot know and does not report. Each tool's description is
generated — the platform, the binding and its pin, the tool's name, and that its arguments are
what the platform's own server defines — and its `inputSchema` is the open object `{"type":
"object"}`. The binding carries tool names only, and the engine will not run a platform's server
just to read its schemas: running it means holding its credentials, which this process must
never do. So a host that validates arguments validates nothing here, and a model must know the
platform's tool from elsewhere — unless the platform pins a snapshot of descriptors that
`connect` captured. The MCP server then reads and verifies that snapshot once, at start, and
serves the server's own descriptions, framed and fenced, with the captured schema's projection
([tool-descriptors.md](tool-descriptors.md)); a tool the snapshot does not hold is described as
above.

**Arguments, byte for byte.** The call's `arguments` member is carried to `/acquire` as the
bytes the client sent, inside the wrapping object, never decoded and re-encoded on the way:
the signer's strict parser is the one that judges them (a fraction, a large integer, a
duplicate member are its refusals, as for a direct `/acquire`). What the receipt commits to
is not those bytes but what the signer commits to for any `/acquire`: the canonical form of
the wrapper `{"tool": ..., "arguments": ...}` under the response's salt — whitespace, member
order and escape spellings are not part of it. An absent `arguments` is `{}`, as `/acquire`
defaults it. A differential test makes the same call through the server and by a direct
`/acquire`, and holds the two receipts' canonical arguments equal and each commitment
recomputable from its own salt; the two salted commitments themselves differ, as any two
acquisitions' do.

**The answer.** A successful acquisition answers with `content` holding one text block — the
serialization of `{session, result, receipt, salts}` — and `structuredContent` holding that
same object, so a client that reads structured content has everything and a client that
reads text loses nothing; `result` is the acquisition's result exactly as `/acquire` returned
it, which for an MCP-shaped source is the platform server's whole tool result, carried in the
canon domain (numbers past it as text) and never re-typed here. The server does not forward
that inner result's content blocks as its own: a resource link inside it names bytes nobody
acquired, and an image block would be a copy of bytes the receipt covers only as a member of
the whole. No `outputSchema` is declared.

**Refusals.** Every tool result that is an error carries `isError: true` — the protocol's
own flag, which an `error` member inside the payload does not replace — and, like a success,
both forms: one text block serializing the error object, and the same object as
`structuredContent`, so a client that reads only text sees the diagnostic. Three kinds, told apart by that object. A
refusal the signer answered — a source that failed, a malformed result, arguments outside the
domain, a sealed session, an unknown source — is `{session, status, error}`, the signer's
status and its own reason, with no receipt and no salts, since none were minted. An outcome
the server does not know — the forward timed out or the connection dropped after the request
was sent — is `{session, outcome: "unknown"}`: the acquisition may have run and minted a
receipt the client never saw, the session is named so the store can be read, and the server
retries nothing; the same holds for a `/seal` whose outcome is unknown. An overload (below),
a stdio call refused by the signer's token check, and a seal the signer refused take the same
shape. An unknown tool, a malformed request or a call breaking the seal tool's schema is a
JSON-RPC error. A token the frontend accepted and the signer refused — expired between the
two, or the two holding different keys — is, over HTTP, a transport-level `401` to the client
carrying the *frontend's* challenge (the signer's bare `Bearer` is not sent on), and over
stdio the error result above. What is receipted is every *successful* acquisition, not every
call.

## Identity

The engine is **one protected resource** with two interfaces: the MCP endpoint, which the
world reaches at `mcp.resource`, and the signer's HTTP surface, an internal component of that
resource reachable on loopback alone — `/acquire` and `/seal` are not a second resource a
client could be issued a token for, they are the inside of this one. The resource's
identifier is `mcp.resource`; its intended audience is the `audience` the `identity` member
names, and the operator's authorization server — the `issuer` — maps that resource to that
audience when it issues tokens (RFC 8707's resource indicator, or the server's own
configuration). The MCP server implements the authorization the protocol requires of a
server. It serves the protected-resource metadata document where RFC 9728 derives it from
the resource's URL — for `https://engine.example.internal/mcp`, at
`https://engine.example.internal/.well-known/oauth-protected-resource/mcp` — readable
without a bearer, exactly:

```json
{"resource": "<mcp.resource>", "authorization_servers": ["<identity.issuer>"], "bearer_methods_supported": ["header"]}
```

and a request without an acceptable token is refused at the transport with `401` and
`WWW-Authenticate: Bearer resource_metadata="<that document's URL>"`, so a conforming client
discovers where to get a token. What the engine does not do is fetch anything: the token is
verified by the MCP server itself with the same `verifyToken` the signer uses — same issuer,
same audience, same key-set file, the key's algorithm, a non-empty subject, `nbf` and `exp`
with thirty seconds' leeway — before the body is read; a request refused before its body is
read is answered at once, and its connection closed after the answer.

A token that passes is sent on, unchanged, to exactly one destination, the signer's
configured `listen` address, and nowhere else; the signer verifies it again and names the
same caller on the receipt. This is not the pass-through the protocol forbids — accepting a
token issued for some other resource and sending it to that resource's API — because there is
no other resource: the signer is inside the one the token was issued for. A token whose
audience is another server's, an MCP gateway's own among them, is refused here however it
arrives; a gateway that wants its users named on receipts forwards *their* tokens for *this*
resource, or names itself. What a bearer proves is possession until expiry; holding the same
token twice within its window is the same authority twice, and this design adds no replay
protection the signer does not already have. Attribution names the principal the token
represents — `verifyToken` asks for a subject, not for a person — so a receipt names an end
user only when that user's own token was sent; the server substitutes nothing and adds
nothing.

**Rotation.** Both processes read the key-set file once, at start, so replacing the file
changes neither until it restarts, and restarting one alone makes the two accept different
keys for as long as they differ. A signer restart also empties its session map and cancels a
running source, so the sessions a consumer relies on are sealed first, and nothing may open
or extend one between that sealing and the restart. The contract, in order: add the new key
under a new `kid` beside the old; restart the frontend; **close admission, at both
processes** — `SIGUSR1` closes a process's gate and `SIGUSR2` reopens it, and a second
`SIGUSR1` while closed reports where the closure stands. The frontend's gate is for its
clients: closed, it answers a new `initialize` `503` and a new acquisition as an overload, and
forwards nothing it did not pass before the closure. **The signer's gate is the barrier**: it
is the one place an acquisition or an action is admitted, so once it is closed nothing more is
admitted, however long a request was in transit to it — a forward the frontend gave up on is
a request the signer may still receive, and the frontend cannot know whether it did — and
`/acquire` and `/act` are answered `503` while `/seal` goes on. Each process reports its
closure on its diagnostics stream, numbered: the signer's is drained ("serve: closure *n*
drained") when nothing it admitted is in flight; the frontend's when every acquisition it
forwarded before the closure has returned, naming how many forwards ended without an answer
since its last drain, which are the signer's closure to vouch for. Closure numbers are each
process's own: the operator reads each process's current closure, not an order across the
two. Then seal every
session to be preserved **by `/seal` directly**, on the signer's loopback
surface under the operator's own token — which works whether or not a transport session of
the frontend's is there to carry `engine.seal`: a session opened before the closure still
carries it, and a new one cannot be opened while closed; stop the signer, then start it, whose
gate starts open; reopen the frontend's admission; issue under the new key. The operator closes
any other ingress to `/acquire` and `/act` too; the signer's gate refuses theirs as well. To retire the old key, wait out the validity window of the tokens it signed,
then remove it from the file and restart both in the same order; to revoke it, remove it and
restart both at once, accepting that sessions not sealed by then are lost. A key removed
from the file is still accepted by a process that has not restarted. The token suite holds
both orders and the stale key; the session suite holds the whole sequence from the
frontend's restart to a successful `/seal` under closed admission, and a request held at the
signer's door while the frontend's forward gives up: refused once the signer's gate is closed,
admitted after the frontend's drain when it is not.

Over stdio there is no request header. The process is started by one host for one principal,
and the token is that principal's, given once at start in the environment (`ENGINE_TOKEN`,
as MCP hosts hand every server its secrets), verified at start the same way, held in memory,
never logged, and sent on every call; when it expires, calls fail with the signer's refusal
until the host restarts the server with a fresh one. Without an `identity` configured the
server sends no token, the signer records `caller: null`, and no action is ever performed.

## Sessions

A receipt chains into a session the caller names (§3a), and a session is sealed by whoever
relies on it, when it is done being written to — not by a transport ending. The server
therefore **never seals a session on its own**: an MCP session closing or a stdio process
exiting seals nothing, and a client that wants a verdict seals first. What the server does:

- **Names a session when the client does not.** Each `tools/call` that carries no session
  runs in a session the server generated for that MCP session (over HTTP) or that process
  (over stdio): `mcp-` followed by 128 bits from the system's random source in lowercase hex,
  which §3a admits and which two processes repeat with negligible probability. Every
  answer's `session` member — a success's and a refusal's alike — says which, so the client
  can seal it, name it again, or verify it.
- **Takes a session the client names.** A call may carry, in its `params._meta`, the member
  `io.judgment-pack/session` — `{"name": "...", "arguments": {...}, "_meta": {"io.judgment-pack/session": "s-2026-09-14-a"}}`
  — a flat token the server sends on as given. A name any client may send is a name any client
  may share: sessions are one namespace under one engine, two callers naming the same session
  chain into it in the order the signer stamps them, each receipt carrying its own caller, and
  either may seal it. That is the engine's rule today for `/acquire`, not a property this
  server adds or removes, and a host that does not forward `_meta` gets the generated session.
- **Seals on request.** One more tool, `engine.seal`, sits in the same table as the
  platforms' tools — a platform named `engine` with a tool `seal` is the same collision as
  any other, refused at start — with the one closed input schema in the list,
  `{"type": "object", "properties": {"session": {"type": "string"}}, "required": ["session"], "additionalProperties": false}`,
  which the server enforces itself — a member besides `session` is a JSON-RPC invalid-params
  error — while the signer's flat-token rule stays the final word on the name.
  It calls `/seal` under the caller's token and answers the seal record as one text block and
  as `structuredContent`; a refusal — an acquisition still in flight, an unknown session, a
  session the signer no longer holds after a restart — is the signer's, as `isError: true`
  with the session named.

What a crash means is what it means today. If this server dies, its sessions are known to
the signer and any authenticated caller who knows the name can seal them by `/seal`. If the
signer restarts, a session it had not sealed cannot be sealed from its count on disk, and a
store holding it reads `unregistered-session` under `gateway verify` until the operator
resolves it; a consumer's verdict is store-wide and fails closed (§5a.1), which is the point.

## Transport profile

Small and explicit, so a conformance test can hold it. **stdio**: newline-delimited JSON-RPC
on stdin and stdout, nothing but protocol on stdout, diagnostics on stderr, one MCP session
for the life of the process. The reader takes a place in a backlog of 64 before it admits a
line, so at most 64 messages are ever admitted and unanswered, and past that the server stops
reading until one is answered; each line is admitted in the order it was read — the
lifecycle, the session a call resolves to, the window, the admission gate and the queue
place — and an admitted call runs while the next line is read, so answers may come in
another order, correlated by id, as JSON-RPC allows; an answer the reader gives itself — a
refusal at admission — waits on the output, which is backpressure; and an answer that cannot
be written ends the transport with that failure, nothing further run.

**Diagnostics.** A process's diagnostics are two kinds of line on one writer of their own. Its
reports to the operator — a gate closed, a closure drained or cut short, the transport ended
— are never dropped and keep the order of the changes they report, each numbered by its
closure; they are held in memory until the stream takes them, one per operator signal or
transition, so a stream that never drains holds as many as the operator sent. What it says
about its traffic is dropped past a buffer and counted. What the process says while it serves names what went wrong by category —
timed out, connection refused, permission denied, the answer past its bound, the HTTP server
unable to accept — never an address, a name or a token, since a host may forward its
servers' stderr anywhere; `net/http`'s own lines reach the stream the same way, their text
dropped. Nothing waits for the stream: one that does not drain holds up no call, no operator
control and no start, and what the process says as it ends is given at most a second. A refusal to start is not a diagnostic of traffic: it
reads the configuration back to whoever started the process — the operator — and names what
it refuses, member and value.

**Streamable HTTP**, one endpoint at `/mcp`, JSON responses only, protocol `2025-06-18`
only, one JSON-RPC message per body. Checks run in the order of the rows, each before the
next, and the first that fails answers:

| Check, in order | Answer |
|---|---|
| `Origin` present and not in `mcp.origins` — present twice, or present and empty, included | `403`, before the body is read; absent `Origin` (a native client) is admitted |
| `Authorization` missing or refused | `401` with `WWW-Authenticate: Bearer resource_metadata="..."`, before the body is read |
| `MCP-Protocol-Version` present and not `2025-06-18` — present and empty, or named twice, included | `400`, before the body is read; absent, `2025-06-18` is assumed, the one version this server speaks |
| body over the bound (1 MiB) | `413` |
| `Mcp-Session-Id` absent, on any method but a `POST` of `initialize` | `400` |
| `Mcp-Session-Id` unknown, expired or ended, on any method | `404` |
| `GET` | `405`, whatever `Accept` says |
| `DELETE` | `200`; the transport session ends, and no receipt session is sealed by it |
| `POST` under whose `Accept` `application/json` is not acceptable by RFC 9110's rules — every field line read, wildcards and quality values honoured, so `*/*` and `application/*` accept it and `application/json;q=0` or SSE alone do not; a range with a media-type parameter applies to no answer of this server's, and a weight outside the `qvalue` grammar makes the header one this server cannot read | `406` |
| `POST` an `initialize` request | `200`, JSON body; a successful one carries a new `Mcp-Session-Id` — the *transport* session, which is not a receipt session and seals nothing — and a refused one carries none and keeps none; `503` when `mcp.sessions` are open or admission is closed |
| `POST` a request | `200`, JSON body, `Content-Type: application/json` |
| `POST` a notification or a response | `202`, no body, when it is of the protocol's shape; `400` with a JSON-RPC error and no id when it is not, or when the message is neither a request nor one of these |

The response carries `MCP-Protocol-Version` too, an extra the specification permits. An
`initialize` that names a live transport session is a request on that session, answered
`200` with an invalid-request error, since a session initializes once. A
transport session expires after `mcp.idleSeconds` without a request, answering `404` after;
expiry seals nothing. A cancelled call cancels nothing at the signer: an acquisition already
started runs to its end and may mint a receipt the client never sees, and a retry mints
another; the server says so in its description, and a consumer that reads the store sees
both.

**Bounds.** A body bound bounds bytes, not work: each call may start a platform's server,
and the signer itself admits acquisitions without bound. The frontend is therefore the layer
that bounds what *it* sends the signer, and only that: `mcp.sessions` transport sessions at
once (`1` to `4096`; a further `initialize` is `503`); `mcp.idleSeconds` before an idle
transport session expires (`60` to `86400`); `mcp.concurrency` **outstanding forwards** — the
frontend's own HTTP operations to the signer not yet answered or timed out — across all
transport sessions (`1` to `64`), with a queue of the same depth behind them, whose place a
call takes when it is admitted and in which it waits at most ten seconds from then before it
is an overload error with nothing forwarded, and a call admitted to a full queue is that
error at once — and a call whose allowance has run out by the time its work begins, or that
takes its slot after it ran out, is that error too, whatever slot is free; `mcp.callsPerMinute` calls per transport
session, or per process over stdio (`1` to `6000`), counted in a fixed window of sixty
seconds from the first call, **a call counted at arrival** — when its message has been read
whole and is admitted, one at a time, in the order admission happens, so no window is
charged an arrival older than its start and no wait named exceeds sixty seconds — whether it is then queued,
forwarded or refused — so a flood refused at the queue still spends its quota — an excess
call answered as an overload error naming the seconds until the window turns; and one
deadline per forward, forty-five seconds — the signer's thirty-second source deadline, its
five-second wait for the source's pipes, and a margin — after which the outcome is unknown
as above, and eight mebibytes of the signer's answer — its own one-mebibyte output bound,
the receipt, the salts and room — past which the outcome is unknown too. When admission
closes for maintenance, a queued call is refused as an overload, not drained, and so is one
that finds its forward slot free at the moment the gate closes, or after the gate closed and
reopened while it waited: a call admitted before a closure is never forwarded after it. The
gate's last word for an acquisition is taken with its slot, under the lock a closure takes,
and counts it as dispatching until it has had its answer; a closure is drained when nothing
is dispatching. The
HTTP server's own deadlines sit behind these: thirty seconds to read a request's headers and
body, then the queue's wait, the forward's deadline and fifteen seconds' margin to answer it,
from the moment the body is read, and a minute for an idle connection.

What these bounds do not bound is the signer's work. A forward past its deadline releases
its slot while the signer may still be running the source and writing the receipt, so zero
outstanding forwards does not mean the signer has drained; a forwarded call continues at the
signer whatever happens at the frontend — a client that disconnects, a queue that empties, a
frontend that stops do not cancel it, and its receipt, if minted, is in the store. The one
statement of the signer's quiet is its own: a `/seal` that succeeds. A ceiling on the
signer's unfinished acquisitions would need coordination in the signer, which this design
does not add. The deployment note says which layer holds which bound, and that the signer's
own ingress is the operator's to bound.

## What a client gets, and what it does not

An MCP gateway registers `engine-mcp` as one more server and sees the engine's platforms'
live tools beside the others; every successful call through it is acquired by the engine's
adapter under the engine's key, and the answer carries the receipt. For the caller to be
named on that receipt, the gateway must forward the caller's own bearer to the server — a
configuration of the gateway's, not a default; ContextForge, for one, forwards upstream
headers only when told to — and a gateway that sends a token of its own names itself.
Calls to servers the engine does not front are not receipted; that is the witness question,
still open and the specification's to answer first.

**What the server can and cannot do to a receipt.** It cannot sign: a receipt it hands over
verifies under the engine's key or not at all. It can alter what it asks — another source,
other arguments — and a receipt of what it asked is still a valid receipt; it can suppress an
answer, lose the salts, or hand a client another session's receipt. So a client relies on
nothing the answer says about itself: it verifies the store under the pinned key, reads the
store-wide verdict, binds the receipt it holds, and re-digests the result it kept to that
receipt's `resultDigest` (§5a.4). Binding means holding the receipt's *signed* members to
what the client meant to ask, each one, since the commitments alone do not: the receipt's
`source` is `<platform>/live` for the platform the client named, by the client's own mapping
of tool name to platform and never the server's word; its `sessionId` is the session the
client named or was told; its `caller` is the principal the client's token represents, when
the client relies on attribution; its commitments open, under the salts it was handed, to the
tool and arguments it sent; and `(sessionId, callIndex)` is among the verifier's `ok`
findings. The case that shows why: a frontend that forwards the call for `platform-a.query`
to `platform-b/live` with the same tool, arguments and session yields a receipt whose
signature, commitments, session and index all check — and whose signed `source` says
`platform-b/live`; only the comparison with the intended source refuses it, and the
acceptance test carries that substitution as a negative case. Receiving `structuredContent`
performs none of those steps.

**Writes.** `/act` is not a tool here, as scope: an action carries a decision record's digest
and citations that a workflow holds and an MCP host has no place for, and the executor's
gate — the record exists, the citations verify — is what it is whether the request came by
HTTP or by MCP; the workflow packages expose it, this server does not, for now. Nor does
omitting `/act` make the tools read-only: `execute_sql` sits in the postgres binding's live
operation and its write operation alike, and what holds a live tool to reading is the
credential the operator gave it — a role that can only read — as `catalog/README.md` says.
The server names tools; it cannot make them harmless.

## Where it lives, and what proves it

In the core module, standard library only, as the `mcp` subcommand of the gateway binary:
JSON-RPC over stdio and `net/http` need nothing the core does not already have, and the
configuration loader and token verifier are reused rather than duplicated. The image carries
the second copy and the user described above; the image check holds the copy's mode and
attributes, the user's entry and groups, the shipped paths' modes against it, and that the
signer's `0700` binary is not the one this process runs; the engine's own loader refuses a
platform on the frontend's user; and the frontend's start-up probe holds the deployment to
what the image cannot see. ADR-0001 gains a follow-on for the fifth process, and
`engine-config.md` the `mcp` member and version `2`. The tests: a conformance suite speaking
the transport matrix above to the server over a pipe and over HTTP against a `serve` with a
command-shaped source — each row of the matrix, the session id lifecycle, the metadata
document and the challenge — holding `structuredContent.receipt` to the file the store holds
and the differential to a direct `/acquire`; a token suite for each refusal, for attribution,
and for rotation in both orders; a session suite for the generated name's form, the named
session, the seal tool and its refusals, and the three refusal kinds; a bounds suite for each
of the four limits; the start-up check against fixtures that mount a readable seed, a readable credentials
file, a readable store, and a missing seed path, each a refusal; and the image check's
negative cases.
