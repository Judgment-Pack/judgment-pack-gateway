# Security policy

## Support status

This is a **reference gateway**, not a hardened deployment. It is pre-1.0, provides no security,
compatibility, or support service-level guarantee, binds localhost, has no authorization on its HTTP
surface beyond a checkpoint witness's registrations and its named operators, and no authentication unless an `identity` is configured (which decides who may call,
never from where; a token presented off the machine can be replayed), and runs as a single operator holding a single signing identity.
It must not be used as the sole control for consequential production decisions, and a `/verify` that
answers `ok` must not be read as a statement that the underlying facts are true — see
[Security boundary](#security-boundary).

## Reporting a vulnerability

Do not open a public issue for a vulnerability that could forge a receipt or a seal, cause
verification to miss a session the gateway actually attested, escape the receipt or artifact store,
disclose or recover the signing key, bypass a fail-closed refusal, or otherwise make the gateway
answer `ok` for a store that is not faithful.

Use this repository's [private vulnerability reporting](https://github.com/Judgment-Pack/judgment-pack-gateway/security/advisories/new)
(Security → Report a vulnerability). If that is unavailable, open a minimal non-sensitive issue
asking a maintainer to establish a private channel. Include:

- a minimal synthetic reproduction;
- the affected endpoint or module and the commit;
- expected and actual behaviour;
- likely impact; and
- any suggested mitigation.

Never include real keys, receipts, source responses, credentials, or proprietary data in a report.
Synthetic fixtures only.

## Security boundary

The ceiling is **byte-lineage, not truth**. Everything below describes what the gateway proves and,
more importantly, what it does not.

**The key is the trust root.** The signing key lives in the service. Its disclosure forges
everything — every receipt, every seal, retroactively. There is no defence against a compromised
gateway, and none is claimed.

**Verification is asymmetric** (receipt versions 2 and 3). Receipts and seals are Ed25519 signatures, so
checking one requires only the **public** key. A verifier gains no power to forge by being able to
verify, and needs no trust relationship with the operator beyond holding the right public key. This
replaced an HMAC format in which anyone who could verify could also forge; that format is gone rather
than deprecated, so the symmetric caveat does not survive in a legacy path.

**But the public key itself must arrive out of band.** Fetching a gateway's public key from that same
gateway and then verifying its store proves *internal consistency*, not authenticity — an impostor
serves its own key and its own store, and both agree. The public key has to be pinned through a
channel that does not depend on the party being audited. Nothing in this repository establishes that
channel; a receipt carries a `keyId`, never a key, precisely so that an implementation cannot
accidentally trust the key a store hands it.

**Signing uses Go's standard library `crypto/ed25519`** — vetted and constant-time. An earlier
revision carried a hand-written pure-Python Ed25519 that was explicitly *not* constant time and was
documented as unfit to hold a real key. Retiring the Python removed that caveat rather than
mitigating it, which is the largest security improvement in this repository's history.
`corpus/ed25519-vectors.json` still checks the signature layer against vectors produced by an
independent implementation.

**A seed and a public key are both 32 bytes**, so no length check distinguishes them. Passing one
where the other belongs is not refused — it silently becomes a *different identity*, whose receipts
fail verification with `key-mismatch`. The gateway prints its `keyId` on startup so an operator can
confirm which identity is live.

**An attestation is not an authentication of the source.** A receipt proves the bytes the gateway
retained are the bytes it attested, under a *caller-configured authority label*. It does not prove
that a genuinely-named upstream produced them. A validly attested but fabricated, incomplete, stale,
or misleading source response yields a valid receipt.

**The caller is outside the trust boundary.** A client supplies a session id, a source name, and
arguments — never a receipt. The gateway produces every receipt, which is what keeps a model or agent
structurally out of the proof path: a caller can assert anything, but it cannot manufacture the
gateway's signature.

Because the caller is untrusted, its inputs are constrained where they reach the filesystem. A session
id names a directory under the store and a verifier **discovers** sessions by enumerating that
directory, so session ids are restricted to a flat token
([`SPEC.md` §2a](SPEC.md)) at the HTTP boundary, at `Registry.seal`, and again at `Store.stamp`. A
value that escaped the receipts root would produce genuinely signed receipts that verification could
never enumerate — `/verify` would answer `ok` for a store missing sessions the gateway itself signed,
silently voiding the coverage guarantee in [`SPEC.md` §3](SPEC.md). Treat any input that can steer
where the gateway writes as a vulnerability in this class, not as a configuration mistake.

**Version 3 receipts, the default, commit to arguments under a per-receipt salt** that is returned
in the acquire response and never retained (SPEC.md §1.2a). A party holding only the store learns
nothing about the arguments from the commitment and cannot compare it with another receipt's;
revealing a committed value takes its salt, so whoever holds the salt can reveal that one value
and nobody else can. Who holds it is a matter of transport and custody: this reference delivers
the response over unauthenticated plaintext HTTP on localhost, so the holder is whoever can read
that exchange, and exclusivity to the caller is not something the reference provides. What the
retained artifact itself discloses is the source's affair. `--receipt-version 2` keeps the
version 2 form for a consumer not yet updated, and with it the oracle described next.

**For the `"command"` shape, a version 3 acquisition record names the source by the digest of the
file the command's first word resolved to**, resolved once and read before anything is started. It is that file at that
moment: a replacement between the read and the start is not detected, and a file that is not a
regular file is refused rather than opened. A directly executed script is digested as the script;
`python3 fetch.py` is digested as the interpreter, and the script, like every further argument of
the command, is operator configuration the record does not repeat. What the record says is which
program the operator configured, not that the program is honest.

**An adapter's acquisition record is its testimony under the gateway's signature.** For a
source declared with `--source-shape`, the endpoint, snapshot, schema, peer identity, upstream
token, adapter identity and observation time in the receipt are what the adapter wrote in its
envelope, held to their stated forms and otherwise taken on its word; the shape, the statement
commitment and the page-item digests are the gateway's own. A compromised adapter can
therefore misreport its acquisition exactly as it can misreport its bytes, and the receipt
attributes both to the source it was configured as. What it cannot do is sign — provided it
cannot read the seed: that is the separation the paragraphs above describe, it is the
operator's to establish with `--source-user` today, and declaring a shape establishes none of
it; an adapter run as the signer's own identity can read the seed, as any source can. A bare
command cannot make its output read as an adapter's record, because the shape is declared by
the operator and never by the source. Only the statement is committed: what an adapter writes
into the endpoint, the snapshot, the peer identity, the upstream token or the result itself is
in the receipt or the artifact in the clear. The adapter binary itself is not named in the
receipt, and nothing in the receipt binds the source name to a program: attributing an
adapter-shape receipt to the program that produced it takes the operator's own record of what
was configured as that source, until the engine configuration and its release make that record
(ADR-0002 records this as open).

**A remote MCP server is a network party that holds the operator's credential for the
connection** ([ADR-0015](docs/adr/0015-a-remote-mcp-server-as-a-source-and-executor.md)).
`adapter-mcp --url` sends the member of its credentials file that `--bearer` names, and nothing
else of the file, to the one URL the operator fixed — `https`, or `http` at a loopback address
written as one — follows no redirect, and refuses an answer that repeats the credential; the
server holds it for as long as it holds the connection, and what it does with it is bounded by
what the platform lets that credential do, not by the adapter. **The adapter cannot tell a read
tool from a write tool**, over HTTP as over stdio: `--tools` is the only thing that keeps a source
to reads, so the tools a binding's `live` operation names are the operator's statement of what may
be called, and a credential the platform holds to reading is what makes that statement true. A
read-only header the server honours, given with `--header`, is the server's promise and nothing
the receipt claims. The record names the URL, the TLS identity the answer came under and the name
and version the server gave itself; it does not say the tool read rather than wrote, that the
server is honest or the vendor's, or anything the session carried. The session id the server
issues is the client's alone and is in no record. For a write, the executor is the same adapter
and the same rules: the write credential goes to the URL its binding names, after the decision
policy has held the write, and a write the policy refuses reaches no server.

**A write-back platform writes as the credential its operator configured, under a decision
policy, and its receipt names the URL it wrote to** (issue #248;
[executor.md](docs/design/executor.md), "The write-back platforms"). The `azure-devops` and
`databricks` bindings name a vendor's remote MCP server for their `write` operation alone, at a URL
template the platform's `parameters` fill. The template writes the scheme and the host, or names
the host `{workspace}` alone, held to a Databricks workspace's host forms; a value is letters,
digits, `.`, `_` and `-`, and cannot leave the path segment it fills; a resolved URL out of the
endpoint form, a placeholder no parameter gives and a parameter no placeholder names refuse the
start; so no parameter can send the write credential to a host the binding does not state. A
parameter is never a secret: the credential is the operation's credentials file, sent by the
adapter as the bearer, and Azure DevOps' read-only header is not sent, since a write needs it
absent. The executor is narrowed to the one tool asked for, and a write is held to its decision
before anything is sent. A decision policy binds what it binds and nothing else: Azure DevOps'
write tools are dispatchers whose `action` argument chooses the operation, and `bind` fixes no
value of its own and refuses no member it does not name, so a policy holds such a tool only by
binding the whole arguments to the write the record states; a policy that binds an id and a
revision alone leaves the action and every other operation to the request. A Databricks function
does what its body does, as the identity's grants allow; every parameter it declares, defaults
included, is bound or is the requester's to fill. **Raw SQL is no write tool**: a decision could
then authorize an arbitrary statement, and no policy can bind a statement argument by argument.
The receipt establishes who asked, which judgment was cited and found verifying, what was sent, to
which resolved URL and which tool, and what the target answered; it does not name the credential
or the TLS identity of the write's answer (ADR-0015, question 2), and it does not establish that
the target applied the write as intended, that the tool did only what its name says, or anything
of the service's own permissions beyond the credential's.

**Version 2's arguments commitment is an equality oracle to callers.** `argumentsDigest` is a deterministic
keyed digest of the canonical arguments, with no per-receipt salt. The keying stops a party that only
holds receipts from brute-forcing a small argument space; it does not stop a party that can also
invoke `/acquire` under the same key, which — since the acquire response carries the complete
receipt — is every caller: such a party can recover another caller's low-entropy arguments by
submitting candidates and comparing digests. Treat arguments as non-secret against the gateway's
caller set. A salted commitment would close this and is a receipt-format change, out of scope for
version 2.

**Sources are operator-configured subprocesses.** The gateway executes what the operator configures
and attests whatever bytes come back. It attaches no transport, authentication, or schema of its own.
Configuring an untrusted command is equivalent to running it.

**A source is started with the environment declared for it, plus `PATH`, and nothing else of the
gateway's.** `--source-env` sets a variable or copies one by name from the gateway's environment
at spawn time; `PATH` is copied unless declared, because it carries no secret and a source that
cannot find a shell is not a source. On Windows, os/exec adds `SYSTEMROOT` to any explicit
environment that lacks it, and that one variable reaches a source there undeclared. The copy-by-
name form is for passing a path through, not a secret: a credential placed in the gateway's
environment is in the signer's memory whatever is declared, and this design does not cover that
configuration — give a source a path to a file its own identity can read.

**The public web source reads one public HTTPS origin, and an operator's redirect policy is the one
exception.** `adapter-web` admits a URL and every redirect only as HTTPS on port 443 without
userinfo, at addresses that are public on every DNS answer at the dial, and holds every redirect to
the requested origin ([public web sources](docs/design/public-web-sources.md)). The operator may
enable `google-grounding` on the adapter's command line (`--redirect-policies=`, or
`JPACK_WEB_REDIRECT_POLICIES` for the managed local plan); nothing in a request, a model's output
or a URL can. It permits exactly one change of origin: from the first response of a plain read of
`https://vertexaisearch.cloud.google.com/grounding-api-redirect/<token>`, with no query, to a
destination admitted like any URL, whose origin every later hop is then held to. Every other
guarantee is unchanged: the address checks and re-resolution on every hop, TLS verification, the
six-request bound, the timeouts, the header and body bounds and the media checks; no cookie,
authorization or referrer is sent on any hop; discovery and site-scoped reads follow no policy
hop. A refusal names the two origins, never a path, a token or a query, and only for a
destination whose DNS answers are all public; one that is private or mixed is refused as
`web-public-only` with no member, policy or not. Enabling the policy is
not evidence about the publisher: a provider choosing the destination makes its content no more
trustworthy, and the record's `redirectPolicy` says which policy was followed, not that
following it was right. Under it the reader's address reaches the publisher the result names,
as it reaches any server the reader reads.

**A Databricks connection reads as the identity its operator configured, and only that identity's
grants keep it to reads** ([connection catalog](docs/design/connection-catalog.md#databricks-version-3)).
A read is one request to a workspace's REST API, over HTTPS to a host of Databricks' own workspace
domains, with no redirect followed and no proxy. The personal access token, or the service
principal's secret and the access token minted for it, stay in the companion's private custody and
are in no receipt, record, status, error or log line: an answer that repeats one, as written or in
JSON escapes, is refused; a failed statement's message that repeats one has it replaced before it
is cut to its bound; and a request that carries one, in its statement, parameters, names or cursor,
is refused before it is sent. A read's receipt establishes the bytes
from that workspace endpoint, under the TLS identity it names, for that statement or listing, at
that time, under the credential the operator configured. It does not establish that the data is
current or correct, that the identity's grants are what the operator intends, or that a statement
read rather than wrote: the statement is sent as given, and the SQL warehouse's and Unity Catalog's
grants on the identity are what keep the profile to reads.
Since the Azure DevOps provider's first review round (#255), what it shares with that provider holds
here too: every request, answer and outgoing text is held against every credential the provider's
custody holds for the principal (each connection's token or secret and each token held), escapes
decoded to the point where decoding changes nothing; `configure` refuses a connection whose own text
spells one; a failed statement's message that still spells one is not repeated; every control answer
is held once more as a whole; and compression is neither asked for nor undone.
Its MCP profile reaches the workspace's managed MCP servers and the Unity Gateway services the
operator enables by exact name, each an endpoint under the workspace with the tools a read may call
on it, over Streamable HTTP under the same credential (a service principal's scope must name
`ai-gateway` for a Unity Gateway service): a server or a tool named with the credential is refused by `configure`; a tool outside
the list, and arguments, a tool or a server carrying the credential, are refused before anything is
sent; no redirect is followed; every answer (`initialize`, each tool listing page, the call) that
repeats the credential, the token in use, any credential custody holds or the session id the server
issued, as written or in escapes, is refused before anything of it is read, the whole message,
envelope and every member, since the Azure DevOps MCP profile's first review round (#256), and a
test's whole answer is held to each session id and not written where it would still spell one; the handshake and the listing are read by their
members' exact names; a refusal's or a failed tool's text has every credential replaced before it is
cut to its bound, and is not reported at all where it still spells one once its own JSON escapes are
decoded; and every error, test field and status field is held once more against the credential, the
token and the session id, which is in no record, error or report. Its receipt establishes the bytes from that server's endpoint, under the
TLS identity it names, for that tool and those arguments, at that time, under the credential the
operator configured. It does not establish that the answer is true, or that the tool read rather
than wrote: Databricks states that its Genie Agent server does not write to tables, while its SQL
server runs what it is sent as far as the identity may, a Unity Catalog function does what its
body does, and a Unity Gateway service is any MCP service registered in Unity Catalog, an external
connector among them, which may write and which the connection claims nothing about; so the
service list, the tools list and the identity's grants are what keep the profile to reads.

**An Azure DevOps connection reads as the credential its operator configured, and only that
credential's scopes keep it to reads** ([connection catalog](docs/design/connection-catalog.md#azure-devops-version-3)).
A read is one request, or for a query-and-get two, to one project of an organization's REST API, over
HTTPS to `dev.azure.com/{organization}` or `{organization}.visualstudio.com` and nothing else, with
no redirect followed, no proxy and nothing retried. The personal access token, its basic
authentication value, or the Microsoft Entra access token the operator pasted, stays in the
companion's private custody; the `Authorization` header is built from it when a request is made and
is stored nowhere. None of them is in any receipt, record, status, test answer, error or log line,
and "them" is every credential the provider's custody holds for the principal, every connection's,
not only the one a request names. Escapes are decoded as deeply as they nest, to the point where
decoding changes nothing; a text still changing after 32 passes is held to carry one. A request that
carries one, in its query, fields, repository, path, version or cursor, is refused before it is sent,
and a `test` is held to the same screen; an answer (or a continuation token) that repeats one is
refused before anything of it is read, a test's answer too; a configured name or project that spells
one is refused by `configure`; a threshold an organization names has every whole one replaced before
it is cut, and is not named where it still spells one; and every error and every control answer,
fixed words included, is held once more against them, written with each replaced, or as a sentence
saying it is not reported, or as an error with no text. Compression is neither asked for nor undone,
so the result bound is on the bytes received. The
members a read is decided by (a query's work items and their ids, an items answer's ids, an error's
type) are read by their exact names, and the ids of a query-and-get's second request are the ids
its query answered, at most 200. An access token at or within a minute of its configured expiry is
not sent, checked immediately before every request; the connection mints none. A read's receipt establishes the bytes from that organization's
endpoint, under the TLS identity it names, for that query or listing, at that time, under the
configured credential, acting with its scopes and its identity's permissions. It does not establish
that a work item is current or complete (a query's results are truncated at 20,000 items without an
error), that the credential's scopes are what the operator intends, or that a call read rather than
wrote: the connection makes only the reads it names, but a token with write scopes would let another
use of it write, and Microsoft's guidance is to select only the scopes a task requires; for this
profile that is Work Items, Code and Build, each Read.
Its MCP profile reaches the organization's remote MCP server, `https://mcp.dev.azure.com/{organization}`,
built from the configured organization URL and never from a request, over Streamable HTTP under the
connection's access token (Microsoft documents no personal access token for it, and a user's token
only; the companion mints none). Each request carries the server's read-only header,
`X-MCP-Readonly: true`, unless the operator turns it off for the server, and the token is held to its
expiry immediately before each one. A tool off the connection's list, and arguments, a tool or a
server carrying any credential custody holds, are refused before anything is sent; a tool named
with one is refused by `configure`; no redirect is followed; compression is neither asked for nor
undone and an answer whose `Content-Encoding` names anything but `identity` is refused; the
session's end is a request like the others and comes before anything is kept, so an end the expiry
refuses leaves nothing; every whole message (`initialize`, each tool listing page, the call, each
event of a stream), envelope and every member, that repeats a credential or the session id the
server issued, as written or as decoded, is refused before any member of it is read; a test's whole
answer is held to the session id too, and not written where it would still spell it; the handshake, the listing and the result are
read by their members' exact names; a refusal's or a failed tool's text has every credential
replaced before it is cut, and is not reported where it still spells one; and every error, test
field and status field is held once more against them and the session id, which is in no record,
error or report. Its receipt establishes the bytes from that organization's MCP endpoint, under the
TLS identity it names, for that tool and those arguments, at that time, under the configured token
acting with its user's permissions. It does not establish that the answer is true or that the tool
read rather than wrote: the read-only header is the server's promise, which the connection neither
checks nor records, a listed tool may be called with any action it takes, and the tools list and
the token's permissions are what keep the profile to reads. The organization's local MCP server is
no connection: the connections run no third-party server process, and an operator runs it as a
source under `adapter-mcp`, whose own rules then hold.

**On Unix a source runs in a process group led by an anchor**, a process the gateway starts before
the source and reaps only after the group has been killed. A group is addressed by its leader's
pid, and a leader that has been reaped frees a pid another process can take; the anchor holds the
group id until the last kill has been sent, so no kill reaches an unrelated process. Cancelling a
source — on the source's timeout (thirty seconds unless `--source-timeout` sets another), on
overflow, or on the gateway's own shutdown — kills the
source and every descendant still in the group, and the group is killed again after the source is
waited for, since an overflow a descendant writes after the source has exited cancels nothing
os/exec still watches. A descendant that has left the group is not reached: it gets a bounded wait
for its pipe, not the acquisition. On Windows there is no process group; the direct child is
killed and any descendant gets the same bounded wait. The gateway carries its own interrupt to
every source in flight, because a source in its own group no longer receives the terminal's, and
it answers every request in flight before it exits — or, if a request is still open when the
grace (the pipe wait plus ten seconds) expires, aborts it and exits non-zero saying so. The anchor
is this executable's own running image where the kernel exposes it (`/proc/self/exe`); elsewhere
the executable's path is re-opened for each acquisition, so replacing or removing the binary
while the gateway runs is not supported — stop and restart it. The anchor mode is selected by an
internal marker variable and an argument together and requires a pipe on stdin; an ordinary
invocation that inherits the marker refuses to run rather than silently succeed. On Linux a root
gateway asked to run a source as another user must hold `CAP_SETUID`, `CAP_SETGID` and
`CAP_KILL`, and refuses to start without them: a process that can switch but cannot kill could
start the source and never stop it. **`--source-user`** runs a source as another OS
user where the platform has one, with that user's own supplementary groups and none of the
gateway's, and `serve` refuses to start rather than fall back to running the source as the signer
when it cannot switch: root may switch, and so may a process that is not root but holds
`CAP_SETUID`, `CAP_SETGID` and `CAP_KILL` on Linux as file capabilities, holding nothing
ambient or inheritable and nothing that reads past permissions, which is how the engine runs its
signer as a user of its own. A source run as another user is started held to the kernel's
`no_new_privs` on Linux, which it inherits and cannot clear, so executing the gateway binary — or
any set-user-id file — grants it nothing; and the engine refuses to start when its binary carries
file capabilities and is executable by anyone but its owner. A process stripped of the capability to switch passes the startup
check only where capabilities cannot be read, and fails at its first acquisition, where the
operating system's reason is reported. **A
source's run is bounded in time** (thirty seconds, or its own `--source-timeout`, from one second
to seven days; an adapter may hold itself to less by a deadline of its own, and the document
and rendering adapters take none past ten minutes), **a request body in size** (one mebibyte;
`/acquire`'s set by `--max-request`, from 1 byte to 64 MiB), and **a source's stdout**
(`--source-max-output`, one mebibyte by default, from 1 byte
to 64 MiB as well — a source's output is parsed under no value budget, so its bytes are the whole
of what bounds that parse); its stderr is bounded and truncated: a source that crosses the stdout
bound is killed, its
acquisition fails, and nothing it wrote is retained. An operator raising `--max-request` weighs
it against what one request may cost. The body is read whole, and its arguments are parsed into
values and canonicalized again for the source's stdin, so a request holds a multiple of its body
that depends on the arguments' shape. As measured on this implementation (the heap's peak,
sampled every millisecond, for one request under Go's default `GOGC`, in a test that streams the
body to the handler), and varying from run to run: an argument that is one large string peaked
at about five and a half to six and a half times the body, 360 to 410 MiB for a 64 MiB body; arguments of
many small values cost far more for each byte — a one-mebibyte body of one-member objects nested
in one another (`{"":{"":0}}`, a hundred deep) peaked at about 85 MiB, and half a million empty
objects, about 1.5 MiB, at about 67 MiB; at the 64 MiB ceiling, one-member objects nested a
hundred deep with names of 129 to 140 bytes peaked at about 550 to 690 MiB of heap, around ten
times the body, with resident memory reaching about 800 MiB. These figures are for one request
and are not bounds: which of the shapes measured cost most changed between runs, a shape not
measured may cost more, and requests in flight at the same time add to them. The arguments are held to a budget of 524,288 JSON values, past which the
request is refused with 400 — a budget a one-mebibyte body cannot reach, so it changes nothing
under the default bound. It limits how many values a raised bound admits, not the memory they
take: member names are not counted. A refusal quotes text taken from the request — a source
name, a member name, a number, a tool name a message to the engine's MCP server carried —
bounded: short text as it was sent, longer text as its first bytes and how long the whole was,
so an answer to a refused request is not itself a multiple of the body sent. The engine's MCP
server holds what it repeats of the signer's own refusal to a bound of its own — 512 bytes and
how long the whole was — so that answer is bounded at the front as well, whatever the signer
sent. What is answered
costs as well: an answer is built whole in memory before any of it is written, and JSON spells
some bytes six times over (`<` becomes `\u003c`), so a result raised towards
`--source-max-output` can be answered as several times its own size — six, for a result made of
such bytes; about its own size for ordinary text.
Parsing and canonicalization run before the source's timeout
starts and are not bounded by it; their time grows with the body. `--max-request`,
`--source-timeout` and `--source-max-output` are command-line options: under an engine
configuration `/acquire` keeps its one-mebibyte bound, the derived sources keep the
thirty-second timeout, and their stdout keeps its own one-mebibyte bound.
**The seed is opened once and judged as the file that was opened** —
a regular file, on Unix also owned by the gateway's own user and readable by nobody else — before
it is read through that same descriptor, so the file checked is the file loaded, and a file larger
than a seed file can be is refused rather than read in part. A Unix seed that fails is refused at
startup with the `chmod` to run. What owner and mode do not see: an access-control list that
grants another user read access, which macOS honours before the mode bits; an operator who grants
one has opened the seed, and nothing here notices. Windows checks that the seed is a regular file
and says the rest is the filesystem's. **On Unix, descriptors the launcher left open are marked
close-on-exec at startup**, enumerated exactly where the kernel lists them (`/proc/self/fd` on
Linux, `/dev/fd` on macOS and the BSDs), so a seed passed as `3<gateway.seed` reaches no source
whatever user or mode protects the file. Where neither listing exists the sweep runs by number up
to the hard limit, capped, and misses a descriptor opened above a limit that was lowered
afterwards — a last resort on platforms this reference does not test. os/exec on Windows hands a
child only the handles it is told to.

What none of this gives: a source that runs as the gateway's own user, because no `--source-user`
was given, can read what that user can read, including the seed; and a gateway that runs as root
can read the files a source user holds. The separation is only as strong as the identities the
operator gives the two sides. **`serve --config`** holds a configuration to both sides at once
([docs/design/engine-config.md](docs/design/engine-config.md)): every platform's adapters run as
a user of their own that is neither root nor the signer nor another platform's, each credentials
file — one per operation — must be owned by that user and readable by nobody else under
directories nobody else can replace it in, a signer that is root must be accepted by name, and so must a host
container-runtime socket an adapter could reach; a non-root signer may hold no capability that
reads past permissions, in its effective or permitted set, and none that is ambient or
inheritable, since either could cross into an adapter and let it switch back — the three it
needs are file capabilities on the gateway binary, and nothing is cleared, as clearing is per
thread. What that holds is
the signer as written: a signer holding `CAP_SETUID` can assume any user, so a compromised
signer is not held out of credentials by the configuration — that takes a privileged launcher
separate from the signer, which is the engine image's job. The checks hold the configuration
to what the filesystem and the kernel report; an access-control list or a socket at another
path is not seen. **`connect`** holds the configuration it would write to the same checks
before it runs a platform's adapters once in check mode — as the platform's user, in the
environment `serve` would give them — and writes the entry only when they answered; the
report an adapter writes crosses to the operator, redacted by the adapter as its diagnostics
are, and nothing is signed from it.

**`identity` decides who may call, never from where.** A configured issuer's tokens are verified
against a key file the operator holds, with the standard library and no fetch on the request path;
a token names who asked at the engine's boundary and proves nothing about what they approved. The
token is never stored and never signed into a receipt, only its digest. Transport is still plain
HTTP on a loopback address: a token presented off the machine can be captured and replayed, and
reaching the engine from another host means a TLS-terminating front the operator runs and trusts.

**A checkpoint witness is reached from other hosts by other parties** ([ADR-0013](docs/adr/0013-checkpoint-witness.md);
[`SPEC.md`](SPEC.md) §6, "Witness endpoints"). It is the first surface of this reference meant
for that, and what the reference does for it is narrow. A submission carries a bearer token of
the configured issuer, verified as every other endpoint verifies one, and is taken only for a
trail registered to the token's subject; each submitter is held to a number of submissions a
minute and a number of trails, and the witness to 32 submissions in flight, 4 of them from one
submitter, and 64 reads, a body
of one mebibyte and a line of 4096 bytes, each read through its bound and held to its form as it
is read, and 30 seconds to write an answer. Reads are open to anyone who names a trail, and the
reference bounds no reader's rate. What it does not do: it speaks plain HTTP on a loopback
address, so reaching it from another host takes a TLS-terminating front the witness's operator
runs, which is also where reads are bounded. A submitter's token opens the witness and nothing
else: it names the witness's audience (`witness.audience`), not the engine's, and every other
token-checked endpoint of the signer — `/seal` among them — and the MCP transport refuse a token
that names it, or that is of a subject among `witness.submitters`; a front that exposes the
submission and the two reads alone is defence in depth, not what keeps the signer's other
endpoints from a submitter; it is one key and one operator, not a multi-tenant service — every trail it
witnesses is signed under the gateway's own seed, the key of its receipts and seals, and its
submitters are the subjects of one issuer, told apart by nothing else; and **a credential is
enough to spoil a trail at that witness for good**: whoever holds a token of a trail's registered
subject can have a checkpoint at the largest sequence signed, after which no honest checkpoint of
the trail is above the latest, and that statement stays in the chain. Revoking the token does not
unsign it: the trail is retired and its operator goes on under a new trail. Under
`"first-submission"`, any subject the issuer names, and `submitters` allows, can claim a trail
whose identity it has learned before its operator does. A witness whose log or marks are damaged
refuses to start, and the rules it recovers by can cost it its key, which is the gateway's key for
receipts and seals too. **An operator's credential administers the witness**: it registers and
retires trails on a running witness, at `POST /witness/registrations` and
`POST /witness/trails/{trail}/retirement`. With `witness.operators`, only the engine-audience
token of an issuer and subject the list names is an operator's credential there, and any other
token the engine takes is refused `403`; with the list present and empty, none is, and the
offline commands remain. Without the list, any token the signer's other token-checked endpoints
take — an engine-audience token of the configured issuer, of any subject not among
`witness.submitters` — is, so name the operators. Whoever holds an operator's credential can
retire any trail it names, for good, and move any trail's registration away from its submitter,
who is then refused; the list says which callers may, not who holds their tokens, and `/seal`
and the signer's other endpoints take any token the engine takes either way. A submitter's
credential cannot, and is refused there as at `/seal`; no operator may also be a submitter. So
a front for other parties passes `/witness/checkpoints`, the two reads under
`/witness/trails/{trail}/` and `GET /publickey`, which a reader with no pinned key holds to the
key identifier a receipt names (below), only, and keeps those two paths on the operator's side, as it keeps
the signer's other endpoints, with the list or without it: a front that passes all of
`/witness/` lets a token from another host administer the witness — any engine-audience token
without the list, a named operator's with it. Repairing the files takes a stop of the witness,
since a running witness holds its files.

**A receipt may name the witness its trail is registered with** ([ADR-0014](docs/adr/0014-a-receipt-names-the-witness.md);
[`SPEC.md`](SPEC.md) §1.2a, `witness`, and §6, "Reading the witness a receipt names"). The member
is the operator's gateway's word and no more. On a receipt that verifies under the operator's
gateway key, it establishes that the holder of that key, minting the receipt at its `servedAt`,
named this origin and this key identifier for this trail. It does not establish that the witness
holds anything for the trail or registered it, that a checkpoint was submitted, that the chain is
countersigned, that the origin serves the key named, that the witness is independent of the
operator, who chose it, or anything about the operator's honesty; and a receipt without it does
not establish that the trail has no witness. Only the operator's configuration names a witness
(`witnessedBy`, `--witnessed-by`), and the gateway refuses its own key as one, since a gateway
whose key the operator can use is no witness against the operator; a request names at most a
trail, and an acquisition's trail is the request's, so a caller can name another trail than the
record that will cite the receipt — the witness named is still the configuration's for that trail,
and a reader holds it to the record's own trail. A reader never takes the witness's key from a
receipt, which names a key and carries none: it uses its own pin whose identifier the receipt
names, or else the key the named origin serves at `/publickey`, held to that identifier and the key
rule, and a reading under a served key is as independent of the operator as the operator's choice
of witness. With `witnessedBy` given, `/act` reads the `trail` of every record it finds, whatever
its tool's policy. The receipt records no token, no registration's issuer or subject, and nothing
of the witness but its origin and key identifier.

**The registry closes replay and rollback only relative to a verifier that trusts the gateway's
registry over the store.** The anchor must be fetched from the key holder, not from the store being
checked. A verifier that reads both from the same untrusted place gets no guarantee.

**Not in scope for this reference:** availability or HA, authenticated transport, access control
beyond a checkpoint witness's registrations and named operators, multi-tenancy, key rotation or custody, rate limiting
beyond a witness's bounds on its submitters, and resistance to a local attacker who can
concurrently rename or replace store ancestors. Run it from a directory whose ownership and write
permissions you control.
