# Design note: the engine's one configuration file

**Status: design note, not normative.** This describes the configuration the engine
([ADR-0001](../adr/0001-one-engine-four-processes.md)) reads through `gateway serve --config`.
It is a convention of this distribution, not part of the receipt format, and it can change
without a corpus vector moving.

## The rule

The file names **platforms, not processes**. An operator writes which systems the engine may
reach and where their credentials are; the engine derives every `--source NAME=CMD` from that
and spawns what it needs. Nothing in the file is a command line, and nothing in it is a secret.

## Shape

```json
{
  "engineVersion": "1",
  "authority": "gateway:acme-finance",
  "seed": "/var/lib/engine/gateway.seed",
  "store": "/var/lib/engine/store",
  "registry": "/var/lib/engine/registry.jsonl",
  "decisionRecords": "/var/lib/engine/decisions",
  "listen": "127.0.0.1:8787",
  "catalog": "/usr/local/share/engine/catalog",
  "runtime": "docker",
  "adapters": "/usr/local/bin",
  "platforms": {
    "finance-warehouse": {
      "binding": "postgres@sha256:…",
      "credentials": {
        "history": { "file": "/run/secrets/finance-warehouse-connector" },
        "live": { "file": "/run/secrets/finance-warehouse-env" }
      },
      "user": "engine-finance",
      "endpoint": "warehouse.internal:5432"
    },
    "policy-documents": {
      "binding": "s3-compatible@sha256:…",
      "credentials": { "history": { "file": "/run/secrets/policy-documents" } },
      "user": "engine-documents"
    },
    "service-desk": {
      "binding": "jira@sha256:…",
      "credentials": { "live": { "file": "/run/secrets/service-desk" } },
      "user": "engine-desk",
      "write": true
    }
  }
}
```

The file is read through the same strict parser the gateway uses for everything else:
duplicate member names refused, integers only, unknown members refused by name. A misspelled
key is an error, never an intention silently dropped. `engineVersion`, `authority`, `seed`,
`store`, `registry`, `decisionRecords`, `listen`, `catalog` and `platforms` are required;
`runtime`, `adapters`, `rootSigner`, `hostRuntime` and `identity` are optional; within a
platform, `binding`, `credentials` and `user` are required, `endpoint`, `environment` and
`write` optional. Every path is absolute.

- `engineVersion` moves on any member change, as `receiptVersion` does.
- `authority`, `seed`, `store`, `registry` are the four positional arguments `gateway serve`
  takes today, named.
- `decisionRecords` is where the runtime's audit trail is expected, so `verify` can resolve
  an action receipt's `decision.recordDigest` ([receipt-v3.md](receipt-v3.md)).
- `listen` is a literal loopback address with a port — `127.0.0.1:8787` or `[::1]:8787` —
  and the engine refuses any other, a name such as `localhost` included, since a resolver may
  map a name elsewhere. The gateway speaks plain HTTP and a token presented over plain HTTP
  off the machine can be captured and replayed; SECURITY.md lists authenticated transport as
  out of scope, and this design does not change that. Reaching the engine from another host
  means a TLS-terminating front the operator runs and trusts, outside this repository.
  `identity` decides who may call, never from where.
- `catalog` is the directory of binding files (below). `runtime` is the container runtime
  command the adapters use, `docker` by default or `podman`, by name or by path. `adapters`
  is the directory holding the adapter binaries; when absent they are found on the engine's
  `PATH`.
- `identity` names the token issuer, the audience the engine expects to be named as, and a
  local copy of the issuer's public keys. The engine verifies tokens with the standard library
  and never fetches keys over the network on the request path; refreshing the key file is the
  operator's job, and a token signed by a key not in the file is refused. Without this member
  every receipt carries `caller: null` and no action is ever performed, because an action
  requires an authenticated requester. **This release refuses a configuration that carries
  `identity`**, since nothing verifies a token yet: a member that did nothing would read as a
  claim.
- `platforms` maps an operator-chosen name — with `/history` or `/live` appended, the `source`
  a receipt will carry — to a **binding** from the catalog, pinned by digest, to where its
  credentials are — **one file per operation** the binding offers, `history` and `live`, since
  a connector's configuration and a server's environment are different files in different
  forms, and a file for an operation the binding does not offer, or none for one it does, is
  refused — and to the OS **user** its adapters run as, which must exist, must not be
  root or the signer, and must be no other platform's. `endpoint` is the host the platform is
  reached at as the operator names it, recorded as the receipt's endpoint; the adapters do not
  read it from the credentials. `environment` is an object of string values the platform's
  adapters receive beside their user's `HOME` and the engine's `PATH` — `DOCKER_HOST`,
  `XDG_RUNTIME_DIR`, whatever selects that user's own runtime — and never a secret: a value
  here is in the configuration and in the signer's memory. It may not set `HOME` or `PATH`.
  `write` defaults to false; a platform that is not marked writable cannot be the target of an
  action no matter what its binding offers.

## What the engine derives

For each platform and each operation its binding offers, one source, declared with the
shape the operation is served by, run as the platform's user, with an environment of that
user's `HOME` (from the user database), the engine's `PATH`, and the platform's
`environment` — a container runtime needs the first two, and a secret never travels this
way:

| Source | Adapter | Command line |
|---|---|---|
| `<platform>/history` | `adapter-airbyte` | `--image <history.image> --credentials <credentials.history.file> --runtime <runtime> [--endpoint <endpoint>]` |
| `<platform>/live` | `adapter-mcp` | `--image <live.server.image> --credentials <credentials.live.file> --runtime <runtime> --tools <live.tools, comma-joined> [--endpoint <endpoint>] [-- <live.server.args>]` |

A binding's `write` operation derives nothing: the executor that performs writes does not
exist yet, and a source that could be asked to write would be a read that writes.

## What the engine refuses

Before anything is written — no store, no registry, before the seed is even loaded — the
engine refuses to start under a configuration the isolation claim of
[ADR-0001](../adr/0001-one-engine-four-processes.md) does not survive:

- a platform without a `user`, or whose user does not exist, is **root** (an adapter running
  as root reads the seed), is the **signer's own** (the same), or is **another platform's**
  (one platform could read the other's credentials);
- a credentials file not owned by the platform's user, or readable beyond its owner (mode
  other than `0600`); and any directory on the way to it that is owned by neither root nor
  that user, or writable beyond its owner without the sticky bit (so someone else could
  replace the file under its name), or that the user cannot traverse (the adapter could not
  open its own credentials, judged by the owner bits when the directory is the user's and by
  the other bits when it is root's). The path is walked component by component from the
  root, and everything the walk meets is held: a symbolic link is allowed only when root owns
  it — a system's own, such as macOS's `/var` — so nobody but root could have placed or could
  retarget it, and the walk then continues through its target's components, each held in
  turn, with a bound of thirty-two hops; the path with every link resolved is the path the
  adapter is then given, so the file judged is the file it opens. The seed's directories are
  held to the same, for the signer, and its path used resolved;
- a signer that runs as **root**, which reads every credentials file whatever protects it,
  unless the operator sets `"rootSigner": "accepted"` — the engine then says in one line at
  startup that the separation between signer and adapters rests on the host, not on the
  configuration. The way to avoid it: run the signer as a user of its own holding
  `CAP_SETUID`, `CAP_SETGID` and `CAP_KILL` **as file capabilities on the gateway binary**,
  which is what lets it switch adapters to their users;
- a non-root signer holding **`CAP_DAC_OVERRIDE` or `CAP_DAC_READ_SEARCH`** in its effective
  or permitted set (a permitted capability is raised without any privilege gained), which read
  past every permission; or holding any **ambient** capability, which would survive the switch
  into an adapter and the exec and let the adapter switch back; or any **inheritable** one,
  which a file the adapter executes could take up. Neither set is cleared, since clearing is
  per thread and cannot be verified for every thread the engine spawns from: the three
  capabilities are held as file capabilities on the gateway binary, which put them in the
  permitted and effective sets and nowhere else, and anything else is refused;
- a **host container-runtime socket** present at `/var/run/docker.sock` (or podman's) while
  the runtime, by its command's base name, is `docker` (or `podman`): an adapter that can reach
  it holds host authority, which includes the seed ([engine-image.md](engine-image.md)),
  unless the operator sets `"hostRuntime": "accepted"`, with the same one-line statement at
  startup;
- the seed file's own checks, as for any `serve`: a regular file, owned by the signer, readable
  by nobody else.

What these checks establish, and no more: every adapter runs as a user that is neither root
nor the signer nor another platform's; no credentials file, and no directory on the way to
one, can be read or replaced by anyone but its owner and root; the signer holds no capability
that reads past permissions and none an adapter could take up. **A signer that holds
`CAP_SETUID` can assume any user**, and so can read any credentials file by becoming its owner:
what this configuration holds is the signer *as written* — it reads no credential — not a
signer that has been compromised. Holding a compromised signer out of credentials takes a
privileged launcher separate from an unprivileged signer, which is the engine image's job and
not this file's. What the checks do not see is stated with them: an access-control list that
grants a read the mode bits do not show; a runtime reachable through a socket at another path;
a platform user that is also in a group the signer's files admit. The engine holds the
configuration to what the filesystem and the kernel report, and no further.

## Credentials

`credentials` is a path, never a value, and never an environment variable: a file the
adapter's OS identity can read and the signer's cannot. The gateway process passes the path to
the adapter it spawns — with an environment of `HOME` and `PATH` alone — and the adapter reads
the secret in its own process. An environment variable is refused as a reference (the member
is unknown to the parser) because the only environment the gateway could copy it from is its
own, which would put the secret in the signer's memory, the one place this design exists to
keep it out of. At startup the engine checks the other direction too, as the refusals above
say: a seed file readable by any adapter identity, or a credentials file readable by the
signer's, is refused before anything listens.

## Bindings

A binding is a file in the catalog that ships with the engine, `catalog/<platform>.json`,
pinned by its digest in the configuration so a catalog update never silently changes what a
running engine reaches:

```json
{
  "bindingVersion": "1",
  "platform": "postgres",
  "operations": {
    "history": {
      "shape": "airbyte",
      "image": "airbyte/source-postgres@sha256:…",
      "licence": "ELv2"
    },
    "live": {
      "shape": "mcp",
      "server": { "image": "…/mcp-postgres@sha256:…", "args": ["--access-mode=restricted"] },
      "tools": ["query"],
      "licence": "MIT"
    }
  }
}
```

One binding per platform; one entry per operation it supports — `history`, `live`, `write` —
each naming its shape, the pinned artifact that serves it, the tools it may call, and the
licence of the artifact it pulls. An `mcp` entry's `server.args`, when present, are the
server's own arguments inside its container — the mode a server runs in, say — each one word
as written: the engine builds the adapter's command line and splits nothing, and the adapter
hands them to the runtime after the image. Its `probe`, when present, is one of its `tools`
that a check calls once with no arguments: a server that starts and lists its tools without a
working connection to its platform answers the handshake all the same, and the probe is what
establishes the connection; its result is discarded. A restriction of streams for the history operation is not yet
applied at acquisition, so a binding may not declare one: a restriction accepted and not
applied would read as applied. `history` is served by the `airbyte` shape and `live`
and `write` by the `mcp` shape; the `http` shape is not shipped by this release, and a binding
naming it is refused. The file is `catalog/<platform>.json`, it must name that platform, and
the configuration pins it as `<platform>@sha256:<digest of the file's bytes>`; a file that
does not digest to its pin is refused, since the catalog changed under the configuration. A
binding with an unpinned image is refused when the engine starts. A binding without a
`licence` for an entry is refused too: the field exists so
an operator hosting the engine for others can see which entries carry terms that forbid it —
the Postgres connector above is one, since Airbyte's database connectors are ELv2 while most
of its API connectors are MIT, and the value is copied from the connector's own metadata for
the pinned digest, never assumed.

Two shapes per platform is the norm, not a duplication: history comes through the connector
protocol because it pages and bookmarks, live reads and writes come through MCP because the
vendor maintains them. What the two must agree on is the facts: a golden record per platform
is fetched both ways and must derive to byte-identical canonical facts.

## `connect`

```
gateway connect --config engine.json service-desk --binding jira \
  --credentials-file live=/run/secrets/service-desk --user engine-service-desk \
  [--endpoint HOST] [--environment KEY=VALUE]... [--write] [--replace]
```

writes the platform entry — the binding pinned by the digest of the catalog file as it is
now, a credentials path per operation as written (`--credentials-file history=… live=…`,
exactly the operations the binding offers), the user, and what else was given; the platform
may stand anywhere among the flags — and it writes nothing until two things have held. First, the configuration as it would be, with the entry
in place, passes every refusal `serve` applies (the platforms it already names included, so a
pin the catalog no longer digests to is found here and not at the next start): the user is
neither root nor the signer nor another platform's, the credentials file is that user's alone
under directories nobody else can replace it in, and so on through the list above. Second,
each of the platform's derived sources is run once in check mode, as the platform's user, in
the environment `serve` would give it: `adapter-airbyte --check` runs the connector's own
`check` with the credentials; `adapter-mcp --check` starts the server, completes the handshake
and lists its tools, failing when a tool the binding names is not offered, and calls the
binding's `probe` once when it names one. What each answered
is printed, one line per operation; the first that cannot answer ends the connect with the
adapter's reason. Nothing is acquired and no receipt is minted. An image the runtime does not
hold yet is pulled during the check, which is why a check is given five minutes where an
acquisition has twenty seconds.

It refuses a binding that is not in the catalog, a platform already configured unless
`--replace` is given — and with it the entry replaced is not resolved, since its pin may be
what is being repaired, while every other platform is — a configuration path that is a symbolic
link, and a configuration that with the entry would exceed the size `serve` reads, judged
before any check runs. The file's directory is held open from the first read to the rename, so
what is read, written beside it and put in place is in that directory whatever a path component
is swapped for meanwhile; one connect at a time holds `<file>.lock` beside it, and a second
refuses rather than waits; the file is put in place only if, read again just before the rename, it
still holds what the checks were run against — which holds against another connect, since
one takes the lock, while an editor that does not is not held out, and its save in the
instant between that read and the rename would be written over; the new file is written in
a directory of the connect's own beside the configuration, so no other user can swap it
before the rename, and it keeps the old one's mode and owner, set through the open
descriptor, or is not put in place; and the seed is judged as `serve` judges it before any
adapter is run, so a connect does not succeed where the next start would refuse. The file is rewritten whole, in the engine's own form —
members in canonical order, indented — and put in place by a rename, so a reader sees the old
file or the new and never a partial one. Every value written is valid UTF-8, since the file
is JSON; a path that is not is refused rather than written as something else. A configuration
with an empty `platforms` object is what the file looks like before its first `connect`; it
parses, and `serve` refuses to start on it.

## What the file is not

- **Not a policy.** It says which systems may be reached, never what a pack means or which
  pack decides what. Selection stays the application's.
- **Not an authorization.** `write: true` says an executor may be pointed at the platform; a
  write still happens only for an approved action citing a decision record.
- **Not portable across engines.** It names local paths and local secrets; the receipts are
  what travel.
