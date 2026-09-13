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
      "credentials": { "file": "/run/secrets/finance-warehouse" },
      "user": "engine-finance",
      "endpoint": "warehouse.internal:5432"
    },
    "policy-documents": {
      "binding": "s3-compatible@sha256:…",
      "credentials": { "file": "/run/secrets/policy-documents" },
      "user": "engine-documents"
    },
    "service-desk": {
      "binding": "jira@sha256:…",
      "credentials": { "file": "/run/secrets/service-desk" },
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
  credentials are, and to the OS **user** its adapters run as, which must exist, must not be
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
| `<platform>/history` | `adapter-airbyte` | `--image <history.image> --credentials <file> --runtime <runtime> [--endpoint <endpoint>]` |
| `<platform>/live` | `adapter-mcp` | `--image <live.server.image> --credentials <file> --runtime <runtime> --tools <live.tools, comma-joined> [--endpoint <endpoint>]` |

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
  open its own credentials) — the path resolved first, so a system's own link such as
  macOS's `/var` is not refused, and the directories held are those the file is actually
  under; the seed's directories are held to the same, for the signer;
- a signer that runs as **root**, which reads every credentials file whatever protects it,
  unless the operator sets `"rootSigner": "accepted"` — the engine then says in one line at
  startup that the separation between signer and adapters rests on the host, not on the
  configuration. The way to avoid it: run the signer as a user of its own holding
  `CAP_SETUID`, `CAP_SETGID` and `CAP_KILL` **as file capabilities on the gateway binary**,
  which is what lets it switch adapters to their users;
- a non-root signer holding **`CAP_DAC_OVERRIDE` or `CAP_DAC_READ_SEARCH`**, which read past
  every permission, or holding any **ambient** capability, which would survive the switch into
  an adapter and the exec and let the adapter switch back — the engine empties its ambient set
  before it switches anyone, and refuses a set it cannot empty;
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
that reads past permissions and no capability an adapter would inherit. **A signer that holds
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
      "server": { "image": "…/mcp-postgres@sha256:…" },
      "tools": ["query"],
      "licence": "MIT"
    }
  }
}
```

One binding per platform; one entry per operation it supports — `history`, `live`, `write` —
each naming its shape, the pinned artifact that serves it, the tools it may call, and the
licence of the artifact it pulls. A restriction of streams for the history operation is not yet
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
engine connect service-desk --binding jira --credentials-file /run/secrets/service-desk
```

writes the platform entry, resolves the binding's digest from the catalog, starts the adapter
once in check mode with the credentials reference, and reports what the platform answered —
without acquiring anything and without minting a receipt. It refuses a binding that is not in
the catalog, and it refuses to overwrite an existing entry unless told to. The entry is written
only when the check succeeds; a platform that cannot be reached is not silently configured.

## What the file is not

- **Not a policy.** It says which systems may be reached, never what a pack means or which
  pack decides what. Selection stays the application's.
- **Not an authorization.** `write: true` says an executor may be pointed at the platform; a
  write still happens only for an approved action citing a decision record.
- **Not portable across engines.** It names local paths and local secrets; the receipts are
  what travel.
