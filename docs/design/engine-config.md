# Design note: the engine's one configuration file

**Status: design note, not normative.** This describes the configuration the engine
([ADR-0001](../adr/0001-one-engine-four-processes.md)) reads. It is a convention of this
distribution, not part of the receipt format, and it can change without a corpus vector moving.

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
  "identity": {
    "issuer": "https://login.example.com/",
    "audience": "judgment-pack-engine",
    "keys": "/var/lib/engine/idp-jwks.json"
  },
  "platforms": {
    "finance-warehouse": {
      "binding": "postgres@sha256:…",
      "credentials": { "file": "/run/secrets/finance-warehouse" }
    },
    "policy-documents": {
      "binding": "s3-compatible@sha256:…",
      "credentials": { "file": "/run/secrets/policy-documents" }
    },
    "service-desk": {
      "binding": "jira@sha256:…",
      "credentials": { "file": "/run/secrets/service-desk" },
      "write": true
    }
  }
}
```

Every member is required except `identity` and `write`. The file is read through the same
strict parser the gateway uses for everything else: duplicate member names refused, integers
only, unknown members refused by name. A misspelled key is an error, never an intention
silently dropped.

- `engineVersion` moves on any member change, as `receiptVersion` does.
- `authority`, `seed`, `store`, `registry` are the four positional arguments `gateway serve`
  takes today, named.
- `decisionRecords` is where the runtime's audit trail is expected, so `verify` can resolve
  an action receipt's `decision.recordDigest` ([receipt-v3.md](receipt-v3.md)).
- `listen` is a loopback address, always. The gateway speaks plain HTTP and a token presented
  over plain HTTP off the machine can be captured and replayed; SECURITY.md lists authenticated
  transport as out of scope, and this design does not change that. Reaching the engine from
  another host means a TLS-terminating front the operator runs and trusts, outside this
  repository. `identity` decides who may call, never from where.
- `identity` names the token issuer, the audience the engine expects to be named as, and a
  local copy of the issuer's public keys. The engine verifies tokens with the standard library
  and never fetches keys over the network on the request path; refreshing the key file is the
  operator's job, and a token signed by a key not in the file is refused. Without this member
  every receipt carries `caller: null` and no action is ever performed, because an action
  requires an authenticated requester.
- `platforms` maps an operator-chosen name — the `source` a receipt will carry — to a
  **binding** from the catalog, pinned by digest, and to where its credentials are. `write`
  defaults to false; a platform that is not marked writable cannot be the target of an action
  no matter what its binding offers.

## Credentials

`credentials` is a path, never a value, and never an environment variable: a file the
adapter's OS identity can read and the signer's cannot. The gateway process passes the path to
the adapter it spawns — with an otherwise empty environment — and the adapter reads the secret
in its own process. An environment variable is refused as a reference because the only
environment the gateway could copy it from is its own, which would put the secret in the
signer's memory, the one place this design exists to keep it out of. At startup the engine
checks the other direction too: a seed file readable by any adapter identity, or a credentials
file readable by the signer's, is refused before anything listens.

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
each naming its shape, the pinned artifact that serves it, the tools or streams it may use, and
the licence of the artifact it pulls. A binding with an unpinned image is refused when the
engine starts. A binding without a `licence` for an entry is refused too: the field exists so
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
