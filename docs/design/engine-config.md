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
      "credentials": { "env": "FINANCE_WAREHOUSE_DSN" }
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
- `listen` binds localhost by default and the engine refuses a non-loopback address unless
  `identity` is configured: an engine with no way to know who is calling does not accept
  callers from off the machine.
- `identity` names the token issuer, the audience the engine expects to be named as, and a
  local copy of the issuer's public keys. The engine verifies tokens with the standard library
  and never fetches keys over the network on the request path; refreshing the key file is the
  operator's job, and a token signed by a key not in the file is refused. Without this member
  every receipt carries `caller: null` and no action is ever performed, because an action
  requires an approver.
- `platforms` maps an operator-chosen name — the `source` a receipt will carry — to a
  **binding** from the catalog, pinned by digest, and to where its credentials are. `write`
  defaults to false; a platform that is not marked writable cannot be the target of an action
  no matter what its binding offers.

## Credentials

`credentials` is a reference, never a value: the name of an environment variable the adapter
process will be started with, or a file path the adapter process will read. The gateway
process resolves neither. It passes the reference to the adapter it spawns, and the adapter
reads the secret in its own process. A configuration file that contained a secret would put
the secret in the gateway's memory, which is the one place this design exists to keep it out of.

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
      "licence": "MIT"
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
an operator hosting the engine for others can see which entries carry terms that forbid it.

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
