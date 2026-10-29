# Design note: the engine's one configuration file

**Status: design note, not normative.** This describes the configuration the engine
([ADR-0001](../adr/0001-one-engine-four-processes.md)) reads through `gateway serve --config`.
It is a convention of this distribution, not part of the receipt format, and it can change
without a corpus vector moving.

## The rule

The file names **platforms, not processes**. An operator writes which systems the engine may
reach and where their credentials are; the engine derives every `--source NAME=CMD` from that
and spawns what it needs. The engine file contains no command line or secret. A pinned customer binding may name a local executable and its argument vector.

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
`runtime`, `adapters`, `rootSigner`, `hostRuntime`, `identity`, `mcp`, `witness` and `witnessedBy` are optional; within a
platform, `binding`, `credentials` and `user` are required, `endpoint`, `environment`, `write`,
`descriptors`, `operationDescriptors`, `descriptorStatements`, `decisionPolicy`
and `parameters` optional. Every path is absolute.

- `engineVersion` moves on any member change, as `receiptVersion` does. The engine reads
  `"1"` to `"12"`: version 2 added `mcp`, version 3 a platform's `descriptors`, version 4 a
  platform's `decisionPolicy`, version 5 a decision policy's `requireSignedRecord`, version
  6 `witness`, version 7 `witnessedBy`, version 8 a platform's `parameters`, version 9 a
  decision policy's `fix` and `closed`, version 10 a decision policy's `shape`, version 11
  `operationDescriptors`, and version 12 `descriptorStatements`. A file of
  an earlier version still loads without the member and is refused by name with it.
  `connect` raises a file to version 12 when it signs a captured snapshot, and to
  version 8 when it carries parameters without a capture, otherwise leaving the version as it found it —
  it never lowers one — so a signer older than version 3 goes on reading every file `connect` has
  not pinned. (ADR-0007 named version 4 for its `services` member, which is not built; ADR-0011
  gave 4 to `decisionPolicy`, ADR-0012 gave 5 to `requireSignedRecord`, ADR-0013 gave 6 to
  `witness`, ADR-0014 gave 7 to `witnessedBy`, ADR-0015's amendment of 2026-10-13 gave 8 to
  `parameters`, ADR-0016 gave 9 to `fix` and `closed`, ADR-0018 gave 10 to `shape`, and
  `services` takes the next version when it is built.)

`descriptorStatements` maps each captured `live` or `write` operation to the
SHA-256 digest of its signed capture statement in the store's artifact space.
When present it covers exactly the operations pinned by `operationDescriptors`,
or the one legacy `descriptors` operation. It is never filled from a source's
response during acquisition. New `connect` captures write these pins before
returning success; existing registrations gain them through explicit recapture.
Acquisition receipts name the matching snapshot, statement and binding, and
verification requires their retained evidence (SPEC.md §9).
- `parameters`, in a version-8 file, fills the placeholders of the platform's remote binding
  ([ADR-0015](../adr/0015-a-remote-mcp-server-as-a-source-and-executor.md), question 1, amended
  2026-10-13; "Bindings" below) —

  ```json
  "parameters": { "organization": "example-org" }
  ```

  — an object of at least one string value, each name a lowercase letter then lowercase letters,
  digits and hyphens (at most 63), each value 1 to 253 letters, digits, `.`, `_` or `-`, not dots
  alone. Nothing in a value can end a path segment or begin a query, a fragment, a user or a port,
  so a value stays where its template puts it. A value is in the configuration and in the
  signer's memory, and is never a secret: the credential stays in the credentials file the
  operation names. `workspace` is held besides to a Databricks workspace's host, as the
  Databricks connection holds one: one to three lowercase labels under `.cloud.databricks.com`,
  `.cloud.databricks.us`, `.cloud.databricks.mil`, `.gcp.databricks.com` or
  `.azuredatabricks.net`, none an internationalized label, the first not the account console's
  (`accounts`, `accounts-dod`). The engine refuses to start on a placeholder of the binding no
  parameter gives, a parameter no placeholder names, and a resolved URL out of the endpoint form,
  each by a sentence naming the rule. A decision policy names a tool by its resolved name.
  `connect` writes the member from `--parameter NAME=VALUE`, repeatable, and keeps the entry's
  own on `--replace` when none is given.
- `decisionPolicy`, in a version-4 file, holds the platform's write tools to their decisions
  ([ADR-0011](../adr/0011-hold-a-write-to-its-decision.md), [executor.md](executor.md)): an
  object keyed by write tool name, each value a policy —

  ```json
  "decisionPolicy": {
    "update_ticket": {
      "outcomes": ["approve"],
      "packs": ["sha256:…"],
      "reviewed": true,
      "bind": [
        { "argument": "/id", "fact": "/ticket/id" },
        { "argument": "/revision", "fact": "/ticket/revision" }
      ]
    }
  }
  ```

  `outcomes` is required, a non-empty array of outcome ids: the record's disposition must be of
  kind `outcome` with one of them, and its handoff state `none`. `packs` is optional, a
  non-empty array of digests the record's pack digest must be among. `reviewed` is optional, a
  boolean; `true` requires the record to carry `"reviewed": true`. `bind` is optional, an array
  of `{argument, fact}`, each an RFC 6901 JSON pointer, the first into the request's
  `arguments` and the second into the record's `inputs.facts`, whose two values must be equal
  as JSON values with their types. Each policy is a closed object, read by the same strict
  parser: an unknown member, a member of another type, an entry named twice in a list, or a
  pointer that is not one is refused. So is a policy for a tool the platform's write binding
  does not name, and a `decisionPolicy` on a platform that does not set `write: true`. A tool
  the member does not name is held to nothing, and its writes read nothing in their decision
  record. An action receipt for a tool with a policy carries `action.policy`, `"sha256:"` and
  the SHA-256 of the canonical form of that policy object as written here (SPEC.md §1.2a), every
  member in it, `fix`, `shape` and `closed` as much as the rest: the same policy spelled another way has
  the same digest, and a policy that writes `"reviewed": false` or `"closed": false` has another
  digest than one that leaves the member out, though the two make the same checks. `connect` has
  no flag for it: the entry it replaces keeps its policy, and a replacement the policy would not
  fit — one without `--write`, or a binding whose write operation does not name a tool the policy
  holds — is refused before any check runs.

  `requireSignedRecord`, in a version-5 file, is optional: a non-empty array of Ed25519 public
  keys, each 64 lowercase hex as `jpack audit key public` prints one, none given twice
  ([ADR-0012](../adr/0012-hold-a-write-to-a-signed-record.md)) —

  ```json
  "requireSignedRecord": ["d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"]
  ```

  — and the record must then be signed by one of them in the runtime's sidecar beside it,
  `signatures.jsonl` ([executor.md](executor.md), step 9). A key that is not the canonical
  encoding of a point, that encodes no point of the curve, or that is of small order, under
  which a signature can be made without any secret, is refused. The keys are trusted as named and no key-rotation line is followed: when the
  runtime's key changes, the next key is added before the project signs with it, and the old
  one removed once no record it signed is still to be acted on. The keys are part of the
  policy's digest, in their order.

  `fix` and `closed`, in a version-9 file, are optional
  ([ADR-0016](../adr/0016-a-policy-fixes-a-value-and-closes-the-argument-set.md)) —

  ```json
  "fix": [
    { "argument": "/action", "value": "update" },
    { "argument": "/priority", "value": 2 }
  ],
  "closed": true
  ```

  — `bind` holds an argument to a fact of the record; it has no value of its own and refuses no
  argument it does not name. `fix` is an array of `{argument, value}`: `argument` an RFC 6901
  pointer into the request's `arguments`, held as `bind`'s are, and `value` any JSON value the
  strict parser reads. The argument at that pointer must be there and equal the value as a JSON
  value with its type, compared as `bind` compares: `"2"` is not `2`, and an object's members may
  come in any order. The engine never fills a value in: a request that leaves a fixed argument
  out, or changes it, is refused and nothing is sent, since the receipt records what the
  requester asked. No pointer may be fixed twice, or both fixed and bound. `closed` is a boolean,
  false when absent; `true` means every member of the request's `arguments`, at every depth, must
  lie under a pointer some `bind` or `fix` entry names. A pointer covers the value it names and
  everything under it, the empty pointer the whole arguments; an object or an array on the way to
  a named pointer has each of its members or elements held in turn; anything else is refused. An
  array's element is reached by its index pointer, in decimal with no leading zero
  (`/updates/0`), or by a pointer that covers the array (`/updates`), so an element past those
  the pointers name is refused; `-` and an index with a leading zero reach none. A closed policy
  with neither `bind` nor `fix` admits only an empty `arguments`. Both members are checked at
  `policy-bind`, after the bindings ([executor.md](executor.md), step 11), and are part of the
  policy's digest; fixed entries in another order are another digest for the same checks.

  `shape`, in a version-10 file, is optional
  ([ADR-0018](../adr/0018-a-policy-holds-a-containers-shape.md)) —

  ```json
  "shape": [
    { "pointer": "/updates", "type": "array", "maxLength": 2 },
    { "pointer": "/labels", "type": "object" }
  ]
  ```

  — a pointer names a value as RFC 6901 does, and RFC 6901 reads a numeric token on an object
  as a member's name, so `bind`, `fix` and `closed` hold the values under a container and not
  whether it is an array or an object. `shape` is an array of entries, each
  `{pointer, type: "object"}` or `{pointer, type: "array", maxLength}`: `pointer` an RFC 6901
  pointer into the request's `arguments`, held as `bind`'s are, and `maxLength` an integer from 0
  to 524288, the value budget an action's arguments are parsed within. An array's entry always
  carries its bound, and an object's never does. The value at the pointer must be there and be of
  the type, and an array must hold at most `maxLength` elements: absent is not the container, as
  it is not a fixed value, and the engine fills nothing in. The refusals are
  `argument "<pointer>" is not of the shape the policy holds it to` and
  `argument "<pointer>" holds more elements than the policy's shape allows`, naming no type,
  bound or length. An entry holds the value at its pointer and nothing above it: a container is
  held to its type only by an entry of its own. No pointer may be shaped twice, or both fixed and
  shaped, since a fixed value holds its own type and length; a pointer both bound and shaped is
  the operator's to write. For `closed`, a shaped pointer reaches its container, which is walked
  as a container on the way to a named pointer is, and covers nothing under it: each member or
  element there is reached only by a pointer of `bind` or `fix`, or is a container another entry
  shapes. So a closed policy whose one entry shapes `/updates` as an array admits
  `{"updates": []}` alone. The member is checked at `policy-bind` after `fix` and before
  `closed`, and is part of the policy's digest; entries in another order are another digest for
  the same checks.
- `descriptors`, in a version-3 file, pins the snapshot of the platform's tool descriptors
  that `connect` captured from its live operation, `sha256:<64 hex>`, kept beside the file in
  `<file>.descriptors/` ([tool-descriptors.md](tool-descriptors.md)). A platform whose binding
  has no live operation may not carry one. The signer parses it and never reads the snapshot;
  the MCP server does.
- `mcp`, when present, is the MCP server's own settings ([mcp-server.md](mcp-server.md)):
  `listen`, a literal loopback address with an explicit port, where `gateway mcp --http`
  listens; `resource`, the absolute `https` URL the server is reached as, without a fragment,
  required for `--http`; `origins`, the exact origins its HTTP transport admits — loopback
  origins when the member is absent, none at all when it is present and empty; and four bounds with their ranges, `sessions` (`1` to `4096`, default
  `64`), `idleSeconds` (`60` to `86400`, default `1800`), `concurrency` (`1` to `64`, default `8`)
  and `callsPerMinute` (`1` to `6000`, default `120`). With `mcp` present the signer's `listen`
  may not name port `0` — by its number, whatever its spelling — since the MCP server finds
  the signer by that value and nothing else. The signer reads the member and does nothing with it; the MCP server reads the whole
  file as metadata and holds `identity.issuer`, when it serves HTTP, to an authorization
  server's identifier (an absolute `https` URL with no query and no fragment), which the
  signer does not demand.
- `witness`, in a version-6 file, makes the signer a checkpoint witness
  ([ADR-0013](../adr/0013-checkpoint-witness.md); SPEC.md §6, "Witness endpoints", and §8): it
  then answers `POST /witness/checkpoints` and the two reads of a trail, and its operator's two
  acts, and keeps what it signs in its own files. A closed object —

  ```json
  "witness": {
    "log": "/var/lib/witness/log/witness.log",
    "marks": "/var/lib/witness-marks/witness.marks",
    "audience": "witness:acme",
    "registration": "operator",
    "submitters": [{ "issuer": "https://login.example", "subject": "desk-acme" }],
    "operators": [{ "issuer": "https://login.example", "subject": "witness-admin" }],
    "trailsPerSubmitter": 100,
    "submissionsPerMinute": 60
  }
  ```

  — whose `log` and `marks` are required, each an absolute, clean path: the log, with the
  registrations (`<log>.registrations`) and what a repair sets aside (`<log>.set-aside`) beside
  it, and the marks, which may be neither the log nor a file beside it. `audience`, required, is what
  a submission token names in place of the engine's `identity.audience`, and must differ from it: a
  token naming it opens the witness and nothing else, and every other token-checked endpoint and
  the MCP transport refuse it, as they refuse a token of a subject among `submitters`
  (SECURITY.md). `registration` is
  `"operator"`, the default, under which the witness's operator registers each trail with
  `gateway witness register`, or, on a running witness, at `POST /witness/registrations` (SPEC.md
  §6, "Administration"), and a submission for a trail nobody registered is refused, or
  `"first-submission"`, under which the first submission accepted for a trail registers it to
  its submitter. `submitters`, when present, is the `{issuer, subject}` pairs allowed to submit
  at all, each issuer `identity.issuer`, none given twice; present and empty, no subject may
  submit, and the witness only serves what it holds; absent, any subject the issuer's tokens
  name may. `operators`, when present, is the `{issuer, subject}` pairs whose engine-audience
  tokens may register and retire trails on a running witness, at `POST /witness/registrations`
  and `POST /witness/trails/{trail}/retirement` (SPEC.md §6, "Administration"), each issuer
  `identity.issuer`, none given twice, and none among `submitters`, since the roles are
  distinct: a submitter's token opens the witness and nothing else. Any other token the engine
  takes is refused there `403`. Present and empty, no one may administer the running witness,
  and `gateway witness register` and `retire` remain for a stopped one; absent, any token the
  engine takes, of a subject not among `submitters`, may, as it may call `/seal`. Name the
  operators, and keep both paths on the operator's side of a front either way (SECURITY.md).
  `trailsPerSubmitter` (`1` to `100000`, default `100`) bounds the trails registered
  to one submitter that hold a statement and are not retired, and `submissionsPerMinute` (`1` to `6000`, default
  `60`) its submissions in a minute. A witness needs `identity`, since a submission is
  authenticated by a bearer token of the configured issuer, and is refused without it; it needs
  no platform, so a configuration whose `platforms` is empty starts as a witness and nothing
  else. None of its files may be the seed or the registry, or be in the store or the
  decision-record directory. The witness signs with the gateway's own seed, under a prefix of
  its own (SPEC.md §8.3): a party that wants the witness's key apart from its receipts' runs a
  second engine with a seed of its own. `connect` keeps the member, its values unchanged.
- `witnessedBy`, in a version-7 file, names the checkpoint witness each trail is registered
  with, so that a receipt minted for the trail names it
  ([ADR-0014](../adr/0014-a-receipt-names-the-witness.md); SPEC.md §1.2a, `witness`, and §6,
  "Reading the witness a receipt names") —

  ```json
  "witnessedBy": {
    "51ef4497ecf27d34c3f56ef0e6efa16c": {
      "origin": "https://witness.example:443",
      "publicKey": "…64 lowercase hexadecimal characters…"
    }
  }
  ```

  an object keyed by trail identity, 32 lowercase hexadecimal characters, each value exactly
  `origin` and `publicKey`. `origin` is where the witness serves its paths, at its root:
  `https://`, a host in lowercase, `:` and an explicit port, nothing after it, or `http://` at a
  loopback address written as one (`127.0.0.0/8` in dotted decimal, or `[::1]`). `publicKey` is the
  witness's key, pinned from the witness's operator as a verifier pins one, held to the key rule
  (SPEC.md §8.4); the receipt names it by its `keyId` and never carries it. An action receipt
  names the witness of its record's trail, read from the record's bytes — with `witnessedBy`
  given, `/act` reads one member, `trail`, of every record it finds, whatever its tool's policy —
  and an acquisition receipt the witness of the trail its request names in `trail`, which is
  refused when no witness is named for it; no request names a witness or a key. The engine
  refuses to start on a trail out of form, an origin out of form, a key the rule refuses, a trail
  given twice, and a witness whose key is the engine's own, compared by the key's bytes: a
  gateway whose key the operator can use is no witness against the operator. A change takes a
  restart; receipts minted before it keep naming what was configured then. It is not `witness`,
  which makes this signer a witness; a gateway may carry both. `gateway serve` without a
  configuration takes the same as `--witnessed-by TRAIL=ORIGIN,PUBLICKEY`, repeatable, for
  version 3 receipts only. `connect` keeps the member, its values unchanged.
- `authority`, `seed`, `store`, `registry` are the four positional arguments `gateway serve`
  takes today, named. `gateway rotate-key --seed <seed> --registry <registry>`, with the
  engine stopped, rotates the key the seed holds (SPEC.md §3b): the next seed takes the
  seed's path, so the configuration is unchanged, and the engine refuses to start under a
  key its registry says it rotated from, or while a rotation under way leaves a next seed or
  a kept record beside the seed, which `rotate-key --resume` finishes; it looks beside the
  seed's configured name, the one `rotate-key --seed` is given, and beside the name it
  resolves to, every link followed, where that is another, so neither hides a rotation. The engine holds a lock
  on its registry while it runs, and `rotate-key` refuses while it is held. A witness under the configuration goes on under the
  next key, its log held to the keys the registry's rotations reached.
- `decisionRecords` is where the runtime's audit trail is expected, so `verify` can resolve an
  action receipt's `decision.recordDigest` ([receipt-v3.md](receipt-v3.md)). The engine refuses
  one that anyone but root, the signer and its owner could write a record into (below).
- `listen` is a literal loopback address with a port — `127.0.0.1:8787` or `[::1]:8787` —
  and the engine refuses any other, a name such as `localhost` included, since a resolver may
  map a name elsewhere. The gateway speaks plain HTTP and a token presented over plain HTTP
  off the machine can be captured and replayed; SECURITY.md lists authenticated transport as
  out of scope, and this design does not change that. Reaching the engine from another host
  means a TLS-terminating front the operator runs and trusts, outside this repository.
  `identity` decides who may call, never from where.
- `catalog` is the directory of binding files (below). `runtime` is the container runtime
  command the adapters use, `docker` by default or `podman`, by name or by path. `adapters` is
  the directory holding the adapter binaries; when absent they are found on the engine's
  `PATH`, once, at start-up. Either way each adapter is held there and launched by the path it
  resolves to (below).
- `identity` names the token issuer, the audience the engine expects to be named as, and a
  local copy of the issuer's public keys. The engine verifies tokens with the standard library
  and never fetches keys over the network on the request path; refreshing the key file is the
  operator's job, and a token signed by a key not in the file is refused. Without this member
  every receipt carries `caller: null` and no action is ever performed, because an action
  requires an authenticated requester. With it, every request that acquires, seals or
  verifies carries `Authorization: Bearer <token>` — a JWT in compact form, signed with a key
  the file holds under the token's `kid` (RSA of 2048 bits or more for RS256, P-256 for
  ES256, Ed25519 for EdDSA; the algorithm is the key's, never the token's word), from
  `issuer`, naming `audience`, within its validity window with thirty seconds' leeway — or is
  refused `401` with one reason and never the token; `/publickey` and `/registry` stay open,
  since a verifier fetches its anchors there and holds no token. A witness's submission carries
  one verified the same way but under `witness.audience`, which the engine's own endpoints refuse
  in turn; its two reads stay open, as `/registry` does. A receipt then carries
  `caller: {issuer, subject, tokenDigest}` (SPEC.md §1.2a). The key file is read once, when
  the engine starts; a key not in it is a key the engine does not know.
- `platforms` maps an operator-chosen name — with `/history` or `/live` appended, the `source`
  a receipt will carry — to a **binding** from the catalog, pinned by digest, to where its
  credentials are — **one file per operation** the binding offers, `history` and `live`, and
  `write` when the platform sets `write: true` and the binding states a write operation, since
  a connector's configuration and a server's environment are different files in different
  forms, and a file for an operation the binding does not offer (or a `write` file for a
  platform that allows no writes), or none for one it does, is refused — and to the OS
  **user** its adapters run as, which must exist, must not be
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
| `<platform>/history` | `adapter-airbyte` | `--image=<history.image> --credentials=<credentials.history.file> --runtime=<runtime> [--endpoint=<endpoint>]` |
| `<platform>/live` | `adapter-mcp` | `--image=<live.server.image> --credentials=<credentials.live.file> --runtime=<runtime> --tools=<live.tools, comma-joined> [--endpoint=<endpoint>] [-- <live.server.args>]` |
| `<platform>/write` | `adapter-mcp` | `--image=<write.server.image> --credentials=<credentials.write.file> --runtime=<runtime> --tools=<write.tools, comma-joined> --error-results [--endpoint=<endpoint>] [-- <write.server.args>]` — derived only for a platform whose configuration sets `write: true`; it is what the executor runs ([executor.md](executor.md)) and never a source `/acquire` may name |

For an operation whose binding names a remote server (below), `live` and `write` are derived
as `--url=<server.url> --credentials=<credentials.<operation>.file> --bearer=<server.bearer>
[--header=<NAME=VALUE>]... --tools=<tools, comma-joined>`, with `--error-results` after the
tools for `write`, and the probe for `live` as above: no runtime, no `--endpoint` — the URL is
the endpoint the receipt names, and for a write the action receipt's `action.tool.endpoint`
([ADR-0015](../adr/0015-a-remote-mcp-server-as-a-source-and-executor.md)) — and no server
arguments. A URL and tools written as templates are filled with the platform's `parameters`
before the line is built: the adapter is given the resolved URL and the resolved tools, and the
acquisition's `endpoint` and the action receipt's `action.tool.endpoint` are the resolved URL,
never the template.

Every flag and its value are one word, `flag=value`: a value that is `--` on its own would be
the delimiter the adapter splits its line at, and a tool, an endpoint or a runtime can be so
named.


## What the engine refuses

Before anything is written — no store, no registry, before the seed is even loaded — the
engine refuses to start under a configuration the isolation claim of
[ADR-0001](../adr/0001-one-engine-four-processes.md) does not survive:

- a platform without a `user`, or whose user does not exist, is **root** (an adapter running
  as root reads the seed), is the **signer's own** (the same), is the **MCP server's**
  (`engine-mcp`, uid 65533: a credentials file would belong to the user that process runs
  as), or is **another platform's** (one platform could read the other's credentials);
- a credentials file not owned by the platform's user, or readable beyond its owner (mode other
  than `0600`); and any directory on the way to it that is owned by neither root nor that user,
  or writable beyond its owner without the sticky bit (so someone else could replace the file
  under its name), or that the user cannot traverse (the adapter could not open its own
  credentials, judged by the owner bits when the directory is the user's and by the other bits
  when it is root's). The path is walked component by component from the root, the file's own
  name included, and everything the walk meets is held: a symbolic link is allowed only when
  root owns it — a system's own, such as macOS's `/var`, or a mounted secret's — so nobody but
  root could have placed or could retarget it, and the walk then continues through its target's
  components, each held in turn, with a bound of thirty-two hops, which also ends a loop; the
  path with every link resolved is the path the adapter is then given, so the file judged is
  the file it opens. A credentials file mounted as a projected secret, its name a root-owned
  link to `..data/<name>`, is so walked to the file it leads to. The seed's way is held to the
  same, for the signer, a link on it, at its own name included, may be the signer's as well as
  root's, and its path is used resolved, so the file the seed's own checks open is the one the
  walk arrived at;
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
- the **gateway binary itself carrying file capabilities while executable by others**: a
  platform user's process that executed it would take them up and switch to the signer; it must
  be executable by its owner alone (the image gives it mode 0700). Besides, every source that
  runs as a platform's user is started held to the kernel's `no_new_privs`, which it inherits
  and can never clear: an `execve` then grants it no privilege it does not have — no file
  capability, no set-user-id bit — so an adapter cannot regain the signer's capabilities by
  executing the gateway binary, nor anything else. The limit that buys: a source that must
  itself gain privilege on exec, such as a rootless container runtime that needs `newuidmap`,
  cannot run as a switched source; the runtime an adapter uses is one that listens on a socket
  the platform user may reach;
- an **adapter executable another user could replace**, since it runs as a platform's user with
  that platform's credentials: every adapter the sources launch is found as a launch would find
  it — by its path under `adapters`, or else on the engine's `PATH`, once, at start-up, so a
  file put on the `PATH` later is never the one launched — and its way is walked as the seed's
  is, component by component from the root, for the signer: every directory owned by root or
  the signer and writable by nobody else unless the sticky bit keeps others from replacing what
  they do not own, every link owned by root or the signer and followed, each link's directory
  and every ancestor of its target held in turn, with the same bound of thirty-two links. The
  file it arrives at must be there, a regular file, owned by root or the signer, writable by
  nobody else, and a **native executable of this host** as far as Go's own parsers read its
  headers: on Linux, an ELF file of type `ET_EXEC` or `ET_DYN` for the host's machine, class
  and byte order (`debug/elf`), whatever OS ABI its header names, which is not checked; on
  macOS, a Mach-O file of type `MH_EXECUTE` for the host's CPU, or a universal file whose
  architecture table parses and holds such a slice (`debug/macho`). `ET_DYN` is how Go builds a
  position-independent executable, and the type cannot tell one from a shared library, so a
  shared library of the host is not refused by this check. The check is a parse of the headers,
  not proof that the file runs: the bytes after a header that parses, outside what the parser
  reads, are not checked. Refused: a script, which starts with `#!`, since the interpreter it
  names, or the one `#!/usr/bin/env` would find, is not held; a file whose headers do not
  parse, a truncated one or a Java class among them; a file for another CPU, class or byte
  order; an ELF object or core file; a Mach-O object or dylib; and a universal file without an
  executable slice for this host. A dynamically linked executable names the loader the kernel
  hands it to (`PT_INTERP`, or `LC_LOAD_DYLINKER`), and that loader is held as the adapter is;
  the shared libraries the loader then finds are not, so an adapter is best linked statically,
  as the image's are (`CGO_ENABLED=0`). The source then launches that resolved path. The
  image's layout passes: the adapters are binaries built from `adapters/`, root's, mode `0755`,
  in root's `/usr/local/bin`. An install that another user owns, such as a Homebrew prefix or
  another user's `~/go/bin`, is refused even with `0755` files, since that user could replace
  them: install the adapters root's (`sudo install -o root -m 0755 adapter-airbyte adapter-mcp
  /usr/local/libexec/engine/`, naming that directory as `adapters`), or run the signer as the
  user who owns them. What the check is: of owners and modes, at start-up. It holds while the
  files and the directories on their way keep that protection, and only against access opened
  after it was in place: a process that opened an adapter for writing before then, or a later
  change of an owner or a mode, is not seen, and the launch runs whatever is at the resolved
  path, not a descriptor held from start-up. It assumes the adapters were installed, by root or
  the signer, from a source they trust;
- a **host container-runtime socket** present at `/var/run/docker.sock` (or podman's) while
  the runtime, by its command's base name, is `docker` (or `podman`), for an engine with a
  platform: an adapter that can reach it holds host authority, which includes the seed
  ([engine-image.md](engine-image.md)), unless the operator sets `"hostRuntime": "accepted"`,
  with the same one-line statement at startup; an engine with no platform runs no adapter, and
  the socket is not judged;
- for a **witness**: a platform where a witness keeps no files — anywhere but Unix, since each
  of its files is locked by what it is and its names are counted; and marks whose directory is
  on the device of the log's directory, as `stat` reports each: the marks are kept on storage
  apart from the log's, another device or volume, so that a log restored from a backup is
  judged against marks no backup of the log's storage restored. A device apart is not proof of
  storage apart — two devices may share a disk, and one backup may take both — so the check
  refuses only what is plainly one storage, and keeping the marks out of every backup the log
  is restored from stays the operator's. After these, the seed and the identity's keys, the witness's files
  are opened and its start-up checks applied (ADR-0013 §4) before the store or the registry is
  made: a witness they refuse leaves nothing made, and is repaired, given a log copy, or given a
  new key before it starts;
- a **decision-record directory** that anyone but root, the signer and the directory's owner
  (the user the runtime writes as) could write a record into, since a decision policy without
  `requireSignedRecord` holds a write to whatever well-shaped record is found there, and a
  receipt's `decision` without a policy means only that one existed: the directory, and every
  directory and regular file beneath it that the walk for a record reads, must be owned by one
  of those three and writable by nobody else, the sticky bit excusing nothing there, since
  whoever may create a file there may create a record; every directory on the way to it is held
  as a credentials file's are, for those three owners (owned by one of them, writable beyond
  its owner only with the sticky bit, a link only when root owns it); and a directory not there
  yet is held through the directory it would be made in, which must be writable by its owner
  alone, sticky or not, since whoever makes it first owns it, and must not be a link. A link at
  the path itself must be owned by root, as a link on the way must; the walk never follows it,
  though the start-up check that a directory is there does, and whoever may write the directory
  the link is in could put a directory of records in its place, so that directory is held as
  for a directory not there yet. Links and special files beneath are passed over, as the walk
  passes over them. The refusal names the path, its owner or mode, and why; there is no
  `"accepted"` for it: make the directory and what is in it writable by its owner alone (`chmod
  -R go-w`);
- the seed file's own checks, as for any `serve`: a regular file, owned by the signer, readable
  by nobody else.

What these checks establish, and no more: every adapter runs as a user that is neither root nor
the signer nor another platform's; as the owners and modes stood when the engine started, no
credentials file, and no directory on the way to one, could be read or replaced by anyone but
its owner and root; nobody but root, the signer and the decision-record directory's owner could
write a file into or beneath that directory, or replace a directory on the way to it; and
nobody but root and the signer could replace the seed or an adapter the engine launches. Those
hold while the files and directories keep that protection, and only against access opened after
it was in place: a descriptor opened for writing before then, or an owner or a mode changed
later, is not seen, and each assumes its files were put there, by their owners, from a source
they trust. The signer holds no capability that reads past permissions and none an adapter
could take up. **A signer that holds `CAP_SETUID` can assume any user**, and so can read any
credentials file by becoming its owner: what this configuration holds is the signer *as
written* — it reads no credential — not a signer that has been compromised. Holding a
compromised signer out of credentials takes a privileged launcher separate from an unprivileged
signer, which is the engine image's job and not this file's. What the checks do not see is
stated with them: an access-control list that grants a read the mode bits do not show; a
runtime reachable through a socket at another path; a platform user that is also in a group the
signer's files admit; a decision record written, or a mode changed, after the engine started,
and a mount that shows the decision-record directory elsewhere. The engine holds the
configuration to what the filesystem and the kernel report, and no further.

## What the engine reports: `/posture`

`GET /posture` answers what `gateway posture --json` prints, for the engine as it runs: which of
the isolation protections in [SECURITY.md](../../SECURITY.md) this host enforces, judged against
the seed and the sources the engine started with. It is the field a desk reads to show its
managed gateway's posture beside the gateway's status. The answer is canonical JSON (SPEC.md
§1.1), so two answers compare byte for byte:

```json
{"platform":"linux","protections":[{"name":"source-user-switch","reason":"every source runs as a user of its own that is not the signer's, and this process can switch to each","state":"enforced"},{"name":"descendant-reaping","reason":"…","state":"enforced"},{"name":"container-custody","reason":"…","state":"enforced"},{"name":"seed-file-protection","reason":"…","state":"enforced"},{"name":"operator-program-confinement","reason":"…","state":"not-enforced"}]}
```

- `platform` is the operating system as Go names it: `linux`, `darwin`, `windows`.
- `protections` holds the five protections, always in this order, each with exactly `name`,
  `state` — `enforced`, `partial`, `not-enforced` or `not-applicable` — and `reason`, one sentence for a
  reader, which a consumer shows and never parses. A reason `/posture` answers names no path and
  no account; the command, run by the operator, may. `not-applicable` is a protection with nothing
  to hold here: no source, no seed, an image this platform does not run.
- `source-user-switch`: every source names a user, none is root, and this process passes the
  check `serve` makes at start, that it can switch to each; `not-applicable` with no source.
- `descendant-reaping`: on Linux, a probe: a child started as a source is, in an anchor-led
  process group, starts a grandchild; the group is killed, and both must be gone — the pipe they
  held closed — within three seconds. The first probe that reaches a verdict is kept for the life
  of the process, so a restart probes again, and its reason ends `checked at` the time it ran, in
  UTC; a call made while a probe runs waits for it, so concurrent calls start one probe between
  them, and a probe that could not run (a fork refused, a start not seen within the wait) is not
  kept: the next call probes again. Where the gateway is PID 1, the probe waits for its own
  grandchild, which is reparented to it ([engine-image.md](engine-image.md), "The processes"). The probe
  runs as the gateway's own user; killing a switched source's group crosses users, which takes
  `CAP_KILL`, and `serve` refuses to start a switched source without it. Elsewhere the line is
  stated, not checked, as `not-enforced`: Windows has no process group, and on macOS and the BSDs
  `adapter-mcp` does not reach the descendants a command server left outside the group, which it
  adopts and kills on Linux.
- `container-custody`: on Linux, the engine image's markers ([engine-image.md](engine-image.md)):
  the running binary is `/usr/local/bin/gateway`, the signer's own at mode `0700` and carrying
  file capabilities, run by a user that is not root with `CAP_SETUID`, `CAP_SETGID` and
  `CAP_KILL` in effect and nothing more — no capability that reads past permissions, nothing
  ambient or inheritable, as `serve --config` holds a signer — beside
  `/usr/share/engine/catalog` and `/usr/share/engine/corpus`, directories of root's that nobody
  else may write. Elsewhere `not-applicable`.
- `seed-file-protection`: on Unix, the seed as `serve` judges it at start, read through a link
  as `serve` opens it — a regular file owned by the signer, readable by nobody else by its mode
  bits; an access-control list is not seen.
  On Windows it is stated as `not-enforced`.
- `operator-program-confinement`: `not-enforced` without a selected wrapper or a
  completed successful boundary check. With version 13 sources it aggregates the
  per-program entries below: `enforced` only when every entry is enforced, otherwise
  `partial` when any entry is enforced or partial.

The seed and the sources are judged at each request, so a mode changed after the start shows;
the descendant probe's verdict is kept for the process. Source sandbox probes are
cached per resolved source after the first completed check; restart the engine to
measure changed policy or backend availability. A failed helper launch is retried
on a later report. As `/verify` does, `/posture` takes a bearer token where `identity` is
configured, and is open where it is not, as on a desk's local gateway. Nothing the engine does
depends on the report.

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
      "probe": { "tool": "query", "failure": "Error:" },
      "licence": "MIT"
    }
  }
}
```

One binding per platform; one entry per operation it supports — `history`, `live`, `write`, at
least one of them, and `write` alone for a platform whose reads are a connection's —
each naming its shape, the pinned artifact that serves it, the tools it may call, and the
licence of the artifact it pulls. An `mcp` entry's `server.args`, when present, are the
server's own arguments inside its container — the mode a server runs in, say — each one word
as written: the engine builds the adapter's command line and splits nothing, and the adapter
hands them to the runtime after the image. An `mcp` entry's `server` may instead name a remote
server reached over Streamable HTTP
([ADR-0015](../adr/0015-a-remote-mcp-server-as-a-source-and-executor.md)):
`{"url": "https://…", "bearer": "MEMBER", "headers": ["NAME=VALUE", …]}`, exactly those, `headers`
optional and the other two required. `url` is held to the endpoint form `SPEC.md` §1.2a gives a
remote server — `https`, or `http` at a loopback address written as one; no user, query or
fragment — since the receipt will carry it; `bearer` is the member of the operation's
credentials file sent as `Authorization: Bearer`, so the platform names a credentials file for
that operation as for any other; and each header is a name and a value the adapter would accept
as a fixed header — a credential's, the protocol's, and the ones the client and the transport
write are refused here, before the engine starts. A remote server has no image to pin: what the receipt names it by is its URL and the TLS
identity its answer came under, and the binding's digest pins the URL.

A remote server's `url`, and each of its operation's `tools`, may be a **template**: `{name}`
stands where a tenant's part goes — an Azure DevOps organization, a Databricks workspace, a Unity
Catalog function — and the platform's `parameters` give each name its value
([ADR-0015](../adr/0015-a-remote-mcp-server-as-a-source-and-executor.md), question 1, amended
2026-10-13). A placeholder's name is a parameter's (`[a-z][a-z0-9-]*`); a `{` that opens none, or
a `}` that closes none, is refused. The template's scheme is written as it is, `https://` or
`http://`, so no value can change it; its host is written as it is, or is `{workspace}` alone
over `https`, a Databricks workspace's host held to the forms above — a placeholder anywhere
else in the host or beside it, in place of a port or a label, could change where the credential
goes, and is refused; and the template, every placeholder taken as a one-letter value, must be of
the endpoint form, so a query, a fragment, a user or plain `http` off loopback in its written
text is refused before any parameter is read. The resolved URL is held to the endpoint form
again, its 2048 characters included. The binding's digest pins the template and the transport;
the platform's configuration says which tenant. The two write-back bindings are written so
([the catalog](../../catalog/README.md)):

```json
"server": { "url": "https://mcp.dev.azure.com/{organization}", "bearer": "token" }
"server": { "url": "https://{workspace}/api/2.0/mcp/functions/{catalog}/{schema}/{function}", "bearer": "token" },
"tools": ["{catalog}__{schema}__{function}"]
``` The engine passes no
`--ca-file`, so a remote server's certificate chains to the system's roots. Its `probe`, when present, is `{"tool", "failure"?}`: `tool` is one of its `tools`
that a check calls once with no arguments — a server that starts and lists its tools without a
working connection to its platform answers the handshake all the same, and the probe is what
establishes the connection — and `failure`, when present, is the text such an answer begins
with for a server that catches its own failure and answers it as ordinary text, `isError`
false; the result is discarded either way. A restriction of streams for the history operation is not yet
applied at acquisition, so a binding may not declare one: a restriction accepted and not
applied would read as applied. `history` is served by the `airbyte` shape and `live`
and `write` by the `mcp` shape; the `http` shape is served by `adapter-http` as a standalone
`--source` ([adapters/README.md](../../adapters/README.md)) and not yet by any binding operation,
so a binding naming it is refused. The file is `catalog/<platform>.json`, it must name that platform, and
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
  [--endpoint HOST] [--environment KEY=VALUE]... [--parameter NAME=VALUE]... [--write] [--replace] \
  [--no-descriptors]
gateway connect --config engine.json --preview-descriptors service-desk
```

writes the platform entry — the binding pinned by the digest of the catalog file as it is
now, a credentials path per operation as written (`--credentials-file history=… live=…`,
exactly the operations the binding offers), the user, the parameters a binding's templates take
(`--parameter`, a version-8 member; on `--replace` with none given, the entry's own are kept, as
its decision policy is), and what else was given; the platform may stand anywhere among the flags
— and it writes nothing until two things have held. The binding judged and checked is the one the
parameters resolve, and a placeholder none gives, or a parameter no placeholder names, is
refused before anything runs. First, the configuration as it would be, with the entry
in place, passes every refusal `serve` applies (the platforms it already names included, so a
pin the catalog no longer digests to is found here and not at the next start): the user is
neither root nor the signer nor another platform's, the credentials file is that user's alone
under directories nobody else can replace it in, and so on through the list above — and
what `serve` judges before it starts holds too: the store, registry and decision-record
paths are what it could make or write (a link to nothing in the place of one is not
absence, and a registry or decision-record path spelled so that the platform could resolve
it otherwise is refused, as SPEC.md §4.1 has it), and every platform's user, the existing ones included, is one this process can
switch to, and the identity's key file, when one is configured, reads as a key set. Second, each of the platform's derived sources is run once in check mode, as the platform's user, in
the environment `serve` would give it: `adapter-airbyte --check` runs the connector's own
`check` with the credentials; `adapter-mcp --check` starts the server, completes the handshake
and lists its tools, failing when a tool the binding names is not offered, and calls the
binding's `probe` once when a live operation names one; a write operation accepts no probe,
and its check calls no tool. What each answered
is printed, one line per operation, a remote server's line naming the URL it was given as the
parameters resolved it — and the endpoint the adapter reports must be that URL, or the connect
ends and nothing it captured is kept; the first that cannot answer ends the connect with the
adapter's reason. Nothing is acquired and no receipt is minted. An image the runtime does not
hold yet is pulled during the check, which is why a check is given five minutes. An
acquisition has less: the adapter gives its work twenty seconds, its default, since the engine
gives it no other, and the gateway cancels the source thirty seconds after it began to start
it ([engine-image.md](engine-image.md) has the two clocks).

The live operation's check, and no other — or, for a binding with no live operation, such as the
two write-back bindings, the write operation's check, at the resolved URL — also captures the
allowed tools' descriptions and input schemas and the server's identity
([tool-descriptors.md](tool-descriptors.md)), unless
`--no-descriptors` is given, for a deployment whose descriptors are confidential beyond what
screening finds. `connect` reads the capture strictly from the report and says, for each allowed
tool, what was captured or why it fell back. A capture holding a tool is kept as an immutable
snapshot in `<file>.descriptors/`, named by its digest, before any configuration names it, and
the entry pins it. A remote server's snapshot names the endpoint it was captured at, and is
served only while the platform's operation resolves to that endpoint: a changed parameter
needs a new capture ([tool-descriptors.md](tool-descriptors.md)). A capture of no tool pins
nothing, and `--replace` without a pin removes the member. With `--replace`, `connect` compares the capture with the snapshot the entry pinned
before, once that verifies against its pin. It then says which processes must restart: the MCP
server alone when only the descriptors' pin changed, and both when anything the signer reads
changed. `--preview-descriptors <platform>` writes nothing: it renders what the MCP server would
serve for the platform's tools, from the snapshot the platform pins, read and verified as the
server reads it, with every character outside printable ASCII escaped. For a platform with no
live operation the MCP server lists no tool — it calls `/acquire` alone, and a write is made
through `/act` — and the preview renders what was captured of the write tools, saying so; the
server still reads and verifies the pinned snapshot at its start.

It refuses a binding that is not in the catalog, a platform already configured unless
`--replace` is given — and with it the entry replaced is not resolved, since its pin may be
what is being repaired, while every other platform is — a configuration path that is a symbolic
link, and a configuration that with the entry would exceed the size `serve` reads, judged
before any check runs. The file's directory is held open from the first read to the rename, so
what is read, written beside it and put in place is in that directory whatever a path component
is swapped for meanwhile; one connect at a time holds `<file>.lock` beside it, and a second
refuses rather than waits — a lock already there is trusted only as a regular file owned by
root, the connect's user or the configuration's owner, since in a sticky directory another
user's file can be unlinked by that user and replaced; the file is put in place only if, read again just before the rename, it
still holds what the checks were run against — which holds against another connect, since
one takes the lock, while an editor that does not is not held out, and its save in the
instant between that read and the rename would be written over; the new file is written in
a directory of the connect's own beside the configuration, so no other user can swap it
before the rename, and it keeps the old one's mode and owner, set through the open
descriptor, or is not put in place; and the seed, the store, the registry and the decision-record directory are judged as
`serve` judges them before any adapter is run — the seed a seed, the store a directory or
absent with a directory to make it in, the registry a regular file or absent likewise — so a
connect does not succeed where the next start would refuse. The file is rewritten whole, in the engine's own form —
members in canonical order, indented — and put in place by a rename, so a reader sees the old
file or the new and never a partial one. Every value written is valid UTF-8, since the file
is JSON; a path that is not is refused rather than written as something else. A configuration
with an empty `platforms` object is what the file looks like before its first `connect`; it
parses, and `serve` refuses to start on it, unless the file carries a `witness`.

## The write-back platforms

Two catalog bindings name a vendor's remote MCP server for their `write` operation alone (issue
#248; [the catalog](../../catalog/README.md)): `azure-devops`, an organization's remote Azure
DevOps MCP server, and `databricks`, the managed MCP server of one Unity Catalog function. Their
reads are the connections' ([connection-catalog.md](connection-catalog.md)), so neither binding
has a `history` or a `live` operation. The platform sets `write: true`, names one credentials file,
`write`, holding `{"token": "…"}` — a Microsoft Entra access token, or a Databricks token, of a
person or a principal the operator holds for writes; the engine mints and renews none — and gives
the parameters its binding's template takes. Each write tool is held to a decision policy, and a
policy is written for each tool the platform is meant to write with: a tool held to none is held
to nothing ([executor.md](executor.md)).

**Azure DevOps.**

```json
"boards": {
  "binding": "azure-devops@sha256:…",
  "credentials": { "write": { "file": "/run/secrets/boards-write" } },
  "user": "engine-boards",
  "write": true,
  "parameters": { "organization": "example-org" },
  "decisionPolicy": {
    "wit_work_item_write": {
      "outcomes": ["approve"],
      "packs": ["sha256:…"],
      "reviewed": true,
      "requireSignedRecord": ["…64 lowercase hex…"],
      "fix": [
        { "argument": "/action", "value": "update" },
        { "argument": "/updates/0/op", "value": "test" },
        { "argument": "/updates/0/path", "value": "/rev" },
        { "argument": "/updates/1",
          "value": { "op": "replace", "path": "/fields/System.State", "value": "Approved" } }
      ],
      "shape": [
        { "pointer": "/updates", "type": "array", "maxLength": 2 }
      ],
      "bind": [
        { "argument": "/id", "fact": "/workItem/id" },
        { "argument": "/updates/0/value", "fact": "/workItem/rev" }
      ],
      "closed": true
    }
  }
}
```

The server's write tools are grouped dispatchers whose `action` argument chooses the operation:
`wit_work_item_write` updates a work item's fields and state (`action` `update`, the work item's
`id`, and `updates`, JSON Patch operations, a `test` of `/rev` first so that Azure DevOps refuses
the update once the revision has changed), and also creates items, updates several at once
(`update_batch`, whose `batchUpdates` name their own items) and adds children;
`wit_work_item_comment_write` adds or updates a comment; `wit_work_item_link_write` links and
unlinks items. `bind` alone fixes no value of its own and refuses no member it does not name, so a
policy that binds the work item's id and its revision alone leaves the `action` to the request —
`update_batch` writes the items its `batchUpdates` name, whatever `id` says — and lets a request
add an operation that changes another field. The policy above, in a version-10 file, holds the
tool to one write ([ADR-0016](../adr/0016-a-policy-fixes-a-value-and-closes-the-argument-set.md),
[ADR-0018](../adr/0018-a-policy-holds-a-containers-shape.md)): `fix` holds `action` to `update`,
the first operation to a `test` of `/rev`, and the second to the operation that sets the state the
outcome maps to; `shape` holds `updates` to an array of at most two elements, and so, with the
second fixed, of exactly two; `bind` holds the work item's `id` and the tested revision to the item
the pack judged, `workItem` in its facts (`{"id": 42, "rev": 3, …}`); and `closed` refuses every
other member and element. For that record it admits one request, up to the order of an object's
members and the spelling of its JSON:

```json
{"action": "update", "id": 42,
 "updates": [{"op": "test", "path": "/rev", "value": 3},
             {"op": "replace", "path": "/fields/System.State", "value": "Approved"}]}
```

A request that names another action, adds an operation (`/updates/2`), adds a member
(`batchUpdates`, `project`, or `from` inside an operation), leaves the test out or names another
item or revision is refused at `policy-bind`, and nothing is sent. So is an object whose members
are named `"0"` and `"1"` in place of the `updates` array: RFC 6901 reads a numeric token on an
object as a member's name, so `fix`, `bind` and `closed` alone read that object as the array's
elements, and it is the `shape` of `/updates` that refuses it. `/updates/0` needs no entry of its
own, since `op`, `path` and `value` resolve only in an object, and the arguments are an object by
the executor's rule. Without the `shape` entry the policy is ADR-0016's, which a version-9 file can
hold: it admits the object as it admits the array, and what the server makes of it is the
server's. The record states
the item it judged and no write; the state the outcome maps to is the operator's, fixed in the policy beside
the outcomes it allows. A policy fixes one value for every outcome it allows, and a platform holds
each tool to one policy, so a write of another state for another outcome is held by a policy of
its own on another platform entry. A policy for the comment and link tools is written the same
way, every argument fixed or bound, and every container its pointers continue through only by an
index shaped. Binding the whole arguments, the empty pointer, to a fact in
which the record states the whole write is still valid, and is what a closed policy with that one
binding is; it puts the write in the pack.

**Databricks.**

```json
"ledger": {
  "binding": "databricks@sha256:…",
  "credentials": { "write": { "file": "/run/secrets/ledger-write" } },
  "user": "engine-ledger",
  "write": true,
  "parameters": {
    "workspace": "dbc-example.cloud.databricks.com",
    "catalog": "main", "schema": "decisions", "function": "record_approval"
  },
  "decisionPolicy": {
    "main__decisions__record_approval": {
      "outcomes": ["approve"],
      "packs": ["sha256:…"],
      "reviewed": true,
      "requireSignedRecord": ["…64 lowercase hex…"],
      "bind": [
        { "argument": "/case_id", "fact": "/case/id" },
        { "argument": "/revision", "fact": "/case/revision" }
      ]
    }
  }
}
```

A write is a Unity Catalog function the workspace's owners wrote, called through its managed MCP
server at `https://<workspace>/api/2.0/mcp/functions/<catalog>/<schema>/<function>`, which offers
the function as one tool, `<catalog>__<schema>__<function>`, whose arguments are the function's
named parameters. Each parameter is bound to a fact, so the write is the decision's: here
`record_approval(case_id, revision)` records that the case was approved at that revision, and the
outcome is in the function's name and in the policy's `outcomes`. Bind every parameter the
function declares, one with a default included: a parameter left unbound is the requester's to
fill. The tool's name and its parameters are the function's, so `connect`'s capture of the
server's descriptors shows the operator the input schema the policy's pointers must match.

**Raw SQL is no write tool.** The catalog names neither the Databricks SQL server nor any tool
that takes a statement: a decision could then authorize an arbitrary statement, and no policy can
bind a statement argument by argument, since its meaning is in its text. A function whose body
runs a statement it is given is raw SQL by another name, and the function's author is the one to
refuse it. The `postgres` binding holds to it: its server's only write tool, `execute_sql`, takes
a statement, so the binding has no `write` operation (2026-10-14, #260). A platform that sets
`write: true` while its binding has no `write` operation is refused at start, naming the platform
and the rule; the flag is never silently ignored.

## What the file is not

- **Not a selection of packs.** It says which systems may be reached, never what a pack means or
  which pack decides what. Selection stays the application's. A `decisionPolicy` says what a
  record must state before a write relies on it, not which pack is to be asked.
- **Not an authorization.** `write: true` says an executor may be pointed at the platform; a
  write still happens only on an authenticated request that cites a decision record and receipts
  the engine finds where it looks ([executor.md](executor.md)), and, for a tool held to a
  `decisionPolicy`, whose record meets it. That a person approved the write is not established
  by anything here: the receipt says who asked.
- **Not portable across engines.** It names local paths and local secrets; the receipts are
  what travel.

## Current owner taxonomy contract

[ADR0021](../adr/0021-owner-taxonomy-binds-current-tool-approval.md) specifies current
bindingVersion2, per-operation snapshotV2/engine11 approval, and opt-in CatalogV5.
Historical readers do not admit unclassified current tools. Metadata grants no authority;
existing acquisition, sealing and action checks remain required.

## Customer MCP bindings

A catalog binding may opt into customer registration with `"customer": true` on
`bindingVersion: "2"`. It offers MCP `live` and optionally `write` operations, each
with an explicit allowed tool set and owner operation/effect declarations. Missing
owner declarations refuse registration. Probes and history operations are refused.
Existing pinned-image and remote-URL server shapes apply. A customer server may
instead use `{"command":["executable","argument"],"workspace":"/srv/source"}`;
`command` is an argument array, never shell text, and `workspace` is an absolute
existing directory below the filesystem root. An optional absolute `sandboxPolicy`
path names the separate operator policy file. No credential belongs in this array.
The binding digest covers the complete server configuration and owner declarations.

Registration uses `adapter-mcp --check --customer-binding` with the existing
`--descriptors-binding`, platform and operation selectors. It captures snapshot
version 3, which adds a complete descriptor digest for every allowed tool.
`connect` stores the snapshot and owner declaration using the existing immutable
approval path; subsequent acquisition refuses a version downgrade or descriptor
drift before `tools/call`. A customer binding is not an exemption from per-platform
OS users, credential separation, write approval or source shape `mcp`.

Local commands use `workspace-write` by default. The optional policy file has
`policyVersion: "1"`, a `defaultMode`, and a `sources` object whose exact
`platform/operation` keys override that default. Supported mode names are
`read-only`, `workspace-write`, and the explicit `danger-full-access`.
The policy must resolve outside the source workspace; its directory and ancestors
must remain operator controlled. `sandbox/escalate` from a server receives the
named refusal `sandbox-escalation-refused`. Backend and enforcement limitations
are documented in [the adapter reference](../../adapters/README.md#customer-bindings).


## Source sandbox policy (engine version 13)

Version 13 launches every source adapter through `adapter-sandbox`, under the
source's configured operating-system user and declared environment. The helper
belongs to the adapters module; the core continues to import only the standard
library. Older configuration versions retain their existing launch behavior and
posture identifies sources without this wrapper as not enforced.
The helper has the same ownership, ancestor, native-executable and loader checks
as the adapter, and both execution and probing use its retained resolved path.

An optional top-level `sandbox` object has `policy` (an absolute operator policy
file path) and `workspaces` (exact source identities mapped to absolute existing
directories). Omitted settings select workspace-write and a fresh private source
workspace for each invocation. A customer command retains its binding's workspace.
A configured workspace or policy that contradicts that binding is refused, and
unknown workspace selectors are refused. The policy must remain outside every
writable source workspace. Full filesystem access always requires an explicit
policy setting.

Customer commands receive `--sandbox-enclosing` before their command delimiter.
This explicit operator assertion skips only redundant native setup inside the
already-confined adapter. Wrapper and adapter receive one effective policy,
source identity and workspace. The adapter keeps all customer approval gates and
reports the assertion as `enclosing-operator` / `not-enforced`; it does not turn
the flag into proof. Its child inherits the wrapper's restrictions and private
temporary environment, which credential variables cannot replace.

Policy version 1 remains readable. Policy version 2 records `default` settings
and whole-setting overrides in `sources`. Each setting records `mode`, `approval`
(`always` or `policy`) and a sorted, duplicate-free `operations` array. `ask` is
always present. `adapter-sandbox preset review|work|full` writes the canonical
expanded policy, with no persisted preset selector:

| Preset | Filesystem mode | Host approval setting | Operation families |
| --- | --- | --- | --- |
| review | read-only | always | ask, check, discover, read |
| work | workspace-write | policy | act, ask, check, discover, propose, read |
| full | danger-full-access | policy | act, ask, check, discover, propose, read |

The active preset is derived from the expanded settings; differing settings are
`custom`. Legacy policies carry no approval or operation-family claim. The gateway
implements the filesystem half; a host consumes the expanded approval and family
settings through its existing policy gate. Neither a preset nor filesystem full
access removes gateway write authorization, receipt checks or effect approvals.

The native probe executes a fixed child as the source user and verifies inside and
outside writes against the selected mode. It invokes no customer program. Its
report concerns filesystem writes at probe time; reads, network access, container
daemon authority and process-lifecycle guarantees remain separately stated.

When sources are configured, canonical posture also contains `programs`, ordered
by source then by the fixed classes `adapter`, `customer-command` or
`container-helper` as applicable. Each entry contains exactly `source`, `class`,
`mode`, `backend`, `state`, `reason`, `preset`, `approval` and `operations`.
Legacy/unavailable selections use mode `unconfigured`, backend `none`, state
`not-enforced`, preset `custom`, approval `""` and operations `[]`. A completed
probe reports its actual selection; policy version 1 has empty approval/families.
No-source posture keeps the original five-line shape without `programs`.
Container-helper entries concern the local runtime client, and are partial even
when its backend enforces all filesystem writes: the external daemon is not
confined by that client boundary. A completed probe is cached for the resolved
source until restart; this is probe-time evidence, not a live per-call assertion.
