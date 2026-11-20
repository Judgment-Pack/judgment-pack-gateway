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
`runtime`, `adapters`, `rootSigner`, `hostRuntime`, `identity`, `mcp`, `witness`, `witnessedBy`, `sandbox`, `delegation`, `sealOpenAtStart`, `acceptOtherHostsOverPlainHTTP`, `measureSandboxAtStart` and `storage` are optional (with `storage`, `store` and `registry` are not given: "The storage kind (engine version 24)", below); within a
platform, `binding`, `credentials` and `user` are required, `endpoint`, `environment`, `write`,
`descriptors`, `operationDescriptors`, `descriptorStatements`, `decisionPolicy`,
`parameters`, `grant`, `writeRequesters`, `scope` and `artifact` optional; each operation's `credentials`
entry is `{"file": …}`, and a live one's may carry `tokenStep` beside `file`. Every path is
absolute.

- `engineVersion` moves on any member change, as `receiptVersion` does. The engine reads
  `"1"` to `"35"`: version 2 added `mcp`, version 3 a platform's `descriptors`, version 4 a
  platform's `decisionPolicy`, version 5 a decision policy's `requireSignedRecord`, version
  6 `witness`, version 7 `witnessedBy`, version 8 a platform's `parameters`, version 9 a
  decision policy's `fix` and `closed`, version 10 a decision policy's `shape`, version 11
  `operationDescriptors`, version 12 `descriptorStatements`, version 13 `sandbox`, version
  14 a required `actionKey`, version 15 `delegation`, version 16 a platform's `grant`,
  version 17 `sealOpenAtStart`, version 18 a platform's `writeRequesters`, version 19
  `acceptOtherHostsOverPlainHTTP`, without which `listen` is a loopback address ("Listening off
  loopback (engine version 19)", below), version 20 a platform's `scope` ("A platform's
  scope (engine version 20)", below), version 21 a live operation's
  `credentials.live.tokenStep` ("A live operation's token step (engine version 21)", below), and
  version 22 a platform's `artifact` ("A platform that keeps no payload (engine version 22)",
  below), version 23 `measureSandboxAtStart` ("Measuring the sandbox at the start (engine
  version 23)", below), version 24 `storage` ("The storage kind (engine version 24)",
  below), version 25 `storage`'s `startWaitSeconds` ("A start that waits for the start lease
  (engine version 25)", below), version 26 `storage`'s `instances` ("Several instances on one
  database (engine version 26)", below), version 27 `identity`'s `callerScopes` ("Caller
  scope identifiers (engine version 27)", below), version 28 `mcp`'s `scope` and
  `scopeFrom` ("The MCP server on scoped platforms (engine version 28)", below), version 29
  the `gcp-asset` shape ("A read-only Cloud Asset Inventory source (engine version 29)",
  below), version 30 a gcp-asset source's `groups` ("Grants through groups on a gcp-asset
  source (engine version 30)", below), version 31 a path template among an http live
  operation's `paths` ("Path templates and links on an http source (engine version 31)",
  below), version 32 a token step's `federatedToken` ("A federated token from the
  platform's metadata server", below), version 33 a token step's `signedBy` and `subject`
  and an http path's `{numericId}` and `{alnumId}` ("A token step with a delegated subject
  (engine version 33)", below), version 34 a token step's `assertionAlgorithm` ("A live
  operation's token step (engine version 21)", below), and version 35 `receiptSink` ("A
  receipt sink (engine version 35)", below). A
  file of an earlier version still loads without the member and is refused by name with it.
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

  For a tool whose binding's `actionRecovery` names an `idempotencyArgument`, the gateway sets
  that top-level argument to the request's `actionKey` before the policy is checked
  ([action reconciliation](action-reconciliation.md)), and `closed` reaches it as the gateway's:
  that one member, while it holds the key, and nothing else by it. A request that sends the
  argument with another value is refused at `action-key` before the policy is read, as before; a
  request with no `actionKey` is given no such member, so one it sends is the caller's and
  `closed` refuses it as any other. A policy of that tool neither binds, fixes nor shapes the
  argument, or a value under it: the gateway's value is the key, so a fixed value would admit
  one key, a shape none, and a binding only a record that states the key. Such a policy is
  refused when the configuration is read, by `serve`, `connect` and `posture` alike, naming the
  entry —
  `platform tickets: decisionPolicy.update_ticket: bind[1] names "/requestId", the tool's idempotency argument "requestId", which the gateway sets to the action key (actionRecovery); a policy neither binds, fixes nor shapes it, nor a value under it`.
  The empty pointer, which covers the whole arguments, is not refused: a policy that binds or
  fixes it holds the gateway's member with the rest.

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
  may not name port `0` — by its number, whatever its spelling — nor an address that is not
  loopback, since the MCP server finds the signer by that value and nothing else, and fronts a
  signer on loopback. From version 28, `scope` (a scope identifier) fixes the server to that
  identifier's platforms, or `scopeFrom` (the string `"caller"`) serves each caller the
  platforms of the scope identifiers its token reaches ("The MCP server on scoped platforms
  (engine version 28)", below); one or neither. The signer reads the member and does nothing with it; the MCP server reads the whole
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
  second engine with a seed of its own. A witness's signer listens on a loopback address: beside
  `witness`, a `listen` that is not loopback is refused, whatever else the file gives ("Listening
  off loopback (engine version 19)", below). `connect` keeps the member, its values unchanged.
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
  on its registry while it runs, and `rotate-key` refuses while it is held; so does a second
  engine on the same registry, which is why a roll-out stops the old engine before it starts
  the new ([README.md](../../README.md), "One gateway per store and registry"). A witness under the configuration goes on under the
  next key, its log held to the keys the registry's rotations reached.
- `decisionRecords` is where the runtime's audit trail is expected, so `verify` can resolve an
  action receipt's `decision.recordDigest` ([receipt-v3.md](receipt-v3.md)). The engine refuses
  one that anyone but root, the signer and its owner could write a record into (below).
- `listen` is a literal loopback address with a port — `127.0.0.1:8787` or `[::1]:8787` —
  and the engine refuses any other, a name such as `localhost` included, since a resolver may
  map a name elsewhere, unless the file is of version 19 and has an `identity` and
  `acceptOtherHostsOverPlainHTTP: true`, and neither `witness` nor `mcp` ("Listening off
  loopback (engine version 19)", below). The gateway speaks plain HTTP wherever it listens, and
  a token presented over plain HTTP off the machine can be captured and replayed; SECURITY.md
  lists authenticated transport as out of scope, and this design does not change that.
  Reaching the engine from another host safely means a TLS-terminating front the operator runs
  and trusts, outside this repository. `identity` decides who may call, never from where.
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
  the engine starts; a key not in it is a key the engine does not know. From version 27,
  `identity.callerScopes` grants each subject the scope identifiers its token may name; a
  caller is held to them at every version ("Caller scope identifiers (engine version 27)",
  below).
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
| `<platform>/live` of an `http` binding | `adapter-http` | `--endpoint=<live.endpoint> --paths=<live.paths, comma-joined> --methods=<live.methods, comma-joined> --credentials=<credentials.live.file> (--bearer=<live.bearer> \| --credential-header=<live.credentialHeader> \| --token-endpoint=<tokenStep.endpoint> --client-id=<tokenStep.clientId> (--assertion-key=<tokenStep.privateKey> [--assertion-alg=<tokenStep.assertionAlgorithm>] \| --federated-token-file=<tokenStep.federatedTokenFile> --federated-token-dir=<its directory, resolved at start> \| --federated-token-metadata-audience=<tokenStep.federatedToken.audience>) [--assertion-x5t=<tokenStep.x5t> \| --assertion-x5t-s256=<tokenStep.x5t#S256>] [--token-scope=<tokenStep.requestScope>]) [--header=<NAME=VALUE>]...` — no runtime, no tools and no platform endpoint ([below](#an-http-api-as-a-platforms-live-operation)); the token step's flags in place of `--bearer` when `credentials.live` carries one ([below](#a-live-operations-token-step-engine-version-21)) |

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

`GET /posture` answers what `gateway posture --json` prints, for the engine as it runs, with one
line more where the gateway signs through a key service: `signing-key-custody` (below), which the
command cannot give, since it calls no key service. It says which of
the isolation protections in [SECURITY.md](../../SECURITY.md) this host enforces, judged against
the seed and the sources the engine started with and the listener it serves on. It is the field
a desk reads to show its managed gateway's posture beside the gateway's status. The answer is
canonical JSON (SPEC.md §1.1), so two answers compare byte for byte:

```json
{"platform":"linux","protections":[{"name":"source-user-switch","reason":"every source runs as a user of its own that is not the signer's, and this process can switch to each","state":"enforced"},{"name":"descendant-reaping","reason":"…","state":"enforced"},{"name":"container-custody","reason":"…","state":"enforced"},{"name":"seed-file-protection","reason":"…","state":"enforced"},{"name":"operator-program-confinement","reason":"…","state":"not-enforced"},{"name":"listener-reach","reason":"the gateway listens on a loopback address, which other hosts cannot reach","state":"enforced"}]}
```

- `platform` is the operating system as Go names it: `linux`, `darwin`, `windows`.
- `protections` holds the six protections, always in this order, each with exactly `name`,
  `state` — `enforced`, `partial`, `not-enforced` or `not-applicable` — and `reason`, one sentence for a
  reader, which a consumer shows and never parses. A reason `/posture` answers names no path, no
  account and no address; the command, run by the operator, may name a path or an account.
  `not-applicable` is a protection with nothing to hold here: no source, no seed, an image this
  platform does not run, no configuration naming a listener.
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
  else may write. Where the binary is not the signer's own at `0700`, `/posture` says so
  without the uids and the mode, which `gateway posture` names. Elsewhere `not-applicable`.
- `seed-file-protection`: on Unix, the seed as `serve` judges it at start, read through a link
  as `serve` opens it — a regular file owned by the signer, readable by nobody else by its mode
  bits; an access-control list is not seen. For a seed `serve` refuses, `/posture` says which
  of the three fails (or, where its owner cannot be read, that `gateway posture` says why),
  naming no uid and no mode; `gateway posture` names the file's owner, the signer's uid and the
  mode. On Windows it is stated as `not-enforced`.
- `operator-program-confinement`: `not-enforced` without a selected wrapper or a
  completed successful boundary check. With version 13 sources it aggregates the
  per-program entries below: `enforced` only when every entry is enforced, otherwise
  `partial` when any entry is enforced or partial.
- `listener-reach`: whether the gateway listens on a loopback address and, where it does not,
  whether it authenticates its callers — the class of the address, never the address or the
  port, from the command and the route alike. `/posture` judges the listener the gateway serves
  on, as it was bound: `enforced` on a loopback address, and `not-enforced` off loopback with no
  caller authenticated, which is `serve` from the command line given `--listen` an address that is
  not loopback and `--accept-unauthenticated-callers`. A listener off loopback that authenticates
  its callers is `partial`, since a bearer token over plain HTTP can be read and replayed on the
  network between, which is `serve --config` under a version-19 `listen` that is not loopback
  ("Listening off loopback (engine version 19)", below). `gateway posture` starts nothing: given
  serve's command line it judges the address `--listen` writes out, or `127.0.0.1` where it names
  none; given `--config`, the configuration's `listen`, with callers authenticated where it has
  an `identity`; given neither, `not-applicable`.
- After the six, a configuration with `delegation` adds its three lines (SPEC.md §11.9), and one
  where some platform gives `writeRequesters` adds `write-requesters`: `enforced` when every
  write tool is held to a requester list, `not-enforced` otherwise, the tools counted and no
  requester named. One with an `identity`, or where some platform is fixed to a scope identifier,
  adds `caller-scope-identifiers`: `enforced` where callers are held to the scope identifiers
  their token and `identity.callerScopes` allow (with no scoped platform it says that a token
  whose `scope_ids` names a scope identifier the configuration does not grant is refused `401`),
  `not-enforced` where `callerScopes` is `"unchecked"` or no `identity` is configured, naming no
  subject and no scope identifier.
- Last, `/posture` of a gateway that signs through a key service's key version (`signingKeyVersion`,
  ADR-0050 and ADR-0053) adds `signing-key-custody`: the key's algorithm (`Ed25519` or `ES256`) and
  the protection level the service answered at start, named in one sentence, naming neither the key
  version nor the key. It is `enforced` at every level the service answers, since the gateway holds
  no private key at any of them; `partial` only where the level is unstated, or for a P-256 key away
  from `HSM`, which the start refuses. It is read at each request, so after a serving
  rotation it names the key then in force. A gateway that signs with the seed reports no such line,
  and `gateway posture`, which calls no key service, reports none.

Windows has no shipped restricted-command backend. Engine versions 13 and later
wrap every configured source adapter, including adapters for remote and container
sources. Omitting `sandbox` settings still selects workspace-write by default.
Read-only and workspace-write wrappers therefore refuse those adapter launches
on Windows and report `backend: none`,
`state: not-enforced`, with the Windows unavailability reason. An explicit
full-access policy is required to launch these adapters there and remains
unrestricted. Remote-server and container-daemon
availability does not establish their confinement by this local wrapper.

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
applied would read as applied. `history` is served by the `airbyte` shape, `write` by the
`mcp` shape, and `live` by the `mcp` shape or, in a binding of no other operation, by the `http`
shape ([below](#an-http-api-as-a-platforms-live-operation)); a binding naming another shape for an
operation is refused. The file is `catalog/<platform>.json`, it must name that platform, and
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

## An HTTP API as a platform's live operation

A platform with a plain HTTP API and neither a connector image nor an MCP server of its own is
read in the engine by the program the plain form runs for `--source-shape NAME=http`,
`adapter-http` ([adapters/README.md](../../adapters/README.md#adapter-http)), named by a binding
whose one operation is `live` of the `http` shape (gateway #384,
[ADR-0024](../adr/0024-an-http-source-in-the-engine.md)):

```json
{
  "bindingVersion": "1",
  "platform": "records",
  "operations": {
    "live": {
      "shape": "http",
      "endpoint": "https://records.example/api",
      "paths": ["/search", "/health"],
      "methods": ["GET", "POST"],
      "headers": ["Accept=application/json"],
      "bearer": "API_TOKEN",
      "checkPath": "/health",
      "licence": "Apache-2.0"
    }
  }
}
```

The members are exactly these, `methods`, `headers`, `checkPath` and `errorCodes` optional, and
exactly one of `bearer` and `credentialHeader`:

- `endpoint` is the base URL every request goes under, held to the endpoint form SPEC.md §1.2a
  gives a remote server — `https`, or `http` at a loopback address written as one, `localhost`
  not among them; no user, query or fragment — with no placeholder, since no platform parameter
  fills one here, and a path the adapter sends as written: no percent sign, which the adapter
  would send decoded and escaped again, no other character its URL escaping would send
  percent-escaped (below), no dot segment and no empty segment, but for one `/` at the end,
  which the adapter drops before the request's path. The binding's digest pins it, and the
  receipt names the URL the adapter sent to under it;
- `paths` are the only paths an acquisition may name, 1 to 128, each sent as written under the
  endpoint: it begins with `/`, is printable ASCII without a space, and carries no query,
  fragment, backslash, dot segment or empty segment — what `adapter-http` accepts — and no comma
  or percent sign, which the engine's command line would split into two paths or the adapter
  would send escaped; nor any other character the adapter would send percent-escaped (below). A
  brace is refused but in the one placeholder `{id}`, a whole segment at most once in a path,
  which from engine version 31 makes the path a template a GUID fills ("Path templates and links
  on an http source (engine version 31)", below). A path given twice is refused, and
  so are paths that, comma-joined after `--paths=`, make a word of 128 KiB or more: the one
  argument of the adapter's command line they are passed in, which Linux would refuse to start a
  program with;
- `methods` are the methods an acquisition may name, `GET` and `POST`, each once; `POST` alone
  when the member is absent, as the adapter's own default;
- `headers` are `NAME=VALUE` pairs sent on every request, 1 to 32 when present, the value
  printable ASCII with no space at either end: a credential's header (`Authorization`,
  `Proxy-Authorization`, `Cookie`), a header the adapter writes itself (`Content-Type`,
  `Content-Length`, `User-Agent`, `Accept-Encoding`, `Host`, `Transfer-Encoding`, `Connection`)
  and a name given twice, or given as the credential's, are refused;
- `bearer` is the member of the platform's live credentials file sent as
  `Authorization: Bearer`; `credentialHeader`, `NAME=MEMBER`, sends that member under `NAME`
  instead, which is neither `Proxy-Authorization` — a proxy reads it, not the endpoint — nor a
  header the adapter writes. One of them is required, since the platform names a credentials file
  for `live` as for every operation, and the adapter reads that member of it and sends nothing
  else;
- `checkPath` is the path a check GETs: one of `paths`, and not a template, which a check would
  have no GUID to fill, with `GET` among `methods`, so a check asks for nothing an acquisition
  could not. Without it a check is the TLS handshake, or, to
  plaintext loopback, the connection alone.
- `errorCodes` declares the endpoint's error codes the gateway may act on (gateway #514 and #524,
  [ADR-0047](../adr/0047-an-endpoints-error-code-from-a-closed-list.md)): an object of exactly `at` and
  at least one of `referenceExpired` and `accessRefused`. `at` is 1 to 4 member names, each 1 to
  64 ASCII letters, digits, `_` and `-`, from the error object's top to the code (`["error",
  "code"]` for an answer `{"error": {"code": …}}`). `referenceExpired` is 1 to 8 objects of
  exactly `status` and `code`, the status a 4xx other than `401`, `403`, `410` and `429`: an
  answer of that status whose code is that code is an expired reference ("An expired reference",
  below). `accessRefused` is 1 to 16 codes an access refusal passes on ("An access refusal",
  below). Every code is 1 to 64 ASCII letters, digits, `_`, `.` and `-`, once in its list, and
  not `unlisted`. Only `adapter-http` reads the body, at most 4 KiB of it, and only a value of
  these lists crosses to the gateway, which holds it to the same lists. It is a binding-format
  member and needs no engine configuration version: the configuration pins the binding by
  digest, and an engine written before it refuses a binding naming it.

A path is sent as written, or refused when the binding is loaded (gateway #407). The adapter sets
a request's path, the endpoint's decoded path followed by the request's, and leaves its escaping
to Go's `net/url`, which sends some printable characters percent-escaped; a path, or the
endpoint's path, holding one would be sent as other bytes than the binding states. The engine
refuses such a path, in `paths` and in the endpoint, by that same escaping rather than by a list
of its own: a path is refused when `url.URL{Path: p}.EscapedPath()` is not `p`. Under Go 1.26
the printable ASCII characters so refused are the space, `!`, `"`, `#`, `%`, `'`, `(`, `)`, `*`,
`<`, `>`, `?`, `[`, `\`, `]`, `^`, `` ` ``, `{`, `|` and `}`; the punctuation sent as written is
`$`, `&`, `+`, `,`, `-`, `.`, `/`, `:`, `;`, `=`, `@`, `_` and `~` (a comma is refused in `paths`
anyway). A template is held to the rule with a GUID in place of `{id}`, since every path it
admits differs from that one only in hex digits. The tests derive the set over every printable
ASCII byte and log it. `adapter-http`
holds the paths it is given, `--paths`, `--check-path` and a request's path, to the same rule, so
the two agree on a path, and a path it was given in the plain form with such a character, a
percent escape among them, is refused rather than sent escaped again.

The source is `<platform>/live` (the table above): `adapter-http`, started as every engine
source is — as the platform's OS user, with `no_new_privs`, under the source sandbox as an
adapter from engine version 13, in an environment of that user's `HOME`, the engine's `PATH` and
the platform's `environment` — with the platform's live credentials file, resolved as the
refusals above resolve every credentials path. It is that process, and no other, that reads the
credential and makes the request; the signer reads the envelope it writes and mints the receipt
the plain form mints for shape `http` (SPEC.md §1.2a): `shape` `http`, the adapter named by its own
digest, the URL sent to as `endpoint`, the request's commitment as `statement`, the answer's
`ETag` or `Last-Modified` as `snapshot`, and the TLS peer's certificate as `peerIdentity`. The
adapter's own bounds, a 1 MiB envelope and twenty seconds, lie inside the engine's on every
source. The 1 MiB is on the adapter's whole answer, the envelope: an answer the endpoint did not
say is JSON is carried in base64, which is four bytes for every three, so such an answer is
refused above roughly three quarters of a mebibyte. No `--ca-file`, `--max-output` or `--timeout`
is passed, so the endpoint's certificate chains to the system's roots, as a remote MCP server's
does.

An endpoint under a private certificate authority is reached only through the platform's
`environment`: on Linux, `SSL_CERT_FILE` replaces the file the adapter reads the system's roots
from and `SSL_CERT_DIR` the directories, so both are set to trust that authority alone. This
changes the roots of that platform's adapter only, since the environment is the platform's. The
binding's digest does not cover it: the environment is the engine configuration's, not the
binding's, so what the binding pins is the endpoint and not the authority its certificate chains
to. The file must be readable by the platform's OS user, and lie outside that user's runtime
directories (`XDG_RUNTIME_DIR`, `/run/user/<uid>`), which the source sandbox hides under
bubblewrap; the sandbox restricts writes, not reads, elsewhere. What a verifier can hold to is
the receipt's `peerIdentity`, the digest of the certificate the endpoint presented.

An acquisition's arguments are the adapter's request, `{"path", "method"?, "query"?, "body"?}`
or `{"link", "method"?, "body"?}`: the path one of `paths`, or a template's with a GUID in
place of `{id}`; a link an absolute URL under the endpoint whose path is one of those ("Path
templates and links on an http source (engine version 31)", below); the method one of
`methods`; anything else is refused by the adapter before a connection is made, and, for a
source with a token step, by the engine before a token is obtained. A `query` object's members
are sent sorted by name and form-encoded, but for `$`, which is sent as written, so an OData
system option (`$select`, `$top`, `$filter`) reaches the endpoint by the name it reads.

**A throttled answer** (gateway #425, [ADR-0029](../adr/0029-a-throttled-source-is-answered-with-its-class.md)).
When the endpoint, or the token step's token endpoint, answers `429` or `503`, `/acquire` answers
that class with the gateway's own sentence and, when the endpoint's `Retry-After` was one line of
delta-seconds or an HTTP-date in the future, `Retry-After` in whole seconds, at most 3600 (SPEC.md
§6, "When an acquisition does not happen"). Nothing is minted or retained, a throttled token
request leaves no token held, and the gateway does not retry. Every other refusing answer — a
`500`, a `502`, a `504`, an endpoint that cannot be reached — is answered `400` as before.

**An expired reference** (gateway #461). When the endpoint answers `410` — the cursor or change
token the request sent is no longer held there — `/acquire` answers `410` with
`"code": "source_reference_expired"` and the gateway's own sentence, nothing of the endpoint's
body (SPEC.md §6, "When an acquisition does not happen"). It is not receipted and takes no
`callIndex`, the sealed token is kept, and the session is left open: the caller drops the
reference it kept and reads again from its first value, in the same session or a new one. A
`410` from the token step's token endpoint is a refused token request, and a `404` or a `400`
from the endpoint is answered `400` as before, unless the binding's `errorCodes.referenceExpired`
declares its status beside the error code it carries (ADR-0047). A declared pair is answered as the
`410` is, with a sentence that names the status the endpoint gave.

**An access refusal** (gateway #524, ADR-0047). When the endpoint answers `403`, or `401` to a
request that carried no token a token step obtained, `/acquire` answers `403` with
`"code": "source_access_refused"`, `endpointStatus` (the endpoint's `401` or `403`), and
`endpointCode`, beside the gateway's own sentence. `endpointCode` is the endpoint's error code when
`errorCodes.accessRefused` lists it, and `unlisted` otherwise, including for a body over 4 KiB, not
JSON, without the code, or with a code of another type. Nothing of the body reaches the caller. It
is not receipted and takes no `callIndex`, the sealed token is kept, and the session is left open.
A `401` to a token the token step obtained is the token refused: the token is dropped, and the
answer is the token step's fixed sentence, as before. A token endpoint's own `401` is a refused
token request.

**Paging is the caller's** (gateway #389). The engine keeps no cursor, no high-water mark and no
"since" for a source of this shape, or for any generic source: each `/acquire` is one request to
the endpoint and one receipt, for the page or the window the request names, and the caller keeps
where it is between them. A caller paging through a source names each page in the request's
`query` or `body`, on a path and by a method the binding admits, and takes the next cursor from
the page it was answered:

```json
{"session": "records-2026-11-13", "source": "records/live",
 "arguments": {"path": "/search", "method": "GET", "query": {"since": "2026-11-12T00:00:00Z", "limit": "100"}}}
```

The answer's `result.body` is the endpoint's page, `{"items": [...], "next": "c-2"}` say; the
caller sends the next request with `"cursor": "c-2"` in `query`, in the same session, and stops
when the page names no next cursor. Each page is its own receipt, `callIndex` 0, 1, 2 and so on,
whose `statement` commits to the query that page was asked with; `/seal` after the last page
fixes the session's count, so a verifier holds the pages as one sealed sequence with none
removed. The high-water mark, here `since`, is the caller's to record, from the pages it holds;
the gateway reads nothing in a result. A page answered `429` or `503` is not receipted and takes
no `callIndex`: the caller waits the `Retry-After` it was given, or its own back-off when none
was, and asks for the same page again in the same session, which is not sealed until it has.
An endpoint that names its next page by a URL, an OData `@odata.nextLink` or a delta round's
`@odata.deltaLink`, is followed by sending that URL as the request's `link`, as written: the
receipt's `statement` then commits to the path and the query the link carried, as `rawQuery`
("Path templates and links on an http source (engine version 31)", below).
The recurring observations of the one built-in provider that has them
([recurring-source-observations.md](recurring-source-observations.md)) are unchanged.

An `http` live operation is its binding's only operation, and the binding's version is 1: no
owner taxonomy is defined for an operation whose acquisitions name no tool, so a
`bindingVersion` 2 or 3 binding naming the shape is refused, and the current admission's
owner-declaration requirement, which is of MCP operations, does not reach it. A platform that
reads by it acts elsewhere: `/act` names another platform's `write`, citing the acquisition, and
takes no write for this one, which derives no write source. The engine refuses, at start and at
`connect`, what such a platform would leave unused and so read as in force — `write: true`, and
with it a `decisionPolicy` or `writeRequesters`; a `grant`, since an acquisition names no tool, so
a delegation's own scope check (SPEC.md §11.5) would refuse every one under the grant as
`out-of-scope` — reason `source` when no scope entry names the source, `tool` when one does — and
a grant would admit nothing; an `endpoint`, since the binding fixes the endpoint; `parameters`,
since nothing names a placeholder; and `descriptors`, `operationDescriptors` or
`descriptorStatements`, since there is no tool to describe. Since the platform names no grant, a
delegated acquisition of it, with a delegation credential presented or not, is refused as
`grant-unknown` (SPEC.md §10, rule 3) before the scope check, the custody, the issuing host or the
adapter is reached. The MCP server lists no tool of the platform; a client reaches it through
`/acquire`, authenticated as every source is.

A source whose provider issues short-lived tokens against a certificate or a federated identity,
and takes no static credential, is given a token step in the platform's `credentials.live`
("A live operation's token step (engine version 21)", below).

No engine version is added: the configuration's members are unchanged, and every release before
this one refuses a binding that names the `http` shape by name, when it loads the binding and
before any source is derived — so an older gateway refuses a configuration that pins one, and a
binding that names no `http` operation derives exactly the sources it did. A path template is
the one later member, of engine version 31 (below).

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
and its check calls no tool; `adapter-http --check` reaches the binding's endpoint and GETs its
`checkPath`, when it names one, which must answer 2xx — the line names the endpoint, the TLS
peer's identity and what the check path answered, the endpoint the adapter reports must be the
binding's, and nothing is captured. What each answered
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
what is being repaired, while every other platform is, each platform naming the same binding
first re-pinned to the file `--replace` pins, in the same write, and named in the output — a
configuration path that is a symbolic
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
  `decisionPolicy`, whose record meets it. A platform's `writeRequesters` narrows who may ask
  for a write through each tool, and only that: it says nothing of what the requester may ask
  for. That a person approved the write is not established by anything here: the receipt says
  who asked.
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
version 3, which adds a complete descriptor digest for every allowed tool; a
`command` server captures version 4, which also binds the resolved executable
(and a script operand) by path and digest. A platform `environment` that names a
dynamic-loader variable (`LD_*`, `DYLD_*` or `GCONV_PATH`) is refused for a binding
that runs a customer command, with `sandbox-loader-variable-refused`.
`connect` stores the snapshot and owner declaration using the existing immutable
approval path; subsequent acquisition refuses a version downgrade or descriptor
drift before `tools/call`. A customer binding is not an exemption from per-platform
OS users, credential separation, write approval or source shape `mcp`.

A customer binding may also declare its server's publisher, `"publisher": {"kind": "registry" |
"repository" | "domain", "name": ...}`, which is refused on a binding that is not a customer's.
`connect` reads its liveness before it runs anything and shows it with the approval. It also flags
a name that closely matches an integration the gateway ships under another publisher
(`name-lookalike`). What it read is kept in `<engine.json>.publishers.json`, under the configuration's lock and
with its mode and owner, which
`gateway publishers --check` reads again on the operator's schedule. Under
`gateway publishers --policy refuse`, an unmaintained publisher (evidence of a lapse, never an
unverifiable one) refuses the registration and each
acquisition and action. See [connection grants](connection-grants.md#publisher-trust-for-customer-mcp).

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
The launcher it runs (bubblewrap, sandbox-exec) is never looked up on `PATH`; it
is taken only from fixed root-owned locations (see the adapter reference).

An optional top-level `sandbox` object has `policy` (an absolute operator policy
file path) and `workspaces` (exact source identities mapped to absolute existing
directories). Omitted settings select workspace-write and a fresh private source
workspace for each invocation. A customer command retains its binding's workspace.
A configured workspace or policy that contradicts that binding is refused, and
unknown workspace selectors are refused. Every effective policy file must lie
outside every configured source workspace, another source's included; the engine
refuses the configuration otherwise. At start the engine holds each policy file as
it holds an adapter: its way walked for the signer, and the file, where it exists,
owned by root or the signer and writable by nobody else. The helper also refuses a
policy path that passes through a link inside the source's workspace. A platform `environment` naming a
dynamic-loader variable (`LD_*`, `DYLD_*`, `GCONV_PATH`) is refused for every
wrapped source, and the helper refuses one in its own environment. Full filesystem
access always requires an explicit policy setting.

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
No-source posture has the six lines above and no `programs`.
With `identity.callerScopes` checked, the `/posture` endpoint served to a caller that
does not reach every source is the report of the sources it reaches alone (ADR-0037,
ADR-0041): `programs` and `readOnlySources` list only them, and `programs` is omitted when it
reaches none; every protection line is judged over them, its state, its counts and the sources
or platforms it names (`source-user-switch`, `operator-program-confinement`, `delegation-grants`,
`write-requesters`, `caller-scope-identifiers`, `read-only-credentials`), so the report does
not change with the sources of a scope identifier the caller does not reach. Where it reaches
no source, `source-user-switch` is `not-applicable`, "this caller's token reaches no source, so there
is none to judge"; where it reaches none fixed to a scope identifier,
`caller-scope-identifiers` says no source the caller's token reaches is fixed to one. The
lines that are not of the sources are the same for every caller. The installation's caller,
`"unchecked"` and a gateway without `identity` are given the report of every source.
Container-helper entries concern the local runtime client, and are partial even
when its backend enforces all filesystem writes: the external daemon is not
confined by that client boundary. Such a source's probe and launch keep
container-runtime sockets reachable (`--container-runtime`), so its adapter entry
is partial too. For every other source, bubblewrap masks the per-user runtime
directory, every listening socket bound to a path, the known runtime sockets and
the one a `unix://` `DOCKER_HOST` or `CONTAINER_HOST` names, after the writable
binds; a listening socket with an abstract name, which no mask hides, makes its
state partial. The masks are defence in depth: `enforced` means the filesystem
write boundary holds, and local services reached over Unix sockets may remain
reachable (a socket created after the launch, bound in another network namespace
or by a relative path is not masked). Every bubblewrap entry, `/posture`'s fixed
sentence included, states that limit. Landlock and Seatbelt name a reachable runtime socket in the reason,
and both are always partial. A `customer-command` entry's reason also says what
runs as the exact approved bytes and what is re-checked by path before the start.

The reasons `/posture` answers for program entries are fixed sentences chosen by
whether the source's helper gave a report and, where it gave none, whether the report's
own time budget (below) ended its check or left it no time to start, then by mode,
backend, state and class. They name no launcher location, masked path, home directory or
uid; `gateway posture`, run by the operator, keeps the helper's own
words.

A completed probe is cached for the resolved source until restart, and every
launch is bound to it; a probe that timed out is not cached. The first launch of a
source without a completed probe takes one first, and refuses if it does not
complete. A restricted launch whose probe measured the boundary as not holding
(`not-enforced` under a restricted mode) refuses with `sandbox-not-enforced`. The launch passes the
probe's mode, backend and `policyDigest` to `adapter-sandbox run`, which refuses
with `sandbox-not-enforced` before the program starts when the policy bytes or
mode now differ, or when the reported backend cannot be used: a bubblewrap that
fails at launch does not fall back to Landlock. A changed policy therefore takes
effect only after a restart measures it, and posture never reports a selection a
launch does not use.

A posture report probes its wrapped sources one at a time, each under twelve seconds of its
own, as a launch's probe is, so one helper that hangs leaves only its own source unmeasured,
and all of them within thirty seconds for the whole report, which `/posture` answers over
HTTP. A probe already kept is answered whatever is left. A source whose check the report's
thirty seconds ended, or left no time to start, is reported `not-enforced`, backend `none`,
with `sandbox-not-enforced: this report's time for backend checks ran out before this source's
check gave a report`; that says nothing of its launch, which probes under its own twelve
seconds.

**When the sandbox cannot be had, in a container or elsewhere.** The backends, their fixed
launcher locations and their limits are in [adapters/README.md](../../adapters/README.md#customer-bindings)
and [SECURITY.md](../../SECURITY.md); what follows is what each needs of the kernel, which a
container can withhold. The probe and every launch run as the source's user, and a source that
runs as a user of its own is started under `no_new_privs`, so a set-user-id bubblewrap gains no
privilege there. bubblewrap is started with `--unshare-user` and `--unshare-pid`: it needs to
make a user namespace and a PID namespace as that user. Before it is used it is checked by
running `/bin/true` under the same options, which bubblewrap finds on the root filesystem it
binds read-only, so that program must be there; a bubblewrap that fails the check when a
source is measured is passed over for Landlock. Landlock needs the kernel to answer
`landlock_create_ruleset` with ABI 3 or newer, and the helper then calls `landlock_add_rule`
and `landlock_restrict_self`. A container's syscall filter that refuses making those namespaces, or refuses the Landlock calls,
takes that backend away; a profile that permits what a backend needs is what enforcement needs
in a container, and loosening the profile is the operator's trade-off. The engine image carries
`adapter-sandbox`, bubblewrap at `/usr/bin/bwrap` and `/bin/true` for its check
([engine-image.md](engine-image.md), "The source sandbox"); under Docker's default seccomp
profile neither backend can be had there. bubblewrap also mounts a fresh `/proc` for the
source, which the kernel can refuse in a container whose `/proc` has masked or read-only paths:
on a host whose Docker lists AppArmor, bubblewrap was measured to fall back to Landlock with the
container's seccomp and AppArmor profiles relaxed, and to enforce once the container's system
paths were unconfined as well (`systempaths=unconfined`). The engine image's quickstart
([engine-quickstart.md](../engine-quickstart.md)) shows this and says what each setting gives up.

With neither backend, the engine still starts, unless the configuration sets
`measureSandboxAtStart` (version 23, below): the start holds the helper and each policy
file, as above, and measures nothing, so it prints nothing about the sandbox. `gateway posture
--config <engine.json>`, run as the user the engine runs as, is the check. Each affected
`programs` entry reads state `not-enforced`, with a reason that begins `sandbox-not-enforced`:
`sandbox-not-enforced: no usable filesystem sandbox backend`, backend `none`, when neither
backend could be prepared; `sandbox-not-enforced: restricted probe could not execute`, under
the backend prepared, when the probe then failed to run under it; or
`sandbox-not-enforced: source-user backend check did not complete successfully: ` and the
cause, the path an operating-system error carries left out, backend `none`, when the helper
itself gave no report. `operator-program-confinement` is then
`not-enforced` unless another entry is `enforced` or `partial`. `/posture` answers a fixed
sentence in place of the helper's reason; where the helper itself gave no report, that sentence
says the source is wrapped and nothing was measured, and is not the sentence of a source with no
wrapper. A launch of a source whose probe completed and measured the boundary as not holding
under a restricted mode refuses before anything is started, with `sandbox-not-enforced: the
source's sandbox probe measured that the <mode> boundary does not hold under <backend>, so the
source is not launched; gateway posture says why`. A launch of a source with no completed probe
probes again first, and where that probe does not complete it refuses whatever the mode,
`danger-full-access` included, before anything is started, with `sandbox-not-enforced: the
source's sandbox posture could not be measured before its launch:` and the cause. A source whose
policy selects `danger-full-access` and whose probe completed launches unrestricted, as it does
on every host.

## Delegated authority (engine version 15)

Version 15 adds the optional `delegation` member (SPEC.md §11.2), which makes the gateway the
enforcing host of spec RFC 0030 (a Draft) for delegated calls: an agent acting for a person or
a service under a signed delegation from an issuing host, the Desk in the reference stack.

```json
"delegation": {
  "hosts": [
    {
      "host": "desk",
      "requester": "service:desk",
      "keys": ["<the issuing host's Ed25519 public key, 64 lowercase hex characters>"],
      "admission": {"url": "https://desk.example/delegation/admission", "credential": "/etc/engine/desk-admission-token"}
    }
  ],
  "operators": ["operator:on-call"],
  "bearerReadOnly": false
}
```

It requires `identity`: the issuing host asks for a credential, and revokes one, with a token
from that issuer whose subject is the host's `requester`. Each key is held to the key rule of
SPEC.md §8.4 when the file is loaded. The admission read goes to `admission.url`, which must be
`https://`, with the token in `admission.credential`, read once at start; a missing, late or
unreadable answer refuses the call. `operators` are the subjects that may reach a delegated
action's retained evidence or read-back as the gateway's operator. `bearerReadOnly` admits a
bearer credential for a chain that only reads; posture reports it.

What it changes for callers, all in SPEC.md §11:

- `POST /delegation/credential` and `POST /delegation/revoke`, for the issuing host alone;
- `/acquire` and `/act` take a credential (`Authorization: DPoP` with a proof, RFC 9449), admit
  each call immediately before it is dispatched, and receipt it with the `delegation` member;
- `/act` takes `reservation`, through which the subject, the issuing host or an operator reaches
  a delegated action by its key, never a dispatch;
- `/posture` adds `delegation-narrowing`, `delegation-sender-constraint` and
  `delegation-grants`, the last naming each platform a delegated call can reach that names no
  `grant` (engine version 16) and so refuses every delegated call `grant-unknown`:
  `not-applicable` when no platform reached names one, the delegation then serving no call, and
  `enforced` otherwise.

A file without the member, and every call made under no delegation, behave as before.

## Sealing at the start what was left open (engine version 17)

Version 17 adds the optional `sealOpenAtStart` member, `true` or `false` and nothing else
(SPEC.md §3c, gateway #395). With it `true`, the engine's start, once it holds its registry
and before it serves, seals each session another process left open whose receipts are
whole with a seal made after an interruption, `sealedVia` `"start"`, and writes each seal on
stderr as `start: sealed after an interruption: <registry line>`. A session that is not
whole, and a directory no session id names, is named on stderr and stays open, and the engine
serves; a session that cannot be read stops the start, nothing sealed. Absent or `false`, the
start does what it did before. `gateway serve` from the command line takes
`--seal-open-at-start` for the same switch, and `gateway seal-open --config <engine.json>`
seals by hand, the engine stopped.

With `storage` naming the PostgreSQL kind (version 24 and later) the member is taken as well
(gateway #466): the start seals once it holds the start lease and before it serves, and
`gateway seal-open --config` takes the start lease and is refused, `start-lease-held`, while an
instance serves (postgresql-store.md, "Sealing the sessions an instance left open"). No engine
version is added for it: no member is added, and a gateway before it refuses `sealOpenAtStart`
beside `storage` by name, so it refuses such a file rather than reading it otherwise.

## A platform's grant (engine version 16)

Version 16 adds a platform's optional `grant` member (SPEC.md §10 rule 3, gateway #368, #372):
the connection grant the platform's delegated calls are admitted under, which the connection
custody holds ([connection-grants.md](connection-grants.md#delegated-calls)).

```json
"boards": {
  "binding": "azure-devops@sha256:…",
  "credentials": {"write": "/run/secrets/boards-write"},
  "user": "engine-boards",
  "write": true,
  "grant": {"provider": "azure-devops", "connection": "boards", "stateDir": "/var/lib/connections", "principal": "operator", "user": "engine-custody"}
}
```

`provider` is one of `google-drive`, `gmail`, `notion`, `databricks` and `azure-devops`;
`connection` is the connection's name in custody, a flat token; `stateDir` is the custody's root,
absolute; `principal` is the custody's principal; `user` is the OS user the custody belongs to,
which `gateway-connections --grants admit` runs as. A platform that does not set `write: true`
may name one too: its delegated acquisitions are admitted under it. Every member is required, and
a member it does not name is refused by name.

At start the engine holds `gateway-connections` as it holds every adapter (in `adapters`, or on
the engine's PATH where `adapters` is not set), and refuses a `grant.user` the host does not have,
root, the signer's own user, the MCP server's, or a platform's. Each delegated call on the
platform is then admitted through the custody, whichever of its operations it runs: a write, an
acquisition of `live`, and the read-back of a delegated key's uncertain action, which runs `live`.
A delegated acquisition of `history` names no tool, so it is always out of scope (SPEC.md §11.5,
reason `tool`) and never asks the custody. No undelegated call is. A delegated call on a platform with no `grant` is refused as
`grant-unknown`. The engine image ships no `gateway-connections` and no custody user, so a file
that names a grant is refused at start there.

`connect --replace` keeps a platform's `decisionPolicy` and `writeRequesters` and drops its
`grant`: the replaced entry's delegated calls are refused until the member is written again.

## Who may ask for a write (engine version 18)

Version 18 adds a platform's optional `writeRequesters` member (SPEC.md §6, "Who may ask for a
write", gateway #383): the requesters `/act` takes a write from, for each of the platform's
write tools. Without it, any requester the identity, or a delegation, authenticates may ask
for a write through any write tool, as before.

```json
"tickets": {
  "binding": "tickets@sha256:…",
  "credentials": {"write": "/run/secrets/tickets-write"},
  "user": "engine-tickets",
  "write": true,
  "writeRequesters": {
    "platform": [
      {"issuer": "https://issuer.example", "subject": "user-17"},
      {"issuer": "https://issuer.example", "subject": "user-42"}
    ],
    "tools": {
      "delete_ticket": [{"issuer": "https://issuer.example", "subject": "user-42"}],
      "close_ticket": []
    }
  }
}
```

Here `user-17` and `user-42` may ask for a write through every tool but two:
`delete_ticket`, which `user-42` alone may ask for, and `close_ticket`, which nobody may.

- **The lists.** `platform` is the list every write tool of the platform inherits; a tool named
  under `tools` is held to its own list instead, never to both. Either may be left out, not both.
  A list that is present and empty names nobody: the member only ever narrows who may ask.
- **The requester** is the one the action receipt names: the configured issuer and a bearer
  token's subject; under a delegation, the delegation's subject (the person or service on whose
  behalf the agent acts), never the agent and never the host that bound the credential; on a
  request naming a reservation, the reservation's subject, never the token subject of the host
  or operator that sends it. The member's name says which one it restricts: who asks for the
  write.
- **Comparison** is exact, issuer and subject each, byte for byte: no case folding, no Unicode
  normalization, no trimming. Each entry names its issuer, so a subject of one issuer never
  matches an entry for another. Without `delegation`, every entry's `issuer` must be
  `identity.issuer`, since nothing else can reach `/act`; with one, a delegation's subject may
  be of another issuer, and an entry may name it.
- **When the file is loaded** (`serve`, `connect`, `connect --replace`, `posture`), the member
  is refused at a version before 18, on a platform without `write: true`, in a file without
  `identity`, with any member but `platform` and `tools` or with neither, with a `tools` that
  names no tool or names one by the empty string or one the binding's write operation does not
  name, with an entry that is not exactly `{issuer, subject}` of non-empty strings, and with a
  requester named twice in a list. The refusal names the entry by its place, as
  `platform tickets: writeRequesters.platform[1]`, and repeats no requester. A tool
  named twice, like any member, is a duplicate name the parser refuses.
- **At `/act`**, a requester a tool's list does not name is refused `403`, `refusedAt`
  `write-requesters`, with one fixed sentence that names nobody and no list, once the session,
  platform and tool are known and before the arguments, the key, the decision, the cites and the
  policy are read. Nothing is sent, read back, journaled or minted. A first send, a replay, a
  reconciliation and a read-back are held alike.
- **`connect --replace`** keeps the member as written, since an entry written without it would
  admit everyone, and refuses a replacement it no longer fits: one without `--write`, or a
  binding whose write operation no longer names a tool the member lists. A replacement whose
  binding names a new write tool holds it to the `platform` list; with only `tools` given, the
  new tool is held to no list. Give a `platform` list, an empty one if need be, so that a tool
  added later is refused until it is named.
- **`/posture`** adds a `write-requesters` line where some platform gives the member: `enforced`
  when every write tool is held to a list, `not-enforced` otherwise, its reason counting the
  tools held and never naming a requester. A file without the member reports no such line.

It establishes that whoever asked was on the operator's list for the tool, and nothing more: a
requester it admits is held to every later step, the decision policy included, and the target
system's own authorization is unchanged.

## Listening off loopback (engine version 19)

Version 19 adds the optional `acceptOtherHostsOverPlainHTTP` member, `true` or `false` and
nothing else ([ADR-0025](../adr/0025-serve-config-listens-off-loopback-with-an-identity-when-acknowledged.md),
gateway #400), by which `serve --config` listens on an address other hosts can reach. A `listen`
that is not loopback loads only where the file has both an `identity`, so that every endpoint but
`/registry` and `/publickey` holds its caller to a token, and the member `true`, which
acknowledges that those tokens cross plain HTTP unless TLS terminates in front of the engine:

```json
"listen": "0.0.0.0:8787",
"identity": { "issuer": "https://login.example", "audience": "gateway:acme", "keys": "/etc/engine/issuer-keys.json" },
"acceptOtherHostsOverPlainHTTP": true
```

- The address is an IP literal and a port, written exactly as the engine binds and prints it:
  IPv4 in dotted decimal, IPv6 in brackets, compressed and in lowercase, an IPv4 address never in
  IPv6 form, the port a number with no sign and no leading zero. A name, `localhost` included, a
  zone and an empty host are refused, and any other spelling is refused naming the one to give.
  `0.0.0.0` is every IPv4 address and no IPv6 one, `[::]` every IPv6 address and no IPv4 one;
  each is bound only when written out, in its own family. The address is held by the rule
  `gateway serve --listen` is held by ([ADR-0023](../adr/0023-serve-listens-off-loopback-only-when-acknowledged.md)),
  the port written beside it.
- Without both, the file is refused, the refusal naming both members and saying which is missing:
  an `identity` alone is not enough, nor the member alone. The member `true` beside a loopback
  `listen` is refused, since it would acknowledge nothing; `false` is taken anywhere and changes
  nothing.
- Beside `witness` such a `listen` is refused: a witness's two reads are open to anyone, and its
  signer listens on a loopback address, behind a front that passes other parties the
  submission, the two reads and `/publickey` alone (SPEC.md §6, "Witness endpoints"). Beside
  `mcp` it is refused: the MCP server finds the signer by `listen` and fronts a signer on
  loopback.
- When what was bound is not loopback the start writes on stderr, before its `gateway on
  http://…` line, `start: listening on <address>, which is not a loopback address: other hosts
  can reach this gateway; it holds every caller but those of /registry and /publickey to a
  token, and speaks plain HTTP, so unless TLS terminates in front of it a token can be read and
  replayed on the network between`. `posture` reports the listener `partial` (above).
- A loopback `listen` is held, rewritten to one spelling and bound as before, at every version,
  and the start writes what it wrote. A file of version 18 or earlier with a `listen` that is
  not loopback is refused as before, and a gateway older than version 19 refuses a version-19
  file by its version.

What this does not give: the gateway does not terminate TLS, so on the network between a caller
and the listener a bearer token can be read and replayed within its validity window, results and
a version 3 response's salts read and a request changed; `/registry` and `/publickey` are open to
whoever reaches the listener; and the gateway limits neither the rate of requests nor the number
of connections. A front that terminates TLS and limits them still belongs in front of it. Such a
listener does close a connection idle for a minute, bound a request's headers at 64 KiB, and give
the answer of `/registry` and of `/publickey` 30 seconds each to be written, a per-answer deadline
rather than a server-wide write timeout, since an `/acquire` or an `/act` has no fixed longest
run.

## A platform's scope (engine version 20)

Version 20 adds a platform's optional `scope` member
([ADR-0026](../adr/0026-a-scope-identifier-fixed-on-a-platform.md), SPEC.md §1.2a, `scope`, and
§6, `/acquire`, gateway #420): a scope identifier the platform's sources are fixed to, which a
request to one of them repeats and its receipts carry under the signature, so that the receipts
of one operator's sources can be told apart by the party each serves.

```json
"warehouse-east": {
  "binding": "postgres@sha256:…",
  "credentials": {"history": {"file": "/run/secrets/east-history"}, "live": {"file": "/run/secrets/east-live"}},
  "user": "engine-east",
  "scope": "east-ledger"
}
```

- **The form.** A string of 1 to 128 bytes of UTF-8 that holds no code point display policy 1
  refuses ([tool-descriptors.md](tool-descriptors.md): controls, bidirectional controls, default
  ignorables, private use, unassigned and noncharacters, as Unicode 15.0.0 assigns them) and
  neither tab nor line feed. Anything else, a string out of that form, `null` or another type,
  is refused naming the platform and the form; the refusal quotes nothing of the value.
- **Opaque.** The identifier means nothing to the engine. It is compared as written, byte for
  byte, and never case-folded, trimmed or normalized, so write it as requests will.
- **What it fixes.** The platform's `history` and `live` sources. A request to either names the
  identifier in `/acquire`'s `scope`; one that names none or another is refused `400` before
  the source runs, the session is admitted or a delegation counts the call, with one fixed
  sentence, `scope: the request's scope does not match the source's`, that names no identifier
  and writes no line on stderr. So is a request that names a scope for a source of a platform
  without one. A gateway whose platforms give no `scope` refuses the request member as unknown,
  as it did before.
- **Live tools are reads.** Each tool of the platform's live operation is declared effect
  `read-external` in its binding's `toolTaxonomies`, whatever the configuration's `mcp` member,
  none included ([ADR-0046](../adr/0046-a-scoped-platforms-live-tools-are-declared-read-external-whatever-the-front.md)):
  no decision policy holds a live tool's call, and the platform enables no write operation.
  A tool declared `propose` or `act`, or one with no declaration, refuses `serve` and `gateway
  mcp` at start, and `connect` refuses to write the platform, with `platform <name>: tool
  "<tool>" is not declared effect read-external, ...`, naming no scope identifier; the tool is
  never left out of a source that starts. The shipped postgres binding's `execute_sql` is an
  act, so a platform of it, like the one above, starts only with a binding that declares it
  `read-external` (under a role that only reads) or names `search_objects` alone.
  **Upgrading:** this holds a file of any version from 20, with no version to raise. A file
  that started before and breaks here either declares the tool `read-external` (for instance
  `{"operation": "read", "effect": "read-external"}`) and approves the binding again with
  `connect --replace`, if the tool only reads, or takes it off the scoped platform: a binding
  whose live operation names reading tools alone, or the platform without `scope`.
- **The receipt** of such a source carries the identifier as its top-level `scope`. A platform
  without the member mints the receipts it minted before, byte for byte.
- **A session is of one scope**, on either storage kind
  ([ADR-0036](../adr/0036-a-session-is-of-one-scope-identifier-and-its-seal-names-it.md)): the
  scope of its first acquisition, the source's identifier or none. An acquisition into it of a
  source of another identifier, of a scoped source into a session of none, or of a source of none
  into a scoped session, is refused `400` before the source runs, with `session <id> holds the
  receipts of a scope other than this source's (another scope identifier, or none): a session's
  receipts are of one scope, so acquire into a new session`, which names neither scope. An `/act`
  into a scoped session is refused at its session step, since an action receipt carries no scope.
  Use one session per scope identifier. A gateway before this one let a session of the
  filesystem kind mix them; such sessions in an existing store verify as they did.
- **Registry lines.** A seal is of one session. The seal of a session of a scope identifier is a
  seal of version 3 that names it under the signature by its digest over the session's scope
  salt, never by the identifier or the salt (`sealVersion` `"3"`, `scopeDigest`; SPEC.md §3, "A
  seal of version 3"; ADR-0042), and so is the seal `gateway seal-open`, or the start's switch,
  makes after an interruption of such a session (SPEC.md §3c, "Naming the scope"). The salt is
  32 random bytes the gateway draws for the session and writes into each of its receipts
  (`scopeSalt`) and into no registry line. A session whose receipts v0.31.0 or v0.32.0 minted,
  carrying no salt, is sealed after an interruption with a seal of version 2, by its digest in
  the session, as those releases sealed it; a session that holds no receipt is sealed in the
  form of a session of no scope. A verifier of this version reports the session
  `seal-scope-mismatch` where an accepted receipt in it carries another scope, none, or another
  salt or none under a seal of version 3. The seal of a session of no scope is the form it was before, byte for
  byte, as are the seals an earlier gateway wrote, which name no scope whatever their sessions
  held. A rotation statement (SPEC.md §3b) is of the key and of no source, and names no scope.
  So the lines that concern a scoped source are the seals of version 3 or 2, each naming by its
  digest the scope identifier of the one session it seals; no line carries a scope identifier, so
  a registry, an export's or a copy, lists none, and on the PostgreSQL kind a gateway of one scope
  reads none of another's from it (ADR-0036, decision 9). A digest of version 3 tests no guess
  without the session's salt, which only its receipts hold; a digest of version 2 is not a
  secret: one who guesses an identifier can digest it in a session's id and test it.
- **`/seal` answers with the seal.** Any caller the gateway admits that names a session this
  process holds may seal it, whatever its scope (ADR-0033, decision 5), and the response is the
  seal's record, so a caller that knows or guesses another scope's session id learns that the
  session is of a scope identifier and the digest it is named by, which tests a guessed
  identifier. The refusals name no scope. Where caller scope identifiers are checked ("Caller
  scope identifiers (engine version 27)", below) a caller that does not reach the session's
  scope is answered `no such session`, as for a session the gateway does not hold, and learns
  neither; with `"unchecked"`, or without `identity`, the disclosure stands (a seal of version
  3 tests no guess without the receipts' salt, which the answer does not carry). A verifier
  written before v0.31.0 reads a seal of version 2, and one written before this release a seal
  of version 3, as a seal it cannot verify and reports the session `unregistered-session`:
  readers of a store with scoped sessions need a verifier of this version.
- **The upgrade is one-way once a seal of version 2 is written.** A gateway written before this
  one does not read a seal of version 2, so it finds the session open: its `gateway seal-open`
  (`--all`, or the session named), or its start with `sealOpenAtStart`, seals the session again
  in the earlier form, and from then on this version's verifier reports the session
  `seal-conflict`. Nothing refuses the older gateway on the store, on either kind. So stop every
  instance of v0.30.0 or earlier before one of this version serves the store, and once a seal of
  version 2 is in the registry never run an older instance, or an older `gateway seal-open`, on
  it (postgresql-store.md, "Several instances on one database"). The same holds again for a seal
  of version 3: v0.31.0 and v0.32.0 do not read it, so stop every instance of them before one of
  this release serves the store, and never run them on it afterwards.
- **`gateway verify --scope <identifier>` and `gateway export --scope <identifier>` cut by one
  scope identifier** (SPEC.md §4, "A verdict by scope"; §5a, "An export by scope"; ADR-0042,
  decisions 6 to 9). Each attributes every session by what its receipts and its seal sign: a seal
  of version 3 through the salt the session's receipts carry, and one of version 2 by recomputing
  its digest. The verdict reports the scope's sessions and names, in `cut.unattributed`, the
  sessions it cannot attribute. It reports their findings and is not `ok` while there are any. An
  earlier release's session left open, or sealed in §3's form over a receipt the store no longer
  holds, is such a session. The export holds the scope's sessions, their artifacts and removal
  records, and of the registry the rotations and the scope's lines; it carries nothing of another
  scope. It is refused, by name, where a session is unattributed or a session of the scope holds a
  receipt of another scope or none, as only an earlier release mints. Such a store is verified and
  exported whole. `/verify` over HTTP stays a verdict of the whole store.
- **When the file is loaded** (`serve`, `connect`, `connect --replace`, `posture`), the member is
  refused at a version before 20, on a platform that sets `write: true` (`/act` takes no scope),
  and in a file with `mcp` that names neither `scope` nor `scopeFrom` (such a server forwards a
  call naming no scope; "The MCP server on scoped platforms (engine version 28)", below). `gateway serve`
  from the command line has no flag for it.
- **`connect --replace`** keeps the member as written, since an entry written without it would
  serve requests that name no scope, and refuses a replacement that sets `--write` before
  anything is asked. `connect` has no flag for it: write it in the file, at version 20.
- **`/posture`** reports nothing of it.

It establishes that the operator fixed the source to the identifier and that the request named
the same one, and nothing more: it is a label and not a credential, so any caller the gateway
admits that names a source's identifier is served by it; a session is held to one identifier
and its seal names it, which tells sessions apart and keeps nothing apart; and every scope
shares the gateway's key, store and registry. A verifier written
before the member reads such a receipt as it read one without it and holds the member to no
form (SPEC.md §1.2a).

**Upgrading.** A version 19 file loads unchanged under a gateway of this version. To fix a
platform to a scope identifier, raise `engineVersion` to `"20"` and add `scope` to the platform;
a gateway older than this one refuses a version-20 file by its version. Callers of the
platform's sources then add `scope` to each `/acquire`; until they do, each is refused.

## A live operation's token step (engine version 21)

Version 21 adds `tokenStep` to a platform's `credentials.live`
([ADR-0027](../adr/0027-an-http-source-obtains-its-token-by-a-client-assertion.md), gateway
#421): for an `http` live operation whose provider issues short-lived access tokens against a
certificate or a federated identity and takes no static credential, how `adapter-http` obtains
the token it sends as the bearer, by the OAuth 2.0 client-credentials grant with a client
assertion (RFC 7523).

```json
"records": {
  "binding": "records@sha256:…",
  "credentials": {"live": {
    "file": "/run/secrets/records-live",
    "tokenStep": {
      "endpoint": "https://login.example/oauth2/token",
      "clientId": "records-reader",
      "privateKey": "SIGNING_KEY",
      "x5t#S256": "…",
      "requestScope": "records.read"
    }
  }},
  "user": "engine-records"
}
```

- **The members.** `endpoint` and `clientId` are required, and exactly one of `privateKey` and
  `federatedTokenFile`, or from engine version 32 exactly one of `privateKey`,
  `federatedTokenFile` and `federatedToken` ("A federated token from the platform's metadata
  server", below), or from engine version 33 exactly one of those three and `signedBy` ("A
  token step with a delegated subject (engine version 33)", below, which takes no `clientId`);
  `x5t`, `x5t#S256`, `requestScope` and, from engine version 34, `assertionAlgorithm` are
  optional. Any other member is refused by name, and a refusal repeats no value.
  - `endpoint` is the token endpoint: `https`, or `http` at a loopback address written as one,
    with no user, query, fragment or placeholder.
  - `clientId` is the client identifier, 1 to 256 printable ASCII characters without spaces,
    sent as `client_id` and as the assertion's `iss` and `sub`.
  - `privateKey` names the member of the live credentials file holding the key, one PKCS #8
    `PRIVATE KEY` PEM block: an RSA key of 2048 bits or more, signed RS256, or a P-256 key,
    signed ES256. The algorithm is the key's, unless `assertionAlgorithm` asks for another.
  - `federatedTokenFile` is an absolute path to a file whose text, read at each token request,
    is sent as the assertion. It is held as the credentials file is: owned by the platform's
    user, readable by that user alone, not a directory, on a way no other user may replace, and
    a path that resolves outside the directory it is named in is refused. That path, cleaned, and
    that directory, resolved, are fixed at start and passed to the adapter, which finds the file
    again at each token request: from the directory, through each link on the way (owned by
    root, its target never out of the directory) and each directory on the way (held as at
    start), to a file it opens once and holds by the open handle, a regular file the platform's
    user owns and alone may read. A token rewritten in place, renamed onto the path, or renewed
    by a link swap inside the directory (as a platform renews a projected token, re-pointing a
    `..data` link to a new directory and removing the old one) is read at the next token request;
    a target outside the directory, or a file that fails a hold, is refused as having no
    credential, and that acquisition fails.
  - `x5t` and `x5t#S256`, at most one, beside `privateKey` only: the certificate's SHA-1 or
    SHA-256 thumbprint, unpadded base64url, placed in the assertion's header as written.
  - `assertionAlgorithm`, from engine version 34 and beside `privateKey` only, is `"RS256"` or
    `"PS256"` ([ADR-0027](../adr/0027-an-http-source-obtains-its-token-by-a-client-assertion.md),
    amendment, gateway #513), passed as `--assertion-alg`. `"PS256"` signs the assertion
    RSASSA-PSS with SHA-256, MGF1 with SHA-256 and a salt of 32 bytes, header `alg` `PS256`, as
    the Microsoft identity platform asks of a certificate's client assertion; `"RS256"` signs
    what the member's absence signs, byte for byte. Absent, the algorithm is the key's, so a file
    without it signs as before. Any other value, or the member beside another kind of assertion
    or in a file before version 34, is refused by name, repeating no value. The engine never
    reads the key, so either value beside a P-256 key is refused by `adapter-http` as no
    credential, in a sentence naming the algorithm asked, before any token request; `ES256` is
    not a value, since only a P-256 key gives it. The sealed token is bound to the value when one
    is given.
  - `requestScope` is sent as the token request's `scope`: scope tokens (RFC 6749 §3.3)
    separated by single spaces, at most 1024 bytes. It is not the platform's `scope`.
- **Where it is taken.** Under `credentials.live` alone, of a binding whose live operation is
  of the `http` shape and sends its credential as `bearer`: under `history` or `write`, beside a
  binding of another shape or one sending `credentialHeader`, or in a file before version 21, it
  is refused. The binding's `bearer` member is not read; the token is the bearer. In federated
  mode the live credentials file is still required, and nothing of it is sent. A platform with a
  token step may not set `ADAPTER_HTTP_SEALED_TOKEN` in its `environment`.
- **The assertion.** With `privateKey`, a JWT: header `alg` (the key's, or `PS256` when
  `assertionAlgorithm` asks for it), `typ` `JWT` and the thumbprint given; claims `iss` and `sub` the client identifier, `aud` the token endpoint as written, a
  random `jti`, `iat` and `nbf` now, `exp` five minutes on. It is sent with
  `grant_type=client_credentials`, `client_id`, `client_assertion_type`
  `urn:ietf:params:oauth:client-assertion-type:jwt-bearer` and `client_assertion`, as a form
  POST.
- **The answer.** Status 200, at most 64 KiB, `application/json`, no member named twice;
  `access_token` a string of RFC 6750's token form of at most 16 KiB; `token_type` `Bearer`, in
  any case; `expires_in`, when present, an integer from 1 to 86400, or a string of its decimal
  digits and nothing else. A token stating no lifetime
  serves the one acquisition it was obtained for. The request is bounded to ten seconds, a
  redirect is refused and not followed, and the endpoint is reached over TLS 1.2 or later
  against the system's roots.
- **Held sealed, by the signer.** The engine runs `adapter-http --token-only` as the platform's
  user, under the source sandbox, and holds what it answers: the token sealed under a key the
  platform's credential derives, which the signer cannot open. It holds one per source and
  scope identifier, in memory alone; one token request runs at a time per source, and
  acquisitions arriving meanwhile wait for it and take its token, or, when it failed, its
  failure, without a request of their own; it is obtained again 60 seconds before the stated
  expiry, and a token stating 60 seconds or less, or nothing, is not kept. Each acquisition is
  handed the sealed token in `ADAPTER_HTTP_SEALED_TOKEN`.
- **One deadline.** The source's timeout, 30 seconds, bounds the whole acquisition: the wait for a token request, the token request, the source, and the token
  request and run once more after a token the adapter could not open. Past it, the acquisition
  fails as a source that did not finish within its timeout does. So an acquisition with a token
  step takes no longer than one without, and the MCP side's forward bound holds for both.
- **The request first.** A request whose `path` is not one of the operation's `paths`, or whose
  `method` (POST when it names none) is not one of its `methods`, is refused before any token is
  requested for it: `source NAME: the request does not name a path and a method the source's
  operation allows; no token was requested`. The check `connect`
  runs obtains a token of its own, and sends it with `checkPath` when the binding names one.
- **What fails, and how.** Each failure is one fixed sentence naming the source and nothing the
  adapter or the token endpoint wrote:
  - `source NAME: the token step has no credential: …; no token was requested` — the key member
    or the federated token is not there, or is not one the adapter can authenticate with.
  - `source NAME: the token endpoint refused the token request, or answered with no token the
    gateway takes`.
  - `source NAME: the source refused the access token the token step obtained; the token is
    dropped, and the request was not sent again` — the source answered 401. The acquisition is
    not retried, since that would read the source twice under one receipt; the next one obtains
    a new token.

  A held token the adapter cannot open — its credential renewed since — is dropped, a new one
  obtained, and the acquisition run once more, since nothing was sent.
- **What is written.** Nothing of the key, the federated token, the assertion, the access token,
  the sealed token or the token endpoint's answer reaches a receipt, a record, `/posture`, a
  response, an error or a log line. The receipt is the one the static form mints: no member is
  added.
- **`connect`** has no flag for it: write it in the file, at version 21. `--replace` keeps it,
  and refuses a replacement whose binding it would not fit, before anything is asked.

**Upgrading.** A version 20 file loads unchanged under a gateway of this version. To give an
http source a token step, raise `engineVersion` to `"21"` and add `tokenStep` to the platform's
`credentials.live`; a gateway older than this one refuses a version-21 file by its version.

**A federated token from the platform's metadata server** (engine version 32; [ADR-0043](../adr/0043-a-federated-token-from-the-platforms-metadata-server.md),
gateway #502). In place of `privateKey` and `federatedTokenFile`, a token step may name
`federatedToken`: `{"kind": "metadata", "audience": "api://records-reader"}`. It has exactly
those two members, `kind` is `"metadata"` alone, and `audience` is 1 to 256 bytes of ASCII
letters, digits and `.` `_` `~` `:` `/` `@` `-`. Exactly one of the three is the assertion's
credential, and `x5t` and `x5t#S256` stay beside `privateKey`. No member names an address.
`adapter-http`, handed `--federated-token-metadata-audience`, asks the metadata server at the
link-local IP literal `169.254.169.254` built into it:
`GET /computeMetadata/v1/instance/service-accounts/default/identity?audience=…&format=full`, the
audience percent-encoded, with `Metadata-Flavor: Google`, within five seconds. No resolver, proxy
or environment variable is consulted. An answer is taken only when it carries
`Metadata-Flavor: Google`, is not a redirect, has status 200 and is at most 16 KiB. It must be a
compact JWS whose `aud` is the audience asked and whose `exp` is more than 60 seconds ahead. The
run that sends the token request asks for the token, holds it in its memory for that request,
and writes it nowhere. Any other answer, and a server that is not reached, is the no-credential
sentence above, and no token is requested. A 429 or 503 carrying the header is a throttled answer,
as the token endpoint's is. The live credentials file holds `sealKey`, a string of at least 32
bytes that the sealed token's key is derived from, since the identity token changes at the
metadata server's will. `sealKey` is checked by the adapter when it first obtains a token, at
the source's first acquisition or its `--check`, not at engine load. A missing or short one is
the no-credential sentence there, since the engine never reads the live credentials file. The
identity token is the compute's: every process on it can ask for
one, so this form does not hold platforms apart by their users as the file form does. Under an
earlier version `federatedToken` is refused by name, and a file without it loads and derives its
sources as before.

## A token step with a delegated subject (engine version 33)

A token step may obtain its access token by the JWT-bearer grant (RFC 7523) with an assertion
that names a fixed delegated subject and that the service account credentials API signs, so no
service-account key is held anywhere the gateway runs
([ADR-0045](../adr/0045-a-delegated-subject-token-signed-by-the-credentials-api.md), gateway
#503). It is the form the Google Workspace Admin SDK takes; the shipped
`google-workspace-directory` and `google-workspace-reports` bindings read under it
([catalog/README.md](../../catalog/README.md#google-workspace-directory-and-google-workspace-reports)).

```json
"tokenStep": {
  "endpoint": "https://oauth2.googleapis.com/token",
  "signedBy": {"kind": "credentials-api", "serviceAccount": "directory-reader@example-project.iam.gserviceaccount.com"},
  "subject": "admin@example.com",
  "requestScope": "https://www.googleapis.com/auth/admin.directory.user.readonly https://www.googleapis.com/auth/admin.reports.audit.readonly"
}
```

- **The members.** Exactly `endpoint`, `signedBy`, `subject` and `requestScope`, all required.
  `clientId` is refused beside `signedBy`, as are `privateKey`, `federatedTokenFile`,
  `federatedToken`, `x5t` and `x5t#S256`; `subject` is refused beside any other form. A refusal
  names the member and repeats no value.
  - `endpoint` is the token endpoint, of the endpoint form every token step's is. It is the
    assertion's `aud`.
  - `signedBy` is exactly `kind`, `"credentials-api"` alone, and `serviceAccount`,
    `NAME@PROJECT.iam.gserviceaccount.com` with `NAME` and `PROJECT` each 6 to 30 lowercase
    letters, digits and hyphens, starting with a letter and not ending with a hyphen. No member
    names an address.
  - `subject` is the administrator the service account acts as: an address of at most 254
    bytes, a local part of 1 to 64 letters, digits and `.` `_` `+` `-`, an `@`, and a domain of
    dot-separated labels of letters, digits and hyphens.
  - `requestScope` is one or more of the Admin SDK's read-only scopes, each once, separated by
    single spaces: `…/auth/admin.directory.user.readonly`, `…/auth/admin.directory.group.readonly`,
    `…/auth/admin.directory.group.member.readonly`,
    `…/auth/admin.directory.rolemanagement.readonly` and `…/auth/admin.reports.audit.readonly`
    (`…` is `https://www.googleapis.com`). Any other scope is refused at load;
    `admin.directory.user.security` among them, since it also deletes a user's tokens.
- **What adapter-http is handed.** `--token-endpoint=E --signed-by-service-account=SA
  --token-subject=S --token-scope=SCOPES`, in place of `--client-id` and the other credential
  flags.

| Flag | From |
|---|---|
| `--token-endpoint` | `endpoint` |
| `--signed-by-service-account` | `signedBy.serviceAccount` |
| `--token-subject` | `subject` |
| `--token-scope` | `requestScope` |

- **The flow.** At each token request: an access token of the compute's own identity from the
  metadata server, `GET /computeMetadata/v1/instance/service-accounts/default/token` at the
  link-local literal built into the adapter, under every rule the identity token above is asked
  under; then `POST https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/SA:signJwt`
  under that token, the address built in, for the claims `iss` the service account, `sub` the
  subject, `scope` the scopes, `aud` the token endpoint, and `iat` and `exp` five minutes apart;
  then the token request, `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer` and
  `assertion` the signed JWT. A signed JWT whose claims are not the ones asked for is not sent.
  The metadata token and the signed JWT are held in the memory of the one run, and written
  nowhere. The live credentials file holds `sealKey`, as the metadata form's does, and nothing
  else is needed in it.
- **Failures.** Anything before the token request is the no-credential sentence, and no token is
  requested; a 429 or 503 of the metadata server or the credentials API is a throttled answer.
- **Paths that name a Workspace object.** From this version an http path may carry, in place of
  `{id}`, `{numericId}` (1 to 32 ASCII digits) or `{alnumId}` (1 to 64 lowercase ASCII letters
  and digits), a whole segment, at most one placeholder of any kind in a path. `{id}` keeps
  taking a GUID alone. An address is never a path segment: a request names one in a query
  member (`users?customer=my_customer&query=email:…`, `groups?userKey=…`).
- **Upgrading.** A file of version 32 or earlier loads and derives its sources as before. Under
  an earlier version `signedBy` is refused by name, and a binding with `{numericId}` or
  `{alnumId}` is refused at start. A gateway older than this one refuses a version-33 file by its
  version.

## A platform that keeps no payload (engine version 22)

Version 22 adds a platform's optional `artifact` member
([ADR-0028](../adr/0028-payloads-a-gateway-does-not-keep.md), SPEC.md §1.2a, `artifact`, §1.3a,
and §6, "Payloads a gateway does not keep", gateway #422): a platform whose sources return
results the operator should not hold beyond the call.

```json
"warehouse-east": {
  "binding": "postgres@sha256:…",
  "credentials": {"history": {"file": "/run/secrets/east-history"}, "live": {"file": "/run/secrets/east-live"}},
  "user": "engine-east",
  "artifact": "not-retained"
}
```

- **The form.** The one string `"not-retained"`, which is the receipt member's value too.
  Anything else — another string, another case, `null` or another type — is refused naming the
  platform and the form, quoting nothing of the value. Absent means every payload is kept, as
  before the member.
- **What it changes.** The platform's `history` and `live` sources, of every shape (`airbyte`,
  `mcp`, `http`). An acquisition answers `result` as before and its receipt's `resultDigest` is
  the digest of those bytes; nothing is written under the store's `artifacts/`, and the version
  3 receipt carries `artifact: "not-retained"` under the signature. A gateway minting version 2
  receipts refuses such an acquisition, since only version 3 can say so. The response is the one
  place the bytes are handed out: a caller that needs them later keeps them, and may give them
  to `gateway verify --artifacts <dir>`, which re-digests them.
- **When the file is loaded** (`serve`, `connect`, `connect --replace`, `posture`), the member is
  refused at a version before 22, and on a platform that sets `write: true`, since `/act` and its
  recovery read an action's result back from the store. It is allowed beside `mcp`, `scope`, a
  `grant` and a delegation, none of which changes what is kept.
- **`connect --replace`** keeps the member as written, since an entry written without it would
  keep the payloads the operator chose not to hold, and refuses a replacement that sets
  `--write` before anything is asked. `connect` has no flag for it: write it in the file, at
  version 22.
- **`/posture`** reports nothing of it.

A receipt with the member verifies `ok` with the observation `artifact-not-retained` where no
bytes for it are there; bytes that are there, in the store or supplied, are re-digested, and
other bytes are `artifact-mismatch`. A verifier written before the member reports
`artifact-missing` for it (SPEC.md §1.3a).

**Removing a kept payload** is `gateway remove-artifact`, not this member: SPEC.md §6.

**Upgrading.** A version 21 file loads unchanged under a gateway of this version. To stop
keeping a platform's payloads, raise `engineVersion` to `"22"` and add `artifact` to the
platform; a gateway older than this one refuses a version-22 file by its version. Payloads the
platform kept before stay where they are.

## Measuring the sandbox at the start (engine version 23)

Version 23 adds the optional `measureSandboxAtStart` member, `true` or `false` and nothing else
([ADR-0030](../adr/0030-the-engine-image-carries-the-sandbox-launcher.md), gateway #385). With
it `true`, `serve --config`, once it knows it can switch to every source's user and before it
loads an identity, opens a witness or makes the store, probes each source's sandbox as that
source's user: the probe a launch takes, one source at a time, each under a launch's own twelve
seconds, so the start is bounded by twelve seconds a source. The engine does not start where a
launch of the source would be refused:

- a probe that gives no report: `source <name>: its sandbox check as its user gave no report:`
  and the cause, the path an operating-system error carries left out;
- a restricted mode measured as not enforced: `source <name>: <mode> is not enforced under
  <backend>:` and the helper's reason, `sandbox-not-enforced: no usable filesystem sandbox
  backend` for one;
- a source the configuration does not wrap, which under version 13 and later is none.

Each such source is named, in name order, on one line that begins `start:
measureSandboxAtStart:` and ends `the engine does not start`, and the process exits 1 with
nothing made. Every other source passes as it launches: `enforced`, `partial` (Landlock's
measured limits, or bubblewrap with a local socket seen reachable), and `danger-full-access`,
which claims no boundary and which the operator chose. The start then prints `start:
measureSandboxAtStart: measured` and, for each source, its name, mode, backend and state, and
serves. A completed probe is kept for the source, as a posture report's is, so each launch
after the start is bound to the posture the start measured; a change on the host after the
start takes effect at the next start. Absent or `false`, the start does what it did before:
it measures nothing, and each launch probes and refuses on its own. `gateway posture --config`
is unchanged and is still the check that says why.

**Upgrading.** A version 22 file loads unchanged under a gateway of this version. To have the
start refuse a host that cannot enforce the sandbox, raise `engineVersion` to `"23"` and add
`"measureSandboxAtStart": true`; a gateway older than this one refuses a version-23 file by its
version, and a file of version 22 or earlier with the member is refused by name.

## The storage kind (engine version 24)

Version 24 adds the optional `storage` member
([ADR-0032](../adr/0032-a-configuration-names-its-storage-kind.md); the operator's page is
[postgresql-store.md](../postgresql-store.md)). Without it the filesystem kind keeps the store and
the registry at `store` and `registry`, both required, exactly as before. With it the PostgreSQL
kind keeps both, and `store` and `registry` are not given:

```json
"storage": {
  "kind": "postgresql",
  "connection": { "file": "/run/secrets/gateway-store-url" },
  "connections": 4,
  "operationSeconds": 30
}
```

| Member | Value | Refused |
|---|---|---|
| `kind` | `postgresql` | any other value |
| `connection` | exactly one of `file`, an absolute path held as the seed's file is, or `environment`, a variable's name matching `^[A-Z_][A-Z0-9_]{0,127}$` | both, neither, any other member |
| `connections` | integer, 1 to 64; 4 without it | outside the range, not an integer |
| `operationSeconds` | integer, 1 to 600; 30 without it | outside the range, not an integer |
| `startWaitSeconds` | integer, 1 to 3600, from version 25; without it the start does not wait (below) | outside the range, not an integer, at version 24 |
| `instances` | `"one"` or `"several"`, from version 26; `"one"` without it (below) | any other value, not a string, at version 25 or earlier |

The connection string itself is never written in the file. A file is read, at most 4096 bytes, at
the start and by `gateway export --config`; a variable is read at the start and removed from the
process's environment. A source's environment never takes it: a source is given its HOME, its
platform's own pairs and PATH (above). `gateway mcp` is denied the file and refuses to start where
its environment holds the variable.

Refused by name, `engine configuration: …`: `storage` in a file of version 23 or earlier; `store`
or `registry` beside `storage`; and, with `storage`, what reads the store on disk, with the error
`storage-kind-unsupported` naming it: `witness`, a platform's `write` and
`descriptorStatements` (postgresql-store.md, "Not available with this kind yet", has the commands
and routes refused besides). A platform's `scope` is taken with `storage`: the kind keeps each
scope identifier's rows apart, and a session's receipts are of one scope (postgresql-store.md,
"Scope identifiers"; ADR-0033). No engine version is added for it: no member is added, and a
gateway before it refuses `scope` beside `storage` by name, so it refuses such a file rather than
reading it otherwise.

**Upgrading.** A version 23 file loads unchanged under a gateway of this version. To move to the
PostgreSQL kind, run `gateway store migrate`, raise `engineVersion` to `"24"`, replace `store` and
`registry` by `storage`, and start; a gateway older than this one refuses a version-24 file by its
version. Moving a store from one kind to the other is not supported: the kind starts empty.

## A start that waits for the start lease (engine version 25)

Version 25 adds `storage`'s optional `startWaitSeconds`, an integer from 1 to 3600
([ADR-0035](../adr/0035-several-instances-on-one-postgresql-database.md), option D; the
operator's page, [postgresql-store.md](../postgresql-store.md), "One instance per database", has
the hand-over it serves):

```json
"storage": {
  "kind": "postgresql",
  "connection": { "file": "/run/secrets/gateway-store-url" },
  "startWaitSeconds": 300
}
```

With it, a start that finds another instance's start lease live does not exit: it listens on
`listen` at once, answers every request `503` with `Retry-After` and one fixed body, and reads the
lease every renewal interval, by the database's clock, holding no row and writing nothing. Once the
lease is released or has expired it takes it, makes the start's checks again and serves on the
listener it bound. Where `listen` is in use, as it is by the instance it takes over from on the
same host, it waits without listening, nothing answering on its behalf, and binds `listen` once it
holds the lease; any other failure to bind ends the start. When the wait runs out, the start is
refused as before the member: exit 1, `start-lease-held`. A read of the lease that fails for the
moment (a connection broken or refused, the server shutting down or at its connection limit, a
serialization failure or a deadlock) is read again within the same wait, and at its end that
failure is the start's. Without the member the start is refused at once, as at version 24.

The stop is the same at every version of the kind: a stop signal closes admission (each
acquisition is answered `503` with `Retry-After`), lets what was admitted finish within
`operationSeconds`, and then releases the lease.

Refused by name, `engine configuration: …`: `storage.startWaitSeconds` in a file of version 24
(`is a version-25 member`), outside 1 to 3600, or not an integer.

**Upgrading.** A version 24 file loads unchanged under a gateway of this version. To have a start
wait for the instance it replaces, raise `engineVersion` to `"25"` and add `startWaitSeconds` to
`storage`; a gateway older than this one refuses a version-25 file by its version.

## Several instances on one database (engine version 26)

Version 26 adds `storage`'s optional `instances`: `"one"`, one instance per database, as without
it, or `"several"`, instances serving one database beside one another
([ADR-0035](../adr/0035-several-instances-on-one-postgresql-database.md), option C; the operator's
page, [postgresql-store.md](../postgresql-store.md), "Several instances on one database", has what
the operator gives each instance and how a session's calls reach the instance that holds it):

```json
"storage": {
  "kind": "postgresql",
  "connection": { "file": "/run/secrets/gateway-store-url" },
  "instances": "several"
}
```

With `"several"`, a start takes a row of the start lease of its own beside the instances serving,
where each signs under the same key id and names the same authority, and is refused beside an
instance of the one-instance mode, which is refused beside it in turn. Each session is held by the
instance that admitted its first call; another instance answers a call into it, or a seal of it,
`409`, before the source runs. The start says so on standard error:

```text
start: instances serve this database beside one another (storage.instances "several"): each session is held by the instance that admitted its first call, and another instance answers a call into it 409
```

The member needs schema version 6 (`gateway store migrate`, every instance stopped), as every
start of this version does.

Refused by name, `engine configuration: …`: `storage.instances` in a file of version 25 or earlier
(`is a version-26 member`), or a value other than `"one"` or `"several"`.

**Upgrading.** A version 25 file loads unchanged under a gateway of this version. To have
instances serve one database beside one another, stop every instance, run `gateway store
migrate`, raise `engineVersion` to `"26"` on each, add `"instances": "several"` to `storage`, and
start them; a gateway older than this one refuses a version-26 file by its version.

## Caller scope identifiers (engine version 27)

Version 27 adds `identity`'s optional `callerScopes`, by which a caller is held to the scope
identifiers its verified identity allows
([ADR-0037](../adr/0037-a-caller-is-held-to-the-scope-identifiers-its-token-and-the-configuration-allow.md);
SPEC.md §6, "Caller scope identifiers"). Two keys must agree: the caller's token names the scope
identifiers it is for in its `scope_ids` claim, and the configuration grants each subject what
it may be granted.

```json
"identity": {
  "issuer": "https://login.example",
  "audience": "gateway:acme",
  "keys": "/etc/gateway/issuer-keys.json",
  "callerScopes": {
    "analyst-a": ["équipe-a"],
    "analyst-ab": ["équipe-a", "équipe-b", "unscoped"],
    "operator": "unscoped",
    "runner": "installation"
  }
}
```

- **The claim**, `scope_ids`: 1 to 256 strings, each once, each a scope identifier or the
  marker `"unscoped"`, which names the sources of no scope identifier. The Runner reads the
  same claim, so one issuer's token means the same at both.
- **An entry**: `"unscoped"`, the sources of no scope identifier alone; `"installation"`, every
  scope identifier and the sources of none, for an installation's own caller such as a Runner;
  or 1 to 256 strings, each once, each a scope identifier or `"unscoped"`. A subject with no
  entry is `"unscoped"`.
- **What a token reaches.** A token with a claim reaches the claim's scope identifiers, and the
  sources of no scope identifier only where the claim holds `"unscoped"`; each member must be
  one the entry grants, or the token is refused `401`, never narrowed. A token with no claim
  reaches every source where its subject is `"installation"`, the sources of no scope identifier
  where the entry is `"unscoped"` or holds the marker, and is refused `401` where the entry is a
  list without it. The two `401`s are one sentence, `the token's scope_ids names a scope
  identifier the configuration does not grant its subject`; a claim out of form is `the token's
  scope_ids is not 1 to 256 scope identifiers, each once`. Neither names a scope identifier or
  the subject. A request under a delegation reaches the sources of no scope identifier where
  its subject's claimless token would, and never a scope identifier: the chain's subject is the
  issuing host's statement, and a host does not widen it.
- **The routes.** `/acquire` answers a scope identifier the caller does not reach with the
  wrong-scope sentence, before anything runs (and a source no platform gives, to a caller that
  does not reach every source, with the same sentence), and on the PostgreSQL kind opens the view of the
  scope identifier both checks held, never one the body alone names. `/act` is refused `403`
  (`refusedAt: "scope-identifier"`) to a caller that does not reach the sources of none, since a
  write source is of none, before its body is read. `/seal` answers a session of a scope the
  caller does not reach `no such session`. `/verify` is served to a caller that reaches every
  source, and, where no source is fixed to a scope identifier and the store holds no session of
  one (a scope since removed from the configuration counts), to one that reaches the sources of
  none; otherwise `403`. `/registry` and `/publickey` stay open and whole.
- **What `/registry` tells anyone.** A seal of a scoped session names its scope by an unkeyed
  digest over the scope identifier and the session's id (SPEC.md §3). Anyone who can reach
  `/registry` and guesses a scope identifier can test it against each sealed session and learn
  which sessions are of that scope, with their final counts and seal times (never a receipt).
  Where tenants must not learn of one another's sessions, choose scope identifiers with at
  least 128 bits of entropy (22 or more characters drawn at random from a 64-character
  alphabet, for example), and keep the names people read outside the identifier.
- **`"unchecked"`** reads no claim: every caller reaches every source, as before the member.
  Without `identity` there is no caller to hold and every request reaches every source.

The check is the default, at every version: a configuration with `identity` and no
`callerScopes`, a file of version 26 or earlier included, holds every caller to the sources of
no scope identifier. Wherever `identity` is configured, or some platform is fixed to a scope
identifier, the start says which rule holds, one of:

```text
start: caller scope identifiers are checked: a request is held to the scope identifiers its token's scope_ids names and identity.callerScopes grants its subject
start: caller scope identifiers are checked: a request is held to the scope identifiers its token's scope_ids names and identity.callerScopes grants its subject; no platform is fixed to a scope identifier, and a token whose scope_ids names one the configuration does not grant its subject is refused 401
start: identity.callerScopes is "unchecked": no caller is held to scope identifiers, and every caller reaches every source
start: no identity is configured, so no caller is held to scope identifiers: every request reaches every source
```

and `/posture` reports it (`caller-scope-identifiers`, above). The receipt names its caller as
before and does not record the claim: its `scope` is the identifier the request was held to.

Refused by name, `engine configuration: …`: `identity.callerScopes` in a file of version 26 or
earlier (`is a version-27 member`), a value of another form, a member whose name is empty, and,
from version 27, a platform whose `scope` is `"unscoped"`, the marker, which no caller is
granted as a scope identifier (a file of version 26 or earlier loads such a platform as before,
and only an `"installation"` caller reaches it).

**Upgrading.** A configuration with `identity` and a platform fixed to a scope identifier
serves its scoped sources after the upgrade only to the callers `callerScopes` grants. Before
upgrading, raise `engineVersion` to `"27"` and write the entries, issuing tokens whose
`scope_ids` names what each caller is for, or write `"callerScopes": "unchecked"` to keep the
behavior before. A gateway older than this one refuses a version-27 file by its version.

The same holds with `identity` and no scoped platform. A token whose `scope_ids` names a scope
identifier is refused `401` on every route but `/registry` and `/publickey` (which take no
token) and a witness's `/witness/*` (which reads no claim and carries no scope data) unless its
subject's entry grants it. That happens when the issuer is shared with the Runner and a
caller's tokens gain `scope_ids` for the Runner: the caller is locked out of this gateway after
the upgrade. Before upgrading such a configuration, write an entry for each such subject
granting what its tokens name (or `"installation"` for a Runner), have the issuer leave the
claim out of the tokens it issues for this gateway's audience, or write
`"callerScopes": "unchecked"`. The start line and `/posture` say the rule in this case too.

## The MCP server on scoped platforms (engine version 28)

`mcp` takes one of two members, or neither, that let the MCP server serve platforms fixed to a
scope identifier ([ADR-0038](../adr/0038-the-mcp-server-on-platforms-fixed-to-a-scope-identifier.md);
[mcp-server.md](mcp-server.md), "Scope identifiers"):

- `scope`, a scope identifier of §1.2a's form: the server serves the live tools of the
  platforms fixed to it and no other, and every forward names it. It runs over `--http` and
  `--stdio`.
- `scopeFrom`, the string `"caller"`: the server serves every platform, and each forward names
  its tool's platform's scope identifier, or none for a platform of none. It needs `identity`
  with `callerScopes` checked, and runs over `--http` alone. Its listing is bounded per scope
  identifier (ADR-0041), so it holds up to (the number of scope identifiers + 1) × 8 MiB of
  described tool entries, with no cap of its own.

In both, a caller is listed, and may call, only the tools of the sources its token reaches
("Caller scope identifiers (engine version 27)", above); any other tool is answered as one the
server does not hold. No tool's arguments name a scope identifier. In both, every live tool of
a platform the server serves is declared effect `read-external` in its binding's
`toolTaxonomies`
([ADR-0044](../adr/0044-a-scoped-mcp-front-serves-only-live-tools-declared-read-external.md)):
under `scope` each platform fixed to it, under `scopeFrom` every platform, those of no scope
identifier included. The shipped postgres binding, whose `execute_sql` is an act, is not served
by either form.

```json
"engineVersion": "28",
"platforms": { "records": { "binding": "records@sha256:…", "scope": "team-a" } },
"mcp": { "listen": "127.0.0.1:8788", "scope": "team-a" }
```

Refused by name, `engine configuration: …`, quoting nothing of the value:

- either member in a file of version 27 or earlier (`is a version-28 member`);
- both members (`two forms of the server`);
- a `scope` out of the form, or `"unscoped"`, the caller scope marker, which no platform is
  fixed to;
- a `scopeFrom` other than the string `"caller"`;
- `scopeFrom` without `identity`, or with `callerScopes: "unchecked"`, where every caller
  reaches every source;
- a platform's `scope` beside an `mcp` of neither member, as before.

`gateway mcp` refuses to start a server whose `scope` no platform is fixed to, and one of
`scopeFrom` over `--stdio`, where one token is given at start for the life of the process.
`gateway mcp` and `serve` both refuse to start, and `connect` refuses to write the platform,
where a server of either form would serve a live tool declared `propose` or `act`, or one with
no declaration: `platform <name>: tool "<tool>" is not declared effect read-external`, naming
no scope identifier. `serve` refuses the same of a platform fixed to a scope identifier with no
`mcp` at all ("A platform's scope (engine version 20)", "Live tools are reads"; ADR-0046).

**Upgrading.** A file of version 27 or earlier loads as before, and an MCP server without
either member serves as before, with one change in a file of any version: under `identity`
with `callerScopes` checked, the server's HTTP transport refuses `401`, before any session, a token whose `scope_ids` claim is
out of form or wider than its subject's entry, with the signer's sentence. Before, that token
was refused at the forward, by the signer. To serve a scoped platform over MCP, raise `engineVersion` to
`"28"` and add one member. A gateway older than this one refuses a version-28 file by its
version. From ADR-0044 a version-28 file whose server names `scope` or `scopeFrom` and serves
a live tool not declared `read-external` no longer starts. If the tool only reads, declare it
`read-external` in the binding and approve it again with `connect --replace`. Otherwise pin a
binding whose live operation names reading tools alone, or serve the platform with no scope
identifier behind an `mcp` of neither form.

## A read-only Cloud Asset Inventory source (engine version 29)

A binding's live operation of the `gcp-asset` shape ([ADR-0039](../adr/0039-a-read-only-asset-inventory-connection-for-configuration-drift.md)
and its Amendment; adapters/README.md, "adapter-gcp-asset") is derived as `<platform>/live`,
served by adapter-gcp-asset as the platform's user with its live credentials file, under the
source sandbox. Its envelope and receipt are the http shape's.

```json
"engineVersion": "29",
"platforms": { "inventory": { "binding": "inventory@sha256:…", "user": "engine-inventory",
  "credentials": { "live": { "file": "/etc/gateway/inventory-live.json", "tokenSource": { "kind": "metadata" } } } } }
```

- `credentials.live.tokenSource`, required on a platform of the shape and refused on any other:
  `{"kind": "metadata"}` or `{"kind": "key"}`.
- `artifact`: the shape keeps no payload by default, as `"not-retained"`; `"retained"`, a
  version-29 value that only a platform of the shape takes, keeps them.
- `scope`, as on any platform: at most one scope identifier; a caller's reach to it is checked
  before the parent.

Refused by name, `engine configuration: …`, quoting nothing of the value: the shape in a file
of version 28 or earlier; `write: true`; no `tokenSource`, one of another kind or form, or one on
another operation or another shape's platform; a `tokenStep`, a `grant`, an `endpoint`; an
`environment` setting `ADAPTER_GCP_ASSET_SEALED_TOKEN`; `artifact: "retained"` on another shape's
platform.

**At the start**, before anything is served, each gcp-asset source obtains its sealed list
token, which the adapter answers only once both tokens are held to their scopes and the write
check passed; the start says each source's token source, the check, its artifact and
`resource-bindings: checked` or `unchecked`. A refusal, or a check that did not complete,
refuses the start. **After it**, every token obtained runs the check again before it is used. A
read-only refusal there, or on a page, closes the source: `serve: source <name> closed on a
refresh|page: <refusal>` on stderr, once, and every acquisition after it is refused until the
engine restarts. A check that could not finish is no refusal: where a call brought back no
answer (the adapter's own time ended, handed to it as `--timeout`, what is left of the
acquisition's time less a margin; or the request's time ended, or the connection failed), the
adapter exits 1, and the start is refused or that acquisition fails, with the source left
serving (SPEC.md §6, "A read-only refusal"). An answer other than a grant or none refuses. A request naming a parent outside the configuration is refused
`parent-not-configured` before any token is obtained.

**`/posture`** adds the line `read-only-credentials` (enforced where every gcp-asset source
serves `IAM_POLICY`, partial otherwise, with its counts of sources, of those serving
`IAM_POLICY` and of those closed among the sources the caller reaches) and `readOnlySources`, one entry
per source within the caller's reach: `source`, `tokenSource`, `writeCheck` (`passed`,
`refused`, `not-run`), `state` (`serving`, `closed`, `not-started`), `artifact`,
`resourceBindings`, and `refusal`, `null` or `{reason, on}`; the refusal's subject is said on
stderr and in the acquisition's answer only. `enforced` and `resourceBindings: "checked"` cover
a role granted at a resource to the source's own principal or to `allUsers` or
`allAuthenticatedUsers`; a grant through a group, or on an asset type the source does not serve,
is not seen (adapters/README.md, "Resource bindings").

`gateway connect` refuses a gcp-asset binding, whose `tokenSource` it has no flag for: write the
platform's entry by hand.

**Upgrading.** A file of version 28 or earlier loads as before, and nothing about the other
shapes changes. To configure the shape, raise `engineVersion` to `"29"`. A gateway older than
this one refuses a version-29 file by its version.

## Grants through groups on a gcp-asset source (engine version 30)

A gcp-asset live operation may set `groups` ([ADR-0039](../adr/0039-a-read-only-asset-inventory-connection-for-configuration-drift.md),
Amendment (gateway #496); adapters/README.md, "Grants through groups"): each `group:` member of
a binding whose role is outside the read-only list, on an `IAM_POLICY` page, is resolved with a
third token of scope `cloud-identity.groups.readonly`, and the principal found in one refuses
`credential-bound-at-resource` and closes the source, as a direct binding does.

```json
"live": {"shape": "gcp-asset", "licence": "Apache-2.0", "parents": ["projects/example-project-1"],
  "assetTypes": ["run.googleapis.com/Service"], "contentTypes": ["RESOURCE", "IAM_POLICY"],
  "groups": {"resolve": true, "depth": 2, "members": 5000, "unresolved": "serve"}}
```

- `resolve`, required: `true` resolves; `false` is as the member absent.
- `depth`, 0 to 4 (default 2): the nested levels read below a group a binding names.
- `members`, 1 to 50 000 (default 5 000): the memberships read for one acquisition; at most 64
  groups are read, and the read takes at most half of the adapter's `--timeout`, and 10 s.
- `unresolved`: `"serve"` (the default) serves a page with a group unresolved and reports it;
  `"refuse"` refuses it `group-unresolved: <reason>`, which fails that acquisition as a failed
  source and does not close the source.

Refused by name, quoting nothing of the value: the member in a file of version 29 or earlier
(`names groups, a version-30 member`), `resolve` false among them; a member other than these
four; `resolve` not a boolean; a setting out of its range or form, whether `resolve` is true or
false.

**At the start**, a source that resolves groups says so beside its other lines: the third token
and that its read-only property rests on its scope, since no write check covers the directory;
the bounds; the `unresolved` setting; that the principal reads only the memberships the
operator lets it view, which the gateway neither grants nor verifies; and what stays outside
(nesting past the depth, `domain:` members, principal sets and pools, groups it cannot read,
deny policies, a membership removed in the directory while IAM still holds its grant). A source
that does not opt in says what it said before. A grant of the third token beyond its scope
refuses the start or the refresh `credential-scope-unknown`, as the others' do.

**`/posture`**: each `readOnlySources` entry gains `groupBindings`, `"off"` where the binding
does not opt in, `"checked"` where it does and every group met since the start was resolved,
`"unchecked"` once one was not, or where the platform serves no `IAM_POLICY`; with
`groupsUnresolved`, the groups left unresolved since the start, and `groupReason`, the last
one's reason (`unreadable`, `unavailable`, `malformed`, `member-type`, `depth`, `members`,
`groups`, `time`, `no-token`), or `null`. It stays `"unchecked"` until the engine restarts. A
page refused under `"refuse"` counts as a group unresolved. No group's name, email or member is
reported. The `read-only-credentials` line is `partial` while any source it is judged over has
`groupBindings` `"unchecked"`; `"off"` changes nothing, and which sources the state is judged
over is as before. Where the caller reaches a source that resolves groups, its text adds how
many it reaches resolve them and how many of those are unchecked.

**Upgrading.** A file of version 29 or earlier loads as before, and a source without `groups`
is started with the command line, says the lines and reports the posture it did, but for
`groupBindings: "off"`, `groupsUnresolved: 0` and `groupReason: null` on its entry. To resolve
groups, raise `engineVersion` to `"30"`, add the member, and let the source's principal view the
memberships of the groups that matter. A gateway older than this one refuses a version-30 file
by its version.

## Path templates and links on an http source (engine version 31)

An http live operation's `paths` may hold templates, and a caller may follow the next page or
the delta an endpoint hands out by its URL
([ADR-0040](../adr/0040-path-templates-and-links-on-an-http-source.md); adapters/README.md,
"adapter-http"). Both exist for an API, a directory's among them, that names a member collection
by an object's id and pages by absolute links; the shipped `microsoft-graph` binding is one
([catalog/README.md](../../catalog/README.md#microsoft-graph)).

```json
"paths": ["/v1.0/groups", "/v1.0/groups/delta", "/v1.0/groups/{id}/members"]
```

**A path template** carries one placeholder, `{id}`, as a whole segment. It admits a request's
path that equals it in every other segment and has, in that one, a GUID: 36 characters, hex
digits of either case with hyphens at the 8-4-4-4-12 places, and nothing more — no brace,
percent sign, dot, slash or other character, so a template admits no path that reaches
another resource than a member of the collection it names. The template is otherwise held to
every rule of a path above, with a GUID in its place, and passed to `adapter-http` as written
in `--paths=`, the bound on that word included. Refused by name when the binding is loaded: a
path with two placeholders (`carries more than one {id} placeholder`), with `{id}` within a
segment, or with any other brace; a `checkPath` that is a template, which a check would have
no GUID to fill; and a template in a file of version 30 or earlier (`names a path template,
paths[N], a version-31 member; engineVersion 30 has none`), at the start and at `connect`,
which names the version to raise to and does not raise it, since the version a file states is
the reading its author reviewed.

**A link** is an acquisition's `{"link": "<absolute URL>", "method"?, "body"?}`, in place of
`path` and `query`: exactly one of `path` and `link`, and no `query` beside a link. The link
is admitted when its scheme and host are the binding endpoint's, compared without regard to
case; its port is the endpoint's, the scheme's default standing for an absent one; it carries
no user and no fragment; its path, as written, is the endpoint's path followed by a path
`paths` admits, fixed or a template's with a GUID, with no percent sign, backslash, dot segment
or empty segment; its query holds only the characters RFC 3986 gives a query, a `%` only
before two hex digits; and it is at most 16 KiB of visible ASCII. The request sent goes to the
binding's endpoint, with the link's path and query byte for byte. A refusal is one fixed
sentence naming the rule and nothing of the link, since a link carries the endpoint's paging
or change token; for a source with a token step the engine refuses such a request before it
obtains a token (`the request does not name a path and a method the source's operation allows;
no token was requested`), as it does a path the binding does not name. A link reaches nothing a path and a query could not, so it is not a member of
the configuration and no version gates it; a gateway older than this one refuses the member
by name.

**What the receipt records.** The `statement` is of the request as sent. A request that named
a path commits to `{"method", "path", "query"?, "body"?}` as before, a template's path with its
GUID; one that named a link commits to `{"method", "path", "rawQuery"?, "body"?}`, the path
under the endpoint and the link's query, as sent, not to the link: its scheme, host and port
are the endpoint's, which the acquisition's `endpoint`, the URL sent to without the query,
names as the binding writes it. A next page followed by its link and the same page asked by
`path` and `query` are therefore two statements, one with `rawQuery` and one with `query`.

**Paging by link.** The caller sends the first page by `path` and `query`, takes
`@odata.nextLink` from the page it was answered and sends it as `link`, in the same session,
until a page names none; a delta round ends with `@odata.deltaLink`, which the caller keeps
and sends as `link` for the next round. Each page is a receipt as any other; `/seal` after the
last fixes the count. A delta token the endpoint no longer holds is answered `410`,
`source_reference_expired` ("An expired reference", above), and the caller starts the round
again from the delta path; a `429` or a `503` is answered with its class and `Retry-After`
("A throttled answer", above).

**`$` in a query object.** A `query` object's members are sent form-encoded with their names
sorted, as before, but `$` is now sent as written, where it was sent `%24`: an OData endpoint
reads `$select`, `$top` and `$filter` by those names, and `$` is a character RFC 3986 gives a
query. A `%` written in a value is still sent `%25`, so every other byte is sent as before.

**Upgrading.** A file of version 30 or earlier loads as before, and a binding with no template
derives the sources it did; a request naming a `query` member with `$` in it reaches the
endpoint with `$` rather than `%24`, and its statement is unchanged. To bind templates, raise
`engineVersion` to `"31"`. A gateway older than this one refuses a version-31 file by its
version.

## A receipt sink (engine version 35)

Version 35 adds the optional `receiptSink` member
([ADR-0049](../adr/0049-a-receipt-is-acknowledged-by-the-sink-before-it-is-answered.md),
SPEC.md §6a, gateway #505). Each receipt `/acquire` mints is delivered to this one endpoint,
and acknowledged by it, before `/acquire` answers.

```json
"receiptSink": {"url": "https://audit-log.example/receipts", "payload": false}
```

- `url` is required: 1 to 2048 bytes, absolute, with no user, query or fragment. It is
  `https`, or plain `http` only to a loopback address written as one: `127.0.0.1` (any of
  127.0.0.0/8) or `[::1]`. A name, `localhost` included, is refused for plain http, so a
  plain-http sink is reached without a name being resolved.
- `payload` is optional, `true` or `false`, and `false` when absent. With `true` the delivery
  carries the result beside its digest, except for a platform whose `artifact` is
  `"not-retained"`: its results are never carried.
- Any other member is refused by name. The member under version 34 or earlier is refused as
  `receiptSink is a version-35 member; engineVersion <n> has no receiptSink`. A refusal
  repeats no value of the url.

Without the member, `/acquire` answers as it did before. With it, a sink that does not
acknowledge refuses the acquisition `503` with `code` `receipt_not_forwarded`. The receipt is
held, and the session's next acquisition and its seal deliver it first and are refused until
it is acknowledged. The delivery, acknowledgment, retry and deadline rules are SPEC.md §6a's.
The member names no credential: the sink checks each receipt against the gateway's public
key, which it pins as any verifier does.

`gateway seal-open --config` delivers each stored receipt of a session to the sink before it
seals the session. `gateway seal-open` given the store by its flags (`--store`, `--seed`,
`--registry`, `--authority`) cannot tell whether the gateway that wrote the store forwarded
receipts, so it refuses, exit 1, with a fixed sentence: `a store given by its flags may have
been written by a gateway that forwards receipts to a receipt sink, and a seal here would not
deliver them first; give --config, which names the sink, or --no-sink for a store with no
receipt sink; nothing was sealed`. With `--no-sink` it seals as before and first writes on
stderr `seal-open: --no-sink: delivery to a receipt sink was skipped; no receipt was delivered
before a seal`. `--no-sink` beside `--config` is a usage error.

## A signer in a key service (engine version 36)

From engine version 36, `signingKeyVersion` names one Ed25519 key version in Cloud KMS
(`EC_SIGN_ED25519`), which signs the gateway's receipts, seals and descriptor statements in place
of the seed's key ([ADR-0050](../adr/0050-an-external-signer-in-a-key-service.md), #431).

```json
"signingKeyVersion": "projects/example-project/locations/global/keyRings/receipts/cryptoKeys/gateway/cryptoKeyVersions/1",
"signingPublicKey": "<the key version's Ed25519 public key, 64 lowercase hexadecimal characters>"
```

- **The pin.** `signingPublicKey` is required whenever `signingKeyVersion` is set, and given only beside it: `signingKeyVersion` without it is refused by name at configuration load. A key version that answers another public key signs nothing.

- **Form.** The value is a resource name of exactly that form: `projects/<project>/locations/<location>/keyRings/<ring>/cryptoKeys/<key>/cryptoKeyVersions/<n>`. Under an earlier version the member is refused by name, and out of form it is refused before anything is asked. Beside `witness` it is refused: the witness's checkpoints are signed by the seed's key.
- **The seed.** `seed` stays required. With a key service it keys the arguments commitment and signs nothing.
- **At start.** The gateway reads the version's public key once, holds it to the version asked, `EC_SIGN_ED25519`, its CRC32C and one Ed25519 key, and derives its `keyId` from it. The registry's walk must end at that key, as at a seed's. The start line names the version, its protection level and the `keyId`.
- **Calls.**
  - Each receipt and each seal is one `asymmetricSign` at the built-in `https://cloudkms.googleapis.com`.
  - The call is authenticated by the gateway's own access token from the metadata server at its fixed link-local address.
  - One signing is bounded by 5 seconds.
  - A key service that cannot be reached, refuses (a 429 or 503 among the refusals) or answers a signature that does not verify fails the acquisition or the seal with a fixed sentence, and nothing is written.
- **The commands under a key service.** `gateway remove-artifact`, `remove-scope`, `seal-open`, `export` and `connect`'s descriptor capture sign through the key version the configuration names, held to `signingPublicKey`. `gateway rotate-key` stays seed-only and refuses through the registry's walk. A key service's key is rotated by SIGHUP on the file kind. On the PostgreSQL kind, where SIGHUP rotation is refused, `gateway store rotate-key` moves an existing store from the seed to a key version, or from one key version to the next, every instance stopped: the configuration names the next key version, and `--from-key-version` with `--from-public-key` names the one rotated from, or neither for the seed (docs/postgresql-store.md, "Rotating the signing key"; ADR-0050, decision 3(a); #563).

## Seals at the receipt sink (engine version 37)

Version 37 adds `receiptSink`'s optional `seals` member
([ADR-0049](../adr/0049-a-receipt-is-acknowledged-by-the-sink-before-it-is-answered.md),
amendment of 2026-11-19; SPEC.md §6a). With it on, each seal is delivered to the same sink,
after every receipt of its session, and acknowledged by its digest.

```json
"receiptSink": {"url": "https://audit-log.example/receipts", "seals": true}
```

- `seals` is optional, `true` or `false`, and `false` when absent. A sink of a file without
  it, version 35's among them, is sent receipts alone, as before.
- The member under version 36 or earlier is refused as `receiptSink: seals is a version-37 member;
  engineVersion 36 has no seals`.

With `seals: true`:
- `/seal` answers only once the sink has acknowledged the seal. A seal not acknowledged is
  refused `503` with `code` `receipt_not_forwarded` and the seal's own sentence. The seal is
  in the registry and held: the session's next `/seal` delivers it again, and answers it once
  it is acknowledged.
- A seal made after an interruption, by the start's `sealOpenAtStart` or by `gateway
  seal-open --config`, is delivered after the session's stored receipts, and named while it
  is not acknowledged.
- The store keeps a marker for each seal pending forwarding: on the filesystem kind a file
  under `seal-forwarding/` in the store's root, on the PostgreSQL kind a document of no
  scope. The start, with or without `sealOpenAtStart`, and `gateway seal-open --config`
  deliver each pending seal before they serve or seal. The marker is no part of what
  `gateway verify` reads. The PostgreSQL kind needs no migration for it: the run-time role's
  grants on `gateway.documents` cover it.

## Retention by acknowledgment (engine version 38)

Version 38 adds the optional `retention` member
(docs/adr/0048-retention-by-acknowledgment-and-store-rotation.md, options A1 and R1):

```json
"retention": { "window": 30, "acknowledgedBy": ["<64 lowercase hexadecimal characters>"] }
```

- `window` is a whole number of days, from 7 to 36500; a shorter window is refused at load.
  30 is recommended.
- `acknowledgedBy` is a list of 1 to 4 distinct Ed25519 public keys, each 64 lowercase
  hexadecimal characters: the keys of the external audit log, or of the operator's shipper on
  its behalf, that acknowledges a session it holds. A single string is not read. A key listed
  twice, a key that is not a sound Ed25519 public key, an empty list and a fifth key are
  refused at load, by their place in the list.

**From version 40, a P-256 key** (docs/adr/0053-an-ecdsa-p256-signer-at-a-key-services-hsm-protection-level.md,
§9) is listed in the object form `{"alg": "ES256", "key": "<66 lowercase hexadecimal characters>"}`,
the key its compressed SEC 1 point, beside Ed25519 keys as strings; the list holds 1 to 4 distinct
keys of either algorithm, each held to its own algorithm's key rule. Each case, with the sentence
that refuses it, each beginning `engine configuration: retention.acknowledgedBy[<i>]`:

| Version | Entry | Result |
|---|---|---|
| 38, 39 | a string of 64 lowercase hex | an Ed25519 key |
| 38, 39 | any object | refused: "is an Ed25519 public key, 64 lowercase hexadecimal characters" |
| 40 | a string of 64 lowercase hex | an Ed25519 key |
| 40 | `{"alg": "ES256", "key": <66 lowercase hex>}`, nothing else | a P-256 key; one off the key rule (`02` or `03`, x below p, a point that exists): "is not a sound P-256 public key" |
| 40 | an object without `alg`, with another `alg`, with any other member, or whose `key` is not 66 lowercase hex | refused: "is an Ed25519 public key of 64 lowercase hexadecimal characters, or {"alg": "ES256", "key": <66 lowercase hexadecimal characters>}" |
| 40 | a string of 66 hex, or of any other form | refused, the same sentence |

A bare string of 66 characters is refused: taking it would choose the algorithm from the key's
length, and a compressed point of another curve is 33 bytes too.

With no `retention` member nothing is removed by age, as before; nothing runs on a timer, and
a schedule is the operator's scheduler running the command. A file of version 37 or earlier
with the member is refused by name: `retention is a version-38 member`.

**An acknowledgment line.** The acknowledgment file holds one canonical JSON object per line
(SPEC.md §1.1: members sorted, no whitespace), each ending in a line feed and under 4096
bytes, at most 10000 lines, read whole. Each line has exactly these seven members:

| Member | Value |
|---|---|
| `acknowledgedAt` | when the log acknowledged the seal: UTC, to the second, `YYYY-MM-DDThh:mm:ssZ`; no earlier than the seal's `sealedAt`, no later than the command's clock |
| `finalCount` | the seal's `finalCount`, as the seal record carries it |
| `keyId` | the id of the key the line is signed under, one `acknowledgedBy` lists: the first 32 lowercase hexadecimal characters of the SHA-256 of its 32 raw public-key bytes (as SPEC.md §1.2 derives a key id), or of a P-256 key's 33-byte compressed point |
| `kind` | `"retention-ack"` |
| `sealSignature` | the seal's `signature`, 128 lowercase hexadecimal characters, as the seal record carries it |
| `sessionId` | the session's id, as its receipts and its seal carry it |
| `signature` | Ed25519, 128 lowercase hexadecimal characters, over the bytes `judgment-pack-gateway/retention-ack/1:` followed by the canonical JSON of the object without `signature`; under a P-256 key, ECDSA P-256 SHA-256 over the same bytes, `r||s` with s ≤ (n − 1)/2, in 128 lowercase hexadecimal characters |

**Under a P-256 key** the line has an eighth member, `alg: "ES256"`, inside what it signs, and the
key its `keyId` names must be listed in the object form. A line whose `alg` is not the listed
key's algorithm (an `alg` on a key listed as Ed25519, or a P-256 signature with no `alg`) and a
high-S signature do not verify under the key named; a DER signature and any other `alg` value
are not of the line's form. The vectors are `corpus/retention-ack/*.json`.

A line names a seal by the seal's own `signature` and `finalCount`, copied as the seal record
carries them, so an audit log that holds the seal fills both without computing anything over
it. A line names no scope identifier: the gateway reads the session's scope from its own store,
and `--scope` narrows the call.

A line that is not of this form, names a key `acknowledgedBy` does not list, or does not
verify under the key it names refuses the whole call, as does a file that names one session
twice. A session the store already records as removed is noted, not refused, so a cumulative
file can be given again.

**A worked example, with a synthetic key.** The key below is derived from a seed of 32 bytes
`0x07`, for testing only; nothing should ever be signed under it. Its public key is
`ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c`, and its key id is
`fe812c12f3ab4ce6ac5db69ac352f906`. Configured as
`"acknowledgedBy": ["ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c"]`, a
line acknowledging session `example-session-1`, sealed with `finalCount` 3 and a seal signature
of `ab` repeated 64 times, at 2026-11-20T10:00:00Z, is signed over these bytes (one line, no
line feed; SHA-256 `15f96ff96474c89c31f1675f7f300e42184f3eeb6e34a7d0294f9149726b18b4`):

```text
judgment-pack-gateway/retention-ack/1:{"acknowledgedAt":"2026-11-20T10:00:00Z","finalCount":3,"keyId":"fe812c12f3ab4ce6ac5db69ac352f906","kind":"retention-ack","sealSignature":"abababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababab","sessionId":"example-session-1"}
```

and the line is (followed by one line feed):

```json
{"acknowledgedAt":"2026-11-20T10:00:00Z","finalCount":3,"keyId":"fe812c12f3ab4ce6ac5db69ac352f906","kind":"retention-ack","sealSignature":"abababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababab","sessionId":"example-session-1","signature":"828e0a5478f544ff5e6a083964b1e3b8dce742c8eadc44bb07bb2853b8508dce5b6678b17a0d348310313ccdba19bda520266e11affc462ec2d23191411b8204"}
```

Ed25519 signatures are deterministic, so an implementation that signs the same bytes under
the same key produces this signature exactly. `go/retain_test.go`
(`TestTheDocumentedAcknowledgmentLineVerifies`) holds this page to it.

**Rotating the acknowledging key.** Because one line that does not verify refuses the whole
call:
1. add the new key to `acknowledgedBy`, beside the old one;
2. have the log sign new lines under the new key;
3. remove the old key only once the file the command is given carries no line under it:
   re-sign those lines under the new key, or leave out the sessions already removed.

**`gateway retain --config <engine.json> --acknowledgments <file> [--scope <identifier>] --by <label>`**,
the gateway stopped, on the filesystem kind; `gateway store retain` on the PostgreSQL kind
(docs/postgresql-store.md, "Retention by acknowledgment"). It removes each sealed session of a
scope identifier, the one `--scope` names if given, when a line names its seal exactly and
`window` has passed since the later of the seal's time and the acknowledgment's. Each removal
is ADR-0034's `session-removal` record alone, appended and made durable before any file goes,
so every verifier of v0.29.0 or later reads the session as `session-removed` and no SPEC change
is needed. It refuses the whole call, by name, before anything is written:
- a line that does not verify under `acknowledgedBy`;
- a line naming a session the store does not hold, an open session, or a seal other than the
  store's;
- a line whose time is earlier than the seal's, or later than the command's clock;
- a session of no scope identifier, or of more than one (it goes only with its whole store);
- a receipt left in the store that cites a session the call would remove.

A session no line names, and one still inside the window, stays, and is named in a note. Its
last line on stderr names the SHA-256 of the acknowledgment file and the acknowledging key's
id, so the call can be traced to the acknowledgments it acted on.

**Retiring one scope identifier.** `gateway export --scope <id>`, kept where exports are kept,
and verified with `gateway verify --scope <id>` on the restored copy; then
`gateway remove-scope --scope <id> --by <label>` (or `gateway store remove-scope`), the gateway
stopped.

**Upgrading.** A file of version 37 or earlier loads as before. To retain, raise
`engineVersion` to `"38"` and add the member. A gateway older than this one refuses a
version-38 file by its version.

## Session labels (engine version 39)

Version 39 adds no member. It changes what the `session` of a request is
([ADR-0051](../adr/0051-a-session-name-is-a-label-in-its-scope-mapped-to-a-minted-session-id.md),
#550): a **label** in its scope's namespace, mapped to a session id the gateway mints.

- **The label.** It has the form a session id has (SPEC.md §3a), so every name a client sends
  today is a valid label. Its namespace is the scope the session is of: the scope identifier of
  the source `/acquire` names, the `scope` `/seal` names, or **none** (a source fixed to no
  scope, `/act`, and `/seal` naming no scope). The same label in two scopes is two sessions.
- **The session id.** On a label's first use in its namespace the gateway mints 32 lowercase
  hexadecimal characters from 128 random bits. The receipt `/acquire` answers carries it, and
  so does the seal `/seal` answers: a caller verifying, exporting or citing reads it there.
  Receipts, seals, the registry and the verifiers are as before.
- **Where it is kept.** On the filesystem kind, one file per label at
  `<store>/labels/<hex>.json`, written exclusively and synced before the session's first
  receipt. The verifiers pass `labels/` over. On the PostgreSQL kind, one row of
  `gateway.session_labels` per label (schema version 9), inserted `ON CONFLICT DO NOTHING` so
  every instance on one database agrees on one id (docs/postgresql-store.md, "Session labels").
  On both kinds an acquisition records a label it minted only once it is admitted, immediately
  before its source starts, and an action (`/act`) once it is admitted, before its dispatch is
  claimed, so a call refused before then leaves no label. An id a label names already is not
  minted for another label.
- **What a caller is answered.** `/seal` looks a label up in the namespace it names alone. A
  label not there is answered `no such session: <label>`, and nothing else is read: not the
  registry, and nothing of another scope. A label whose session is sealed is refused as a sealed
  session is: a label names one session for its life, so a job labels each run. Callers of one
  scope share its namespace, and one of them can learn by that refusal that a label is in use
  in its own scope.
- **The MCP front.** In the caller form the seal tool takes an optional `scope`, held to the
  caller's token and forwarded as `/seal`'s.
- **Operators.** `gateway sessions --config <engine.json> (--scope <identifier> | --no-scope)
  [--label <label>]` prints `label sessionId` lines for one namespace, with the gateway running
  or stopped, and writes nothing. `--no-scope` names the namespace of none; `--scope none` names
  the scope identifier `none`. Every other command takes session ids, as before.
  `gateway remove-scope` and `gateway store remove-scope` remove the scope's labels, also where
  the scope holds labels and no session, and `gateway retain` and `gateway store retain` the label
  of each session they remove, once their records are durable and before the receipts, so a run
  cut off leaves no label naming a session it removed; the label is then free, and its next use
  starts a new session. `gateway export` carries no labels, and `gateway store rotate` starts
  the new store with none.

**Upgrading.** A file of version 38 or earlier loads as before, and the name a request sends is
the session id. A session left open from before version 39 is sealed before the upgrade: stop
the gateway, run `gateway seal-open --all`, raise `engineVersion` to `"39"` and start. The start
refuses while the store holds a session open that no label names, and its refusal says the same.
A session a gateway at version 39 left open, at a crash, is named by its label and does not
refuse the start; it is refused at use as any session another process left open is, and
`gateway seal-open` seals it. On the PostgreSQL kind every instance moves together: stop all,
`gateway seal-open --all`, `gateway store migrate` (schema version 9), and start all at version
39; an instance at version 39 is refused beside one at an earlier version, by name. Going
back needs every session sealed first, too; the older engine then passes `labels/` over.

## A P-256 key version at the HSM level (engine version 40)

Version 40 adds one member, `signingKeyAlgorithm` (ADR-0053). Its one value is `"ES256"`: the key
version `signingKeyVersion` names is an ECDSA P-256 key, `EC_SIGN_P256_SHA256`, at the key service's
`HSM` protection level. Absent, the key version is Ed25519, as from version 36. The example names a
regional location, so a copy of it holds wherever the service offers that protection level; the key
ring's location is the operator's.

```json
"signingKeyVersion": "projects/example-project/locations/europe-west1/keyRings/receipts/cryptoKeys/hsm/cryptoKeyVersions/1",
"signingPublicKey": "<the compressed point, 66 lowercase hexadecimal characters>",
"signingKeyAlgorithm": "ES256"
```

- **Only beside `signingKeyVersion`.** The seed stays Ed25519, so the member beside the seed alone is
  refused by name; so is any other value, and the member before version 40.
- **The pin follows the member.** `signingPublicKey` is 64 lowercase hexadecimal characters for an
  Ed25519 key version and 66, the compressed point, under `"ES256"`. Each form is refused under the
  other.
- **The start checks the key version.** The service's answer must name `EC_SIGN_P256_SHA256` and the
  `HSM` protection level. `SOFTWARE`, `EXTERNAL` and `EXTERNAL_VPC` are refused, naming the level
  answered and the one required. An Ed25519 key version keeps its software level.
- **What changes in the records.** Every record the key signs carries `alg: "ES256"` inside what it
  signs, and the gateway mints version 3 receipts alone under it. `/publickey` answers
  `"algorithm": "ES256"` with the compressed point. The witness is still refused beside
  `signingKeyVersion`.
- **Rotation.** On the file kind, SIGHUP reads `signingKeyVersion`, `signingPublicKey` and
  `signingKeyAlgorithm` again; on the PostgreSQL kind, `gateway store rotate-key` names the key rotated
  from with `--from-key-algorithm ES256` where it is a P-256 key. A rotation from a P-256 key to an
  Ed25519 one is allowed and named on the standard error.

An earlier gateway refuses a version-40 file by its version.

## Keyed actions (engine version 14 and later)

Version 14 and every later version require a caller-chosen `actionKey` on `/act`: 64 lowercase hex
characters, retained and reused for the same approved intent across retries.
Older configurations may opt in per request. On Windows, where keyed dispatch is
unsupported, every `/act` under version 14 or 15 refuses, a delegation configuration
(version 15) included. A changed payload or approval under
the same key is refused as `action-key-conflict`; install paths, the adapter
command line a release derives, the platform environment and the OS user are not
part of the key's identity, so an upgrade into another directory, or to a release
that derives other adapter flags, does not strand a key reserved under identity
version 2. A key v0.23.0 reserved keeps v0.23.0's identity, which binds the
derived command line: under a release that derives other adapter flags it answers
`action-key-conflict`, settled or not, and nothing is sent. Never send a conflicting key's write
again under a new key. A write program that was never started answers
`action-not-dispatched` and frees the key for the same request. A request may also send
`keyScope: "authority"`, which holds the key to its first subject across a change of worker,
and `reconcile: true`, which asks and never dispatches (SPEC.md §1.2b; they need no version
and no configuration). A request that sends neither behaves as before on a key no record names;
SPEC.md §1.2b states exactly where it differs on one that another scope holds. The key does not replace authorization, decision policy or a
lease fence. Clients must retain the key and approved content before submitting
a write; changing the key after a timeout creates a distinct action.

The gateway durably reserves the key in its private `actions/` store directory
before dispatch. A completed request replays its retained response; an uncertain
one may run only the pinned read-back contract and returns `{action,
reconciliation}`. Unsupported or failed read-back returns HTTP 409 with `error`
and the retained `action` evidence. A `committed` read-back reports the matching
key observed by the read tool; `unknown` never permits another dispatch.

Binding version 3 retains owner declarations and adds a per-write-tool
`actionRecovery` map, including explicit null entries for unsupported tools.
The shipped write bindings declare unsupported recovery. An operator-owned
contract may name an idempotency argument and a read-only live tool; updating
the binding requires a new digest pin and recaptured descriptor approval. The
gateway sets the idempotency argument to the action key, and a closed decision
policy reaches it as the gateway's; a policy of that tool may not bind, fix or
shape it (`closed`, under the platform's `decisionPolicy` above). See
[action reconciliation](action-reconciliation.md) and SPEC.md §1.2b.

The initial durable journal requires Unix file and directory synchronization;
other hosts refuse keyed dispatch. A failed sync, partial record or corrupt
cache refuses safely and never creates a fresh dispatch opportunity. Preserve
`actions/` with the receipt store in operational backups. Attestation exports
exclude this private journal and cannot serve as a dispatch-history backup. The
journal's retention, its offline compaction and the procedure for a damaged entry
are in [action reconciliation](action-reconciliation.md#operating-the-journal).
