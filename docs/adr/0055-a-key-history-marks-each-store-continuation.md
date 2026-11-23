---
status: accepted
date: 2026-11-22
deciders: maintainer
---

# A key history of version 2, one store at a time, each after its signed store continuation

> **Summary.**
>
> - **Chosen: option 1**, in a flat form. A history of `keyHistoryVersion` `"2"` lists the history one
>   **store** at a time, in order. Each store after the first carries its registry's store continuation
>   (SPEC.md §3d) as its own signed registry line. Within a store, the rotation at place *i* has `rotation`
>   *i*, as §3b's walk of that store's registry followed it. So the ordinal starts again at 1 only after a
>   continuation, and a repeated or skipped ordinal is refused from the history alone.
> - **New members of the answer:** `keyHistoryVersion: "2"`; `stores`, an array of stores; `base`, which is
>   optional and holds the version `"1"` history that was carried into the first store, as a JSON value. A
>   store is `{keys, continuation}`. `keys` is an array of entries, each entry exactly as in version `"1"`.
>   `continuation` is a string: the store's registry's first line, without its `0x0A`. Every store after the
>   first holds a `continuation`, and so does the first where `base` is present.
> - **New engine configuration member:** `keyHistoryVersion`, whose one value is `"2"`, from engine
>   configuration version `42`. Absent, the gateway answers `"1"`, as today.
>   A store that carries a version `"2"` history answers `"2"` whatever the configuration says.
> - **New consumer option, not a wire member:** `requireVersion: "2"` in the Go and TypeScript checks. When it
>   is given, an answer of version `"1"` is refused.
> - **Unchanged:** version `"1"`, byte for byte, with its check; every `keyHistoryDigest` that names a version
>   `"1"` history; §3b's statements and walk; §3d's continuation (`continuationVersion` stays `"1"`); every
>   store vector.

## Context and problem statement

A key history's `rotation` ordinal is held to its form alone (SPEC.md §3e; `checkKeyHistory`,
`go/key_history.go:166`). The ordinal counts within one registry (§3b, step 3 of the walk) and starts again
at 1 after a store continuation (§3d, ADR-0052). `keyHistoryVersion` `"1"` carries no mark of a store
continuation. The gateway splices the carried history and its own walk into one list of keys
(`go/key_history.go:149`), and the continuation line itself is not in the answer.

So a verifier that reads only the history cannot tell two cases apart:

- a repeated ordinal after a real `gateway store rotate`;
- a rotation given twice, or a history corrupted or spliced.

The registry walk refuses the second as **`rotation-order`**: "an ordinal skipped or given again" (§3b,
step 3). #578 calls it `rotation-ordinal-replay`. That is the name of the corpus vector that holds this
finding (`corpus/README.md:99-100`), not a finding of its own: the finding the code names is
`rotation-order`, and this record uses that name throughout.

## Decision drivers

- **Version `"1"` stays as it is.** Version `"1"` histories stay unchanged, and so do the carried
  `.key-history` bytes, the `gateway.key_history` row, and every `keyHistoryDigest` that names them. A gateway
  that is not asked for the new version answers exactly what it answers today.
- **The history alone is enough.** A verifier that reads only the history, Go or TypeScript, refuses a
  repeated or skipped ordinal under the new version, and accepts a restart only where it can check the
  restart from the answer alone.
- **The registry's records do not change.** §3b's statements, §3d's continuation and their walks keep their
  bytes. Every store a verifier of v0.38.0 verifies `ok` still verifies `ok`.
- **Older consumers fail closed.** A consumer of an earlier release refuses the new version. It never reads
  the new version as `"1"`.
- **Both storage kinds can produce it.** The filesystem kind and the PostgreSQL kind both make it from what
  they already hold: the registry, its first line, and the carried history's bytes.
- **It adds no trust.** Every new rule is checked from the key pinned, as ADR-0052 requires.

## Considered options

1. **A store-continuation mark in the history.** The history carries each store continuation it crossed,
   signed as the continuation already is. Ordinals may start again at 1 only after such a mark.
2. **Ordinals that keep counting across store rotations**, so any repeat is a replay.
3. **Other forms weighed:**
   - (a) the mark as a member of the entry of the key in force (`storeContinuations` on that entry), keeping
     version `"1"`'s single list of keys;
   - (b) an answer signed by the key in force;
   - (c) the carried history nested inside the answer, as a string or as a value.

## Decision outcome

**Option 1, in the flat form of the Summary.** It is the only option that lets a verifier conclude the
whole of what #578 asks from the answer alone. It changes no record that a verifier of the registry reads.
The mark it carries is a line that is already signed, and that both kinds already hold.

### Why not option 2

- **It changes the registry walk, not the history.** §3b step 3 holds a `key-rotation`'s ordinal to one
  more than the rotations followed in that registry, counting from 0, and the ordinal is inside both
  statements' signatures. If ordinals kept counting, a new store's first rotation would be signed as *N*+1.
- **Older verifiers would refuse every continued store.** Every verifier of the registry, of v0.38.0 and of
  this release, would refuse that rotation as `rotation-order`, unless the registry told it *N*. Telling it
  *N* means one of two things:
  - a new member of the continuation, so `continuationVersion` `"2"`, which a verifier of v0.38.0 refuses as
    `continuation-forged` (exact members, `go/store_continuation.go:80`, `verify-ts/src/verify.ts:1850`);
  - or a walk that reads the carried history, which ADR-0052 kept away from verifiers.
- **It breaks the drivers.** Either way it breaks the registry-records driver, and it makes registry
  verification worse in order to fix a history problem.
- **`rotate-key` would depend on the history.** `rotate-key` and its forms would have to read the carried
  history to learn *N*.
- **It concludes less.** A history-only verifier would learn that no ordinal repeats. It would not learn
  where the store rotations were, and nothing would bind the history before a rotation to that rotation.

### Why not option 3

- **(a) A mark on the entry.** A continuation names the exact bytes carried by its `keyHistoryDigest`. The
  entry the bytes would rebuild from is the one holding the mark, but in the rebuilt history it would have
  lost its later `validTo` and its later marks. So a verifier would have to edit the history before hashing
  it. One entry would also hide which part of a key's validity belongs to which store. The flat form needs
  no edit: each store is carried byte for byte as it was answered.
- **(b) A signed answer.** It adds trust in the key in force instead of chaining from the key pinned
  (ADR-0052, first driver). It needs a new signing prefix and record kind. It still leaves the old ordinals
  uncheckable.
- **(c) Nesting the carried history.**
  - As a string, each store rotation escapes every quote again, so the backslashes grow exponentially with
    the number of store rotations.
  - As a value, the depth grows by one per store rotation.

  The flat array makes the same binding at constant depth.

### 1. The answer of version 2

```
{"keyHistoryVersion":"2","stores":[{"keys":[<entry>, ...]}, {"continuation":"<registry line>","keys":[<entry>, ...]}, ...]}
{"base":<a version "1" history>,"keyHistoryVersion":"2","stores":[{"continuation":"<registry line>","keys":[...]}, ...]}
```

- **The store.** A store is the history of one registry. Its `keys` are exactly what `historyOfWalk` makes
  of that registry's own walk (`go/key_history.go:52`): the first entry is the key the walk starts at, with
  no `validFrom` and no statements, and each key a followed rotation reaches is the next entry.
- **Its last entry.** The store's last entry has no `validTo`, because it was in force when that store's
  history was made. For the last store, that is the key in force now. For every other store, it is the key
  that signed the next store's continuation.
- **The key at a boundary.** The key at a boundary is listed twice: as the last entry of one store and as the
  first entry of the next. Its end, if it was rotated from in the later store, is the `validTo` of the later
  entry.
- **Carried stores, byte for byte.** A gateway answering version `"2"` answers the stores carried into its
  store, and `base` if one was carried, exactly as they were carried. Its own store comes after them.
- **The continuation that precedes a store.** The `continuation` of a store is its own registry's first line.
  That line names the old registry by `previousLines` and `previousDigest`. Its `previousDigest` is the
  SHA-256 of the old registry's bytes, whole; #578 calls this "the old store's last line digest". The
  continuation also names the history carried, by `keyHistoryDigest`. The line's SHA-256 is the old store's
  `store-rotated:` mark (§3d), so an operator who holds the old store can match the mark to the
  continuation.
- **`previousDigest` stays as it is.** The issue's "the old store's last line digest" is met by the existing
  whole-registry digest, which is stronger.
- **What `base` holds.** `base` holds a version `"1"` history, carried into the first store by a gateway that
  answered `"1"`. It is the way onto version `"2"` for a store that already crossed a store rotation under
  version `"1"`. Without it, such a store and every store after it could never answer `"2"`: its carried
  bytes hide their own restarts.

### 2. The check of version 2

The check is version `"1"`'s check, store by store, with these rules in place of the ordinal's form:

1. **Members.** The answer has exactly `keyHistoryVersion`, `stores` and, optionally, `base`, each of its
   form. Each store has exactly `keys` and, where required, `continuation`. Each entry has exactly version
   `"1"`'s members.
2. **`base`.** Where present, `base` holds version `"1"`'s check from the key pinned. Inside it, ordinals are
   held to their form alone.
3. **First entries.**
   - With no `base`, the first store's first entry is the key pinned, with the algorithm it was pinned with.
   - Every other store's first entry is the key of the last entry before it, with the same `keyId`, `alg` and
     `publicKey`. That last entry is the last entry of `base` for the first store, and the last entry of the
     store before for every other store.
   - A first entry has no `validFrom`, `keyRotation` or `keyContinuation`.
4. **Keys.** No other entry is the key of an earlier entry, of either algorithm: not in its own store, not in
   an earlier store, and not in `base`.
5. **Ordinals.** The statements of the entry at place *i* of a store, counting the first entry as place 0,
   have `rotation` *i*.
6. **Continuations.** A store's `continuation` holds §3d's form, with `continuationVersion` `"1"` and `alg`
   present exactly for a P-256 key. Its `keyId` and its `alg` are those of the store's first entry. Its
   signature verifies under that key, by that algorithm, over `judgment-pack-gateway/store-continuation/1:`
   and `canon` of the continuation without `signature`.
7. **Digests.** A continuation's `keyHistoryDigest` is the SHA-256 of `canon` of the history before it:
   - for the first store, the history before it is `base`;
   - for any later store, it is `{keyHistoryVersion: "2", stores: <the stores before it>}`, with `base` where
     present.
8. **Time.** A continuation's `continuedAt` is not before any `rotatedAt` or `continuedAt` before it, and not
   after the `validTo` of its store's first entry, if that entry has one. The order of `rotatedAt` values
   across the whole answer is version `"1"`'s rule.
9. **`requireVersion`.** A consumer that gives `requireVersion: "2"` refuses an answer of version `"1"`.

**Why the digest rule is exact.** `canon` is a function of the value. A gateway's answer is `canon` of its
values. So the history before a continuation, rebuilt from the parsed answer, has exactly the bytes that the
store rotation carried, and its digest is exactly the one the key in force signed. A gateway answering `"2"`
over a carried version `"1"` history holds `canon` of the parsed value to the carried bytes. It answers
`500` where they differ, which a gateway's own writing never produces.

### 3. What a history-only verifier concludes

**Under version `"1"`, as today:** every key in order, each one reached by a rotation pair that the key
before it and the key itself both signed.

**Under version `"2"`, from the answer alone, also:**

- **Ordinals.** Each store's rotations are the 1st, 2nd and so on of its registry, with none given twice and
  none skipped. A `rotation-order` that §3b's walk would find is now found from the history.
- **Restarts.** Each restart of the ordinal is a store rotation that the key then in force signed, over the
  exact history before it. So no store, rotation or entry before a continuation can be added, removed,
  reordered or changed without that key's signature.
- **Replays.** A store given twice repeats its keys, and is refused.

**What it does not conclude:**

- **The old registry.** It does not show that `previousLines` and `previousDigest` name the real registry
  before. They are held to their form alone. `gateway verify --previous` holds them (§3d).
- **Forks.** It does not show that no other history leads from the key pinned. A holder of a key in force
  can sign another rotation or continuation, as under version `"1"`.
- **The latest rotations.** It does not show that the answer holds the gateway's latest rotations. A
  history cut after its last continuation still holds, and a receipt under a key it omits is refused.
- **Inside `base`.** Ordinals inside `base` are held to their form alone.

### 4. Which version a gateway answers, and how a consumer learns it

- **Opt-in, not "the store is new".** Version `"1"`, unless the engine configuration, of version
  `42` or later, holds `"keyHistoryVersion": "2"`.
  - A configuration of an earlier version holding the member is refused at load, by its version.
  - Any other value is refused with the sentence `engine configuration: keyHistoryVersion is "2", or
    absent`.
  - Being "new" is not recorded anywhere a gateway reads: a fresh registry reads as one that was never
    rotated.
  - A new store answering `"2"` by default would break every consumer of v0.38.0 pointed at it, with no
    operator action.
- **Once carried as `"2"`, always `"2"`.** A store whose carried history is of version `"2"` answers `"2"`
  whatever the configuration says, because the opt-in is recorded in the carried bytes. A store's key-history
  version only moves forward, never back: with the member removed from a store that already carries a `"2"`
  history, the gateway keeps answering `"2"`. Only a store that never carried a version `"2"` history goes
  back to `"1"` when the member is removed.
- **What `gateway store rotate` carries.** It carries the history the old store's gateway answers under the
  configuration the rotation is given. Given by its flags (filesystem kind), it uses no configuration, and
  carries `"2"` only where the old store already carries `"2"`. To opt a store in at its rotation, give
  `--config`. No new flag.
- **Several instances on one database.** On the PostgreSQL kind, every instance on one database answers the
  one registry and row they share, by the version its own configuration names (or `"2"` where the row is
  `"2"`). During a configuration change, instances may answer different versions, and both answers hold.
  Nothing refuses the mixed state for now. The window is before the first continued rotation: until then an
  instance that has not opted in answers `"1"`, and that answer is still valid for that store. The release
  notes tell operators to set the member on every instance before rotating. A start-lease column that holds
  every instance to one version is a later record.
- **How a consumer learns the version.** From the answer's own `keyHistoryVersion`, read before anything
  else. `/publickey` and `/posture` do not change.
- **A consumer of v0.38.0 refuses version `"2"` whole.** Its check refuses any top-level member besides
  `keyHistoryVersion` and `keys` (`go/key_history.go:172`, with the allowed members at `:32`), which refuses
  `stores` and `base`. It refuses any `keyHistoryVersion` but `"1"` (`go/key_history.go:175-176`, "keyHistoryVersion
  is not \"1\""). It refuses any entry member it does not list (`go/key_history.go:33`, `:241`). verify-ts of
  v0.38.0 has no key-history check (ADR-0053 §3: "not read"; it holds only the continuation's
  `keyHistoryDigest` to its form, `verify-ts/src/verify.ts:1846`, `:1868`), so nothing there reads either
  version.
- **A gateway of v0.38.0 on a store that carries version `"2"`.** It refuses the carried bytes at
  `go/key_history.go:128`. `/publickey/history` answers `500`. Every writer that builds the history refuses,
  because each one calls `registryKeyHistory`:
  - `rotate-key` (`go/rotate_key.go:303`);
  - its SIGHUP form (`go/rotate_serving.go:147`);
  - `store rotate-key` (`go/store_rotate_key_pg.go:340`);
  - `store rotate` (`go/store_rotate.go:513`, `:542`).

  It fails closed. It is the rollback cost the release notes must state.

### 5. With `alg` (ADR-0053), `keyRotation` and `keyContinuation`

- **Entries are unchanged.** `alg` is present exactly for a P-256 key, and `publicKey` is then 66 characters.
  Each statement's `alg`, `nextAlg` and `previousAlg` follow version `"1"`'s check. Key ids are never
  repeated across both algorithms, except for the key at a boundary.
- **A continuation that a P-256 key signs** carries `alg: "ES256"` inside what it signs (§3d). The check
  holds that `alg` to the store's first entry's `alg`, and verifies by that algorithm, low-S, `r||s`.
- **`keyRotation` and `keyContinuation` are unchanged** in form and in what they sign. Version `"2"` adds one
  rule: the ordinal they share is the entry's place in its store.

### 6. `/publickey/history`, `keyHistoryDigest`, and what names a history by digest

- **The route.** Same path, same `Content-Type`, still open, still the same `500` sentence. The answer grows
  by one continuation line and one repeated entry per store rotation, about 1 KiB each. It is held by the
  route's existing write bound.
- **`keyHistoryDigest` (§3d) names the carried bytes, of either version.** The continuation keeps
  `continuationVersion` `"1"`. Every store-continuation vector of `corpus/stores` is unchanged.
- **The carried bytes.** The `.key-history` file and the `gateway.key_history` row (a `bytea`,
  `go/store_pg_definitions.go:61`) hold either version, so no schema change is needed. A rerun holds the
  carried bytes to the digest as today, whichever version they are.
- **The registry.** `gateway verify` does not read the history, and nothing it reads changes.

### 7. The SPEC text

**§3d**, in the table, in the `keyHistoryDigest` row. The current Statement cell reads "the SHA-256 of the
key history the rotation carries beside the new registry (§3e), its exact bytes". It becomes:

> the SHA-256 of the key history the rotation carries beside the new registry (§3e), its exact bytes, of
> either version

Nothing else in §3d changes.

**§3e**, five changes:

1. At the end of **The answer.**, after "The first key has no `validFrom`: no statement says when it came
   into force.", add:

   > This is the history of version `"1"`. A gateway answers the history of version `"2"` (below) in its
   > place where its engine configuration asks for it or its store carries one.

2. In **Across a store rotation.**:
   - "writes the old store's key history, the exact bytes its gateway answers," becomes:

     > writes the old store's key history, the exact bytes its gateway answers under the configuration the
     > rotation is given (below),

   - "A registry whose first line is a store continuation that loads answers the history carried beside
     it," becomes:

     > A registry whose first line is a store continuation that loads answers, as version `"1"`, the history
     > carried beside it,

3. In **Checking it.**:
   - "A consumer that pinned a key holds the answer, read by §1.1's parser, to:" becomes:

     > A consumer that pinned a key holds an answer of version `"1"`, read by §1.1's parser, to:

   - "The `rotation` ordinal is held to its form alone: it counts within one registry, and starts again at 1
     after a store continuation." becomes:

     > In a history of version `"1"` the `rotation` ordinal is held to its form alone: it counts within one
     > registry, and starts again at 1 after a store continuation, which version `"1"` does not mark, so its
     > consumer cannot tell a rotation given twice, which §3b's walk finds as `rotation-order`, from the first
     > rotation after a store rotation. Version `"2"` marks each store continuation, and its consumer can.

4. A new paragraph, with its table, after **Checking it.**:

   > **Version 2.** `canon` (§1.1) of `{keyHistoryVersion, stores}`, or of `{base, keyHistoryVersion,
   > stores}`: `keyHistoryVersion` the string `"2"`; `stores` an array of one **store** or more, one for each
   > registry the history crosses, in order, the gateway's own last; and `base`, where present, a history of
   > version `"1"` that a store rotation carried into the first store, as the JSON value its bytes are. A
   > store is an object of these members and no other:
   >
   > | Member | Form | Store |
   > |---|---|---|
   > | `keys` | an array of one entry or more, each of the members of version `"1"`'s table and no other | every: the keys its registry's walk reached (§3b), listed as version `"1"` lists the keys of a registry that continues no store |
   > | `continuation` | a string | every but the first, and the first where `base` is present: its registry's first line, the store continuation (§3d), without its `0x0A` |
   >
   > A store's first entry is the key its registry's walk starts at, with no `validFrom`, `keyRotation` or
   > `keyContinuation`, and its last entry is the key in force when its history was made, with no `validTo`:
   > for the last store, the key in force when the gateway answers; for every other, the key that signed the
   > next store's `continuation`. A gateway answering version `"2"` answers the stores carried into its
   > store, and `base` where one is carried, as they were carried, byte for byte, and its own store after
   > them; answering it over a carried history of version `"1"`, it answers that history as `base`, where
   > `canon` of its value is its bytes, and `500` as above otherwise.
   >
   > **Checking version 2.** A consumer that pinned a key holds an answer of version `"2"`, read by §1.1's
   > parser, to: exactly the members above, each of its form; `base`, where present, to the check of version
   > `"1"` from the key pinned; and each store's `keys` to the check of version `"1"`, entry by entry, with
   > these differences. A store's first entry is the key pinned, with the algorithm it was pinned with, where
   > it is the first store and there is no `base`; otherwise it is the key of the last entry before it, of
   > the same `keyId`, `alg` and `publicKey` -- the last of `base`, for the first store, and of the store
   > before, for every other. No other entry is the key of an earlier entry, of either algorithm, in its store,
   > an earlier one or `base`. The `keyRotation` and `keyContinuation` of the entry at place *i* of a store,
   > the first at place 0, have `rotation` *i*: within a store the ordinals run from 1, one more at each
   > entry, as §3b's walk of its registry follows them, and start again at 1 only after a `continuation`. A
   > store's `continuation` holds §3d's form; its `keyId` and its `alg` are those of the store's first entry,
   > and its signature verifies under that key by that algorithm; its `keyHistoryDigest` is the SHA-256 of
   > `canon` of the history before it -- of `base`, for the first store, and otherwise of
   > `{keyHistoryVersion, stores}`, `keyHistoryVersion` `"2"` and `stores` the stores before it, with `base`
   > where present; and its `continuedAt` is not before any `rotatedAt` or `continuedAt` before it, and not
   > after the `validTo` of its store's first entry, if it has one. Its `previousLines` and `previousDigest`
   > are held to their form alone: a consumer holds no registry. A consumer may ask for version `"2"`, and
   > then refuses an answer of version `"1"`.
   >
   > **What version 2 establishes.** What version `"1"` does, and, from the answer alone, that each store's
   > rotations are its registry's in order, none given twice and none passed over, and that each store
   > rotation the history crosses was signed by the key then in force over the exact history before it, so
   > that no store, rotation or entry before a `continuation` is added, taken away or changed without that
   > key. It does not establish that a `continuation` names the registry that was before it (§3d's
   > `--previous` holds that), that no other history leads from the key pinned, or that the answer holds the
   > gateway's latest rotation; and within `base` the ordinal is held to its form alone.

5. A new paragraph after that:

   > **Which version is answered.** Version `"1"`, unless the gateway's engine configuration, of version
   > `42` or later, holds `keyHistoryVersion: "2"`, or the history carried
   > into its store is of version `"2"`; then version `"2"`. A history a store rotation has carried as
   > version `"2"` is so answered by every store after it. `gateway store rotate` carries the history the old
   > store's gateway answers under the configuration it is given, and, given by its flags, under none. A
   > consumer learns the version from the answer's `keyHistoryVersion`; one written before version `"2"`
   > refuses the answer whole.

### 8. The engine configuration

- **The member.** `keyHistoryVersion`, a string whose one value is `"2"`, from version
  `42`. When it is absent, the gateway behaves as today.
- **Who reads it.** `serve` reads it, and so do its SIGHUP rotation and the commands given `--config`
  (`store rotate`, `store rotate-key`). Each of them builds the history the route answers.
- **Commands given by their flags.** `rotate-key`, and `store rotate` given by its flags, build the history
  of the version their carried history implies. That is enough: the registry's own walk already holds every
  rotation to version `"2"`'s ordinal rule, so a record such a command checks holds under either version.
- **Its section.** `docs/design/engine-config.md` gains a section after "A P-256 key version at the HSM
  level (engine version 40)".

### 9. The vectors

**The family.** A new family, `corpus/key-history/*.json`. No history is in the corpus today (ADR-0052).
Each vector holds:

- `pin`: the name of a published key, or `{alg, key}` for the P-256 one;
- `requireVersion`: optional;
- `history`: the answer's bytes, as a JSON string, so that they are exact;
- `expected`: `{"accepted": {"keys": <distinct keys>, "inForce": <keyId of the last entry>}}`, or
  `{"refused": <class>}`.

**The classes.** Both checks name one of these classes, so the two implementations are compared on the
reason and not only on the verdict. The eight classes are part of the corpus contract: a runner that names
another class for a refused vector disagrees with it.

| Class | Covers |
|---|---|
| `version` | a version that is unknown, or not the one required |
| `form` | the members, their forms and their presence |
| `key` | a key rule, a `keyId`, a key repeated, or a first key that is not the pinned key or the boundary key |
| `rotation` | a pair that is not a rotation from the entry before |
| `ordinal` | an ordinal that is not its place |
| `time` | `validFrom`, `validTo`, `rotatedAt` or `continuedAt` out of order |
| `continuation` | a continuation of the wrong form, signed by the wrong key, or with the wrong `keyId` or `alg` |
| `carried` | a `keyHistoryDigest` that is not the history before |

**How they are made.** `gateway conform` runs the family in process, as it runs `retention-ack`, with no
process-contract command. verify-ts's corpus test runs it too. The signatures are made once, by a script
independent of this repository, as ADR-0053 §11's are, and then frozen: they are verify-only, and no test
signs them again.

**Keys.** `K0` is `TEST-PUBLIC-KEY`. `K1` and `K2` are the published corpus rotation keys 1 and 2. `K3` is
rotation key 3, published with this record by the existing seed rule: the SHA-256 of the text ending in `3`. `P` is
`TEST-P256-PUBLIC-KEY`.

**Notation.** `[K0, K1(1)]` is a store whose keys are K0, then K1 reached by a rotation of ordinal 1.
`c(K1)` is a continuation that K1 signs, over the history before it.

**Accepted:**

| Vector | Version | History | Expected |
|---|---|---|---|
| `kh-v1-one-key` | 1 | `[K0]` | accepted, keys 1, in force K0 |
| `kh-v1-ordinal-given-twice` | 1 | `[K0, K1(1), K2(1)]`, the statements S1 (K0→K1) and S2 (K1→K2, ordinal 1) | **accepted**, keys 3, in force K2: the gap #578 names |
| `kh-v2-one-store` | 2 | `[[K0, K1(1), K2(2)]]` | accepted, keys 3 |
| `kh-v2-across-store` | 2 | `[[K0, K1(1)], c(K1) [K1, K2(1)]]`, S1 and S2 byte for byte as in `kh-v1-ordinal-given-twice` | accepted, keys 3, in force K2 |
| `kh-v2-two-continuations-one-key` | 2 | `[[K0], c(K0) [K0], c(K0) [K0, K1(1)]]` | accepted, keys 2 |
| `kh-v2-base` | 2 | base `[K0, K1(1)]`; `[c(K1) [K1, K2(1)]]` | accepted, keys 3 |
| `kh-v2-base-ordinal-given-twice` | 2 | base `[K0, K1(1), K2(1)]`; `[c(K2) [K2]]` | accepted, keys 3: inside `base` the ordinal is held to its form alone |
| `kh-v2-p256-continuation` | 2 | `[[K0, P(1)], c(P, alg ES256) [P]]` | accepted, keys 2, in force P |

**Refused:**

| Vector | Version | History | Expected |
|---|---|---|---|
| `kh-v2-ordinal-given-twice` | 2 | `[[K0, K1(1), K2(1)]]`, S1 and S2 byte for byte as in `kh-v1-ordinal-given-twice` | **`ordinal`**: refused under `"2"`, accepted under `"1"` |
| `kh-v2-ordinal-skipped` | 2 | `[[K0, K1(1), K2(3)]]` | `ordinal` |
| `kh-v2-ordinal-kept-counting` | 2 | `[[K0, K1(1)], c(K1) [K1, K2(2)]]` | `ordinal`: option 2's shape |
| `kh-v2-store-without-continuation` | 2 | `[[K0, K1(1)], [K1, K2(1)]]` | `form` |
| `kh-v2-continuation-another-key` | 2 | as `kh-v2-across-store`, but the continuation is signed by K2, with K2's `keyId` | `continuation` |
| `kh-v2-continuation-signature-changed` | 2 | as `kh-v2-across-store`, with one bit of the continuation's signature changed | `continuation` |
| `kh-v2-continuation-alg-stripped` | 2 | as `kh-v2-p256-continuation`, with the continuation's `alg` removed | `continuation` |
| `kh-v2-continuation-names-version-1` | 2 | as `kh-v2-across-store`, but `keyHistoryDigest` names the version `"1"` bytes of `[K0, K1(1)]`, and K1 signs it | `carried` |
| `kh-v2-history-before-changed` | 2 | as `kh-v2-across-store`, with the first store's S1 replaced by another valid K0→K1 pair of a later `rotatedAt` | `carried` |
| `kh-v2-boundary-key-not-joined` | 2 | `[[K0, K1(1)], c(K1) [K2, K3(1)]]` | `key` |
| `kh-v2-key-repeated-across-stores` | 2 | `[[K0, K1(1)], c(K1) [K1, K0(1)]]` | `key` |
| `kh-v2-continued-before-its-key` | 2 | as `kh-v2-across-store`, with `continuedAt` before K1's `validFrom`, re-signed | `time` |
| `kh-v2-continued-after-the-next-rotation` | 2 | as `kh-v2-across-store`, with `continuedAt` after K2's `validFrom`, re-signed | `time` |
| `kh-v2-base-of-version-2` | 2 | `base` holds `keyHistoryVersion` `"2"` | `form` |
| `kh-v2-store-unknown-member` | 2 | a store that also holds `"note"` | `form` |
| `kh-v1-version-2-required` | 1 | `kh-v1-one-key`, with `requireVersion` `"2"` | `version` |
| `kh-v3` | 3 | `kh-v2-one-store` with `"3"` | `version` |

The pair that #578 asks for is `kh-v1-ordinal-given-twice` (accepted) and `kh-v2-ordinal-given-twice`
(refused). Both hold the same two statements.

### 10. What the release notes must say

- **Default unchanged.** `/publickey/history` answers version `"1"`, byte for byte as before, unless
  `keyHistoryVersion: "2"` is set in an engine configuration of version `42`. Every version `"1"` history, carried file, `gateway.key_history` row and `keyHistoryDigest`
  verifies as before.
- **Upgrade consumers first.** Upgrade every consumer of `/publickey/history` before opting in. v0.38.0
  refuses version `"2"` in two places: a consumer of v0.38.0 or earlier refuses a version `"2"` answer whole,
  and a gateway of v0.38.0 on a store that carries one answers `500` at `/publickey/history` and refuses the
  rotate commands (below). Operators therefore upgrade every reader before opting in.
- **Several instances on one database.** Set the member on every instance before the first continued
  rotation. Until then an instance that has not opted in answers `"1"`, which is still valid for that store;
  nothing refuses the mixed state.
- **No way back after a store rotation.** Once a store rotation carries a version `"2"` history, that store
  and every store after it answer `"2"` whatever the configuration says. There is no way back to `"1"` for
  them.
- **Rollback to v0.38.0.** On a store that carries a version `"2"` history, a gateway of v0.38.0 answers
  `500` at `/publickey/history`, and refuses `rotate-key`, its SIGHUP form, `store rotate-key` and
  `store rotate`, until it is upgraded again.
- **`base`.** A version `"2"` history that continues a version `"1"` one carries it as `base`. Inside
  `base`, ordinals are still held to their form alone.
- **verify-ts gains a key-history check.** It checks both versions, and is exported beside the store
  verifier. The Go check names refusal classes.
- **`requireVersion: "2"`.** Consumers can set it to refuse a version `"1"` answer. Set it only once the
  gateway answers `"2"` and the member stays.
- **Opting in at a store rotation.** `gateway store rotate` given by its flags carries `"2"` only where the
  old store already does. To opt in at the rotation, give `--config`.
- **Size.** The answer grows by about 1 KiB per store rotation.
- **Not established.** Neither version shows:
  - that a continuation's `previousLines` and `previousDigest` name the real old registry;
  - that there is no fork by a key holder;
  - that the answer holds the latest rotation.

### 11. The build plan: one pull request

**Go (`go/key_history.go` and the writers):**

- `checkKeyHistory` dispatches on `keyHistoryVersion`. The version `"1"` path keeps its code, and its errors
  gain classes only. A new `checkKeyHistoryV2` implements decision 2, and the check takes `requireVersion`.
- `registryKeyHistory`, `keyHistoryDocument` and `walkKeyHistory` take the version, and make stores for
  `"2"`:
  - no carried history: one store;
  - a carried `"1"` history: `base`, after the round-trip check;
  - a carried `"2"` history: its stores, then this store.
- `historyToCarry` and every writer pass the version: `go/rotate_key.go:303`, `go/rotate_serving.go:147`,
  `go/store_rotate_key_pg.go:340`, `go/store_rotate.go:513`, `:525`, `:542`, and the PostgreSQL rotation in
  `go/store_rotate_pg.go`.
- `keyHistoryWriteRefusal` takes the history's last time, the later of its last `validFrom` and its last
  `continuedAt`.
- The member is parsed in `go/engine.go`, behind the version.
- `go/conform_key_history.go` runs the family, following `go/conform_retention_ack.go`.

**TypeScript:**

- A new `verify-ts/src/key-history.ts` holds the whole §3e check, version `"1"` and version `"2"`, with the
  same classes. It is exported as `checkKeyHistory(bytes, pin, {requireVersion})`.
- It reuses the statement form and signature checks of `verify-ts/src/rotation.ts` (exported for it), and
  the continuation check `continuationOf`, which moves out of `verify-ts/src/verify.ts:1850` so the store
  verifier and the history share it.
- `verify-ts/test/key-history.test.ts`, and `verify-ts/test/corpus.test.ts` reads the new family.

**Corpus and documents:**

- The 29 vectors (25 at acceptance; four `form` vectors added in review), a "Key-history vectors" section in `corpus/README.md`, and rotation key 3.
- SPEC.md: the text of decision 7.
- `docs/design/engine-config.md`.
- `docs/postgresql-store.md`: the row holds either version.
- This record's row in the ADR README.

**Not in this pull request:** a command-line check for consumers (`gateway check-key-history`). It is a later
record.

**Tests (narrow: the touched packages):**

- **Version `"1"` golden.** A fixed registry, and a fixed carried history, give today's bytes exactly, with
  the member absent.
- **The answer of version `"2"` from the gateway:**
  - for no carried history;
  - for a carried `"1"` history (`base`);
  - for a carried `"2"` history;
  - across a P-256 boundary;
  - for a carried `"1"` history that is not canon: `500`.
- **The sticky rule.** A carried `"2"` history with the member absent still answers `"2"`.
- **`store rotate`:**
  - with `--config` and the member, it carries `"2"`;
  - by flags, it carries `"2"` only after `"2"`;
  - a rerun holds the `"2"` digest.
- **The PostgreSQL kind.** Its rotation writes a `"2"` row, under the PG test harness.
- **The engine configuration.** The member is refused below its version, and any other value is refused.
- **The family.** Every vector, in both Go and TypeScript.

**Mutation checks** (one mutant each, in a scratch copy, ten in all; each must fail the vector or test
named):

| # | Verifier | Mutant | Must fail |
|---|---|---|---|
| 1 | Go | drop the place-equals-ordinal rule | `kh-v2-ordinal-given-twice` |
| 2 | Go | skip the continuation's signature | `kh-v2-continuation-signature-changed` |
| 3 | Go | skip the `keyHistoryDigest` check | `kh-v2-history-before-changed` |
| 4 | Go | allow a store without a continuation | `kh-v2-store-without-continuation` |
| 5 | Go | let the boundary exception cover any repeated key | `kh-v2-key-repeated-across-stores` |
| 6 | Go | ignore `requireVersion` | `kh-v1-version-2-required` |
| 7 | Go | answer by the configuration alone | the sticky-rule test |
| 8 | TS | drop the ordinal rule | `kh-v2-ordinal-given-twice` |
| 9 | TS | skip the continuation's signature | `kh-v2-continuation-signature-changed` |
| 10 | TS | skip the digest check | `kh-v2-history-before-changed` |

### Consequences

- **Good:** a history-only verifier refuses a repeated or skipped ordinal, and every restart it accepts is
  one that the key in force signed over the exact history before it.
- **Good:** nothing a registry verifier reads changes. Version `"1"` and its digests stay byte for byte as
  they are. Older consumers fail closed.
- **Good:** both kinds build the answer from what they hold, with no schema change.
- **Bad:** there are two history versions to keep in both verifiers. verify-ts gains the whole §3e check at
  once.
- **Bad:** the opt-in cannot be undone after a store rotation, and a rollback to v0.38.0 then loses
  `/publickey/history` and the rotation commands.
- **Bad:** a store that crossed a store rotation under version `"1"` keeps the old weakness inside `base`
  for good.
- **Revisit when:**
  - a consumer needs the old registry's link checked from the history;
  - several instances on one database must be held to one version.

## Acceptance

The maintainer accepted option 1 and answered the open questions as follows. Each answer is folded into the
body above.

1. **Removing the member on a store that carries `"2"`.** A store's key-history version only moves forward,
   never back. With the engine member removed from a store that already carries a `"2"` history, the
   gateway keeps answering `"2"` (decision 4).
2. **Mixed versions across PostgreSQL instances.** Left unrefused for now. The window is before the first
   continued rotation: an instance that has not opted in answers `"1"`, and that answer is still valid for
   that store. The release notes tell operators to set the member on every instance before rotating. A
   start-lease column is a later record (decisions 4 and 10).
3. **The refusal classes.** The eight classes are part of the corpus contract (decision 9).
4. **A command-line check for consumers.** Not in this pull request; it is a later record (decision 11).
5. **Corpus rotation key 3.** Published by the existing seed rule (decision 9).

`previousDigest` stays as it is: the issue's "the old store's last line digest" is met by the existing
whole-registry digest, which is stronger (decision 1). The release notes list both refusals of v0.38.0, the
consumer's and the gateway's, so operators upgrade every reader before opting in (decision 10).

This record supersedes nothing. It extends ADR-0052's key history and its carrying across a store rotation,
and ADR-0053 §8's entries.
