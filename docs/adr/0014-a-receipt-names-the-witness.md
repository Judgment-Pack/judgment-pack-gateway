---
status: proposed
date: 2026-10-12
deciders: maintainer
---

# A receipt names the witness its trail is registered with, in an optional signed member of version 3, so that a verifier holding a decision record and its receipts can find the witness, fetch the trail's head and read the countersigned coverage; the reader of the chain is unchanged

Issue #199, its second ask: "a new receipt version or a negotiated extension" for the witness,
and the retrieval endpoint's place in the receipt format. ADR-0013's delivery is complete
(gateway v0.11.0, runtime v0.28.0, Desk ADR-0012). The maintainer chose the receipt route, as
recorded on the issue: a receipt is to name the witness a trail is registered with, under the
gateway's signature, so that a verifier holding only a decision record and its receipts can
discover the witness, fetch the trail's head and read the countersigned coverage with
`jpack audit verify --witness`, and the scenario is testable end to end. This record proposes the
design; nothing is built. The maintainer accepts or amends it by answering the questions at the
end.

**Checked against** gateway `main` at `845cf18`; Desk `main` at `39d5184` (ADR-0005, ADR-0012,
`witness.go`, `local_gateway_worker.go`, `researchrelay.go`); runtime `8270e99` (v0.30.0). Nothing
was run.

## Context and problem statement

**What exists.** The witness (ADR-0013; `SPEC.md` §6 "Witness endpoints", §8) signs statements
over the runtime's checkpoints, chains them per trail, and serves a trail's head and statements to
anyone who names it. It signs with its gateway's seed, so its statements' `keyId` is its
`/publickey`'s (§8.3). Its operator registers each trail, by default; no registration is served,
and no endpoint lists trails. The runtime's reader, `jpack audit verify --witness-key --witness
--witness-head` (v0.28.0 and later), reads a chain from index 0 against the trail and reports
`countersigned`, under a key of 64 hexadecimal characters "obtained out of band"; it fetches
nothing. Desk's holder (Desk ADR-0012) keeps one witness per desk: a URL, `https` or `http` to a
loopback address; a key pinned from the witness's operator, never from `/publickey`; and a token
bound to the URL's origin, "the scheme, the host in lowercase, and the port" (`witnessOrigin`). A
verifier holds, with a record, the runtime evaluation record (`trail`, `sequence`, `cites`), the
acquisition receipts it cites and the action receipts naming it by `decision.recordDigest` (§1.2a,
§4 steps 5 to 8), under the operator's gateway key pinned out of band (§5).

**What is missing.** Nothing a verifier holds says which witness holds the trail, or whether one
does: without Desk's settings it must be told, and no witness lists its trails to be asked.

**The four routes weighed.**

1. **Out of band.** Nothing signed names the witness, and no scenario starts from the record.
2. **Statements carried beside the trail, as the stamps are.** The file is the operator's: an
   operator who rewrites a trail presents an older file that still matches (ADR-0013, Context).
3. **A receipt naming the witness.** Chosen: discoverable from what the verifier already holds,
   under a signature it already checks, and testable end to end.
4. **The witness in the trail.** Declined: it makes the trail depend on the witness answering.

**Where receipts come from, which shapes route 3.** `POST /act` mints an action receipt after it
has found the record by its digest (`go/act.go`); the record's `trail` is in bytes it walks, which
it keeps and reads only for a tool held to a decision policy (ADR-0011, determination 2).
`/acquire` mints an acquisition receipt before any record exists, so it knows no trail. A seal is
not a receipt (§3), is of a session and not a trail, and signs a fixed object of four members, so
a member added to it is unsigned unless the seal's version moves. Desk's managed gateway is
`gateway serve` with flags, not an engine with `engine.json` (`local_gateway_worker.go`), shared by
the desks of one Desk process, with a store and registry per run (Desk ADR-0005); it mints
acquisitions only, and Desk never calls `/act` (`researchrelay.go`). A record made at a desk is
reached through acquisition receipts alone.

## Decision drivers

- A verifier finds the witness from the record, its receipts and the operator's gateway key.
- The naming is the operator's gateway's word, and reports say it is no more: never that the
  witness holds anything, or is independent of the operator.
- Every store a released verifier verifies today, it verifies after; no request, which an
  assistant may write, chooses a witness or a key.
- The countersignature is read only as ADR-0013 reads it, by the runtime; Desk's gateway names
  only the witness Desk submits to; the whole scenario runs in CI.

## Considered options

**Where the witness is named** (question 1).

- **A. A member on each receipt of the trail**, `witness: {origin, keyId, trail}`, set from the
  operator's gateway configuration as it mints the receipt. *Fetch:* nothing beyond the receipts
  held. *A change of witness:* later receipts name the new one, earlier ones the old, each with its
  `servedAt`. *Cost:* an optional member of version 3 (below), about 150 bytes a receipt, and two
  witnesses named for one trail after a change, each read.
- **B. One binding receipt per trail**, a new kind such as `witness-binding`, sealed once in a
  session named for the trail, found through the registry. *Fetch:* the binding is not among the
  record's receipts but in the operator's store, which no endpoint serves (`/registry` serves
  seals), and with Desk's stores per run, in the run that made it. *A change:* a sealed session
  takes no further receipt (§3), so each change is a new session. *Cost:* a third `kind` is
  `malformed` at §1.4 order 1, so it is receipt version 4, and one such session fails the whole
  store, store-wide by default (§5a.1), for every released verifier, Desk's pinned gateway and
  verify-ts among them; and `source`, `argumentsCommitment` and `resultDigest` with its artifact
  each need a meaning for a binding.

**The version** (question 6). An optional member of version 3, as `action.policy` (ADR-0011) and
`decision.recordBytes` (ADR-0012) were added: "a verifier written before the member tolerates it,
as it tolerates any signed member it does not know" (§1.2a). Version 4 would have every released
verifier refuse every new receipt, for a member whose absence costs only discovery. A negotiated
extension: §1.2 states no negotiation and the code has none, so it would be a mechanism built for
one member. ADR-0013 declined a version 3 member for the countersignature (F1) because no released
verifier would enforce it; here the member is a pointer, and the countersignature is still read
only from statements by the runtime, so a verifier that ignores it accepts nothing new.

**Where the reader's key comes from** (question 7). The reader's own pin, matched to `keyId`; the
key the named origin serves at `/publickey`, held to `keyId` and §8.4's rule; or the key in the
receipt, declined: "a receipt therefore carries a `keyId` and never a key, so an implementation
cannot accidentally trust the key a store hands it" (§5).

## Decision outcome

Chosen: route 3 as option A, an optional signed member of version 3; the reader's key pinned, or
else served by the named origin and held to `keyId`; the runtime's reader unchanged.

### 1. The member (questions 2 and 3)

A version 3 receipt may carry `witness`, a top-level object:

| Member | Form | Meaning |
|---|---|---|
| `origin` | `https://` or `http://`, a host in lowercase, `:` and a port in decimal with no leading zero, nothing after; `http` only with a loopback address written as one (`127.0.0.0/8`, `[::1]`); at most 2048 characters | where the witness serves §6's paths, at its root; the form Desk binds a submission token to (`witnessOrigin`, `checkWitnessURL`) |
| `keyId` | 32 lowercase hexadecimal characters, derived as §1.2 derives one | the witness's key: the `keyId` its statements carry |
| `trail` | 32 lowercase hexadecimal characters | the trail the gateway named the witness for |

- **The time** is the receipt's `servedAt`, signed with the member.
- **Never recorded:** the submitter's token or its digest, the registration's issuer or subject,
  the witness's audience. A registration is never served (§6), by a receipt either.
- **On an action receipt,** when the record `/act` found is a runtime evaluation record (§4 step 8)
  whose `trail` is 32 lowercase hexadecimal characters and the configuration names a witness for
  it; `trail` is the record's, read from the bytes whose digest matched.
- **On an acquisition receipt,** when the request names a `trail`, a new optional member of
  `/acquire`, that the configuration names a witness for; naming another is refused `400` before
  the source runs. A request names at most a trail, never an origin or a key. Never on a seal.

### 2. How the operator's gateway learns it (question 4)

`witnessedBy` in `engine.json`, at the next free `engineVersion` (`"7"` unless `services` takes it
first): an object keyed by trail identity whose values are `{origin, publicKey}`, `publicKey` 64
lowercase hexadecimal characters, as Desk pins a witness key. `gateway serve` without a
configuration, as Desk runs it, takes `--witnessed-by TRAIL=ORIGIN,PUBLICKEY`, repeatable. It is
not `witness`, the member that makes a gateway a witness (ADR-0013 §4); a gateway may be both. At
start the gateway refuses an origin out of form, a key §8.4's rule refuses, its own key (a gateway
whose key the operator can use is no witness against the operator, ADR-0013 §1) and a trail given
twice, and derives `keyId`; a change takes a restart. Per trail, not per gateway: a witness
registers trails one by one, Desk's one gateway serves desks with witnesses of their own, and a
value for a whole gateway would name a witness for trails never registered there. With
`witnessedBy` given, `/act` reads one member, `trail`, of every record it finds.

### 3. What the member establishes, and what it does not

| | Establishes | Does not establish |
|---|---|---|
| `witness` on a receipt that verifies under the operator's gateway key | the holder of that key, minting the receipt at `servedAt`, named this origin and key identifier for this trail | that the witness holds anything for the trail, or registered it; that a checkpoint was submitted; that the chain is countersigned; that the origin serves the key named; that the witness is independent of the operator, who chose it; anything about the operator's honesty |
| The same on an action receipt, its `trail` the record's (§4 step 8) | the action was minted on a record of that trail | where in the trail the record is: the trail copy shows that |
| A receipt without the member | nothing | that the trail has no witness |
| The chain then read (determination 4) | what ADR-0013 §6 and `SPEC.md` §8.8 say, under the key used | with a key the origin served, not one the reader pinned, any independence beyond the operator's choice of witness |

### 4. What a verifier does (questions 7 to 9)

**Offline,** in `gateway verify` and verify-ts, held by the corpus: at §1.4 order 1, a `witness`
present has its three members in their forms, or the receipt is `malformed` (a member it does not
name is tolerated, as everywhere in a receipt); at §4 step 8, an action receipt's `witness.trail`
is the `trail` of its runtime evaluation record, or **`decision-trail-mismatch`**, beside its `ok`;
and the report gains **`witnesses`**, the distinct `{trail, origin, keyId}` named by receipts whose
ladder status is `ok`, absent when none. Like `observations` it is never part of `ok`; unlike
them the corpus compares it, as a set. A reader takes it only from a verdict it acts on (§5a.1).

**Online,** after the verdict, by a reader — Desk, a script, or the reference `gateway witness
fetch` — held by the scenario (determination 6), not the corpus, as §6's surface is not:

1. Take each triple whose trail is the record's; with none, "No receipt names a witness for this
   trail." Several, after a change, are each read and reported apart.
2. Hold `origin` to `https`; `http` on loopback only when the reader asks (`--allow-loopback`, for
   its own machine and for tests), otherwise **`witness-origin-refused`**.
3. The key: the reader's pinned key whose identifier is `keyId`; otherwise `GET <origin>/publickey`,
   no redirect followed, its `publicKey` held to §8.4's rule and to `keyId`, or
   **`witness-key-not-named`** and nothing from that origin is read. The report says which.
4. `GET <origin>/witness/trails/{trail}/head`, then `/statements?from=` from index 0, or after the
   reader's continuation, to the head's index, within §8.7, with no token and no redirect.
5. `jpack audit verify --witness-key <key> --witness <statements> --witness-head <head>`, with
   `--witness-resume`, `--witness-save` and `--require-countersigned-through` as the reader
   chooses. Its report — `countersigned`, the `witness` section, the sentences — is the reading.

When the witness is **unreachable** (no answer, a timeout, an answer not of its form), step 5 runs
without `--witness-head` over the statements the reader holds — Desk keeps every one — under its
pin, and the reading is historical, as far as supplied; with no pin there is no key and nothing is
read. Either way: "The witness the receipts name could not be reached."
When it **refuses**, a `404` `unknown-trail` reads as a trail never submitted (§8.8); nothing is
credited, and its reason and sentence are given verbatim: "The witness the receipts name holds
nothing for this trail." When it **serves another key**, `witness-key-not-named`, and statements
under another key are `witness-signature-invalid` in the runtime, the named key being the only one
supplied. After a witness goes on under a new key (ADR-0013 §4, rule 3), receipts minted before
the operator's change name the old key, whose chain a reader that kept it reads under its pin,
historically. Two fixed sentences join the report: "The operator's gateway named this witness for
this trail under its own key at T; that is not a statement of the witness." And, for a served key:
"The key was served at an origin the operator's gateway named, so this reading is as independent
of the operator as the operator's choice of witness."

**The runtime needs nothing** (question 8): it reads a key file, statements and a head. **The
front:** §6 has a witness's front pass the submission and the two reads only; a reader without a
pin needs `GET /publickey`, open already, so the front passes it too (question 7).

### 5. Desk (question 10)

- **Its managed gateway** is started with `--witnessed-by` for each desk whose witness URL is at
  its origin's root, from the `witness.json` Desk submits from (the URL's origin as `witnessOrigin`
  gives it, and the pinned key), restarted when either changes. A URL with a path is not named,
  and the settings say so (question 3). Desk sets `trail` on each `/acquire` it sends or relays
  there for a desk so named, and refuses one the page sets, since the assistant drives the page.
- **An external gateway** (`research.gateway`) is not Desk's to configure and is sent no `trail`.
  Desk compares the `witnesses` its verification reports for the desk's trail with its own: a
  triple at another origin or key is shown, "The receipts name a witness this desk does not submit
  to", and Desk reads no chain under a key it did not pin. The panel shows each triple named.

### 6. The acceptance scenario, as the test

A gateway CI job: the gateway built at the pull request's head, the runtime from an image pinned by
digest at v0.28.0 or later (the Dockerfile's pin, 0.21.0, predates `--witness`), every process on
`127.0.0.1`.

1. **Witness W:** an engine from the reference with its own seed, `witness` configured,
   registration by its operator, and a test issuer as `go/witness_serve_test.go`'s `edIssuer`. Its
   public key is `K_W`.
2. **The operator's gateway G:** an engine with its own seed, the test issuer, a source and a
   write tool that are the test's programs, a decision-record directory, and
   `witnessedBy: {T: {origin: "http://127.0.0.1:<W's port>", publicKey: K_W}}`.
3. **The trail:** an acquisition at G naming `T`; the pinned runtime writes chained records of `T`
   into the directory, `R` at sequence `n` citing that receipt; `T` registered at W
   (`POST /witness/registrations`); `audit checkpoint` through `n` submitted: `200`, a statement.
4. **The action:** `POST /act` at G on `R`, citing the acquisition; the session sealed. Both
   receipts carry `witness: {origin, keyId(K_W), trail: T}`.
5. **The verifier** holds `R`'s line and the trail, G's store, registry and pinned key, and nothing
   about W. `gateway verify --decision-records` answers `ok`, `witnesses` naming W for `T`;
   `gateway witness fetch --allow-loopback` takes W's key from `/publickey`, matched to the named
   identifier, and the head and statements; `jpack audit verify --witness-key …` reports
   `countersigned` through `n`, current, with no `witness-*` finding.

The negatives:

- **W stopped** after step 3: the fetch reports it unreachable; with `K_W` pinned from before,
  the kept statement's reading is historical, as far as supplied, countersigned through `n`.
- **A key W does not hold**, G naming W's origin with another key: the fetch is
  `witness-key-not-named`, and W's statements under the named key are `witness-signature-invalid`.
- **Another origin than the statements came from**, G naming a second witness W2, its own seed,
  holding nothing for `T`: `404` `unknown-trail`, and W's statements under W2's key are
  `witness-signature-invalid`. Nothing is countersigned.

Both verifiers, Go and TypeScript, answer new vectors in `corpus/v3/stores/`: an acquisition and
an action carrying the member, `ok`, with `witnesses`; two witnesses named for one trail; a receipt
failing the ladder, which names nothing; `decision-trail-mismatch`; `malformed` for an `http`
origin off loopback, an origin with a path and a `keyId` in upper case; and `signature-mismatch`
for the member appended after signing.

### 7. Delivery, after acceptance

| # | Repository | What | Needs |
|---|---|---|---|
| 1 | gateway | This record | the maintainer's answers |
| 2 | gateway | `SPEC.md` §1.2a, §1.4, §4 step 8 and `witnesses`, §6 (`trail` on `/acquire`, `/act`, the front's `/publickey`, the online steps), §7; the vectors of determination 6 in `gateway conform` and verify-ts, with the corpus README's counts; `witnessedBy`, `--witnessed-by`, `gateway witness fetch`. One cross-vendor round: public-surface, documented-claim, conformance, security | 1 |
| 3 | gateway | The scenario of determination 6 in CI, in row 2's release, so the member never ships unexercised | 2 |
| 4 | runtime | Nothing: its reader reads what row 2's fetch writes | — |
| 5 | desk | An amendment to Desk ADR-0012 §1 and its build: the managed gateway named from `witness.json`, `trail` on its acquisitions, the comparison with an external gateway's `witnesses`, the panel's triples; pins moved to row 2's release | 2 and 3 released |

### Consequences

- Good, because a verifier finds the witness from a record and its receipts, under a signature it
  checks; a change shows receipt by receipt; no released verifier fails or accepts more; it runs
  in CI.
- Bad, because receipts for a named trail grow about 150 bytes, and `/act` reads every record's
  `trail` once `witnessedBy` is given.
- Bad, because an acquisition's trail is the request's, so a caller can name another trail than
  the citing record's; the witness stays the configuration's, and readers use the record's trail.
- Bad, because a reader without a pin trusts the operator's choice of witness; a witness's front
  passes `/publickey`; and the online steps are held by the scenario alone, not the corpus.
- Bad, because Desk's relay reads a member it carried unread, a witness URL with a path cannot be
  named, and a reader with no pin reads nothing while the witness is down.
- Revisit when a trail has two witnesses at once; when the seal moves version; when the
  specification takes up the witness (RFC 0017, draft); or when a registration is to be served.

### How this sits with earlier records

ADR-0013's statement, endpoints and reading are unchanged; its F1 objection is answered above;
under its question 6 the named `keyId` is the witness gateway's own; and its question 10 bears
here: a trail continued under a new identity is a new `witnessedBy` entry, a witness under a new
key a changed one, and receipts minted before keep naming what was configured then. ADR-0011's
and ADR-0012's optional members are this one's precedent, and ADR-0011's determination 2, that a
tool held to no policy reads nothing of its record, is narrowed: with `witnessedBy`, `/act` reads
the record's `trail`. Desk ADR-0012's witness, pin and origin rule are the values named.

## Questions for the maintainer

1. **A member on each receipt, or a binding receipt per trail?** **Proposed:** a member (A); a
   binding kind is version 4, which fails the whole store for every released verifier.
2. **Which receipts carry it?** **Proposed:** actions, the trail read from the record; and
   acquisitions whose request names a configured trail, which desks' records cite. No seal.
3. **What is recorded?** **Proposed:** `origin` (scheme, lowercase host, explicit port, paths at
   its root), `keyId`, `trail`; the time is `servedAt`; no token, subject or registration.
4. **How does the operator's gateway learn it?** **Proposed:** `witnessedBy` per trail at the next
   free `engineVersion`, `--witnessed-by` for `serve`; its own key refused; never a request.
5. **What does it establish?** **Proposed:** determination 3: the operator's gateway named this
   witness for this trail then, under its key; nothing of the witness, the chain or the operator.
6. **Version 4, or an extension?** **Proposed:** an optional signed member of version 3, as
   `action.policy` and `decision.recordBytes` are; §1.2 states no negotiation.
7. **Where does the reader's key come from?** **Proposed:** its pin, or else the named origin's
   `/publickey` held to `keyId` and the key rule, the report saying which; never the receipt.
8. **Does the runtime need anything?** **Proposed:** no; discovery and fetching are the reader's,
   the reference one being `gateway witness fetch`.
9. **Unreachable, refusing, another key?** **Proposed:** a historical reading of what is held; the
   refusal verbatim, nothing credited; `witness-key-not-named`, nothing read.
10. **Desk's one value?** **Proposed:** its managed gateway started from `witness.json`, the trail
    set by Desk; an external gateway's `witnesses` compared with its own, a difference shown.
11. **ADR-0013's question 10 (retirement, new trail, new key)?** **Proposed:** nothing of its own:
    each is a configuration change; receipts keep what was configured when minted.

## More information

- `SPEC.md` §1.2, §1.2a, §1.4, §3, §4, §5, §5a, §6 and §8; `corpus/README.md`, `corpus/v3/stores/`;
  `go/act.go`, `go/serve.go`, `go/verify_v3.go`, `verify-ts/src/structure.ts`;
  [engine-config.md](../design/engine-config.md).
- [ADR-0011](0011-hold-a-write-to-its-decision.md),
  [ADR-0012](0012-hold-a-write-to-a-signed-record.md) and [ADR-0013](0013-checkpoint-witness.md);
  Desk ADR-0005 and ADR-0012; the runtime's guide, "Reading a witness's statements"; issue #199.
- Material-decision categories, once accepted: public-surface, documented-claim, conformance,
  security.
