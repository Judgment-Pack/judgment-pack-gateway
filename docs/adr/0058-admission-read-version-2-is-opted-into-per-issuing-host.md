---
status: accepted
date: 2026-11-23
deciders: maintainer
---

# The admission read version "2" is opted into per issuing host, and names the tool's descriptor digest

0058 is a placeholder, assigned at merge. The engine version this record adds is
`<engine-version: assigned at merge>`, called *the new engine version* below: it takes its number
in merge order, and 47 is expected. The maintainer accepted this record with the rulings at its
end, which answer its open questions.

## Context and problem statement

Spec RFC 0030's amendment, §2a (*The admission reads on the wire*), states the admission read
version `"1"` as this gateway sends it and adds version `"2"`: a call read carries two more members
in `call`, `version` (the called tool's descriptor digest, or `null`) and `skills` (the skills loaded
in the run, or `null` from a sender that does not observe them), and may be answered with two more
step-12 refusals, `tool-version-refused` and `skill-refused`. An issuing host answers a body it does
not read with `{"refusal": "read-version-unsupported"}` or `{"refusal": "read-malformed"}`. A
sender's version is configured, never negotiated, and never falls back. The RFC's acceptance plan
(build step 4) needs version `"2"` reads at the gateway, passing one shared set of conformance
cases.

Today the gateway sends only `"1"`: `readBody` writes `readVersion` `"1"`
(`go/delegation_admission.go:161`), and `admissionReadAt` (`go/delegation_admission.go:173`) takes
exactly the three answer forms of SPEC.md §11.5, refusing everything else as `admission-unknown`.
Its tools/list (`gateway mcp`) carries each tool's owner declaration in `_meta`
(`go/descriptor_start.go:493`) but not the descriptor digest, so a client that approves a gateway
tool cannot record the digest the gateway's own read will name (RFC open question 24).

## Decision drivers

- `"1"` stays the default, and stays byte for byte what it is; `"2"` is opt-in.
- The version is the operator's configuration for one issuing host, never negotiated, never
  retried at another version (RFC §2a, *Which version a sender sends*).
- `version` comes from the approval the gateway dispatches under, never from the request, the model
  or the tool's answer, as the effect does (SPEC.md §11.5, *The call's scope*).
- Every new answer form fails closed, and a step-12 refusal counts nothing.
- One set of conformance cases serves the gateway and the agent library alike.
- No receipt, verifier or corpus change unless one is needed.

## Considered options

For the configuration:

- A. A member of each issuing host's entry: `delegation.hosts[i].admission.readVersion`.
- B. One gateway-wide member: `delegation.readVersion`.
- C. Ask the host which versions it reads. Refused by the RFC: a sender never negotiates.

For the version label:

- L1. The label goes in the tools/list `_meta` beside the digest; the read's `call.version` is the
  digest alone.
- L2. `call.version` holds the label where one is declared. Refused: §2a's form of `version` is a
  digest or `null`, and a host answers `read-malformed` to a member of another form.
- L3. A third member of `call` for the label. Not available: §2a defines no such member, and a
  member "not defined at that version" is `read-malformed`. It would need an RFC amendment.

## Decision outcome

Chosen options: "A" and "L1". A, because the RFC fixes the version per issuing host ("the version
its configuration names for that host") and its upgrade order moves each sender only once its host
says it reads `"2"`, which one gateway-wide switch cannot follow when the gateway serves hosts at
different stages. L1, because it is the only option the RFC's wire form admits. The plan's earlier
wording, "label in `call.version`", meant this: the label beside the digest in `_meta`. The RFC
needs no amendment (ruling 1).

### 1. The configuration member

From the new engine version, `delegation.hosts[i].admission` takes an optional `readVersion`, the
string `"1"` or `"2"`, beside `url` and `credential`. Absent is `"1"`. `"1"` written out is the same
as absent. Any other value, a non-string included, refuses the configuration, naming the host and
both values. Below the new engine version the member is refused by name, as `admission` refuses any
member it does not define today (`exactlyMembers` at `go/delegation_config.go:142`). The value is
read once at start, as the rest of `admission` is; a change takes a restart.

```json
"admission": {
  "url": "https://issuer-a.example/delegation/admission",
  "credential": "/etc/engine/issuer-a-admission-token",
  "readVersion": "2"
}
```

Every read the gateway sends to that host is at that version: the call read, the binding read of
§11.3 (`call` `null`) and the standing read of §11.8.

### 2. The bodies at "2"

At `"2"` the gateway sends §2a's bodies exactly, in `canon`:

- **call read:** version `"1"`'s body with `readVersion` `"2"` and `call` holding `count`, `effect`,
  `skills`, `source`, `tool` and `version`;
- **binding read:** version `"1"`'s with `readVersion` `"2"`, `call` `null`;
- **standing read:** version `"1"`'s with `readVersion` `"2"`.

A synthetic call read at `"2"`:

```json
{"at":"2030-01-01T00:00:00.000Z","audience":{"kind":"gateway","name":"gateway.example"},"call":{"count":true,"effect":"read-external","skills":null,"source":"tracker/live","tool":"search","version":"sha256:<64 lowercase hex>"},"chain":["sha256:<64 lowercase hex>"],"host":"issuer-a","readVersion":"2"}
```

The gateway sends no skill-load read: only the library loads skills.

### 3. What `call.version` holds

`call.version` is the `descriptorDigest` of the called tool's entry in the descriptor snapshot the
call's operation pins: the live operation's for `/acquire`, the write operation's for `/act` and for
a dry run (ADR-0054). It is read once at start from the pinned snapshot, its bytes checked against
the pin before they are parsed (`parseSnapshot`, `go/descriptors.go:158`; the member at
`go/descriptors.go:258`), and held per source and tool beside the effects the call sites already pass
(`go/serve.go:1469`, `go/act.go:347`, `go/act.go:612`, `go/act_dry_run.go:180`). A pinned snapshot
that cannot be read refuses the start, as it already refuses the frontend's start.

- **A tool with no label:** `call.version` is the digest. The label never enters the read, with or
  without one (L1).
- **`null`:** where the operation pins no snapshot, or pins one of a version that holds no
  `descriptorDigest` (snapshot versions 1 and 2). §2a: "`null` where that approval records none".
- **Never from the request:** an argument, a header or a body member naming a version changes
  nothing. The descriptor drift check before `tools/call` (`mcp-descriptor-drift`) keeps the
  approved digest the descriptor of the tool called.

### 4. What `call.skills` holds

Always `null`. The gateway does not observe what a run has loaded and takes no list from a caller
(§2a, *What a gateway read carries instead*). A request member naming skills is not read.

### 5. The answers, and how they reach `/acquire` and `/act`

At `"2"` the gateway takes §11.5's three answer forms and, beside them:

| Answer | Taken when | `/acquire` | `/act` (and a dry run) |
| --- | --- | --- | --- |
| `{"admission": "refuse", "refusal": "tool-version-refused"}` | the read names a call | `403`, `{"error", "refusal": "tool-version-refused"}` | the same, with `"refusedAt": "delegation"` |
| `{"admission": "refuse", "refusal": "skill-refused"}` | the read names a call | `403`, `{"error", "refusal": "skill-refused"}` | the same, with `"refusedAt": "delegation"` |
| `{"refusal": "read-version-unsupported"}` | any read | `403`, `{"error", "refusal": "read-version-unsupported"}` | the same, with `"refusedAt": "delegation"` |
| `{"refusal": "read-malformed"}` | any read | `403`, `{"error", "refusal": "read-malformed"}` | the same, with `"refusedAt": "delegation"` |

- Each answer is exactly those members; any other member, or one of these at a read it is not taken
  at (a step-12 refusal answering a binding read, the spec's case `read-v2-binding-step-12`), is
  `admission-unknown`.
- At `POST /delegation/credential` the binding read's `read-version-unsupported` or `read-malformed`
  refuses the binding, `403` with that `refusal` (§11.3, step 3).
- A standing read answered either form is `standing-unknown` (RFC §2a; §11.8), as any other answer
  that is not `current` or `removed`.
- Nothing is dispatched, retained or minted on any of them, and `error` is one fixed sentence per
  name that repeats nothing of the answer.

**Order.** In `admitDelegated` (`go/delegation_admission.go:266`), `read-version-unsupported` and
`read-malformed` are reported where steps 8 to 10 are, before the gateway's own part of step 11, as
`admission-unknown` is (RFC §2, the refusals outside the table). `tool-version-refused` and
`skill-refused` are step 12, reported after the gateway's own step 11, as `subject-mismatch` and
`subject-unauthorized` are. The grant's owner refusals stay after step 12 (§11.5).

**Counting.** Unchanged: `count` is `true` only as §11.5 says. A step-12 refusal counts nothing at
the host. A lost answer to a counting read still refuses and may have been counted, which fails
closed.

### 6. No fallback, no retry

A `"2"` read answered `read-version-unsupported`, or refused in any way, is never sent again at
`"1"`. A host at `"1"` is never sent `"2"`. A test double counts the reads made, and a refused call
makes exactly one.

### 7. The tools/list `_meta`

From the new engine version, each served platform tool's `_meta` (`listingEntry`,
`go/descriptor_start.go:493`) adds:

- `descriptorDigest`: the live operation's snapshot entry's digest, as in decision 3; absent where
  that would be `null`;
- `versionLabel`: the label the binding declares for the tool (decision 8); absent where it declares
  none.

The seal tool carries neither. Below the new engine version the listing is byte for byte as before,
and `testdata/tool-taxonomy/served-listing.json` is unchanged; a second vector,
`testdata/tool-taxonomy/served-listing-read-v2.json`, holds the listing at the new engine version. Both members are information for a host approving a tool, which it can
check against the snapshot it approves; they grant nothing, like the rest of `_meta`. The two members
add up to about 170 bytes to an entry, inside the listing budget (*Budgets*, tool-descriptors
design), so a listing near the budget sends some tools without their descriptions sooner.

### 8. The version label in the binding

A bindingVersion 2 MCP operation may declare, beside `toolTaxonomies`, `toolVersions`: an object
whose keys are among the operation's allowed tools and whose values are labels, 1 to 64 characters
of `A-Z a-z 0-9 . _ + -`, the first a letter or digit. It is stripped beside `toolTaxonomies` before
the operation's members are checked (`go/taxonomy.go:152`). Below the new engine version a binding
that holds it is refused by name; an engine built before this record refuses it as a member the
operation does not define. Declaring or changing a label changes the binding's digest, so it needs
the operator's recapture, as any binding change does. The label is the binding author's name for a
version; nothing reads it as authority, and no admission judges it.

### 9. Receipts: nothing more

Item 1 needs no new receipt member. Both values follow from bytes a receipt already commits to by
digest:

- an action receipt's identity carries `binding` (`go/action_execution.go:238`), `approval` with
  `descriptorPin`, the pinned snapshot's digest (`go/action_execution.go:151`, `:248`), and, where
  the registration has it, `descriptorProvenance` (`go/action_execution.go:252`);
- an acquisition receipt of shape `mcp` carries `acquisition.descriptorProvenance.snapshot` (SPEC.md
  §9), and an owner-declared acquisition's statement holds `descriptorSnapshot`.

The snapshot holds the tool's `descriptorDigest`, which is `call.version`; the binding pinned by
digest holds the label. The `delegation` member (§11.7) is unchanged and does not record the read
version (ruling 4). No verifier, corpus family or receipt version changes.

### 10. What is unchanged for "1", byte for byte

With no `readVersion`, or `"1"`: every body, the answers taken, the refusals and their order, the
counting, the timeouts and the caps are as today; the existing admission tests pass unchanged, and
the conformance case `read-v1-call` is the bytes the gateway sends. At `"1"`, every answer of
decision 5 is `admission-unknown`, as RFC §2a states (`read-v1-sender-new-answer`). Below the new
engine version nothing changes at all, the tools/list included.

### 11. Posture names each host's read version

From the new engine version, `/posture` (§11.9) names each issuing host's `readVersion`, `"1"` or
`"2"`, so a host left at `"1"` or moved to `"2"` is visible to the operator before a call is
refused (ruling 3). Below it, posture is as before. Receipts do not record it (decision 9).

### Upgrade order

1. The issuing host reads `"1"` and `"2"` and says so in the contract it publishes.
2. The operator installs this release. Nothing changes until the configuration does.
3. The operator moves the configuration to the new engine version and sets
   `admission.readVersion: "2"` for that host alone, then restarts. Other hosts stay at `"1"`.
4. Optionally, the binding author declares `toolVersions`, and the operator recaptures.

The gateway and the agent library move in either order (RFC §2a, *The upgrade order*, step 2).

### Rollback

Remove `readVersion`, or set `"1"`, and restart: the gateway sends `"1"` again. Nothing stored
depends on the version: credentials are in memory only and end at the restart, and receipts are
unchanged. Rolling the binary back below this release also needs the engine version moved back
first (an older engine refuses the new one at start) and any binding holding `toolVersions`
replaced by one without it, with a recapture.

### Tests planned

- The shared conformance set, vendored byte for byte and pinned by its SHA-256 as
  `go/delegation_es256_test.go:19` pins `es256-statements.json`: every case whose `applies` holds
  `sender` and whose `senders` names the gateway, against an issuing-host test double. A case whose
  sender part is "never emits" is passed as ruling 2 says.
- `"1"` byte for byte: a host with no `readVersion` and one with `"1"` send identical bytes,
  `read-v1-call`'s; the existing `delegation_admission` tests unchanged.
- Configuration: `"2"` below the new engine version refused by name; `3`, `"3"`, `""` refused;
  `toolVersions` form, keys outside the allowed tools refused, and the member refused below the
  version.
- Bodies at `"2"`: `/acquire`, `/act` and a dry run each name the right operation's digest; `null`
  for a version-2 snapshot and for no pin; a request carrying a version or skills changes no byte.
- Answers: each row of decision 5 at `"2"`, and each as `admission-unknown` at `"1"`; a step-12
  refusal answering a binding read is `admission-unknown`; extra members refused.
- Order: `read-malformed` before the gateway's own `out-of-scope`; `tool-version-refused` after it.
- No retry: one read per refused call; never a `"1"` read after a `"2"` refusal.
- The standing read and the binding read at `"2"`, and their refusals.
- tools/list: the new vector; the old one unchanged below the version.
- Posture: each host's `readVersion` at the new engine version; nothing new below it.

### Mutants planned (four, each in a scratch copy)

1. Resend at `"1"` after `read-version-unsupported`: the no-retry test fails.
2. Take `tool-version-refused` at `"1"`: the `"1"` answer test fails.
3. Take `version` from the request's arguments: the body test fails.
4. Report `read-malformed` after the gateway's own `out-of-scope`: the order test fails.

### What the release notes must say

- Read `"2"` is opt-in per issuing host (`admission.readVersion`, new engine version); `"1"` is the
  default and is unchanged byte for byte.
- Set `"2"` only once that host says it reads `"2"`. There is no negotiation and no fallback: a
  host that does not read `"2"` refuses every delegated call, binding and standing read from this
  gateway until the setting is undone.
- The four new refusal names on `/acquire`, `/act` and `/delegation/credential`, with their order.
- The gateway's reads always carry `skills: null`; a host whose policy refuses `null` skills
  refuses every gateway read (RFC open question 25).
- tools/list `_meta` gains `descriptorDigest` and `versionLabel` at the new engine version, and a
  listing near its budget may send fewer descriptions.
- `toolVersions` in a binding, and that it needs a recapture.
- Receipts, verifiers and the corpus are unchanged.
- The rollback steps above.

### Consequences

- Good, because a host can judge the exact tool version a gateway call is made at, and a client
  approving a gateway tool can record the same digest from `_meta`.
- Good, because `"1"` is untouched, and each host moves alone.
- Bad, because a misconfigured `"2"` refuses every delegated call to that host; it fails closed by
  design, and posture shows it (decision 11).
- Bad, because a label in a binding forces a recapture, and the label is judged by nobody.
- Revisit when the RFC defines a machine-readable statement of the versions a host reads (open
  question 26 there), or a member for the label.

## More information

- Spec RFC 0030, §2 (step 12 and the refusals outside the table) and §2a, at
  [`4b51a575`](https://github.com/Judgment-Pack/judgment-pack-spec/blob/4b51a575aae13b4c549c93ea41a73872e62eb890/rfcs/0030-agent-principals-and-delegated-authority.md);
  its *Conformance cases the amendment of 2026-11-22 adds*, tables 4 and 5.
- SPEC.md §11.2, §11.3, §11.5, §11.7, §11.8, §9.
- [ADR-0021](0021-owner-taxonomy-binds-current-tool-approval.md),
  [ADR-0054](0054-act-takes-a-scope-a-dry-run-is-signed-as-no-action-and-an-action-cites-approval-records.md),
  `docs/design/tool-descriptors.md`.

**The shared conformance set.** One file in the specification repository,
`conformance/delegation/admission-reads.json`, beside `es256-statements.json`, listed in that
directory's README with its case count and SHA-256. It holds table 4 and table 5, one case per name
(a row naming several cases becomes several), and the case ruling 5 adds. Each case holds `name`,
`table`, `kind`, `applies` (the side it holds, `issuing-host`, `sender` or both, each with what that
side does; ruling 2), `senders` (`["gateway"]`, `["library"]` or both; the `skills` and skill-load
cases are the library's), the sender's
configured `readVersion` and the versions the host double reads, `inputs` (the chain by the name of
a case in `ed25519-statements.json`, `at`, `audience`, the call or the load, the approved `version`,
the loaded skills, `count`, and the host double's policy where a case needs one), `body` (the exact
`canon` bytes as a string, or `null` where no read is made), `answer` (the exact answer bytes, or
`null` for none), and `expect` (the verdict, whether anything is counted, that nothing is resent,
and for table 5 what is loaded). Bodies are strings because `canon` bytes, an over-cap body among
them, must compare byte for byte. The file is hand-written and needs no signer, but is frozen once
both implementations pin it. The gateway copies it as `testdata/delegation/admission-reads.json`
and pins its SHA-256 in the test; the library as its README states. A change is a new digest and a
new copy in each repository. That set, passed by both, is the RFC's acceptance evidence for spec
`v0.6.1`, stated as two separately written implementations, same vendor, not a cross-vendor claim.

## Rulings on the open questions

The maintainer's rulings, at acceptance:

1. **A label in `call.version`.** No. The version label goes in the tools/list `_meta` only, beside
   `descriptorDigest`, never in `call.version`, which is a digest or `null` (RFC §2a). The RFC needs
   no amendment. The plan's earlier wording "label in `call.version`" meant the label beside the
   digest in `_meta`.
2. **Table 4's reader-side cases.** The malformed-body cases (`read-version-not-a-string`,
   `read-v1-with-skills`, `read-v2-skills-missing`, `read-v2-skills-unsorted`,
   `read-v2-skills-repeated`, `read-v2-call-and-load`, `read-body-over-cap`) are passed by both
   implementations as senders: they never emit such a body, and they refuse correctly when answered
   `read-malformed`. The conformance file's `applies` says so per case
   (`"sender": "never emits; refuses on read-malformed"`); the reader verdicts stay an issuing
   host's evidence.
3. **Posture.** `/posture` shows each issuing host's `readVersion` (decision 11).
4. **The read version on the receipt.** Not recorded: receipts do not record it.
5. **A step-12 refusal answering a binding read.** It is `admission-unknown`, and the spec gains a
   case for it, `read-v2-binding-step-12`, in the same change that adds the conformance file.
