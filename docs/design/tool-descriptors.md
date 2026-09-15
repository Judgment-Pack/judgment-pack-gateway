# Tool descriptors, captured at connect

[mcp-server.md](mcp-server.md) serves each platform tool with a generated description and the
open schema `{"type": "object"}`, which admits any object and constrains no member. It says why:
the binding carries tool names only, and the frontend never runs a platform's server, because
running it means holding its credentials. So a host validating arguments learns nothing about a
tool's arguments, and a model must know the tool from elsewhere. It names the follow-on:
descriptors captured by `connect`, which already runs the adapter in check mode under the
platform's own user. This note designs that follow-on before code. It changes no receipt, no
signer route and nothing in `SPEC.md`. **Nothing captured becomes an engine claim:** no receipt
covers a description or a schema, and the engine's key signs neither.

## Scope

Version 1 accepts little on purpose, and says so. A schema is served only from a
reference-free subset: objects with primitive fields, arrays, ordinary bounds, and simple
unions, `null` included. That fits what Pydantic emits for a flat model, and what
`zod-to-json-schema` emits for a flat object with references off. It does not fit a nested
Pydantic model, which emits `$defs` and `$ref`, or any schema with a `format` or a `pattern`.
Such a schema falls back whole: one unsupported field costs the tool its schema. Expanding local
references within bounds is a later design, with its own limits after expansion. Removing an
unsupported keyword silently is never done, since that would serve a schema the server did not
write.

## What is captured, and from where

Descriptors are captured from one check only: the `<platform>/live` MCP check, which `connect`
runs as the platform's user with the live operation's credentials. A write operation's check is
never a source: it may run under other credentials, against another server. The check lists
tools as it does today, page by page, at most 32 pages. Two conditions fail the whole check,
since a listing that meets them cannot be pinned: a cursor seen twice, and a tool name offered
twice anywhere in the enumeration, even with an identical descriptor. A tool the live operation
allows and the server does not offer fails the check, as it does today. `connect` asks that
check, and no other, to capture, by handing its adapter the platform's name and the pinned
binding (`--descriptors-platform`, `--descriptors-binding`). The adapter then writes the
snapshot whole, so the snapshot's bounds are exact where tools are admitted. It judges each
allowed tool as the page holding it is read, and keeps only what it captures and why the rest
fell back, so no descriptor outlives its page.

For each allowed tool, two members of its descriptor are candidates:

- `description`, a string, which may be absent;
- `inputSchema`, the object the server declares for the tool's arguments.

A third candidate is the server's identity: the `name` and `version` its `initialize` answer
gives. They are taken from the answer itself, never from the redacted copies today's report
prints.

These are not captured:

- **`outputSchema`.** The frontend's answer is `{session, result, receipt, salts}`, where `result`
  is the whole MCP tool result carried into the canonical domain, not the server's
  `structuredContent`. Declaring an `outputSchema` would oblige the frontend to produce
  conforming structured content, which it does not. Receipts keep what they carry today: an
  MCP-shaped acquisition digests the `outputSchema` it saw into `acquisition.schema`, at call
  time.
- **`title` and `annotations`.** A title is one more untrusted surface a host shows a person, and
  annotations are the server's claims about side effects, booleans included. The tool's name,
  `<platform>.<tool>`, is the label.

## Three representations, and strict decoding at each boundary

**On the wire from the server.** Today's validation stays exactly as it is for acquisitions. A
message that is not UTF-8, that holds a lone surrogate, or that names a member twice anywhere
fails the check. The adapter canonicalizes a message to validate it and discards the result, as
it does today. A candidate's **original bytes** are the bytes the server wrote for that member,
cut from the message.

**In the check report and in the snapshot.** The report gains a `descriptors` member holding the
snapshot in the canonical form of `SPEC.md` §1.1, which is the file's content. `connect` decodes
that member strictly, not with the lenient decoding `describeCheck` uses for the rest of the
report:

- exact member names, and exact types for each;
- no member name twice, at any depth;
- UTF-8 only, no lone surrogate, and nothing after the value.

A report whose `descriptors` member fails those rules fails the check; it is not a fallback. A
schema candidate is stored as a JSON **string** holding its original bytes, `inputSchemaText`, so
no encoder along the way can compact, reorder or respell it. The frontend decodes the snapshot
by the same strict rules.

**Served.** The serving projection of a schema is its original text parsed strictly, with the
annotations removed at schema locations (below), and re-encoded compactly. Every number keeps its
spelling, and member order is not kept, since it carries no meaning in JSON. The display policy
and the secret screening examine decoded string values; the grammar examines the parsed schema.

## What a candidate must be

### The display policy, version 1

The policy applies to every string a model or a person could be shown: the description, the
server's name and version, and within a schema every property name and every string value. Its
classes are defined by the **Unicode 15.0.0** character database, the version of the Go release
that builds both processes. They are committed as tables generated from that database, so
neither process consults its runtime's own Unicode tables for them. A string is refused when it
holds a code point of any of these classes (the named properties are the definition, and the
examples are only examples):

- `General_Category=Cc`, other than U+0009 (tab) and U+000A (line feed): the C0 controls,
  DEL and the C1 controls;
- `Bidi_Control`: U+061C, U+200E, U+200F, U+202A–U+202E, U+2066–U+2069;
- `Default_Ignorable_Code_Point`: for example U+00AD, U+034F, U+115F–U+1160, U+17B4–U+17B5,
  U+180B–U+180F, U+200B–U+200F, U+2060–U+206F, U+3164, U+FE00–U+FE0F, U+FEFF, U+FFA0, and
  U+E0000–U+E0FFF;
- `General_Category=Co` (private use), `General_Category=Cn` (unassigned in Unicode 15.0.0), and
  `Noncharacter_Code_Point`.

The policy refuses; it never strips or normalizes. Stripping would change what the secret check
saw, and a schema's names and constants mean what they spell. That costs legitimate text: a
description whose emoji or Indic script needs a joiner falls back. Confusable letters pass. No
character rule catches them, and the note does not claim one does. A snapshot records
`"policy": 1`. A frontend refuses to start on a snapshot whose policy it does not implement.

### The schema grammar, version 1

**Locations.** A schema is a JSON object. A boolean schema is refused everywhere, except as the
value of `additionalProperties`. The schema locations are:

- the root;
- each value of `properties`;
- the value of `items`;
- an object value of `additionalProperties`;
- each element of `anyOf`, `oneOf` and `allOf`;
- the value of `not`.

Nothing else is a schema: the members of `properties` are names, and `examples`, `default`,
`enum` and `const` hold data.

**Keywords.** At a schema location, only these keywords may appear, with these values:

| Keyword | Value |
|---|---|
| `type` | one of `null`, `boolean`, `object`, `array`, `number`, `string`, `integer`, or a non-empty array of distinct ones; at the root, exactly `"object"` |
| `properties` | an object of at most 256 members, each a schema |
| `required` | an array of at most 256 distinct strings |
| `additionalProperties` | a boolean or a schema |
| `items` | a schema; the array form is refused |
| `enum` | a non-empty array of at most 256 distinct scalars |
| `const` | a scalar |
| `minimum`, `maximum`, `exclusiveMinimum`, `exclusiveMaximum` | a number (the older boolean exclusive forms, from draft-04, are refused) |
| `multipleOf` | a number greater than zero |
| `minLength`, `maxLength`, `minItems`, `maxItems`, `minProperties`, `maxProperties` | a non-negative integer, written without fraction or exponent, at most 2^53−1 |
| `anyOf`, `oneOf`, `allOf` | a non-empty array of at most 16 schemas |
| `not` | a schema |
| `description`, `title`, `$comment` | a string |
| `examples` | an array |
| `default` | any value |
| `deprecated`, `readOnly`, `writeOnly` | a boolean |
| `$schema` | at the root only: `https://json-schema.org/draft/2020-12/schema` or `http://json-schema.org/draft-07/schema#` |

Every other keyword refuses the schema. That includes `format`, which a host may validate with
regular expressions or handlers of its own; `pattern`, `patternProperties` and `propertyNames`;
and every reference or identifier keyword (`$ref`, `$dynamicRef`, `$defs`, `definitions`,
`$id`, `$anchor`, `$recursiveRef`).

**Numbers.** A number is written in at most 32 characters, with an exponent, if any, within ±308.
An integer where the table asks for one is written as one.

**Dialect.** An absent `$schema` is taken as 2020-12. That is this gateway's own policy: MCP
2025-06-18, the version both processes speak, names no default. The subset means the same under
2020-12 and draft-07. Every accepted schema is valid under both dialects' meta-schemas, which the
implementation's tests check offline.

**Limits.**

| Limit | Bound |
|---|---|
| nesting of schema locations | 32, the root the first |
| schema locations in all | 2048 |
| a property name | 128 bytes |
| any other string in a schema | 1024 bytes |
| a schema's original text | 16384 bytes |
| a description | 4096 bytes |
| the server's name, and its version | 256 bytes each |

A refusal names the JSON Pointer of what it refuses, except for the whole-text bound and the
count of locations. Which location is one too many depends on the order a walk takes, and two
implementations need not share one.

**What it bounds.** With no references, no regular expressions and bounded size, what a host
does to a value because of the schema is linear in the schema's size. What it does also depends
on the size of the value it validates and on the host's own limits, which the gateway does not
set. What a host chooses to render from a schema is the host's.

### Secrets

A candidate is refused, never redacted, when any of its decoded strings contains a value the
check's secret collection finds in the credentials. That covers property names and the server's
name and version. Three kinds of string are the grammar's own words in their own places, the
same whatever the credentials hold, and are not screened: a keyword the grammar names, as a
member of a schema location; a type name, as the value of `type`; and a dialect's URI, as the
root's `$schema`. Screening them would only refuse, for example, every schema that uses
`required` beside a PostgreSQL credential `sslmode=require`. The exemption is by role, not by
spelling: a property name, a string of data, a description, a title, a comment or a name
`required` lists is screened even when it spells one of those words, since a server chose it. A
refused identity is omitted, and the provenance names no server. The report says only that a
candidate held a credential value, never which. Screening finds the values the collection finds:
whole scalars of the credentials file, the user, password and query values of a URL in it, and
the scalars of JSON nested in its strings. It does not find a secret split across strings or
spelled in another encoding. A snapshot is written readable to every local user, mode `0644`.
The design therefore assumes a descriptor is not confidential beyond the values screening finds.
A deployment for which that is not so should not capture descriptors.

## Budgets

The limits below are exact, and when one is reached the overflow is deterministic:

- **Candidates:** each within the limits above.
- **A snapshot:** at most 320 KiB, the whole file. Of that, the candidates' text, the
  descriptions' bytes and the schemas' original texts, totals at most 256 KiB, leaving the rest
  for names, identity and the wrapper. The adapter admits tools in the server's order while both
  bounds hold with the tool added. Every later tool falls back, reported as over the platform's
  budget. A platform or binding so long that the snapshot passes its bound with no tool in it
  admits none, and the report carries no snapshot and says why.
- **The check report:** at most 1 MiB, as `connect` bounds it today. Every field outside
  `descriptors` is capped:
  - the list of offered tool names, and the fallback reasons, at 64 KiB each, with what passes
    a cap counted, not listed;
  - every other string field, at 512 bytes, the marker of a cut included: the adapter's
    identity, the server's name and version, the probe's tool name, the protocol version.
    Today's redaction cuts the server's name and version at 512 bytes and then adds a
    three-byte marker; the report's cap counts the marker.

  So the report without `descriptors` is at most about 130 KiB, and with a snapshot of at most
  320 KiB it stays inside 1 MiB. The adapter checks the serialized report against 1 MiB before
  writing it. Should it pass anyway, the adapter drops `descriptors`, so every tool falls back,
  and says so. It never lets `connect` kill the check.

  The report names each fallback by its part (the server's identity, a description, an input
  schema, or a whole tool) with the reason, and a tool's by its position among the tools the
  check was told to allow, `allowed`, beside a label redacted and cut for the operator; the
  position, not the label, is the tool's identity. It counts what a cap leaves unlisted in
  `toolsUnlisted` and `fallbacksUnlisted`, and says why a dropped snapshot was dropped in
  `descriptorsDropped`.
- **The configuration:** checked, as today, against 1 MiB as it would be written, pins and
  version included.
- **The listing:** the frontend's whole `tools/list` answer, serialized, is at most 8 MiB. When
  rendering would pass that, the frontend drops platforms' snapshots whole, in reverse table
  order, until it fits, and its start reports which it dropped. If the listing would still pass
  8 MiB with every snapshot dropped, the frontend refuses to start, saying how many of its
  tools, counted in the configuration's order, pass the bound; it counts no further, and makes
  its tool table no further. A binding with tens of thousands of tools does that with today's
  generated descriptions alone. The bound is on what is built, not only on what is sent: a
  snapshot's labels can render to far more than the snapshot, so the frontend builds no
  description past the room the listing has left. It reads and verifies one snapshot at a time,
  every pinned snapshot whether or not the bound drops it, and lets each go once its tools are
  described; what it holds after start is the listing.

## What the frontend serves

**Four cases**, per tool:

| Description | Schema | `description` served | `inputSchema` served |
|---|---|---|---|
| captured | captured | the full template | the projection |
| absent or refused | captured | the schema-only template | the projection |
| captured | refused | the description-only template | `{"type": "object"}` |
| absent or refused | refused | today's template, unchanged | `{"type": "object"}` |

**Today's template** stays for the last case, word for word except for how identifiers are
rendered: "Tool `<tool>` of platform `<platform>` (binding `<pin>`), called by the engine's own
adapter under the engine's key. Its arguments are what the platform's server defines; the engine
does not read that server's schema. The answer carries {session, result, receipt, salts}." The
identifier rendering under "Literal text" applies to all four templates, this one included.
Today the frontend writes identifiers raw; that changes for every tool.

**The other three** replace its middle sentence, which would be false once a schema is served,
and add a provenance sentence and a quoted block:

> Tool `<tool>` of platform `<platform>` (binding `<pin>`), called by the engine's own adapter
> under the engine's key. Its arguments are {declared by the platform's server's schema, as
> captured | what the platform's server defines}. The answer carries {session, result, receipt,
> salts}. When `connect` ran at `<time>`, the platform's server described it as follows, in its
> own words, which are not the engine's and which no receipt covers:

The quoted block is a fenced code block. Its fence is a run of backticks one longer than the
longest run of backticks in its content, and at least three. It holds, in order:

1. a line `server: <name> <version>`, when the identity was captured;
2. the captured description;
3. a line `<label>: <text>` for each `description` at a schema location, in the order the server
   wrote them.

A text spanning lines keeps its lines, each after its first indented by two spaces. A label is the schema
location's JSON Pointer from the root: `/properties/billing/properties/id`,
`/properties/tags/items`, `/anyOf/1/properties/x`, with `~` and `/` in names written `~0` and
`~1`. The root's own description is labelled `(root)`. The root's JSON Pointer is the empty
string, which would show as nothing, and `(root)` cannot be a pointer, since every pointer to a
schema location below the root begins with `/`. Every label is unique by construction. The
traversal follows schema locations only: a property named `description` is a name, not an
annotation. Block items 1 and 3 appear in the schema-only and description-only templates when
they have content.

**Literal text.** In a CommonMark or GitHub-flavored Markdown renderer, a fenced code block's
content is literal: no link, image, heading or HTML inside it renders, and a fence longer than
any run of backticks inside cannot be closed from inside. Every string the server wrote is
inside the block. The provenance sentence holds only the engine's words, the capture time, and
the identifiers an operator chose: the tool's and platform's names and the binding's pin. The
binding's rules let a tool's name hold a line break or markup. So each identifier is written in
the prose as a code span, whose backtick run is longer than any inside it. Every control
character in it, line feed included, is written as a visible escape, `\u{XXXX}`, as is every
character of the display policy's classes. No identifier then leaves its line, opens an HTML
block, or reaches the fence. The value the table routes by is untouched; only its rendering
changes. A host that renders other markup is outside this claim. To a host that renders
nothing, the fences are two lines of backticks.

**The schema served** is the projection. Its annotations (`description`, `title`, `examples`,
`default`, `$comment`, `deprecated`, `readOnly`, `writeOnly`) are removed at schema locations,
and nothing that bears on validation is removed. This loses information, deliberately. A host
that builds a form from a schema loses field-level help, defaults, examples and write-only hints.
A model is given the descriptions in the block instead, where the frame reaches them.

**Framing is attribution, not a boundary.** Quoted text can still instruct a model: to disclose
something, to call another tool, or to misuse this one. The engine cannot stop that. The display
policy, the fence and the removal of annotations bound what is shown. The pin bounds when it can
change. The operator is the one control over what it says. A description served from a snapshot
is as trustworthy as the server that wrote it was when `connect` ran, and the frame says so.
Routing, the table and the names are unchanged: a description cannot add, rename or reroute a
tool.

**Who judges arguments.** The captured schema is the server's declaration, not the gateway's
domain. `tools/call` does not consult it. The arguments go to the signer byte for byte, and the
signer refuses what its canonical domain refuses: a fraction, an exponent, an integer past the
safe range, a member name twice. A schema can therefore admit arguments the gateway cannot
carry. A host's refusal, the signer's refusal, and a live MCP error (`isError: true`, which fails
the acquisition) each mint no receipt. Only a result the adapter accepts is receipted.

## Where it is kept

`connect` keeps descriptors in a directory derived from the configuration's own path,
`<configuration>.descriptors/`, beside the configuration and on its filesystem. No
configuration member names it. Each snapshot is one immutable file named by its content's
digest, `<64 lowercase hex>.json`:

```json
{
  "platform": "tickets",
  "binding": "tickets@sha256:…",
  "capturedAt": "2026-09-15T00:00:00Z",
  "policy": 1,
  "server": {"name": "…", "version": "…"},
  "tools": {
    "search_tickets": {"description": "…", "inputSchemaText": "{\"type\":\"object\",…}"}
  }
}
```

Every member is required except `server`, and a tool's `description` or `inputSchemaText`. A
tool with neither is not listed. `capturedAt` is RFC 3339 in UTC, to the second. The platform's
entry pins the snapshot with a new member, `"descriptors": "sha256:<hex>"`, and the file's name
derives from that pin.

**Writing, and the crash story.** `connect` writes in this order:

1. **The directory.** If `<configuration>.descriptors/` does not exist, `connect` makes it, mode
   `0755`, owned by the configuration's owner; if it does, it holds it to the frontend's
   invariants. It holds the directory open, judged before the open and after as the directory
   opened, and does every later step inside it, so its name swapped for a link meanwhile
   changes nothing. It then syncs the configuration's directory, whether the entry was made now
   or by a `connect` that stopped before its own sync, so it survives a crash before anything
   names it.
2. **The snapshot, staged.** It writes the snapshot in the held directory under a staging name
   no snapshot has, which the directory's ownership keeps private, sets its final mode `0644`
   and owner, then syncs it.
3. **The snapshot, published without replacing.** It links the staged file to `<hex>.json`; a
   link never replaces an existing name. If the name is taken, it opens the existing file as
   the entry it is, judged again after the open, so no link is followed. It checks that it is
   a regular file, of the specified mode and owner, that digests to `<hex>`, and syncs it: a
   file found may never have reached the disk. A match is reused. Anything else refuses the
   `connect`, before any configuration names it. It then removes the staged name and syncs the
   descriptors directory. Just before the configuration's rename, it judges the directory's
   name again: still the directory held.
4. **The configuration.** It writes the configuration with today's writer, changed in two ways:
   the mode and owner are set before the file is synced, and the configuration's directory is
   synced after the rename.

**The commit point** is the configuration's rename. A failure before it leaves the old
configuration in place; any snapshot already published is then unpinned, immutable and harmless.
A failure after it, in the directory's sync, leaves the new configuration visible but perhaps not
durable. `connect` reports that the configuration was replaced but may not survive a crash, and
exits non-zero. After a crash at any point, the configuration found, old or new, finds its
snapshot. Removing unpinned snapshots is a separate operation that this note does not design.

**Ownership invariants**, which the frontend verifies at start:

- the directory and each snapshot are owned by root or by the configuration's owner;
- neither is writable by group or others;
- neither belongs to the frontend's user or group.

**The configuration.** Compatibility across versions:

| `engineVersion` | `mcp` | `descriptors` member |
|---|---|---|
| `"1"` | refused, as today | refused |
| `"2"` | accepted | refused |
| `"3"` | accepted | optional, per platform whose binding has a live MCP operation |

`connect` writes version `"3"` exactly when the entry it writes carries a pin, and otherwise
leaves the version as it found it. `--replace` that captures nothing removes the member. A
capture of no tool pins nothing. `connect --no-descriptors` asks the live check to capture
nothing and writes no pin: the choice for a deployment whose descriptors are confidential beyond
what screening finds. The changes land in `engineVersions`, `platformMembers`, the parser and
the renderer, and the version diagnostics name `"3"`. The signer parses a version-3
configuration and never reads a snapshot. A signer binary older than this change refuses version
3, so the rollout is binaries first, then `connect`.

## What the frontend reads, once

At start, and only then, the frontend reads each pinned snapshot. The read runs in the
frontend's own constructor, which is given the configuration's path, apart from the
configuration loading the signer shares. For each snapshot, in order:

1. it opens the descriptors directory relative to the configuration's directory, following no
   link, and checks the open directory's owner and mode;
2. it opens `<hex>.json` relative to that directory, following no link, and checks the open file:
   a regular file, of the invariant owner and mode, at most 320 KiB;
3. it reads at most 320 KiB plus one byte from that descriptor, and checks the bytes digest to the
   pin before anything parses them;
4. it decodes strictly (members, types, duplicates, UTF-8, trailing content), and checks that
   `platform`, `binding` and `policy` are the entry's name, the entry's pin and a policy it
   implements, that `capturedAt` is well-formed, and that its tools are among the binding's live
   tools;
5. it checks that every candidate passes the display policy, the grammar and the limits again.
   The frontend holds no credentials, so it cannot repeat the secret screening; that screening
   happened in the adapter, which did.

Any failure refuses the start. A pinned snapshot is never a fallback; only an entry with no pin
is. The frontend keeps the listing it builds from the verified snapshots, not the snapshots, and
both transports list from that one listing, subject to the listing budget. Nothing reads the file
again, so a rewrite after start changes nothing until the next start, and that start then
verifies what it reads.

## Change, and the operator

The pin makes a change operator-authorized: nothing a server says after `connect` is served
until an operator runs `connect --replace` and restarts. `connect --replace` rewrites the whole
platform entry. It reports whether anything the signer reads changed: the binding's pin, a
credentials path, the user, the endpoint, the environment, or the write flag. If only the
descriptors pin changed, restarting the frontend alone suffices. Otherwise both processes
restart, as mcp-server.md requires for any change to the configuration.

`connect` prints, for each allowed tool, one of:

- captured, with its sizes;
- fallen back, with the reason;
- against the previous snapshot: added, removed, changed, now fallen back, or no longer fallen
  back.

It compares only after verifying the previous snapshot against its pin. When the previous
snapshot is missing or does not verify, it says so and compares with nothing. The previous
binding says which tools were allowed before; when it cannot be read, as when its catalog file
was updated in place, `connect` says so and says only what the two snapshots show, never that
a tool was added nor that nothing changed. The server's identity is compared as the tools are. The capture time
never counts as a change. `connect --preview-descriptors <platform>` renders exactly what the
frontend would serve for that platform: the templates, the fenced blocks and the schema
projections, before any listing-budget drop across platforms. Every character outside printable
ASCII is escaped for the terminal, each line the server would serve is written after `  | ` so
none passes for a line of the preview's own, and the output is labelled a preview. The note
claims the change waited for an operator, not that the operator read it.

**Staleness is visible, not prevented.** A server that changes a tool after `connect` is served
with the snapshot until the operator refreshes. A host may then refuse arguments the server
would take, or pass ones the server refuses. A description with a captured part names its capture
time. A tool that fell back, and `engine.seal`, name none.

## Tests, each written to fail on the defect it names

- **The adapter:**
  - capture from the live check only;
  - a repeated name, or a cursor seen twice, failing the check;
  - each display-policy class refused, checked against the Unicode 15.0.0 tables;
  - each grammar rule and limit refused, with accepted fixtures valid under both meta-schemas
    offline. The vectors are shared (`testdata/tool-descriptors`), and the frontend's own
    implementation answers to them as well;
  - accepted fixtures from Pydantic and `zod-to-json-schema` output;
  - a credential in a description, a property name or the identity refused without disclosure;
  - the snapshot and report budgets, with their deterministic overflow, including an
    oversized server name and version in the `initialize` answer.
- **connect:**
  - the write order and its syncs, including today's writer changed;
  - a taken name reused only when it verifies;
  - a failure before and after the commit point;
  - the version upgraded only with a pin;
  - the signer-change report;
  - `--preview-descriptors` against the frontend's rendering.
- **The frontend's start:**
  - each of the five checks refusing the start;
  - a rewrite after start not served;
  - both transports listing the same snapshot;
  - the listing budget's deterministic drop.
- **Serving:**
  - the four templates;
  - a fence against content holding backtick runs;
  - Markdown and HTML inside the block rendering as text in a CommonMark renderer;
  - the complete rendered template, surrounding prose included, in all four cases, fallback
    included, with a tool name holding a line break and markup, rendering no HTML block and no
    element;
  - JSON Pointer labels, including escaped names and a property named `description`;
  - annotations removed at schema locations only;
  - routing unchanged, whatever a description says.

## Decisions taken in the design review

1. `title`: deferred. The generated name is the label, and a title adds an untrusted surface.
2. `outputSchema`: deferred. The frontend's `result` is the whole tool result in the canonical
   domain, and declaring a schema would oblige conforming structured content.
3. Where descriptors live: a directory derived from the configuration's path, holding immutable
   snapshots named by digest.
4. `$schema`: at the root only, 2020-12 or draft-07. An absent one is 2020-12 by this gateway's
   policy.
5. `format`: refused, like `pattern`, since a host may evaluate it with expressions of its own.
6. References: refused in version 1, and the compatibility cost is stated in the scope.
