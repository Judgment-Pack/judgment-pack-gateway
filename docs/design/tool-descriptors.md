# Tool descriptors, captured at connect

[mcp-server.md](mcp-server.md) serves each platform tool with a generated description and the
open schema `{"type": "object"}`, which admits any object and constrains no member. It says why:
the binding carries tool names only, and the frontend never runs a platform's server, because
running it means holding its credentials. The consequence is that a host validating arguments
learns nothing about a tool's arguments, and a model must know the tool from elsewhere. It names
the follow-on: descriptors captured by `connect`, which already runs the adapter in check mode
under the platform's own user. This note designs that follow-on before code. It changes no
receipt, no signer route and nothing in `SPEC.md`. **Nothing captured becomes an engine claim:**
no receipt covers a description or a schema, and the engine's key signs neither.

## What is captured, and from where

Descriptors are captured from one check only: the `<platform>/live` MCP check, which `connect`
runs as the platform's user with the live operation's credentials. A write operation's check is
never a source: it may run under other credentials, against another server. The check lists
tools as it does today, page by page, at most 32 pages. Two conditions fail the whole check,
since a listing that meets them cannot be pinned: a cursor seen twice, and a tool name offered
twice anywhere in the enumeration, even with an identical descriptor. A tool the live operation
allows and the server does not offer fails the check, as it does today.

For each allowed tool, two members of its descriptor are candidates, and nothing else:

- `description`, a string. It may be absent. The tool then keeps the generated description and
  may still have its schema served.
- `inputSchema`, the object the server declares for the tool's arguments.

These are not captured:

- **`outputSchema`.** The frontend's answer is `{session, result, receipt, salts}`, where `result`
  is the whole MCP tool result carried into the canonical domain, not the server's
  `structuredContent`. Declaring an `outputSchema` would oblige the frontend to produce
  conforming structured content, which it does not. Receipts keep what they carry today: an
  MCP-shaped acquisition digests the `outputSchema` it saw into `acquisition.schema`, at call
  time.
- **`title` and `annotations`.** A title is one more untrusted surface a host shows a person,
  and annotations are the server's claims about side effects, booleans included. The tool's
  name, `<platform>.<tool>`, is the label. Both are deferred to a separate decision.

**Decoding.** The check already refuses a message that is not UTF-8 or that names a member twice,
anywhere in it; that stays a fatal refusal, as it is for acquisitions. Within a well-formed
listing, a candidate is kept as the bytes the server sent for that member, as a
`json.RawMessage`. It is never re-encoded, so a number keeps its spelling and no canonical-domain
parser ever reads it. A candidate that fails anything below is not captured. Its tool falls back
to the generated description and open schema, and the report names the tool and the reason.
That fallback is not an error.

## What a candidate must be

**The display policy, version 1.** It applies to every string a model or a person could be
shown: the description, the server's name and version in the provenance line, and within the
schema every property name and every string the schema holds. A string is refused when it holds
any of these:

- a control character other than tab and line feed, including DEL and the C1 range;
- a bidirectional control: U+061C, U+200E, U+200F, U+202A–U+202E, U+2066–U+2069;
- a default-ignorable or invisible code point: U+00AD, U+180E, U+200B–U+200D, U+2060–U+2064,
  U+FEFF, the variation selectors, and the tag characters U+E0000–U+E007F;
- a private-use, unassigned or noncharacter code point.

The policy refuses; it never strips or normalizes. Stripping would change what a secret check
saw, and a schema's names and constants mean what they spell. It costs legitimate text: a
description whose emoji or Indic script needs a joiner falls back. Confusable letters pass. No
character rule catches them, and the note does not claim one does.

**The schema subset, version 1.** A schema is served only when it is, at every depth, built from
these keywords:

- `type`: one type name, or an array of distinct type names;
- `properties`: an object of subschemas;
- `required`: an array of distinct property names;
- `additionalProperties`: a boolean or a subschema;
- `items`: a single subschema, never the array form;
- `enum`: at most 256 scalars;
- `const`: a scalar;
- the numeric and length bounds: `minimum`, `maximum`, `exclusiveMinimum`, `exclusiveMaximum`,
  `multipleOf`, `minLength`, `maxLength`, `minItems`, `maxItems`, `minProperties`,
  `maxProperties`, each of its right type;
- `anyOf`, `oneOf`, `allOf`: at most 16 subschemas each; `not`: a subschema;
- `format`, as an annotation only;
- the annotations `description`, `title`, `examples`, `default`, `$comment`, `deprecated`,
  `readOnly`, `writeOnly`;
- `$schema`, only as `https://json-schema.org/draft/2020-12/schema` or
  `http://json-schema.org/draft-07/schema#`, which mean the same for this subset. An absent
  `$schema` is 2020-12, as MCP takes it.

The root's `type` is `"object"`. Any other keyword refuses the schema: `pattern`,
`patternProperties` and `propertyNames`, whose regular expressions a host may evaluate with
catastrophic backtracking, and every form of reference or identifier (`$ref`, `$dynamicRef`,
`$defs`, `definitions`, `$id`, `$anchor`, `$recursiveRef`). That leaves nothing a host resolves,
and no recursion. The limits are:

| Limit | Bound |
|---|---|
| nesting of subschemas | 32 |
| subschemas in all | 2048 |
| properties in one object | 256 |
| a property name | 128 bytes |
| any other string | 1024 bytes |
| a schema as written | 16384 bytes |
| a description | 4096 bytes |

Schemas outside the subset fall back, and the report says which keyword or bound refused them.
The subset bounds what a host must do to validate: no references, no regular expressions, and
bounded size and depth. It does not bound what a host chooses to do with a schema. That, and
how a host renders one, remain the host's.

**Secrets.** A candidate is refused, never redacted, when any of its strings contains a value the
check's secret collection finds in the credentials. The strings include a property name, and a
description after the display policy has passed it. Because nothing is transformed after this
check, no later step can reassemble a secret it missed. The report says only that the candidate
held a credential value, never which. The collection has the limits its source states: a secret
split across strings, or spelled in another encoding, is not found. The operator's review below
is the remaining control for that.

**Budgets.** One platform's captured candidates total at most 512 KiB as written. Candidates past
that fall back, in the server's order, so the check report stays inside `connect`'s 1 MiB bound
with room for the rest of it.

## What the frontend serves

For a tool with captured candidates, `tools/list` gives two things.

**The `description`** is the generated sentence the frontend serves today, followed by a
provenance sentence and a quotation block:

> Tool `<tool>` of platform `<platform>` (binding `<pin>`), called by the engine's own adapter
> under the engine's key. The answer carries {session, result, receipt, salts}. Its platform's
> server, `<name> <version>`, described it this way when `connect` ran at `<time>` — the server's
> words, not the engine's, and not covered by any receipt:

The quotation block then holds the captured description, followed by the parameters' own
descriptions. Each parameter is named by its property name and quoted. The block's delimiters
are fixed. Each line of the captured text is served with the line's first character escaped
when it could open Markdown or HTML: `#`, `>`, `-`, `*`, `+`, a digit followed by `.`, `<`, `` ` ``
or `[`. So a host that renders descriptions shows the text as text. It shows no heading, link,
image or tag the server wrote.

**The `inputSchema`** is the captured schema with its annotations removed (`description`, `title`,
`examples`, `default`, `$comment`, `deprecated`, `readOnly`, `writeOnly`). Nothing that bears on
validation is removed. The parameters' descriptions are served in the framed block above
instead, not inside the schema, where no frame can reach.

A tool without captured candidates is served exactly as today, generated template and open
schema, with no provenance sentence. Routing, the table and the names are unchanged. The
descriptors decide nothing about routing: a description cannot add, rename or reroute a tool.

**Framing is attribution, not a boundary.** Quoted text can still instruct a model: to disclose
something, to call another tool, or to misuse this one. The engine cannot stop that. The display
policy, the removal of annotations and the escaping bound what is shown. The pin bounds when it
can change. The operator's review is the one control over what it says. A description served
from a pinned snapshot is exactly as trustworthy as the server that wrote it was when `connect`
ran, and the frame says so.

**Who judges arguments.** The captured schema is the server's declaration, not the gateway's
domain. `tools/call` does not consult it. The arguments go to the signer byte for byte, and the
signer refuses what its canonical domain refuses: a fraction, an exponent, an integer past the
safe range, a member name twice. A schema can therefore admit arguments the gateway cannot
carry. A host's refusal, the signer's refusal, and a live MCP error (`isError: true`, which fails
the acquisition) each mint no receipt. Only a result the adapter accepts is receipted, as today.

## Where it is kept

`connect` keeps descriptors in a directory derived from the configuration's own path,
`<configuration>.descriptors/`, beside the configuration and on its filesystem. No
configuration member names it, so two configurations never share one by accident. Each snapshot
is one immutable file named by its content's digest, `<64 lowercase hex>.json`:

```json
{
  "platform": "tickets",
  "binding": "tickets@sha256:…",
  "capturedAt": "2026-09-15T00:00:00Z",
  "policy": 1,
  "server": {"name": "…", "version": "…"},
  "tools": {
    "search_tickets": {"description": "…", "inputSchema": {"type": "object", "…": "…"}}
  }
}
```

`server` appears only when its strings passed the display policy. `tools` holds only the tools
whose candidates were captured. The platform's entry pins the snapshot with a new member,
`"descriptors": "sha256:<hex>"`, and the file name derives from that pin.

**Writing.** `connect` writes in this order:

1. It stages the snapshot in the private directory it already uses beside the configuration.
2. It syncs the snapshot and renames it into `<configuration>.descriptors/`. A file of that name
   is already that content.
3. It syncs the directory.
4. Only then does it write the configuration, as it does today: staged, renamed under its lock,
   and with its directory synced too.

A reader of either configuration, old or new, finds its pinned snapshot there, including after
a crash at any step. A configuration write that fails leaves an unpinned snapshot. The snapshot
is immutable and names its own content, so it is harmless. Snapshots an older configuration
pinned are kept. Removing unpinned snapshots is a separate operation that this note does not
design.

**Ownership.** The directory is created by `connect` with mode `0755`, and each snapshot with
`0644`, both owned by the configuration's owner. The frontend's user reads them. Nothing in
them is a secret: a candidate holding a credential value is never captured. The reach check and
the image check are unchanged, and neither establishes these properties. The frontend checks
them at start (below).

**The configuration.** Compatibility across versions:

| `engineVersion` | `mcp` | `descriptors` member |
|---|---|---|
| `"1"` | refused, as today | refused |
| `"2"` | accepted | refused |
| `"3"` | accepted | optional, per platform whose binding has a live MCP operation |

`connect` writes version `"3"` exactly when the entry it writes carries a pin, and otherwise
leaves the version as it found it. `--replace` that captures nothing removes the member. The
changes land in `engineVersions`, `platformMembers`, the parser and the renderer, and the
version diagnostics name `"3"`. The signer parses a version-3 configuration and never reads a
snapshot. A signer binary older than this change refuses version 3, so the rollout is binaries
first, then `connect`. The configuration's 1 MiB bound is checked, as today, on the file as it
would be written.

## What the frontend reads, once

At start, and only then, the frontend reads each pinned snapshot. The read runs in the
frontend's own constructor, apart from the configuration loading the signer shares. For each
snapshot, the frontend checks, in order:

1. the directory and the file are not links;
2. the file is a regular file, at most the platform budget in size;
3. its bytes digest to the pin, before anything parses them;
4. it parses strictly, and its `platform`, `binding` and `policy` are the entry's;
5. its tools are among the binding's live tools;
6. every candidate passes the display policy and the schema subset again.

Any failure refuses the start. A missing, unreadable, oversized, malformed or mismatched pinned
snapshot is never a fallback; only an entry with no pin is. The frontend keeps the verified bytes
in memory, and both transports list from that one snapshot. Nothing reads the file again, so a
rewrite after start changes nothing until the next start, and that start then verifies what it
reads.

**The listing's size.** The frontend serves one `tools/list` page. The captured bytes it serves,
across all platforms, total at most 4 MiB. Past that, tools fall back in the table's order, and
the start reports which.

## Change, and the operator

The pin makes a change operator-authorized: nothing a server says after `connect` is served
until an operator runs `connect --replace`, and then restarts the frontend. `connect` does not
signal a running frontend, and a running frontend keeps its snapshot. That gives a review point
between the two steps. `connect` prints, for each allowed tool, one of:

- captured, with its sizes;
- fallen back, with the reason;
- against the previous snapshot: added, removed, changed, now fallen back, or no longer fallen
  back.

It compares only after verifying the previous snapshot against its pin. When the previous
snapshot is missing or does not verify, it says so and compares with nothing. The capture time
never counts as a change. `connect --show-descriptors <platform>` prints a snapshot with every
character outside printable ASCII escaped, so an operator reads exactly what a model would be
given, invisible characters included. The note does not claim that an operator read it; it
claims the change waited for one.

**Staleness is visible, not prevented.** A server that changes a tool after `connect` is served
with the snapshot until the operator refreshes. A host may then refuse arguments the server
would take, or pass ones the server refuses. Every served description names its capture time.

## Tests, each written to fail on the defect it names

- **The adapter:**
  - capture from the live check only;
  - a repeated name, or a cursor seen twice, failing the check;
  - each display-policy class refused;
  - each subset keyword and bound refused;
  - a candidate holding a credential refused without disclosure, including one hidden behind a
    control character;
  - the platform budget.
- **connect:**
  - the write order;
  - a failed configuration write leaving the old pin and its snapshot intact;
  - `--replace` removing a pin;
  - the version upgraded only with a pin;
  - the change report, including a previous snapshot that does not verify;
  - `--show-descriptors` escaping.
- **The frontend's start:**
  - each of the six checks refusing the start;
  - a rewrite after start not served;
  - both transports listing the same snapshot;
  - the 4 MiB listing budget.
- **Serving:**
  - the frame;
  - the escaping of a line that opens Markdown or HTML;
  - annotations removed from the schema;
  - a tool without candidates served as today;
  - routing unchanged whatever a description says.

## Decisions taken in the design review

1. `title`: deferred. The generated name is the label, and a title adds an untrusted surface.
2. `outputSchema`: deferred. The frontend's `result` is the whole tool result in the canonical
   domain, and declaring a schema would oblige conforming structured content.
3. Where descriptors live: a directory derived from the configuration's path, holding immutable
   snapshots named by digest. Binding identity alone cannot tell deployments' captures apart.
4. `$schema`: restricted to 2020-12 and draft-07, which mean the same for the subset. Anything
   else falls back, with its reason.
