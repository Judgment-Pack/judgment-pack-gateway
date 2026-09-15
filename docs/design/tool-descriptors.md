# Tool descriptors, captured at connect

[mcp-server.md](mcp-server.md) serves each platform tool with a generated description and the
open schema `{"type": "object"}`. It says why: the binding carries tool names only, and the
engine will not run a platform's server just to read its schemas, because running it means
holding its credentials, which the frontend must never do. The consequence it states is that a
host validating arguments validates nothing, and a model must know the platform's tool from
elsewhere. It names the follow-on that closes this: descriptors captured by `connect`, which
already runs the adapter in check mode under the platform's own user, and stored beside the
configuration. This note is that follow-on, as it must be before code. It changes no receipt,
no signer route and nothing in `SPEC.md`.

## What is captured

`adapter-mcp --check` already lists every tool the platform's server offers, page by page, and
already holds each tool's whole descriptor while it does; it keeps the names and drops the rest
(`listTools`). The check now keeps, for each tool the binding's **live** operation allows — the
only tools the frontend serves — two members of the descriptor, and nothing else:

- `description`, a string;
- `inputSchema`, the JSON object the server declares for the tool's arguments.

What is not captured, and why:

- **`outputSchema`.** The frontend's answer is `{session, result, receipt, salts}`, not the
  platform's result, and it declares no `outputSchema` (mcp-server.md, "The answer"). A schema
  for the platform's result describes one member of that answer; serving it as the tool's would
  be false. Receipts keep what they carry today: an MCP-shaped acquisition digests the
  `outputSchema` it saw into `acquisition.schema`, at call time.
- **`title` and `annotations`.** A title is a label a host shows a person, and annotations are
  the server's claims about side effects. Both are untrusted text with no check behind them, and
  the tool's name, `<platform>.<tool>`, already labels it. They can be added later, as a
  separate decision.
- **Anything for a tool the live operation does not allow.** History and write tools are never
  served by the frontend.

A captured descriptor is **held to bounds, or not served**:

- `description` at most 4096 bytes of UTF-8;
- `inputSchema` a JSON object whose `type` is `"object"`, at most 65536 bytes as written, with
  no member name twice at any depth;
- no `$ref` or `$dynamicRef` whose value is not a fragment of the schema itself (`#…`): a host
  that resolves a reference to anything outside the schema would fetch what nobody captured.

A descriptor outside these bounds is not an error. That tool keeps its generated description
and open schema, and `connect` prints one line naming the tool and the bound it broke.

**Secrets.** The check already redacts the credentials' secrets out of every server string it
reports. A descriptor is redacted the same way, every string in it, but without the 512-byte cap
the redaction of diagnostics applies: a description is content, and truncating it silently
would serve something the server never said. A schema whose `default` or `examples` held a
credential then holds `[redacted]` there, which changes that schema's meaning, rightly.

**Numbers.** A schema's numbers are carried as written. The check does not pass descriptors
through `canon.CarryNumbersAsText`, which would turn `0.5` into `"0.5"` and change what the
schema means, and the core never parses a descriptor with its canonical-domain parser, which
refuses non-integers. The descriptor file is read with the standard decoder, and a schema is
served as the bytes captured.

## Where it is kept

`connect` writes one file per platform, `<descriptors>/<platform>.json`, where `descriptors` is a
new top-level member of the configuration: an absolute, clean directory path, as the store and
the registry are. The platform's entry gains a member of the same name holding the file's digest,
`sha256:` and 64 lowercase hex. The file is

```json
{
  "platform": "tickets",
  "binding": "tickets@sha256:…",
  "capturedAt": "2026-09-15T00:00:00Z",
  "server": {"name": "…", "version": "…"},
  "tools": {
    "search_tickets": {"description": "…", "inputSchema": {"type": "object", "…": "…"}}
  }
}
```

with `server` as the check report names it, redacted, and only the tools whose descriptors held
their bounds. The configuration moves to `engineVersion` `"3"`; a version 2 file has no
descriptors and is served as today.

The file is written as the configuration is. It is written whole, in the private directory
`connect` already uses, keeping the old file's mode and owner. It is put in place by rename,
under the configuration's lock, before the configuration that pins it. A reader therefore never
sees a pin to a file that is not yet there. A file left behind by a failed configuration write is
harmless, because nothing pins it.

**The pin is the point.** At every start, the frontend reads the file bounded, as `loadBinding`
reads a catalog file, and refuses to start when it does not digest to its pin. The signer does
not read it: it serves no descriptor, and an acquisition should not depend on a file only the
frontend uses. The pin makes the served descriptors the ones captured at connect, not whatever
the server says today:
a server that rewrites a tool's description after connect, the rug-pull that tool-poisoning
attacks rely on, changes nothing until an operator runs `connect --replace`. `connect --replace`
prints which tools' descriptors changed from the file it replaces, so a change is seen before it
is served.

## What the frontend serves

For a tool with a captured descriptor, `tools/list` gives:

- **`description`**: the generated sentence it serves today, which names the platform, the
  binding and its pin, and says the engine calls the tool under its own key. Then a second
  sentence stating provenance: the platform's server described the tool this way at connect,
  with the time and the server's name and version. Then the captured text, set apart as a
  quotation.
- **`inputSchema`**: the captured schema, as captured.

A tool without one is served exactly as today. The table, the names and the routing are
unchanged. The frontend still never reads a platform's server, and `tools/call` does not
consult the schema: the arguments go to the signer byte for byte, and the platform's own server
judges them, as it does today.

**The text is untrusted.** A description is the platform server's words, and a model reads it.
The frontend therefore frames it as a quotation, never as its own words. It serves it without
the C0 and C1 control characters, apart from line feed and tab, and without the bidirectional
controls U+202A–U+202E and U+2066–U+2069. It never lets the text change the table: a description
cannot add a tool, rename one or reroute one. What the frontend cannot do is make the words
true. The operator reads them at connect, and the pin keeps them from changing without the
operator seeing it.

**Staleness is visible, not prevented.** A server that changes a tool's arguments after connect
is served with the old schema until `connect --replace`. A host may then refuse arguments the
server would take, or pass ones it refuses. The server's refusal is what the receipt records,
as it records any other result. The capture time is in every description, so a reader can see
the schema's age.

## What reads it, and what proves the rest still holds

The frontend reads one more file: the descriptors file of each platform it serves. That file is
not a secret. It is written by `connect`, which runs as root or as the signer, and a deployment
makes it readable to `engine-mcp` as the configuration already is. The two checks that bound
what the frontend reaches are unchanged. The reach check denies the seed, the store and every
credential, and a descriptors file under the configuration's directory is none of those. The
image check refuses anything owned by the frontend's user outside its home, and anything under
`etc/engine` baked into the image, and a descriptors file is a deployment mount, as the
configuration is. mcp-server.md's list of what the process reads gains the file.

Tests, each written to fail on the defect it names:

- **the adapter:** descriptors of allowed tools only; redaction without truncation; each bound
  refused, with its reason; numbers kept as written;
- **connect:** the file written before the pin, with its mode and owner kept; a failed
  configuration write leaving no pin; `--replace` naming changed tools;
- **the frontend's start:** a file that does not digest to its pin refused; the signer's start
  unaffected by it;
- **the frontend:** the framed description and the captured schema served; a tool without a
  descriptor served as today; control and bidirectional characters removed; routing unchanged
  whatever a description says.

## Open questions, for the design review

1. Should `title` be served, cleaned and bounded, now or later? Leaving it out keeps the label
   the engine's own.
2. Should the frontend declare an `outputSchema` for its own answer, with `result` typed by the
   captured `outputSchema`? A host that validates `structuredContent` would then refuse a
   result that breaks its own server's schema. That is arguably right, but it is a new failure
   mode.
3. Should the descriptors live beside the configuration, as proposed, or beside the catalog,
   keyed by binding? The catalog is curated by an operator and pinned. Descriptors depend on the
   platform entry, its credentials and its endpoint, not only on the binding.
4. Should `$schema` be held to known dialect URIs? A host that fetches it would fetch a URL.
   Hosts in practice do not.
