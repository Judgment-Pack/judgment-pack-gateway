# n8n-nodes-judgment-pack

An n8n community node for the [Judgment Pack engine](https://github.com/Judgment-Pack/judgment-pack-gateway):
acquire facts with a signed receipt, perform an approved write as an action with its receipt, and
seal a session — the engine's HTTP surface (`SPEC.md` §6) as a node.

The node is a client. The engine's own adapters fetch the bytes and the engine's own key signs;
the node carries the answer — `result`, `receipt`, `salts` — into the workflow as data. **It
verifies nothing.** A receipt is worth what `gateway verify` says about it, over the store, the
registry and a public key pinned out of band (`SPEC.md` §4, §5), and the consumer — the workflow
itself, or whoever relies on the bytes — checks that verdict before relying on them (§5a): the
verdict is store-wide and it is the JSON, never an exit code.

## Operations

| Operation | Calls | Parameters |
|---|---|---|
| Acquire | `POST /acquire` | Session, Source, Arguments (any JSON value; empty for the engine's default, `{}`) |
| Act | `POST /act` | Session, Platform, Tool, Arguments, Decision (`recordDigest`, `packDigest`), Cites (array of `{sessionId, callIndex, signature}`) |
| Seal | `POST /seal` | Session |

The session is a flat token the workflow chooses (`SPEC.md` §3a) — an expression such as
`{{ $workflow.id }}-{{ $execution.id }}` — and sealing it is the workflow's own step. An Act is
refused by the engine unless the requester is authenticated, the platform is writable, the tool
is the binding's, every cited receipt is in the engine's store and verifies, and the decision
record exists; the node checks only the shape of what it sends. The receipt an Act yields says
who asked, never that anyone approved.

The node is usable as a tool by an n8n agent: an agent may ask the engine for facts — it can ask,
it cannot sign — and an Act from an agent still needs a person's token and passes the engine's
judgment gate like any other.

## Credentials

`Judgment Pack Engine`: the engine's URL (`http://127.0.0.1:8787` by default) and, when the engine
is configured with an `identity`, a bearer token its issuer signed. The token names the caller on
every acquisition receipt and the requester on every action receipt; an engine with no identity
records `caller: null`, and an Act needs a token. The header is sent only when a token is given.
The credential test calls `GET /publickey`, which shows an engine answers at the URL and nothing
about the key's authenticity.

## Example

1. **Acquire** with source `tickets/live`, arguments `{"tool": "get_ticket", "arguments": {"id": "T-1"}}`.
2. **Seal** the acquisition session.
3. Verify the store: `gateway verify <store-root> <registry-path> <authority> < publickey.raw`,
   with the public key pinned out of band, and read the JSON verdict. Then bind before relying
   (`SPEC.md` §5a.4): the receipt the node handed back is signature-checked under that pinned key
   and its `(sessionId, callIndex)` is among the verifier's `ok` findings, and the `result` the
   workflow kept re-digests to that receipt's `resultDigest`. Only then are the bytes attested
   bytes.
4. Evaluate the facts with the runtime, which writes a decision record citing the receipt.
5. After a person approves, **Act** in a new session on platform `tickets`, tool `update_ticket`,
   citing the decision record's digest and the receipt from step 1; **Seal** that session too.
6. Verify again, now with `--decision-records <dir>`, so the action receipt's citations and its
   decision record are checked.

With **Continue On Fail** set, an item the node refuses before asking, or one the engine
refuses, yields an error item and the next item still runs.

## Development

```
npm install
npm run build && npm run lint && npm test
```

Built with `@n8n/node-cli`; MIT; no runtime dependencies, no environment variables, no files.
