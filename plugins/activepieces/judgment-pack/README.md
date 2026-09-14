# @activepieces/piece-judgment-pack

An Activepieces piece for the [Judgment Pack engine](https://github.com/Judgment-Pack/judgment-pack-gateway):
acquire facts with a signed receipt, perform an approved write as an action with its receipt, and
seal a session — the engine's HTTP surface (`SPEC.md` §6) as a piece.

The piece is a client. The engine's own adapters fetch the bytes and the engine's own key signs;
the piece carries the answer — `result`, `receipt`, `salts` — into the flow as data. **It
verifies nothing.** A receipt is worth what `gateway verify` says about it, over the store, the
registry and a public key pinned out of band (`SPEC.md` §4, §5), and the consumer — the flow
itself, or whoever relies on the bytes — checks that verdict before relying on them (§5a): the
verdict is store-wide and it is the JSON, never an exit code.

## Actions

| Action | Calls | Properties |
|---|---|---|
| Acquire | `POST /acquire` | Session, Source, Arguments (JSON object) |
| Act | `POST /act` | Session, Platform, Tool, Arguments, Decision (`recordDigest`, `packDigest`), Cites (array of `{sessionId, callIndex, signature}`) |
| Seal | `POST /seal` | Session |

The framework's custom-call action is not offered: the pinned `@activepieces/pieces-common`
sends through a client that disables certificate verification for the whole process before it
sends (`NODE_TLS_REJECT_UNAUTHORIZED=0`), which would let an impersonating engine over https
collect the bearer. The piece sends through Node's own `fetch` instead, which verifies
certificates and touches no process state; a test holds it to that.

The session is a flat token the flow chooses (`SPEC.md` §3a) and sealing it is the flow's own
step. An Act is refused by the engine unless the requester is authenticated, the platform is
writable, the tool is the binding's, every cited receipt is in the engine's store and verifies,
and the decision record exists; the piece checks only the shape of what it sends. The receipt
an Act yields says who asked, never that anyone approved.

## Connection

The engine's URL (`http://127.0.0.1:8787` by default) and, when the engine is configured with an
`identity`, a bearer token its issuer signed. The token names the caller on every acquisition
receipt and the requester on every action receipt; an engine with no identity records
`caller: null`, and an Act needs a token. The header is sent only when a token is given. The
connection's validation calls `GET /publickey`, which shows an engine answers at the URL and
nothing about the key's authenticity.

## Example

1. **Acquire** with source `tickets/live`, arguments `{"tool": "get_ticket", "arguments": {"id": "T-1"}}`.
2. **Seal** the acquisition session.
3. Verify the store: `gateway verify <store-root> <registry-path> <authority> < publickey.raw`,
   with the public key pinned out of band, and read the JSON verdict; rely on the bytes only then.
4. Evaluate the facts with the runtime, which writes a decision record citing the receipt.
5. After a person approves, **Act** in a new session on platform `tickets`, tool `update_ticket`,
   citing the decision record's digest and the receipt from step 1; **Seal** that session too.
6. Verify again, now with `--decision-records <dir>`, so the action receipt's citations and its
   decision record are checked.

## Development

This directory is laid out as `src/index.ts`, `src/lib/auth.ts`, `src/lib/actions/` — the shape
the Activepieces monorepo's pieces take — and builds standalone here against the framework's
published packages, pinned:

```
npm install
npm run build && npm run lint && npm test
```

Contributing it upstream is not a copy: the monorepo generates a piece's scaffold (`npm run cli
pieces create`) with workspace dependencies and its own lint rules (which, for one, restrict
imports from `@activepieces/shared`), so the source here is copied into that scaffold and
adapted to the monorepo revision it targets, then registered in `tsconfig.base.json`.
