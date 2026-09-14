# @activepieces/piece-judgment-pack

An Activepieces piece for the [Judgment Pack engine](https://github.com/Judgment-Pack/judgment-pack-gateway):
acquire facts with a signed receipt, perform an approved write as an action with its receipt, and
seal a session — the engine's HTTP surface (`SPEC.md` §6) as a piece.

The piece is a client. The engine's own adapters fetch the bytes and the engine's own key signs;
the piece carries the answer — `result`, `receipt`, `salts` — into the flow as data. **It
verifies nothing.** A receipt is worth what `gateway verify` says about it later, over the store,
the registry and a public key pinned out of band (`SPEC.md` §4, §5); that is run by whoever needs
the verdict, never by the flow that asked.

## Actions

| Action | Calls | Properties |
|---|---|---|
| Acquire | `POST /acquire` | Session, Source, Arguments (JSON object) |
| Act | `POST /act` | Session, Platform, Tool, Arguments, Decision (`recordDigest`, `packDigest`), Cites (array of `{sessionId, callIndex, signature}`) |
| Seal | `POST /seal` | Session |
| Custom API Call | any path | the framework's generic call, with the connection's headers |

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

## Development

This directory is laid out as `packages/pieces/community/judgment-pack` in the Activepieces
monorepo expects, and builds standalone here against the framework's published packages:

```
npm install
npm run build && npm run lint && npm test
```

Contributing it upstream is a copy of `src/` and the four config files into
`packages/pieces/community/judgment-pack`, plus the registration line in the monorepo's
`tsconfig.base.json`.
