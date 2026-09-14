---
status: proposed
date: 2026-09-14
deciders: maintainer
---

# A fifth process speaks MCP, as a client of the signer and nothing more

## Context and problem statement

[ADR-0001](0001-one-engine-four-processes.md) gave the engine four processes: the signer, the
adapters, the runtime and the verifier. The plan's last phase asks that a team already running
an MCP gateway get receipts on the tool calls it routes. A plugin inside that gateway would be
a witness — it would hand the engine bytes the engine never acquired, which SPEC.md §6 admits
from no caller — and [docs/design/plugins.md](../design/plugins.md) leaves that question to the
specification. The other path is for the engine to speak MCP itself, so the engine's own
adapter makes the call and the engine's own key signs. That needs a process that speaks the
protocol without holding the key, and a place for it in the isolation claim.

## Decision drivers

- No new party may add or remove assurance: a receipt handed over by MCP must mean exactly
  what a `curl` of `/acquire` would have got.
- The process that parses an outside protocol must be unable to reach the seed, a credentials
  file or the store, provably, not by intention.
- No specification change: the receipt, the source contract and the verifier stay as they are.
- One protected resource, one audience: a token for the engine is a token for its MCP
  interface, and a token for anything else is refused.

## Considered options

- A witness plugin in the MCP gateway, handing observed calls to a new engine surface.
- The engine as an MCP server: a fifth process that forwards each call to `/acquire`.
- No MCP surface: workflow tools only, through the client packages.

## Decision outcome

Chosen option: "the engine as an MCP server", as [docs/design/mcp-server.md](../design/mcp-server.md)
states it, because it is honest by construction — the engine acquires, the engine signs —
and needs no change to the specification; the witness stays an RFC question.

The fifth process is `engine-mcp`: the gateway executable copied before the signer's
capabilities were written to it, run under its `mcp` subcommand as a user of its own, with a
check of its own reach at start and a loader rule that reserves its user against platform
use. It holds no key, no credential and no store; it verifies the caller's token as the
signer does and forwards it to the signer alone; it never seals a session on its own.

### Consequences

- Good, because any MCP client — a gateway federating servers, an agent's host, a desk — gets
  receipts on the engine's platforms' live tools by registering one server.
- Good, because the isolation claim is checked in three named places: the image, the launch
  and the loader.
- Bad, because a fifth process is one more the operator starts and keeps current with the
  signer's configuration, and its rotation contract touches the signer's restart.
- Bad, because the tool list carries names only: a host that validates arguments validates
  nothing, until descriptors captured by `connect` close that, which is a follow-on.
- Not changed: calls to servers the engine does not front are not receipted; that is the
  witness question, still the specification's to answer.

## More information

[docs/design/mcp-server.md](../design/mcp-server.md) is the design, frozen after six
cross-vendor review rounds; [docs/design/engine-config.md](../design/engine-config.md) has the
`mcp` member and configuration version 2; [docs/design/engine-image.md](../design/engine-image.md)
the second executable copy and the user.
