---
status: proposed
date: 2026-11-11
deciders: maintainer
---

# `serve --config` listens off loopback only with an `identity` and an acknowledgement that its tokens cross plain HTTP, and never as a witness or behind the MCP server

## Context and problem statement

`gateway serve --config` binds its configuration's `listen`, which the configuration held to a
loopback address. [ADR-0023](0023-serve-listens-off-loopback-only-when-acknowledged.md) let
`serve` from the command line listen elsewhere, under an acknowledgement that it authenticates no
caller, and kept the engine form on loopback. The engine form is the one that can authenticate
its callers (`identity`), so a deployment that wanted an authenticated listener reachable from
another host still needed a forwarding process beside it (issue #400). Letting the engine form
listen elsewhere changes who can reach a signer whose tokens cross plain HTTP, so the change is a
decision about the security boundary and not only a member.

## Decision drivers

- Every configuration that loaded before loads and starts as before: a loopback `listen` keeps
  its rule and its rewrite to one spelling, and the start writes what it wrote.
- The rule for an address that is not loopback is at least as strict as ADR-0023's: an IP
  literal, no name, no zone, every address of a family only when written out, bound in its own
  family.
- A changed address alone does not expose the listener, and neither does an `identity` alone,
  since a bearer token crosses plain HTTP unless TLS terminates in front.
- A gateway older than this one refuses such a configuration, rather than binding loopback
  silently.
- Off loopback, what answers without a token is `/registry` and `/publickey`, and nothing else.
- The gateway stays one binary on the standard library.

## Considered options

- An `identity` alone allows a `listen` that is not loopback.
- An acknowledging member alone allows it.
- An `identity` and an acknowledging member together allow it.
- The gateway terminates TLS itself.

## Decision outcome

Chosen option: an `identity` and an acknowledging member together, because the identity is what
holds a caller to a token, and the acknowledgement is where the operator states, in the file, the
one fact that makes the token weak: that it crosses plain HTTP. An identity alone would let a
changed address expose the listener with that fact unstated; an acknowledgement alone would expose
a signer that admits every request.

1. Engine configuration version 19 adds `acceptOtherHostsOverPlainHTTP`, a top-level member,
   `true` or `false` and nothing else. Under version 18 or earlier the member is refused by
   name, and a `listen` that is not loopback is refused as before; a gateway older than this one
   refuses a version-19 file by its version.
2. A loopback `listen` (`127.0.0.0/8`, `::1`) keeps its rule: an IP literal and a port, rewritten
   to one spelling. `acceptOtherHostsOverPlainHTTP: true` beside one is refused, so the member is
   never in a file with nothing to acknowledge; `false` is taken.
3. From version 19 any other `listen` is an IP literal and a port written exactly as the gateway
   binds and prints it: IPv4 in dotted decimal, IPv6 in brackets, compressed and in lowercase, an
   IPv4 address never in IPv6 form, the port a number with no sign and no leading zero. A name,
   `localhost` included, a zone and an empty host are refused, so no resolver decides where the
   engine listens; any other spelling is refused naming the one to give. `0.0.0.0` and `[::]` are
   taken when written out. The address is held by the function `--listen`'s is held by, so the
   two forms differ only in what surrounds it: the configuration writes the port beside the
   address, and takes no other spelling of the whole.
4. Such a `listen` is refused at load unless the configuration has an `identity` and
   `acceptOtherHostsOverPlainHTTP: true`; the refusal names both members and says which is
   missing.
5. It is refused beside `witness`: a witness's two reads are open to anyone, and `SPEC.md` §6
   places a witness's signer on loopback, behind a front that passes other parties the
   submission, the two reads and `/publickey` alone. It is refused beside `mcp`: the MCP server
   reaches the signer at `listen`, and fronts a signer on loopback.
6. The address is bound in its own family, so `0.0.0.0` binds no IPv6 address and `[::]` no IPv4
   one. When what was bound is not loopback, the start writes a `start:` line on stderr, before
   the readiness line, saying that other hosts can reach the gateway, that it holds every caller
   but those of `/registry` and `/publickey` to a token, and that it speaks plain HTTP, so a
   token can be read and replayed on the network between unless TLS terminates in front of it. A
   loopback `listen` is bound as before and writes nothing more.
7. `posture` reports such a listener in its `listener-reach` line as `partial`, from the command
   (`gateway posture --config`) and the route (`/posture`), naming neither the address nor the
   port; the line's states and sentences are those of #401, unchanged.

The gateway does not terminate TLS, and that option is out of scope here: it would bring
certificate custody, rotation and their configuration into a reference whose scope (`SPEC.md`
§5) claims no authenticated transport, and the deployments that ask for this change — a container
behind a proxy or a load balancer — already have a place that terminates TLS.

This supersedes in part determination 5 of ADR-0023, "An engine configuration's `listen` remains
a loopback address": that remains true of every configuration of version 18 or earlier, of one
with a `witness` or `mcp`, and of one without both members, and is no longer true of the rest.
It narrows once more the sentence of [ADR-0013](0013-checkpoint-witness.md) that ADR-0023 narrowed
to the engine form, "The engine listens on a loopback address only": it remains true of an engine
that is a witness.

### Consequences

- Good, because an authenticated engine in a container answers on its published port with nothing
  forwarding in front of it, and every configuration that loaded before loads and starts as
  before.
- Good, because the acknowledgement is in the file and in the first line the start writes, where
  a reviewer of a deployment sees it, and posture reports the listener `partial`.
- Bad, because the transport is still plain HTTP. The gateway does not terminate TLS and cannot
  check that anything in front does; on the network between a caller and the listener a bearer
  token can be read and replayed within its validity window, every result and a version 3
  response's salts can be read, and a request changed.
- Bad, because `/registry` and `/publickey` are readable by anyone who reaches the listener, as
  they are on loopback, and the gateway limits neither the rate of requests nor the number of
  connections, so what is in front should limit them.
- Bad, because a witness or an MCP server cannot share such a signer: each keeps its signer on
  loopback, behind a front.
- Bad, because a launcher that reads the first line of stderr as the readiness line reads the
  `start:` line first when the address is not loopback.
- Revisit when the gateway terminates TLS itself, when a witness or the MCP server is asked to
  share a signer off loopback, or when a deployment needs a name or a zone in `listen`.

## More information

`SPEC.md` §6, [SECURITY.md](../../SECURITY.md#security-boundary), the README's "Listening off
loopback", [engine-config.md](../design/engine-config.md) ("Listening off loopback (engine
version 19)"), `go/engine.go` (`engineListen`), `go/serve_listen.go` (`listenIP`,
`otherHostsListen`, `listenForConfig`), issue #400.
