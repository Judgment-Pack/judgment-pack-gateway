---
status: accepted
date: 2026-11-11
deciders: maintainer
---

# `serve` from the command line listens off loopback only when the operator names the address and acknowledges that no caller is authenticated

## Context and problem statement

`gateway serve <store> <seed> <authority> <registry>` listened on `127.0.0.1` and nowhere else.
A gateway run in a container, or behind a proxy on another host, could not be reached without a
second process inside the same network namespace forwarding to it (issue #387). This form of
`serve` has no `identity`: it admits every request and records no caller. Letting it listen
elsewhere changes who can reach an unauthenticated signer, so the change is a decision about the
security boundary and not only a flag.

## Decision drivers

- The default stays what it was, byte for byte: loopback, same port, same first lines on stderr.
- Nobody reaches an unauthenticated listener from another host by accident, by a default, by a
  name that resolves differently tomorrow, or by a wildcard they did not write.
- The gateway stays one binary on the standard library; it does not grow an authentication
  scheme for this form.
- The engine form (`serve --config`), which can authenticate, is not loosened in passing.

## Considered options

- Keep loopback only; document a forwarding sidecar.
- `--listen ADDRESS` alone.
- `--listen ADDRESS`, an IP literal only, with a second, acknowledging option required for any
  address that is not loopback.
- Require an `identity` before listening off loopback.

## Decision outcome

Chosen option: `--listen ADDRESS` with `--accept-unauthenticated-callers` required off loopback,
because it serves the container and proxy cases with nothing added in front of the process,
while the operator has to state, in the command itself, the one fact that makes it dangerous.

1. `--listen` takes an IP address in the form the gateway prints it, the address alone; the port
   stays `--port`'s. A host name (`localhost` included), a zone, a port and an empty value are
   refused, so no resolver decides where the gateway listens.
2. The address is bound in its own family. `0.0.0.0` is every IPv4 address and no IPv6 one; `::`
   is every IPv6 address and no IPv4 one. Every address of a family is bound only when written
   out.
3. A loopback address (`127.0.0.0/8`, `::1`) needs nothing more. Any other address is refused,
   before anything is bound, unless `--accept-unauthenticated-callers` is beside it.
4. When what was bound is not loopback, the start writes a `start:` line on stderr, before the
   readiness line, saying that other hosts can reach the gateway and that it authenticates no
   caller.
5. `serve --config` takes neither option. An engine configuration's `listen` remains a loopback
   address.

This narrows one sentence of [ADR-0013](0013-checkpoint-witness.md), "The engine listens on a
loopback address only": it remains true of the engine form, `serve --config`, and is no longer
true of `serve` from the command line, which listens where `--listen` says under the rule above.

### Consequences

- Good, because a gateway in a container answers on its published port with no forwarding
  process, and the default is unchanged.
- Good, because the acknowledgement is in the command line and in the first line the process
  writes, where a reviewer of a deployment sees it.
- Bad, because the gateway can now be run reachable from other hosts with no authentication and
  over plain HTTP; what decides who reaches it, terminates TLS and limits requests is whatever
  the operator puts in front, and the gateway cannot check that anything is there.
- Bad, because a launcher that reads the first line of stderr as the readiness line reads the
  `start:` line first when the address is not loopback.
- Revisit when the engine form is asked to listen off loopback (it would require an `identity`
  there), or when `serve` from the command line gains a way to authenticate callers.

## More information

[SECURITY.md](../../SECURITY.md#security-boundary), the README's "Listening off loopback",
`SPEC.md` §6, `go/serve_listen.go`, issue #387.
