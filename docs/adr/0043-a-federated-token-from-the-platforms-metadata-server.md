---
status: accepted (autopilot; maintainer may revise)
date: 2026-11-18
deciders: maintainer
---

# A token step's federated token is asked of the platform's metadata server, at a fixed address

## Context and problem statement

A token step with a federated credential ([ADR-0027](0027-an-http-source-obtains-its-token-by-a-client-assertion.md))
reads the identity token it presents as its client assertion from a file at each token request.
On a platform that issues identity tokens from a metadata server, something outside the gateway
must fetch the token and keep that file fresh (issue #502). The ask is a second source for the
federated token: `adapter-http` asks the platform's metadata server for an identity token of the
audience the token endpoint expects. The address is built in and configuration names the
audience only, so this path reaches no other host. The token is never written to disk or logged.
An unreachable or refusing metadata server fails the token step closed with a fixed sentence, and
a throttled answer is answered as today's token-step throttling
([ADR-0029](0029-a-throttled-source-is-answered-with-its-class.md)).

Four things need deciding: the configuration's form, how the address is pinned, what is held
between acquisitions, and the key the access token is sealed under, since today that key derives
from the federated token itself.

## Decision drivers

- No configuration member, flag or environment variable names a host, a port, a path or a URL
  for this path. The one address it reaches is built into the adapter.
- No resolver is trusted to say where the metadata server is.
- The identity token reaches no disk, no stdout, no diagnostic and no signer memory.
- The audience cannot add a query member, whatever it holds.
- A configuration without the new member loads and behaves byte for byte as before, and the
  file and key forms do not change.
- Every failure is one of ADR-0027's fixed results; a 429 or 503 is ADR-0029's throttled answer.
- `go/` links the standard library only, and the tests need no cloud account.

## Considered options

1. Keep the file form alone: a sidecar fetches the token and rewrites the file.
2. `tokenStep.federatedToken: {"kind": "metadata", "audience": "…"}`, the address built in as
   the IP literal `169.254.169.254`.
3. The same member, the address built in by the name `metadata.google.internal`.
4. A configurable metadata URL beside the audience.

## Decision outcome

Chosen option: 2. Option 1 is the gap the issue names: a process outside the gateway, and the
token on disk. Option 4 lets a configuration point the path at any host. Option 3 asks the system
resolver, so a hosts file, a search domain, a resolver on the network or a spoofed DNS answer
could steer the request. On the platform the name resolves to the same link-local address, so it
gains nothing but reach on IPv6-only compute (below).

1. **The configuration.** Engine configuration version 32, the version after the path-template change adds
   `credentials.live.tokenStep.federatedToken`, an object of exactly `kind` and `audience`.
   `kind` is `"metadata"` and no other value is taken. A token step has exactly one of
   `privateKey`, `federatedTokenFile` and `federatedToken`. `x5t` and `x5t#S256` stay beside
   `privateKey` only. Under an earlier version the member is refused by name. The form is tagged
   by `kind`, as the version-29 `credentials.live.tokenSource` (`{"kind": "metadata"}`) is, so a
   configuration names its metadata-backed sources one way. The object is closed: a later source
   is a new `kind`, and no member of any kind names an address. The engine passes the step to
   `adapter-http` as `--federated-token-metadata-audience=AUDIENCE`, in place of
   `--federated-token-file`.
2. **The audience.** 1 to 256 bytes of ASCII letters, digits, `.`, `_`, `~`, `:`, `/`, `@` and
   `-`. That covers URI-form audiences (`api://…`, `https://…`, `//…`) and bare client
   identifiers, and excludes `&`, `=`, `?`, `#`, `%`, a space and every control character. The
   engine holds it at load and the adapter holds it again. The query is then built by form
   encoding, so the audience is percent-encoded whatever it holds. A refusal repeats no value.
3. **The address.** The metadata server asked is the Google Cloud metadata server
   (`Metadata-Flavor: Google`, `/computeMetadata/v1`):
   `GET http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/identity?audience=<encoded>&format=full`
   with `Metadata-Flavor: Google`. The address is the IP literal, so no resolver is asked. It is
   link-local (RFC 3927): a router does not forward it, so the request does not leave the host's
   link. The platform documents it as fixed on its compute and serverless runtimes. No proxy from
   the environment is used, since a proxy would carry the request off the link. No environment
   variable is read: the platform's client libraries take one that names another host, and this
   path takes none. The connection is dialed to that address and port alone. It is plain http,
   as the platform serves it. What holds the answer to the platform is the address and the
   flavor header, not TLS. Off a cloud host, anything on the link can answer at that address
   with the header and a well-formed token. Only the token endpoint's verification of that
   token stops it. The audience, which is not secret, reaches whatever answers there. The address is a variable of the adapter's package that only that
   package's tests set, to a local stand-in. No configuration, flag or environment variable
   reaches it.
4. **The answer.** It must carry `Metadata-Flavor: Google`, exactly once. That is checked before
   the status, so a 429 from something else at that address is not taken as throttling. A
   redirect is refused and not followed. The request is bounded to five seconds and the answer
   header to 64 KiB. Status 200, a body of at most 16 KiB (the file form's bound), its text
   without the white space around it a compact JWS of three base64url parts. Its payload's `aud`
   is the audience asked for, as a string, and its `exp` is an integer more than 60 seconds
   ahead. The claims are read, not verified: the token endpoint verifies the token, and the
   adapter reads the claims only to refuse a token for another audience or one about to lapse.
5. **The holding.** The identity token is asked for by the run that sends the token request:
   `--token-only`, `--check`, or an acquisition handed no sealed token. It is held in that
   process's memory alone, for that one request. It is presented only while more than 60 seconds
   remain before its `exp`. It is kept out of every diagnostic, as the file's text is, and
   nothing writes it. What is held between acquisitions is the access token, sealed, by the
   signer, in memory, until 60 seconds before its stated expiry (ADR-0027, decision 5,
   unchanged). An acquisition handed a sealed token does not ask the metadata server.
6. **The seal's key.** It cannot derive from the identity token. An acquisition handed a sealed
   token would have to ask the metadata server only to derive the key, and a token the server
   renewed between the token request and the acquisition would leave the seal unopened. Instead
   the live credentials file, which every token step already requires, holds `sealKey`, a string
   of at least 32 bytes, as a gcp-asset metadata source's does
   ([ADR-0039](0039-a-read-only-asset-inventory-connection-for-configuration-drift.md), A3). The
   seal's binding gains `metadata` and the audience. The file and key forms' bindings are
   unchanged.
7. **The failures.** Everything about the metadata server is no credential, exit 3: unreachable
   or slow, no flavor header, a redirect, a status other than 200, 429 or 503, an answer over
   16 KiB, out of form, for another audience, or lapsing. No token request is sent, and the
   signer answers ADR-0027's fixed sentence for no credential. A 429 or 503 that carries the
   flavor header is a throttled answer, exit 7, as the token endpoint's is (ADR-0029): the caller
   is answered with the class and the wait, and nothing is held. Each adapter diagnostic is a
   fixed sentence that quotes nothing of the answer.
8. **The time.** The metadata request's five seconds and the token request's ten fall inside the
   source's one timeout of 30 seconds (ADR-0027, decision 6). That leaves the source at least
   fifteen seconds when both are slow.
9. **Nothing else moves.** No receipt member, no `/posture` member, no new signer sentence, and
   no change to a token step of the file or key form or to a source without one.

### Consequences

- Good, because no sidecar is needed and the identity token is never on disk.
- Good, because no software input can point this path at another host: no configuration member,
  flag, environment variable or DNS answer. The network path to the link-local address (the
  host's routes and the link itself) is the platform's, as the address is.
- Bad, because the identity token is the compute's identity, not the platform's user's. Every
  process on that compute can ask the metadata server for an identity token of any audience,
  the signer's user included. The per-platform user separation the file form has does not hold
  for this credential. Two platforms on one gateway with this form present the same identity,
  told apart only by audience. The seal keeps the signer as written from holding the access token
  in the clear. It is no boundary against a process on the compute that asks the metadata server
  itself. A deployment that needs platforms held apart by their users keeps the file form.
- Bad, because IPv6-only compute is not served: it reaches its metadata server at another
  address, and the IP literal here is the IPv4 one.
- Bad, because each token request costs a link-local request. An identity token is not reused
  across access-token refreshes.
- Bad, because the operator writes a `sealKey` into the live credentials file.
- Revisit when IPv6-only compute is needed (a second fixed literal, chosen by the address
  family the host has, never by configuration), when another platform's metadata server is asked
  for (a new `kind`), or when a long-lived holder per platform is reconsidered (ADR-0027,
  option 4).

## More information

- Holding the identity token sealed beside the access token, and handing it back at the refresh,
  was considered and not taken. It saves one link-local request per refresh. It also hands the
  identity token to every acquisition and changes the signer's refresh, and the access token's
  lifetime is commonly the identity token's, so the token is near its own margin at the refresh
  anyway.
- [engine-config.md](../design/engine-config.md), "A live operation's token step (engine version
  21)"; [adapters/README.md](../../adapters/README.md#adapter-http);
  `adapters/httpsource/metadata.go`; `go/token_step.go`.
- Extends [ADR-0027](0027-an-http-source-obtains-its-token-by-a-client-assertion.md); supersedes
  nothing.
