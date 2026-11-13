---
status: proposed
date: 2026-11-12
deciders: maintainer
---

# An http source obtains its access token by a client assertion, and the signer holds it sealed

## Context and problem statement

An http live source ([ADR-0024](0024-an-http-source-in-the-engine.md)) sends a static value read
from its credentials file. A provider that issues short-lived access tokens against a
certificate or a federated identity, and not against a client secret, cannot be configured:
something outside the gateway has to obtain the token and rewrite the file (issue #421). The ask
is a token step: a token endpoint and a client identifier fixed in the configuration, and either
a private key held as a named credential, with which the gateway signs the client assertion, or
a federated identity token read from a configured file. The token is held until shortly before
it expires and is never written to a receipt, record, status, error or log line, and a step with
no credential, or whose token request is refused, fails closed with a result that says which.

The isolation the engine rests on is that the signer never reads a credential: the platform's
adapter does, as the platform's OS user ([SECURITY.md](../../SECURITY.md); ADR-0024;
[engine-config.md](../design/engine-config.md), "Credentials"). A token held in the gateway
between acquisitions and a signer that never holds a credential pull against each other. That,
and what each failure answers, is the decision here.

## Decision drivers

- The signer reads no private key, no federated token and no access token, in memory or
  anywhere else.
- A configuration without a token step loads and behaves byte for byte as before, and no
  receipt member is added.
- One acquisition sends its source one request: nothing is sent twice under one receipt.
- The three failures are told apart: no credential, a token request refused or answered with
  no token the gateway takes, a token the source refused. Each names the source and never the
  endpoint's answer.
- The token endpoint is held as the source's endpoint is: https, or http at a loopback address;
  no redirect followed; the answer and the time bounded.
- `go/` links the standard library only.

## Considered options

1. adapter-http obtains a token at every acquisition, and nothing is held between them.
2. adapter-http obtains the token, and the signer holds it in the clear and hands it to each
   acquisition.
3. adapter-http obtains the token and answers it sealed, under a key only the platform's
   credential derives; the signer holds the sealed token and hands it to the next acquisition.
4. A long-lived helper per platform, running as the platform's user, holding the token.

## Decision outcome

Chosen option: 3. Option 1 sends a token request for every acquisition, which a provider's rate
limits and the ask's "cached" both refuse. Option 2 puts the access token in the signer's
memory, which the isolation rule exists to keep it out of. Option 4 adds a process the engine
must start, supervise and reach, as the platform's user, for one value; option 3 has the same
holder (the adapter's user) of every secret with no process kept running.

1. **The configuration.** Engine configuration version 21 adds `credentials.live.tokenStep`:
   `endpoint` and `clientId` required; exactly one of `privateKey`, the name of the member of the
   platform's live credentials file holding the key, and `federatedTokenFile`, an absolute path;
   at most one of `x5t` and `x5t#S256`, fixed thumbprints sent in the assertion's header, beside
   `privateKey` only; and `requestScope`, sent as the request's `scope`. It is refused before
   version 21, under `history` or `write`, beside a binding whose live operation is not of the
   `http` shape or sends its credential under `credentialHeader`, and a platform with one may not
   set `ADAPTER_HTTP_SEALED_TOKEN` in its `environment`. The federated token file is held as a
   credentials file is: owned by the platform's user, readable by that user alone, on a way no
   other user may replace. What is fixed at start is the configured path, cleaned, and the
   directory it is named in, resolved; a path that resolves outside that directory is refused.
   The file is found again at each token request: from that directory, through each link on the
   way, owned by root and its target never out of the directory, and each directory on the way,
   held as at start, to a file opened once and held by the open handle, a regular file the
   platform's user owns and alone may read. So a token rewritten in place, renamed onto the
   path, or renewed by a link swap inside the directory (as a platform that projects an identity
   token into a volume re-points a `..data` link to a new directory and removes the old one) is
   read at the next token request; a target outside the directory, or a file that fails a hold,
   is refused as no credential.
2. **The assertion.** With `privateKey`, a JWT the adapter signs: RS256 for an RSA key of 2048
   bits or more, ES256 for a P-256 key, the algorithm taken from the key (a PKCS #8 `PRIVATE
   KEY` PEM block); the header `alg`, `typ` `JWT` and the thumbprint given; the claims `iss` and
   `sub` the client identifier, `aud` the token endpoint, a random `jti`, `iat` and `nbf` now and
   `exp` five minutes on. With `federatedTokenFile`, the file's text, read at each token request.
   The request is RFC 7523's client-credentials grant with `client_assertion_type`
   `urn:ietf:params:oauth:client-assertion-type:jwt-bearer`, as a form POST.
3. **The answer.** Status 200, at most 64 KiB, `application/json`, no member named twice;
   `access_token` a string of RFC 6750's token form of at most 16 KiB; `token_type` `Bearer` in
   any case; `expires_in` an integer from 1 to 86400, or a string of its decimal digits as some
   endpoints answer it, or absent, when the token serves the one acquisition it was obtained for. Ten seconds bound the request; a redirect is not followed;
   TLS 1.2 or later against the system's roots.
4. **Sealing.** `adapter-http --token-only` answers `{"sealed": …, "expiresIn": N | null}`: the
   token sealed with AES-256-GCM under a key HKDF-SHA256 derives from the step's credential (the
   key's PEM text or the federated token), bound to the source's endpoint, the token endpoint,
   the client, the credential named and the scope, and opened until 30 seconds before the stated
   expiry, or for a minute when none is stated. A sealed token handed in under another
   configuration or credential, or past its time, is refused.
5. **The holding.** The signer holds each source's sealed token in memory alone, keyed by source
   and the platform's scope identifier; one token request runs at a time per source and
   concurrent acquisitions wait for it, taking its token or, when it failed, its failure, with
   no request of their own; it is obtained again 60 seconds before the stated expiry, and one
   stating 60 seconds or less, or nothing, is not kept. The acquisition is handed it in
   `ADAPTER_HTTP_SEALED_TOKEN`. A request naming a path or a method the operation does not allow
   is refused before any of this, so it costs the token endpoint nothing.
6. **One deadline.** The source's timeout, 30 seconds, bounds the whole acquisition: the wait for
   another acquisition's token request, the token request, the source, and the token request and
   run once more after a status 6. It is the same number a source without a token step runs
   under, and not one deadline per run, because the MCP side's forward bound (45 seconds) is
   sized for one: that deadline, the five-second wait for a source's pipes, and a margin. With a
   deadline per run, four runs could take four deadlines, and a forward the MCP side had given up
   on could still mint a receipt. The token request's own ten seconds fall inside it, leaving the
   source at least twenty when the token endpoint is slow.
7. **The failures.** adapter-http exits 3 for no credential, 4 for a token request refused or
   answered with no token it takes, 5 when the source answered 401 to the token, and 6 for a
   sealed token it does not open; the signer answers fixed sentences that name the source and
   nothing the adapter wrote. On 5 the sealed token is dropped and the acquisition fails, since
   sending the request again would read the source twice under one receipt; the next acquisition
   obtains a new token. On 6 the sealed token is dropped, a new one obtained and the acquisition
   run once more, since nothing was sent; a second 6 is the refused sentence.
8. **`connect`** has no flag for the member; `--replace` keeps it, and refuses a replacement it
   would not fit.
9. **Nothing else moves.** No receipt member, no `/posture` member, no binding version, no
   change to a source without a token step.

### Consequences

- Good: the private key, the federated token, the assertion and the access token stay with the
  platform's user, as a static credential does; the signer as written holds only ciphertext and
  never reads the token in the clear, and a configuration without a token step is unchanged.
  The seal is not a boundary against a compromised signer, which can read the credential or
  switch to the platform's user and derive the key, as it can reach every credential.
- Good: a provider that issues tokens only against a certificate or a federated identity can be
  read without a process outside the gateway rewriting a credentials file.
- Bad: a token request costs an extra adapter process, and each acquisition opens the sealed
  token.
- Bad: a token the source revoked before its stated expiry costs one acquisition, which fails;
  the caller retries, not the gateway. A federated token renewed, rewritten in place or swapped
  in by a link, costs one extra process (status 6, then a new token).
- Bad: in federated mode the way to the file is walked again at each token request, a few
  system calls per request; it is what lets a link swap be followed without following a link
  anywhere else.
- Bad: the token endpoint is reached against the system's roots; the source's own CA file does
  not apply to it. In federated mode the live credentials file is still required, though nothing
  of it is sent, and under a token step the binding's `bearer` member is not read.
- Neutral: what a receipt of such a source establishes is what one of the static form does — the
  adapter sent the request with the credential its configuration names. Which identity the
  token was issued to, and that the token endpoint is the one the source trusts, it does not
  establish.

## More information

- RFC 7523 §2.2 and RFC 7521 §4.2 (client assertions), RFC 6749 §3.3, §4.4 and §5.1 (scope, the
  client-credentials grant, the answer), RFC 6750 §2.1 (the token form), RFC 7515 §4.1.7 and
  §4.1.8 (`x5t`, `x5t#S256`).
- [engine-config.md](../design/engine-config.md), "A live operation's token step (engine version
  21)"; [adapters/README.md](../../adapters/README.md#adapter-http); `go/token_step.go`;
  `adapters/httpsource/token.go`.
- Supersedes nothing; extends [ADR-0024](0024-an-http-source-in-the-engine.md).
