---
status: accepted (autopilot; maintainer may revise)
date: 2026-11-19
deciders: maintainer
---

# A token step's JWT-bearer assertion names a fixed delegated subject and is signed by the credentials API

## Context and problem statement

A token step ([ADR-0027](0027-an-http-source-obtains-its-token-by-a-client-assertion.md)) obtains
its access token by the client-credentials grant, with a client assertion it signs with a key, reads
from a file, or asks of the platform's metadata server
([ADR-0043](0043-a-federated-token-from-the-platforms-metadata-server.md)). The Google Workspace
Admin SDK's Directory and Reports APIs take none of these. They take an access token of a service
account acting as an administrator of the domain (domain-wide delegation): a JWT-bearer assertion
(RFC 7523, section 2.1) whose `iss` is the service account and whose `sub` is the administrator,
signed by the service account's key. Today that needs a service-account key file (issue #503).

The ask is a token step that holds no key: the service account credentials API signs the assertion
(`signJwt`), authenticated by the gateway's own identity from the metadata server. The subject and
the scopes are fixed per platform in configuration, and catalog bindings for the two APIs are read
only.

Seven things need deciding: the configuration's form, the flow, what is held, which endpoints are
fixed in code, the scopes, the failures, and how a request names a Workspace object in a path,
since a Workspace key is not the GUID ADR-0040's `{id}` takes.

## Decision drivers

- No service-account key, file or member, is read or held by the gateway.
- Nothing a caller sends changes the subject, the scopes, the service account or a host.
- The compute's access token reaches the credentials API alone, at an address fixed in code.
- The scopes a platform can ask for are read only.
- A request path admits no character that changes what the path names: no `/`, `.`, `%`, `@`,
  `?` or `#` in a filled segment.
- A version-32 file loads and behaves byte for byte as before.
- Every failure is one of ADR-0027's fixed results; a 429 or 503 is ADR-0029's throttled answer.
- `go/` links the standard library only, and the tests need no cloud account.

## Considered options

1. A service-account key in the live credentials file, signed by the adapter (the key form with
   `iss`/`sub` changed).
2. `tokenStep.signedBy: {"kind": "credentials-api", "serviceAccount": …}` with a fixed `subject`
   and `requestScope`; the credentials API and the metadata server fixed in code, the token
   endpoint from configuration.
3. As 2, with the credentials API's address in configuration as well.
4. A federated token exchanged first (workload identity federation) and then `signJwt`.

## Decision outcome

Chosen option: 2. Option 1 is the key file the issue rules out. Option 3 lets a configuration send
the compute's access token, a bearer for every API its scopes reach, to a host of its choosing.
Option 4 adds an exchange the platform's compute does not need: it already has an identity.

1. **The configuration.** Engine configuration version 33 adds
   `credentials.live.tokenStep.signedBy`, an object of exactly `kind` and `serviceAccount`. `kind`
   is `"credentials-api"` and no other value is taken; the object is closed, tagged by `kind` as
   `federatedToken` is, so a later signer is a new `kind`. A token step has exactly one of
   `privateKey`, `federatedTokenFile`, `federatedToken` and `signedBy`. Beside `signedBy`,
   `subject` and `requestScope` are required, and `clientId`, `x5t` and `x5t#S256` are refused:
   the JWT-bearer grant authenticates no client, the assertion's `iss` is the service account,
   and the adapter signs nothing. `subject` is refused beside any other form. Under an earlier
   version `signedBy` and `subject` are refused by name, and from version 33 a step without
   `signedBy` still requires `clientId`, as before. The names say what each holds: `signedBy` is
   who signs the assertion, `subject` is its `sub` (RFC 7519), and `requestScope` is the member
   the other forms already send as `scope`. The engine passes the step to `adapter-http` as
   `--token-endpoint=E --signed-by-service-account=SA --token-subject=S --token-scope=SCOPES`,
   with no `--client-id`.
2. **The forms.** `serviceAccount` is a service account's address under a project's domain, which refuses the default compute and App Engine accounts:
   `NAME@PROJECT.iam.gserviceaccount.com`, `NAME` and `PROJECT` each 6 to 30 lowercase letters,
   digits and hyphens, starting with a letter and not ending with a hyphen. It is the one value
   that enters the credentials API's path, and the form admits no `/`, `%`, `?`, `#` or `:`.
   `subject` is an address of at most 254 bytes: a local part of 1 to 64 ASCII letters, digits and
   `.`, `_`, `+`, `-`, one `@`, and a domain of dot-separated labels of letters, digits and
   hyphens. It enters only the claims, which are JSON-encoded. The engine holds both at load and
   the adapter holds them again; a refusal names the member and repeats no value.
3. **The scopes.** `requestScope` is one or more of these, each at most once, separated by single
   spaces, and nothing else:
   `https://www.googleapis.com/auth/admin.directory.user.readonly`,
   `https://www.googleapis.com/auth/admin.directory.group.readonly`,
   `https://www.googleapis.com/auth/admin.directory.group.member.readonly`,
   `https://www.googleapis.com/auth/admin.directory.rolemanagement.readonly`,
   `https://www.googleapis.com/auth/admin.reports.audit.readonly`. Any other scope is refused at
   load, the refusal naming `requestScope` and no value. `admin.directory.user.security` is left
   out: it is the scope the Directory API's tokens resource takes, and it also authorizes deleting
   a user's tokens and application-specific passwords and signing a user out. An access token
   holding it is a write credential whatever the binding sends, and a read-only claim would rest
   on the binding's methods alone. The tokens resource is therefore not bound. The engine holds
   the list at load and the adapter holds it again.
4. **The flow.** At a token request, and only then:
   1. `GET http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token`, with
      `Metadata-Flavor: Google`, no query, under every rule of ADR-0043, decisions 3 and 4: the
      address the IP literal, no resolver, no proxy, no environment variable, the connection
      dialed to that address alone, the answer taken only with the flavor header once, checked
      before the status, no redirect followed, five seconds, the header at most 64 KiB. Status
      200, at most 64 KiB of JSON read as a token endpoint's answer is (ADR-0027): `access_token`
      of RFC 6750's form, `token_type` Bearer, `expires_in` 1 to 86400 when present.
   2. `POST https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/SA:signJwt` with
      `Authorization: Bearer` the metadata token and the JSON body `{"payload": CLAIMS}`, CLAIMS
      the JSON text of exactly `iss` the service account, `sub` the subject, `scope` the scopes as
      configured, `aud` the token endpoint as configured, `iat` now and `exp` five minutes after
      (ADR-0027's assertion lifetime; the token endpoint takes at most one hour). TLS 1.2 or
      later, no redirect followed, ten seconds, the answer at most 64 KiB of `application/json`
      of exactly `keyId`, a string, and `signedJwt`, a compact JWS of at most 16 KiB whose payload's `iss`, `sub`, `scope`
      and `aud` are the ones asked for and whose `exp` is the one asked for. An assertion of other
      claims is not sent.
   3. `POST` the token endpoint, form-encoded, `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer`
      and `assertion` the signed JWT, and read the answer as ADR-0027 reads it.
5. **What is held.** No key is read: the service account's key stays with the credentials API.
   The metadata access token and the signed JWT are held in the memory of the run that sends the
   token request (`--token-only`, `--check`, or an acquisition handed no sealed token), for that
   one request, kept out of every diagnostic, and written nowhere. The access token is sealed
   under the live credentials file's `sealKey`, as ADR-0043, decision 6, decides, and held by the
   signer as ADR-0027, decision 5, holds it. The seal's binding gains `credentials-api`, the
   service account and the subject; the other forms' bindings are unchanged.
6. **The endpoints.** The metadata server's address and path are fixed in code (ADR-0043). The
   credentials API's base, `https://iamcredentials.googleapis.com`, is fixed in code: the
   metadata token is the compute's bearer for every API its scopes reach, and no configuration
   or flag names another host for it. The call, like every token request, goes through the
   proxy `HTTPS_PROXY` names when the environment sets one, with TLS still to that host, so a
   proxy sees which host is called and when, never the token. Each is a variable of the adapter's package
   that only that package's tests set, to a local stand-in. The token endpoint is the
   configuration's `endpoint`, under the endpoint rule every token step has: `https`, or `http` at
   a loopback address written as one. It may come from configuration because what is sent there,
   the signed JWT, names it as `aud`: an assertion for another endpoint is not one the platform's
   token endpoint takes. A configuration holds no host for the metadata server or the credentials
   API.
7. **The failures.** Everything before the token request is no credential, exit 3, and no token
   request is sent: the metadata server unreachable, slow, without the flavor header, redirecting,
   answering another status than 200, 429 or 503, or no token; the credentials API unreachable,
   slow, redirecting, answering another status than 200, 429 or 503, or an answer out of form or
   of other claims. A 429 or 503 from either (the metadata server's with the flavor header) is
   ADR-0029's throttled answer, exit 7, and nothing is held. The token request's failures are
   ADR-0027's. Each adapter diagnostic is one fixed sentence that quotes nothing of an answer, the
   subject, the scopes or the service account. The signer answers its fixed sentences, unchanged.
8. **The time.** The metadata request's five seconds, the `signJwt` request's ten and the token
   request's ten fall inside the source's one timeout of 30 seconds (ADR-0027, decision 6). A
   source whose three requests are all slow fails as a source that did not finish in time.
9. **Paths that name a Workspace object.** A Workspace user, role or role assignment is named in
   a path by its unique id, a decimal number; a group by its unique id, lowercase letters and
   digits. ADR-0040's `{id}` takes a GUID alone, and that rule is unchanged. From engine version
   33 a binding path may carry, in place of `{id}`, one of two placeholders of their own, each a
   whole segment, at most one placeholder in a path of any kind:
   - `{numericId}`: 1 to 32 ASCII digits and nothing else.
   - `{alnumId}`: 1 to 64 lowercase ASCII letters and digits and nothing else.
   Neither admits a character that changes what a path names, an uppercase letter, or the empty
   segment. They are two names rather than one wider form so a path that takes a number takes
   only a number. A binding with either under an earlier engine version is refused by name, as a
   template is under version 30. The engine and the adapter hold a request to them alike, against
   the one table ADR-0040 decided (`testdata/http-requests/cases.json`).
10. **An address as a key.** A Workspace user or group may also be named by its address, which
    carries `@` and `.`. That is not admitted in a path segment: no third placeholder, no
    percent-encoding. A request names an address in a query member instead, which is
    form-encoded as every query is: `users?customer=my_customer&query=email:…`,
    `groups?userKey=…`, `roleassignments?userKey=…`. A caller reaches a user's own object by its
    numeric id from those listings.
11. **The catalog.** Two read-only bindings, under `https://admin.googleapis.com`, each `GET`
    alone, the bearer `token` (the token step's), and only its read paths:
    `google-workspace-directory` (users, a user, groups, a group, a group's members, roles, a
    role, role assignments, a role assignment; the check the roles listing, which
    `admin.directory.rolemanagement.readonly` answers) and
    `google-workspace-reports` (the activities of all users for each of the applications `admin`,
    `login`, `token`, `user_accounts`, `groups`, `saml`, `drive` and `mobile`, as fixed paths; the
    check the `admin` application's). Two rather than one, because a platform has one token step
    and one set of scopes: a platform that reads the audit log asks for the audit scope alone,
    and each binding's check is answerable under its own API's scope. Paging is by the `pageToken`
    query member both APIs take; no link is needed.
12. **Nothing else moves.** No receipt member, no `/posture` member, no new signer sentence, and
    no change to a token step of another form or to a source without one.

### Consequences

- Good, because no key is held anywhere the gateway runs, and the subject and scopes are the
  configuration's alone.
- Good, because the compute's access token reaches the metadata server's and the credentials
  API's addresses alone, both fixed in code.
- Bad, because the identity is the compute's again (ADR-0043, consequences): every process on that
  compute can ask the metadata server for the same access token, and the service account's
  `signJwt` permission is held by that identity, not by the platform's user alone.
- Bad, because domain-wide delegation lets the service account act as the subject over the whole
  domain within the scopes granted to it in the Workspace admin console. A process that can call
  `signJwt` as that identity can mint an assertion for any subject and any of those scopes; the
  configuration fixes what the gateway asks for, not what the identity can ask for. The
  deployment keeps the delegation's scopes to the read-only list and the subject to an
  administrator whose role reads alone.
- Bad, because each token request costs three requests, and a service account outside
  `*.iam.gserviceaccount.com` (a default compute or App Engine account) is refused.
- Revisit when another platform's credentials API is asked for (a new `kind`), when the tokens
  resource is wanted under a read-only scope, or when a key other than an id is needed in a path.

## More information

- [engine-config.md](../design/engine-config.md), "A token step with a delegated subject (engine
  version 33)"; [adapters/README.md](../../adapters/README.md#adapter-http);
  `adapters/httpsource/delegated.go`; `go/token_step.go`; `go/http_request_target.go`;
  `catalog/google-workspace-directory.json`; `catalog/google-workspace-reports.json`.
- Extends [ADR-0027](0027-an-http-source-obtains-its-token-by-a-client-assertion.md),
  [ADR-0040](0040-path-templates-and-links-on-an-http-source.md) and
  [ADR-0043](0043-a-federated-token-from-the-platforms-metadata-server.md); supersedes nothing.
