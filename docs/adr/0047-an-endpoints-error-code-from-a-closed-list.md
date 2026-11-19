---
status: accepted, 2026-11-19
date: 2026-11-19
deciders: maintainer
---

# An endpoint's error code is read from a closed list the binding declares; a 401 or 403 is answered as an access refusal

## Context and problem statement

Two classes of an http source's refusing answer are answered today by their class alone and
nothing of the endpoint's body: a `410` as `source_reference_expired` (gateway #461, ADR-0029's
amendment), and a `429` or `503` as throttled (ADR-0029). Two more need the same treatment, and
each needs one fact that only the body holds.

- **#514.** Some APIs say an expired delta or change token with another 4xx and an error code in
  the body (`syncStateNotFound`, `resyncRequired`). It is answered as a plain `400`, so a caller
  cannot tell "read again from the first value" from any other refused request.
- **#524.** An endpoint's `401` or `403` is answered `400` with `source failed: adapter-http:
  the endpoint answered 403 Forbidden: <excerpt of the body>`. A caller that must tell "this
  stream is refused to this credential" from any other failure parses the sentence, and the
  endpoint's own text reaches it. The status alone cannot tell "the directory lacks the licence
  this read needs" from "the credential lacks the permission"; the endpoint's error code can.

Both read the same thing: the endpoint's error object. The question is how the gateway reads a
fact from a body it has always kept from the caller, without passing on the body.

## Decision drivers

- Nothing of the body reaches the caller: what crosses is a value the configuration's pinned
  binding states, matched byte for byte, never the endpoint's bytes.
- One parser, bounded, strict, and fail-closed: anything it cannot read is "no code".
- The lists are the binding's (catalog), closed and bounded, and changing one is a binding
  change. The engine holds no code of any API.
- A token step's refusals keep their meaning: the gateway drops a token the source refused.
- Every other refusing answer, and every adapter written before, is answered as before.

## Considered options

1. The gateway reads the adapter's stderr for the code.
2. The adapter reports the endpoint's code as it found it, and the gateway holds it to the list.
3. The binding declares, under its http live operation, where the code sits and the two closed
   lists; the adapter alone reads the body and reports only a value on a list; the gateway holds
   the report to the same lists again.
4. For #514 only: keep `410` alone and document that callers recognise the other forms
   (#514's option (b)).

## Decision outcome

Chosen option: 3 (#514's option (a)). Option 1 reads a diagnostic as a protocol. Option 2 carries
the endpoint's text across the source boundary into the gateway's memory, bounded but not the
binding's. Option 4 leaves every caller to parse what the gateway already reads.

1. **The member.** An http live operation may name `errorCodes`, an object of exactly `at` and at
   least one of `referenceExpired` and `accessRefused`:
   - `at`: 1 to 4 member names, the path from the error object's top to the code
     (`["error", "code"]` for `microsoft-graph`); each 1 to 64 bytes of ASCII letters, digits,
     `_` and `-`.
   - `referenceExpired`: 1 to 8 objects of exactly `status` and `code`. The status is a 4xx no
     other class answers: not `401` or `403` (an access refusal), not `410` (an expired reference
     whatever its code) and not `429` (throttled).
   - `accessRefused`: 1 to 16 codes.

   Every code is 1 to 64 bytes of ASCII letters, digits, `_`, `.` and `-`, once in its list, and
   never `unlisted`, so the marker below is unambiguous. A refusal names the member by its place
   and repeats no value. The engine passes the member to `adapter-http` as one word per flag:
   `--error-code-at=error.code`, `--expired-codes=400:syncStateNotFound,…`, and
   `--access-codes=…`. The character sets exclude `,` and `:`, and `at`'s also excludes `.`, so
   each word splits back exactly.
2. **The one parser.** On a refusing answer, `adapter-http` reads the code from the body as
   follows:
   - The body must be at most **4 KiB** (4096 bytes; the same bound as the diagnostic's
     excerpt). A longer body is read for no code at all.
   - It must be exactly one JSON value, and no object in it may repeat a member name. Which of
     two codes is the endpoint's would otherwise be the decoder's choice.
   - Each name of `at` in turn must be an object's member, and the last must be a string of the
     code form.

   Anything else is no code: a body that is not JSON, is over the bound, lacks the code, or has
   a code of another type or form. The code is then compared byte for byte with the lists, and
   what is reported is the list's own copy.
3. **#514, the declared pairs.** A source answer whose status and code are a declared pair is an
   expired reference. The adapter exits 8, as for a `410`, and writes
   `{"referenceExpired": {"code": C, "status": S}}`. The gateway reads that form only when
   (S, C) is a pair of the source's binding. It answers exactly as for a `410`: status `410`,
   `"code": "source_reference_expired"`, unreceipted, no `callIndex`, the session left open, the
   sealed token kept. Only the sentence differs, since it names the status the endpoint gave:
   `source failed: the source's endpoint answered 400 Bad Request with an error code its binding
   declares an expired reference: …`. An undeclared pair, a pair reported for a source whose
   binding declares none, and an unreadable body stay the plain `400` with the stderr text, as
   before. The `410` report and answer are unchanged byte for byte.
4. **#524, the access refusal.** An endpoint's `403`, and its `401` where no token step obtained
   the token sent, is an access refusal. The adapter exits **10** (9 is `adapter-gcp-asset`'s
   read-only refusal, and each status keeps one meaning across the engine's adapters). It writes
   `{"accessRefused": {"code": C, "status": 401 | 403}}`: C is the body's code when it is on
   `accessRefused`, and `unlisted` otherwise. Its stderr is the diagnostic it always wrote. The
   gateway reads the report beside status 10 only from a source declared `http` that is not a
   `gcp-asset` source, and not from a token request. It holds the report strictly: two members,
   the status 401 or 403, a 401 refused from a source with a token step, and the code
   `unlisted` or of the code form. It then passes the code on only when its own copy of the
   binding lists it, and otherwise passes `unlisted`, whatever the adapter reported. A report out
   of its form is a failed source, `400`, as before.
5. **The answer.** The answer is `403`, for a `401` as for a `403`:

   `{"code":"source_access_refused","endpointCode":"<listed code or unlisted>","endpointStatus":403,"error":"source failed: the source's endpoint answered 403 Forbidden: it refused this read to the source's credential; nothing was retained or minted"}`

   (`401 Unauthorized` in the sentence for a `401`.) The two members sit at the top level beside
   `error` and `code`, as `code` does for the `410` class. `endpointStatus` is the endpoint's
   status; `endpointCode` is a code from the binding's list or `unlisted`. The status is not
   passed through as the `429` and `410` classes pass theirs, for two reasons. A `401` from the
   gateway means the caller's own credential is refused (ADR-0037), and a caller that reads it so
   would discard a good token. RFC 9110 §15.5.2 also requires a `WWW-Authenticate` header that
   the gateway cannot write for the endpoint's scheme. `403` with the class code is told from the
   gateway's own `403` refusals by `code`. The text begins as a failed source's does, so
   `gateway adapter-conform` classes it `source-failed`.
6. **Receipting.** Nothing is receipted, as for the `410` and `429` classes. A refusal is a read
   that did not happen: nothing is minted, retained or recorded, the session is left open, and
   the gateway does not retry. Under a delegation, the call is counted as any failed call is
   (ADR-0029, determination 10).
7. **A token step.** The step's three refusals are distinct, and none of them reads a code:
   - **The token endpoint's own `401`**, or any of its refusals other than `429` or `503`, stays
     a refused token request (status 4, `errTokenRefused`, nothing held). The token endpoint is
     not the source, and its answer is not read for a code. The gateway does not read a report
     beside a token request's status. It reads none beside status 8 either, as before.
   - **The source endpoint's `401` to a token the step obtained** stays `TokenRejectedBySource`
     (status 5). The gateway drops the token and answers its fixed `errTokenRejected` sentence.
     That 401 says the token was refused, which the next acquisition answers by obtaining
     another; it does not say the credential lacks the read, so it is not this class.
   - **The source endpoint's `403` under a token step** is an access refusal. The token is kept,
     since the source took it and refused the read.
8. **No engine configuration version.** `errorCodes` is a binding-format member, and needs no
   engine configuration version (version 35 stays unused). Four reasons:
   - The configuration pins the binding by digest, so the member is part of the bytes its author
     reviewed.
   - An engine released before the member refuses a binding naming it by name (the strict
     parser), so the member is never silently unread.
   - The member widens nothing the source reads or reaches. It only classes a refusal the
     endpoint already gave, and passes on a literal the binding states. ADR-0040's path
     templates were gated because a template admits paths an earlier reading did not; this
     member admits no path.
   - The access class itself applies to every http source, with no list (`unlisted`), as the
     `410` and `429` classes did under ADR-0029, decision 4, with no version.

   No receipt, record, schema or binding version moves.
9. **The plain form.** A source given to `serve --source-shape NAME=http` by hand has no binding,
   so the gateway holds no list for it. Its access refusals are answered `unlisted` whatever
   flags the operator gave the adapter, and its only expired reference is a `410`.
10. **The catalog.** `microsoft-graph` declares:
    - `at` as `["error", "code"]`, the directory service's error object ("Microsoft Graph error
      responses and resource types").
    - The pairs (`400`, `syncStateNotFound`), (`404`, `syncStateNotFound`), (`400`,
      `resyncRequired`) and (`404`, `resyncRequired`). The delta query overview says an expired
      token is answered "a 40X-series error with error codes such as `syncStateNotFound`", and
      `400` and `404` are the two the catalog's notes name.
    - `accessRefused` as `["Authorization_RequestDenied"]` alone, the permission not granted.

    A further code is added to that one array, a binding change re-pinned by digest.

### Consequences

- Good: a caller tells an expired reference by one code, whatever status the API gives it, and
  an access refusal by one code. When the binding lists the endpoint's code, it can say which
  refusal it was.
- Good: nothing of the body crosses. What crosses is a status, and a literal the pinned binding
  states that the gateway holds the report to.
- Bad: a code the binding does not list is `unlisted`, and so is one in another case or
  spelling. A code an API documents but the binding omits gives the caller nothing until the
  binding is changed and re-pinned.
- Bad: the declared statuses for `microsoft-graph` follow the documentation. Which status the
  service gives an expired directory delta token has not been observed here.
- Bad: a body over 4 KiB is read for no code, so an endpoint that pads its error object loses
  its code.
- Bad: an access refusal and the gateway's own `403` share a status and differ by `code`.
- Neutral: a new `adapter-http` beside an older gateway is answered as before: the older gateway
  does not read statuses 8 (for a pair) or 10, and the stderr is unchanged. The engine starts the
  `adapter-http` of its own release (ADR-0007).
- Neutral: the MCP front lists no tool of an http platform (ADR-0029, decision 8), and is
  unchanged.

## More information

- SPEC.md §6, "When an acquisition does not happen" and "Adapter sources";
  `docs/design/engine-config.md`, "An http live operation"; `catalog/README.md`, `microsoft-graph`.
- RFC 9110 §15.5.2 (401) and §15.5.4 (403); ADR-0029 and its amendment (gateway #461); ADR-0027
  (the token step's failure kinds); ADR-0040 (why path templates were version-gated).
