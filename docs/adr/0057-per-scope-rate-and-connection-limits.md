---
status: accepted with conditions, 2026-11-23
date: 2026-11-23
deciders: maintainer
---

# Each scope, and each caller within it, has a request rate and an in-flight limit, counted by each instance at the first step that knows the scope

> **Number.** 0057 is a placeholder, assigned at merge. An open pull request holds 0056.

> **Summary.**
>
> - **Chosen:** a top-level `limits` member (engine configuration version
>   `44` (`requestLimitsVersion`)), keyed by scope identifier, with `"unscoped"` for the
>   sources of none, and a `default` for every scope it does not name. Each entry gives a token bucket
>   (`requestsPerMinute` and `burst`), an in-flight cap (`inFlight`), and the same three for each
>   caller within the scope (`perCaller`). Beside them, one gateway-wide in-flight cap
>   (`beforeScope`) holds the requests not yet tied to a scope. Without the member, nothing changes,
>   byte for byte.
> - **Counted:** every `/acquire`, `/act`, `/seal` and `/verify` request, `/act` dry-runs included
>   (ADR-0054 decision 6). Every request but `/publickey` and `/publickey/history` takes a slot of
>   the gateway-wide cap when it arrives, before its token is read, and gives it back once its token
>   is read: never across its body or its run (the maintainer's rulings, below). A request of those
>   four routes is charged once, at the first step that knows its scope: to the one scope its caller
>   reaches, or, for `/verify` from a caller of several, to every scope it reaches, all or nothing.
>   That step comes before the body is read when the caller's token reaches one scope alone.
>   Otherwise it comes right after the route's own scope step. It is always before any session
>   lookup, key lock, source run, store walk, signing or delivery. A request with no token to read,
>   `/registry` among them, holds its gateway-wide slot until it is answered.
> - **Answered:** `429`, `Retry-After`, `{"error", "code": "limit_reached", "limit"}`, and
>   `"refusedAt": "limit"` on `/act`. The sentence is fixed for each `limit`, names no scope and gives
>   no other scope's state, and `Retry-After` comes from the refusing state alone. Nothing is minted,
>   journaled, stored, admitted or sent to the receipt sink.
> - **Isolated:** each scope's state is its own, in an immutable map built at start, and is taken with
>   atomics and that scope's own mutex. The gateway-wide cap is one atomic counter. No request waits
>   on a limit. At most 4096 callers are held for each scope, and a new caller is refused, never
>   served uncounted, when every held caller is busy.
> - **Per instance, for this release:** each instance counts its own requests (ADR-0035). N instances
>   admit up to N times each limit, and an operator running several instances sets each limit divided
>   by N. `/posture` says so. A count shared by the instances is gateway #593 (v0.41.0).
> - **Reported:** a `request-limits` line, and a `limits` member listing the effective values, both
>   judged over the scopes of the sources the caller reaches alone (ADR-0041), and the count of
>   unauthenticated refusals.
> - **Bounded, not removed:** the limits bound one scope's effect on another. They do not remove it.

## Context and problem statement

Gateway #507. One gateway serves the sources of several scope identifiers (ADR-0026) and those of
none. Nothing bounds how many requests one scope's callers send, or how many they keep open. The
listener has a header timeout, a read timeout, an idle timeout and a body cap (`go/serve.go:3250`,
`listenerServer`), and nothing that knows a scope. Every scope's requests pass through points they
share: the gateway's lock for admission and the stamp, the store's append, and the signer. Under a
key service, the signer is one quota and one signing at a time, up to 5 seconds each (ADR-0050). One
scope's callers can therefore slow every other scope, or spend a key service's quota for all.

ADR-0054 adds a case and binds this record (decision 6). Each `/act` dry-run is one signing call, so a
permitted writer of one scope could spend the signing quota of all. The per-scope limits must
therefore count every `/act` request, dry-runs included.

The issue asks for four things: request-rate and concurrent-connection limits per scope, and per caller
within a scope, configurable; a `429` with `Retry-After` for an exceeded limit, with nothing receipted
and other scopes unaffected; the limits in `/posture`, each judged over the caller's own scopes; and
tests that one scope at its limit does not delay another.

Five facts in the code shape the answer:

1. **A connection has no scope.** The gateway learns the caller from its token. It learns the scope
   from the token only when the token reaches one scope alone. A caller that reaches several, the
   installation's caller among them, names the scope in the body: in `/acquire`'s `source` and
   `scope`, in `/act`'s `scope` (ADR-0054), and in `/seal`'s `scope` or its session. An idle
   keep-alive connection is of no scope. Go's HTTP/1.1 server serves one request at a time on a
   connection. A "connection limit" per scope is therefore a limit on the scope's requests **in
   flight**, and this record calls it that.
2. **`/act` is not served on the PostgreSQL kind.** It is refused `501` at `refusedAt: "storage"`
   before the body is read (`go/serve.go:2801`). Under ADR-0035's several instances, the routes that
   sign are therefore `/acquire` and `/seal`, until `/act` is served there. The count of `/act`
   applies on that kind once `/act` is served there, with no change to this record.
3. **A delegated request reaches the sources of none alone** (`go/caller_scopes.go:192`, `reachOf`),
   and so does a reservation sender (§11.8). A delegated scoped write waits for the RFC 0030 scope
   binding (ADR-0054 decision 1).
4. **A limit bounds a share; it removes no shared point.** Within its limit, a scope's admitted
   requests still take the gateway's lock, the store's append and the signer, as today. The limiter
   adds one shared point of its own, the gateway-wide cap's counter: an atomic, taken by
   compare-and-swap and never waited on (decision 4). It bounds how many of one scope's requests can
   be queued at the existing ones.
5. **An unauthenticated request has no scope at all.** A flood of requests with no token, or a bad
   one, is refused `401` before any scope step, so no scope's limit would ever count it.

## Decision drivers

1. **Unchanged by default.** A configuration without the member answers, starts and reports as it
   does today, byte for byte.
2. **Isolation.** A scope at its limit adds no lock, no wait and no state to another scope's request.
   The requests not yet tied to a scope are bounded together, apart from every scope's own share.
3. **A request is charged only to a scope its caller reaches.** No caller spends another scope's share,
   and no answer tells a caller anything of a scope it does not reach (ADR-0041).
4. **Before any cost.** A request is counted before anything is run, read from the store, locked,
   reserved, signed or delivered. Where the scope is known before the body, it is counted before the
   body is read.
5. **ADR-0054 decision 6.** Every `/act` request is counted, dry-runs included.
6. **Fail closed.** A request that cannot be counted is refused. It is never served uncounted.
7. **Bounded memory,** whatever the number of callers a token issuer can name.
8. **No format change.** Receipts, seals, the registry, the journal, the store and both verifiers are
   unchanged.

## Considered options

**Where the configuration lives.**

- **C1.** A `limits` member on each platform.
- **C2.** A member on each scope entry.
- **C3.** A top-level `limits` member, keyed by scope identifier.

**The unit.**

- **U1.** A fixed window: N requests per window.
- **U2.** A sliding log of request times.
- **U3.** A token bucket (rate and burst) for the request rate, beside a cap on requests in flight.

**Where the request is counted.**

- **P1.** Always after the body is read, at one step per route.
- **P2.** At the first step that knows the request's scope: before the body for a caller that reaches
  one scope, and after the route's scope step otherwise.
- **P3.** Before the body, per caller only, with no scope.

**Across instances.**

- **I1.** Each instance counts its own requests.
- **I2.** The instances count together, in the database they share.

## Decision outcome

Chosen: **C3, U3, P2 and I1.**

- C3 is the only form that is a per-scope limit. A scope spans the platforms fixed to it, and
  `"unscoped"` spans every platform of none.
- U3 keeps two numbers per key, gives a true `Retry-After`, and can be taken without a lock.
- P2 counts each request once, to the right scope, at the earliest step that can know it.
- I1 adds nothing to the path every scope shares.

### 1. The configuration

From engine configuration version `44` (`requestLimitsVersion`), a configuration may carry a
top-level `limits` member:

```json
"limits": {
  "beforeScope": {"inFlight": 1024},
  "default": {
    "requestsPerMinute": 600, "burst": 60, "inFlight": 16,
    "perCaller": {"requestsPerMinute": 120, "burst": 20, "inFlight": 4}
  },
  "scopes": {
    "east-ledger": {"requestsPerMinute": 1200, "burst": 100, "inFlight": 32},
    "unscoped": {"requestsPerMinute": 60, "burst": 10, "inFlight": 4}
  }
}
```

- **`scopes`** maps a scope's key to its entry. A key is a scope identifier that some platform is fixed
  to, compared byte for byte, or `"unscoped"` (`unscopedMarker`, the string `identity.callerScopes`
  already uses for the sources of none, which from engine version 27 no platform is fixed to) where
  some platform is of none.
- **`default`** is the entry of every scope that `scopes` does not name, `"unscoped"` included.
- **An entry** has any of `requestsPerMinute`, `burst`, `inFlight` and `perCaller`, and at least one
  of them. An entry in `scopes` replaces `default` whole for its scope. Members are not merged, so
  what an entry leaves out is unlimited for its scope, whatever `default` says.
  - `requestsPerMinute` is an integer from 1 to 600000. `burst` is an integer from 1 to 10000. Each
    is given only with the other: the bucket holds `burst` requests and refills at
    `requestsPerMinute`.
  - `inFlight` is an integer from 1 to 4096: the scope's requests counted and not yet answered.
  - `perCaller` holds the same three members, at least one of them, and no `perCaller`. Each caller
    within the scope has its own bucket and its own cap.
- **`beforeScope`** is the gateway-wide cap (decision 2, "The gateway-wide cap"): `inFlight`, an
  integer from 1 to 65536, and no other member. It holds every request not yet tied to a scope.
- **The defaults.** Without `limits`, nothing is counted, and every answer, start line and posture
  report is as today, byte for byte. Without `default`, a scope that `scopes` does not name is
  unlimited. A member an entry leaves out is unlimited. Without `beforeScope`, a configured `limits`
  holds 1024 requests in flight before their scope.
- **Counted by each instance, for this release.** Every value is counted by each instance alone
  (decision 6). N instances admit up to N times each limit, so an operator running several
  instances sets each limit divided by N. A count shared by the instances is gateway #593
  (v0.41.0).
- **The load-time refusals.** Each one names the member and the form and quotes no value. The gateway
  will not start on any of the following:
  - the member under an earlier version: `limits is a version-<n> member; engineVersion <m> has no
    limits`;
  - a `limits` with none of `beforeScope`, `default` and `scopes`, or with any other member;
  - an entry with no member, or with any other member;
  - a number that is out of range, not an integer, or written with a fraction or an exponent;
  - `requestsPerMinute` without `burst`, or `burst` without `requestsPerMinute`;
  - a key of `scopes` that no platform is fixed to, or `"unscoped"` where no platform is of none. A
    misspelled identifier would otherwise leave the scope it meant unlimited, without a word;
  - `perCaller` in a configuration without an identity. There is no caller to count, and a limit that
    holds nothing would be a label posing as a bound;
  - a `perCaller` value above the same entry's scope value for the same member. It would never be
    reached.
- **The start line.** Where `limits` is configured, the start writes one line on stderr:
  `request limits: <n> of <m> scopes are limited, counted by this instance alone`. Without it, the
  start writes nothing new.
- **Read at start.** The limits are read at start. A `SIGHUP` does not change them, since it rotates
  the key alone. A change needs a restart.

**Options not taken.** C1 was not taken: a scope of three platforms would get three budgets, and the
sources of none would get one budget per platform. C2 was not taken: the configuration has no scope
entry. A scope is a string on platforms and in `callerScopes` grants, so C2 is C3 under another name.
U1 was not taken: it lets twice the limit through across a window's edge, and its `Retry-After` is
the edge, not the wait. U2 was not taken: it keeps one time per request, so its memory grows with the
rate.

### 2. What is counted, and at which step

**The routes.**

- **Charged to a scope:** `/acquire`, `/act`, `/seal` and `/verify`. Each one runs a source, signs a
  receipt or a seal, walks the decision-record directory and signs, or walks the store. `/act` is
  counted whether it writes or is a dry-run (ADR-0054 decision 6). `/verify` walks the whole store,
  so it is the costliest route a caller reaches.
- **`/act` on the PostgreSQL kind** is refused `501` at `refusedAt: "storage"`, before its scope is
  known (context, fact 2), so there it holds a gateway-wide slot alone. Its count applies on that
  kind once `/act` is served there.
- **Held by the gateway-wide cap alone:** every other request the listener serves.
  - `/posture`, which reads the configuration and signs nothing.
  - `/registry`, an open route with no caller and no scope, which serves the whole registry log
    and is bounded by `openRouteWriteTimeout` too, on a loopback listener as on any other once
    limits are configured (#595). `/publickey` and `/publickey/history` are not
    held at all (the maintainer's rulings, below), so verifiers and probes still answer while the cap
    is full.
  - The issuing host's endpoints, `/delegation/credential` and `/delegation/revoke`, whose caller is a
    host, not a scope.
  - A witness's `/witness/*`, and a route the gateway does not serve.
- **Not requests:** an `/act`'s read-back is part of its `/act` and is counted once with it. Start-time
  sealing (`sealOpenAtStart`) and the commands run while the gateway is stopped (`seal-open`,
  `retain`, `store rotate`, `remove-scope`) are not requests.

**The gateway-wide cap** (`beforeScope`) holds the requests not yet tied to a scope.

- Every request the listener serves, but `/publickey` and `/publickey/history`, takes one of its
  slots when it arrives, before its token is read. A request over the cap is answered `429`
  `gateway-in-flight` at once, and its token is never read.
- A request gives its slot back once its token is read, whatever the check answers, and so never
  holds it across its body or its run. One middleware takes the slot and releases what the request
  still holds when its handler returns, however it ends. A request of a route charged to a scope
  holds its scope's slots from the step that charges it.
- A request with no token to read holds its slot until it is answered: `/registry`, a witness's
  open reads, and a route the gateway does not serve. A slow client holds no slot: the slot is taken
  only once the headers are read, and the listener's read-header timeout (10 seconds) and read
  timeout (30 seconds, headers and body) cut a client that sends slowly.
- An unauthenticated flood therefore holds at most `beforeScope` requests in flight at once, each
  for the time its token check takes, and a request already charged to a scope holds no slot of the
  cap. The flood cannot starve every scope of the gateway. While the flood keeps the cap full,
  though, a request that arrives is refused before its token is read, whatever its scope. The cap
  bounds the flood's effect; it does not remove it.
- The cap's refusals, and every `401` answer, are counted together since start as the instance's
  unauthenticated refusals. `/posture` gives the count (decision 5), and a later refusal
  journal relies on it.

**The scope a request is charged to.** A request is charged to exactly one scope, and only to one its
caller reaches.

- **A caller whose reach takes one scope alone** is charged to that scope. Its reach is either exactly
  one scope identifier, or the sources of none and nothing else. Every request of such a caller is
  either of that scope or refused later, before it costs anything. Delegated requests and reservation
  senders are among these callers (`"unscoped"`). So is a front fixed to one scope identifier.
- **A caller whose reach takes several scopes, or every source,** is charged to the scope the request
  names, once its route has held that scope to the caller's reach. The installation's caller, the
  `"unchecked"` mode and a gateway with no identity are among these callers.
- **A request whose scope is not established** is charged to no scope. Its scope is not established
  when it names an unknown source, a source of a scope the caller does not reach, a malformed body, or
  no scope where the caller does not reach none. Such a request is refused by its route's own step,
  as today. That step runs nothing and signs nothing. Charging the request to the scope it named
  would let a caller spend a scope it does not reach. It holds its gateway-wide slot until answered.
  One such request still runs a lookup before its answer: a `/seal` from a caller of several scopes,
  of a session this process does not hold, looks for it in the registry and the store, since a
  session another process or instance sealed or holds is answered so (ADR-0035), never as no such
  session. That `/seal` takes a gateway-wide slot again once its body is read, and holds it until its
  answer is written, as `/registry` does; over the cap it is refused `429` `gateway-in-flight`, not
  counted as unauthenticated (#595).
- **A `/verify`** names no scope and has no body. It is charged after authentication and its reach
  check, before the store is read, to every scope the caller reaches, all or nothing (the
  maintainer's rulings, below): a caller whose reach takes one scope alone is charged to that scope
  (where no platform is fixed to a scope identifier, ADR-0037, that is `"unscoped"`), and a caller
  whose reach takes several, or every source (the installation's caller, `"unchecked"`, or no
  identity), to each of them. Where one refuses, none is charged and that scope's refusal answers.
  A `/verify` refused `403` for its reach is refused before the step.

**The step, on each route.**

| Route | Caller reaches one scope | Caller reaches several, or every source |
|---|---|---|
| `/acquire` | after authentication, before the body is read | after the source's scope check (§6: "before the trail, the publisher policy, the grant, the admission, a delegation's count or the source"), and before them |
| `/act` | step 3a: after `storage`, before step 4 reads the members | step 8a: after step 8 holds `scope` to the caller's reach, before step 9 looks up the label. A request naming no scope is charged to `"unscoped"` only where the caller reaches none: any other is refused at step 2 or step 8, before step 8a, which refuses nothing but by the limit, so the limits never change who may write |
| `/seal` | after authentication, before the body is read | after the members are read, where the request names `scope` (held to the reach by `narrowedTo`). Otherwise after the session is found and held to the reach, before the seal is signed or delivered. A request whose scope is not established takes a gateway-wide slot at that step instead, held until it is answered |
| `/verify` | after authentication and the reach check, before the store is read | the same step, charged to every scope the caller reaches, all or nothing |

The body of a request whose scope comes from the body is read before it is counted. That read is
bounded by the body cap and the read timeout, and it takes no shared lock.

**The caller within the scope.** The key is the identity the request is authenticated as. It is a
SHA-256 over a domain-separated encoding of three things: the kind (`token` or `delegated`), the
issuer and the subject.

- A direct request is keyed by its token's issuer and subject.
- A request under a delegation is keyed by its authenticated sender (`delegatedSender`: actor,
  subject, host or operator, with that sender's issuer and subject), not by the delegation's subject.
  Two actors for one subject each get their own share, and no actor spends its subject's own direct
  share.
- A reservation sender (§11.8) is keyed by itself in the same way.
- With no identity there is no caller: the scope's limits hold, and `perCaller` is refused at load.

**When the RFC 0030 scope binding is built** (ADR-0054 decision 1), a chain bound to one scope
identifier reaches that scope alone. It is then charged to that scope before the body is read, by the
first row of the table, with no change to this record.

**Refusals.**

- A request refused **at** the limit step takes nothing: no token and no slot. A caller that keeps
  sending while refused does not push its own `Retry-After` further out.
- A request refused **before** the limit step is charged to no scope. It held its gateway-wide slot
  alone, until its answer. That covers a `401`, a `404` method, `/act`'s pre-body
  `scope-identifier` and `storage`, and a malformed body.
- A request refused **after** the limit step stays counted. It took its token and holds its slot until
  its answer is written. Examples are a session refusal, a decision-policy refusal, a dry-run's
  outcome, and a throttled source.

**The slots are released** when the handler returns, after the answer is written, whatever the
answer: the scope's and the caller's, or the gateway-wide slot of a request never tied to a scope.
They are released by a deferred call, so a panic that the server recovers releases them too.

### 3. The `429` answer

- **Status:** `429`.
- **`Retry-After`:** delta-seconds, sent on every limiter refusal. It is computed from the state that
  refused alone: the caller's own bucket or cap, the caller's own scope's bucket or cap, or the
  gateway-wide cap where that refused. No other scope's state, and no other caller's, enters it.
  - For a refused bucket, the whole seconds until the bucket that refused holds one request, rounded
    up. That is at least 1, and at most 60 under the smallest rate allowed.
  - For a full in-flight cap, the gateway-wide cap among them, `1`. A slot frees when any of the
    requests holding one is answered, which the gateway cannot foresee, so `1` is a hint and not a
    promise.
- **The body:** `{"error": <sentence>, "code": "limit_reached", "limit": <which>}`, where `limit` is
  one of these:
  - `scope-rate`: `limit: the request rate of this request's scope is reached; send it again after
    Retry-After`;
  - `scope-in-flight`: `limit: this request's scope has as many requests in flight as it is allowed;
    send it again after Retry-After`;
  - `caller-rate`: `limit: this caller's request rate within this request's scope is reached; send it
    again after Retry-After`;
  - `caller-in-flight`: `limit: this caller has as many requests in flight within this request's scope
    as it is allowed; send it again after Retry-After`;
  - `callers`: `limit: this request's scope holds as many callers as it can count, each with a request
    in flight or a spent bucket; send it again after Retry-After` (decision 4);
  - `gateway-in-flight`: `limit: the gateway has as many requests in flight that are not yet tied to
    a scope as it is allowed; send it again after Retry-After` (decision 2, "The gateway-wide cap").
- **The sentence is fixed.** Each sentence is a constant, chosen by `limit` alone. None names a scope
  identifier, a caller or a number, and none gives any other scope's state: the same refusal from
  the same state answers the same bytes whatever any other scope's entry, load or refusals.
- **On `/act`,** the body adds `"refusedAt": "limit"`, at step 3a or 8a.
- **The order of the checks:** the gateway-wide cap, at arrival. Then, at the limit step, the callers'
  table (decision 4), the caller's cap, the scope's cap, the caller's bucket, then the scope's bucket.
  The first one that refuses answers. Everything taken at the limit step before it is given back, so
  a caller over its own share does not spend its scope's tokens.
- **Nothing is receipted.** The refusal comes before every step that mints, journals, stores, admits,
  counts or sends.
  - No receipt or seal is signed.
  - No store or registry line is written, and no label is recorded.
  - No session is admitted or created.
  - No action key is locked, reserved or journaled: step 3a and step 8a both come before step 18.
  - No delegation call is counted at an issuing host.
  - Nothing goes to the receipt sink.
  - No line is written on stderr. A flood of refusals must not become a flood of log lines.
- **Distinct from ADR-0029.** A throttled source is also answered `429` or `503` at `/acquire`, with
  the source's wait and no `code`. A caller tells the two apart by `code`. A client that waits for
  `Retry-After` on any `429` is right for both.

### 4. Isolation and bounded memory

- **Per-scope state, built at start.** At start, each scope with an effective entry gets its own
  limiter, in a map from the scope's key to the limiter. The map is never written after start, so it
  is read with no lock. A scope with no entry has no limiter and is not counted.
- **The scope's bucket** is a GCRA token bucket: one atomic 64-bit theoretical arrival time, in
  monotonic nanoseconds since start, taken and given back by compare-and-swap. A wall-clock step never
  refills it.
- **The scope's cap** is one atomic counter, raised by compare-and-swap only while it is below
  `inFlight`, and lowered when the slot is released.
- **The callers' table** is each scope's own map from the 32-byte caller key to that caller's bucket
  and cap, which are atomics like the scope's. The map is guarded by that scope's own mutex. The mutex
  is held only to find, add or drop an entry, and never across a request, a wait or another scope's
  lock.
- **No wait.** A request over a limit is answered at once. Nothing queues, sleeps or retries inside the
  gateway, so the limiter adds no time to any request, refused or served.
- **The gateway-wide cap** is one atomic counter, beside one atomic count of the unauthenticated
  refusals. It is raised by compare-and-swap like a scope's cap, with no mutex, once at arrival, and
  lowered once, at the limit step or at the answer. It is never waited on.
- **No global lock on the path.** A request of scope A touches only A's map entry, A's atomics and A's
  mutex, beside the gateway-wide cap's counter. It never touches B's state.
- **Bounded memory.** A scope holds at most 4096 callers (`maxLimitedCallers`), roughly 100 bytes each.
  - A caller whose bucket is full and who has nothing in flight is **idle**. A fresh entry would be
    the same, so dropping it loses nothing.
  - A new caller that finds the table full sweeps the idle entries, at most once a second
    (`limitSweepInterval`), so a full table of busy callers costs one walk a second and not one per
    newcomer. A newcomer refused in between is told `Retry-After: 1`.
  - If none is idle, the request is refused `429` with `limit: "callers"` and `Retry-After: 1`. It is
    not served uncounted (driver 6). Only that scope, which has `perCaller` set, is affected.
- **What isolation does not give.** A scope within its limit still shares the gateway's lock, the
  store's append and the signer with every scope, as today (context, fact 4). The limit bounds how many
  of one scope's requests can wait at them: at most its `inFlight`. It bounds one scope's effect on
  another; it does not remove it. The same holds of the gateway-wide cap: a flood that keeps it full
  refuses every scope's new arrivals before their tokens are read (decision 2).

### 5. `/posture`

- **The line.** A new protection, `request-limits`, is given only where `limits` is configured.
  Without the member there is no line, byte for byte. It is judged over the scopes of the sources the
  caller reaches (`reachedSources`, ADR-0041), as every line is, and it takes one of these states:
  - `enforced`: each of the reached scopes has both a bucket and a cap, and callers are checked;
  - `partial`: some reached scope lacks a bucket or a cap; or callers are not checked (`"unchecked"`,
    or no identity), so any caller can spend any scope's share;
  - `not-enforced`: no reached scope has a limit;
  - `not-applicable`: the caller reaches no source.

  The reason gives counts over the reached scopes alone (for example "2 of the 3 scopes this caller's
  token reaches"). It always ends "counted by this instance alone; under several instances each one
  counts its own".
- **The member.** The report gains `limits`, given only where the member is configured. It is an array
  with one entry for each reached scope that has an effective entry, sorted by the scope's bytes:
  `{scope, requestsPerMinute?, burst?, inFlight?, perCaller?}`, with the values after `default` is
  applied. `scope` is the identifier, or `"unscoped"`.
- **The unauthenticated refusals.** The report gains `unauthenticatedRefusals`, given only where the
  member is configured: the number of requests this instance has refused since start before their
  token was accepted, at the gateway-wide cap or at authentication. It is of no scope, since no
  request it counts was tied to one, and every caller that reads the line reads it. `gateway
  posture`, run apart from a serving instance, has no count and leaves it out. The line's reason
  gives the gateway-wide cap's value.
- **The filtering.** The line and the member change with nothing of a scope the caller does not reach:
  not its existence, not its key, not its values, and not whether `default` covers it. That is SPEC.md
  §6's rule for `/posture` (served to a caller that does not reach every source). The installation's
  caller, `"unchecked"` and no identity reach every source and read every scope. `gateway posture`, run
  by the operator, reports every scope.

### 6. Several instances (ADR-0035)

- **Per instance, for this release.** Each instance counts the requests it serves. Its state is in its
  memory, and each start begins with every bucket full and nothing in flight. A caller cannot cause a
  start, so it cannot reset its own share.
- **Under N instances,** N instances admit up to N times each limit, the gateway-wide cap's among
  them. An operator running several instances sets each limit divided by N: for a ceiling C across
  N instances, C / N. That operator accepts two costs:
  - under session affinity (ADR-0035: each session is held by the instance that minted it), one
    instance may refuse a scope while another has room;
  - during a hand-over, both instances serve for a while, and each has its full share.
- **Signing quota.** The instances on one database sign with one key (ADR-0035). The signing calls
  that the limits allow add up across instances, and an operator sizes the sum against the key
  service's quota.
- **I2 was not taken for this release.** Counting in the shared database would put a round trip, and
  a row lock, on every counted request of every scope. That is the coupling decision 4 forbids. It
  would also give every scope a new refusal whenever the database is slow, whether the limiter then
  failed open or closed. Shared counting is gateway #593, for v0.41.0, with its own record.

### 7. Compatibility, rollback and the release notes

- **Compatibility.**
  - Without `limits`, every answer, start line and posture report is unchanged.
  - An earlier engine refuses the member by name (`exactlyMembers`), and the version gates it.
  - No receipt, seal, registry line, journal entry or store row changes form. There is no corpus
    family, and neither verifier changes.
  - SPEC.md §6 gains the `429` `gateway-in-flight` of every route, the `429` of `/acquire`, `/act`,
    `/seal` and `/verify`, `/act`'s steps 3a and 8a, and the `request-limits`
    line, the `limits` member and `unauthenticatedRefusals` of `/posture`.
- **Rollback.** Remove `limits` and set the version back. The limits keep nothing in the store, so
  there is nothing to undo.
- **What the release notes must say.**
  - From engine version `44` (`requestLimitsVersion`), a top-level `limits` member sets, for
    each scope identifier, for `"unscoped"`, or by `default`, a request rate (`requestsPerMinute`,
    `burst`), a cap on requests in flight (`inFlight`), and the same for each caller within the scope
    (`perCaller`), beside one gateway-wide cap on the requests not yet tied to a scope
    (`beforeScope`, 1024 when left out). Without it, nothing changes.
  - `/acquire`, `/act` (dry-runs included), `/seal` and `/verify` may answer `429` with `Retry-After`
    and `{"error", "code": "limit_reached", "limit"}`, and `/act` with `"refusedAt": "limit"`. Any
    route may answer `429` `gateway-in-flight` while the gateway-wide cap is full. The sentence is
    fixed, and `Retry-After` comes from the caller's own scope, or from the gateway-wide cap where that
    refused. Nothing is minted, journaled or forwarded for such an answer.
  - The limits are counted by each instance alone, in this release. N instances admit up to N times
    each limit, so an operator running several instances sets each limit divided by N. Shared
    counting is gateway #593 (v0.41.0).
  - `/act` is still `501` on the PostgreSQL kind. Its count applies there once it is served.
  - A delegated request, and a reservation sender, are counted in `"unscoped"`, each by its own sender.
  - `/posture` adds `request-limits` and `limits`, judged over the caller's own scopes, and the count
    of unauthenticated refusals.
  - The limits bound one scope's effect on another. They do not remove it.
  - `perCaller` needs an identity, and a `scopes` key must name a configured scope.

### 8. The build plan

There are two pull requests. Each runs its touched tests only, and CI does the full run. The member is
readable only in the pull request that enforces it, so no inert configuration ever ships. A
security-focused review is done on the second pull request. At most ten mutants are run in each pull
request, each on a safeguard and in a scratch copy, and each must make a named test fail.

1. **L1, the limiter** (`go/limits.go`, unexported, with no configuration and no route).
   - It holds the gateway-wide cap and its count of refusals, the GCRA bucket, the cap, the callers'
     table, give-back on a later refusal, the idle sweep, the refusal when the table is full, and the
     fixed refusal value with its `Retry-After`, all with an injected monotonic clock.
   - Tests:
     - rate and burst;
     - `Retry-After` rounding and its bounds;
     - a refused take leaves the state unchanged;
     - a caller refused by the scope gets its token back;
     - idle entries are dropped, and a full table of busy callers refuses: the 4097th caller is
       refused, never admitted uncounted;
     - the in-flight caps, and their release on every path, a panic among them;
     - isolation: scope A at its rate and at its cap, with requests held inside it and A's mutex held
       by the test, while B's take succeeds. It is asserted by order, with channels, not by timing;
     - the gateway-wide cap: full, it refuses and counts the refusal; a request charged to a scope
       gives its slot back; a request never charged, as an unauthenticated `/verify` is, holds it
       until it is released;
     - `/verify`: a request charged to its caller's scope holds that scope's slots like any other;
     - the fixed sentence: each `limit` answers the same bytes whatever any other scope's state, names
       no scope, and takes its `Retry-After` from the refusing state alone;
     - concurrent take and release under `-race`, which ends with every counter at zero.
   - Mutants:
     - (1) a refused take still counted, caught by the unchanged-state test;
     - (2) the give-back dropped, caught by the token-back test;
     - (3) a full table admits the caller uncounted, caught by the full-table test;
     - (4) every scope's table behind one mutex, caught by the isolation test;
     - (5) a caller's slot not given back on release, caught by the release test;
     - (6) `Retry-After` taken from the scope's bucket when the caller's bucket refused, caught by the
       fixed-sentence test;
     - (7) the gateway-wide cap not checked, caught by the gateway-wide test.
2. **L2, the member, the routes and the report.**
   - The engine version, the parse and every load-time refusal of decision 1, `beforeScope`'s among
     them, and the start line.
   - The gateway-wide cap on the listener, the charge points of decision 2, `/verify`'s among them,
     the answer of decision 3, and the line, the member and the count of decision 5.
   - SPEC.md §6, and a section in `docs/design/engine-config.md`. The section says that each instance
     counts alone in this release, that N instances admit up to N times each limit, that an operator
     running several instances sets each limit divided by N, and that shared counting is #593.
   - Tests:
     - **Load.** Each load-time refusal. Without `limits`, the start output and the posture report
       match the previous release byte for byte.
     - **Isolation, in flight.** Scope A has `inFlight: 1`. A's first `/acquire` runs a source that
       blocks on a pipe the test holds. A's second request is answered `429`, `scope-in-flight`,
       `Retry-After: 1`. Scope B's `/acquire` is answered `200` while A's first request is still held,
       which asserts order, not timing. Only then does the test release A, and A's first request is
       answered `200`.
     - **Isolation, rate.** A's bucket (`burst: 1`) is spent, A is answered `429` `scope-rate`, and B
       is answered `200`.
     - **Decision 6.** With `burst: 2`, two dry-runs and then a write are made. The write is answered
       `429` at `refusedAt: "limit"`, and the journal, the store, the labels and a fake sink are
       unchanged by it.
     - **Nothing receipted.** After a `429` at `/acquire`, the store's lines, the registry and the fake
       sink's count are unchanged, and no session exists.
     - **Reach.** A caller of S and T that names a source of an unreached scope U leaves U's state
       unchanged. An `/act` that names no scope, from a caller that does not reach none, leaves
       `"unscoped"` unchanged.
     - **Delegation.** Two delegated actors for one subject each get their own `perCaller` share in
       `"unscoped"`.
     - **What counts.** A `401` is charged to no scope, and holds its gateway-wide slot alone. A request
       refused after the limit step is counted.
     - **Posture.** A caller of scope A reads the same `request-limits` line and `limits` member, byte
       for byte, whether B's entry exists, changes or is removed.
     - **Gateway-wide cap.** With `beforeScope: 1`, a request of a caller of several scopes is held
       while its body is unread, after its token is read. A second request, with a bad token, is
       answered `401` and not `429` (the slot was given back at the token), and
       `unauthenticatedRefusals` rises by one. With the cap held full, `/publickey` and
       `/publickey/history` answer, and `/registry` and every other route are refused `429`
       `gateway-in-flight`. A client that stalls in its headers holds no slot and is cut at the
       read-header timeout.
     - **`/verify`.** A `/verify` from a caller of one scope at its `inFlight` is answered `429`
       `scope-in-flight` before the store is read; with no identity configured, it holds the
       gateway-wide cap.
     - **The fixed sentence.** For each `limit` a route can answer, the `429` body is the same bytes
       whether B's entry exists, changes or is spent, and `Retry-After` is the refusing state's.
   - Mutants:
     - (8) one limiter shared by every scope, caught by the isolation test;
     - (9) a process-wide mutex held across the request around the limiter, caught by the isolation
       test;
     - (10) the dry-run skipping the limit step, caught by the decision 6 test;
     - (11) step 8a charging a scope the caller does not reach, caught by the reach test;
     - (12) the posture member judged over every scope, caught by the posture test;
     - (13) the `perCaller` load refusal without an identity removed, caught by the load test;
     - (14) the gateway-wide slot taken after the token is read, caught by the gateway-wide cap test;
     - (15) `/verify` left uncounted, caught by the `/verify` test.

### Consequences

- **Good:** one scope's callers can no longer take every other scope's share of the gateway, or of a
  key service's signing quota. ADR-0054's dry-run is bounded as decision 6 requires, and so is
  `/verify`'s walk of the store.
- **Good:** an unauthenticated flood holds at most `beforeScope` requests at once.
- **Good:** without the member nothing changes, and no record or verifier changes with it.
- **Good:** the limiter adds no shared lock and no wait. Its memory is bounded per scope.
- **Bad:** a caller of several scopes has its body read before it is counted.
- **Bad:** under several instances, the configured values are per instance, and the operator divides.
- **Bad:** a request is counted once whatever it costs. An `/act` with a read-back signs twice and
  counts once.
- **Bad:** a scope within its limit still waits at the shared points it waits at today.
- **Bad:** while a flood keeps the gateway-wide cap full, every scope's new arrivals are refused
  before their tokens are read.
- **Revisit when** `/act` is served on the PostgreSQL kind, when shared counting lands (#593,
  v0.41.0), or when a cost weight per request (signing calls) is needed.

### What is not established

- That one scope within its limit adds no delay to another at the gateway's lock, the store's append
  or the signer. The limits bound that delay; they do not remove it. No test with a slow signer is in
  this plan.
- That a flood cannot keep the gateway-wide cap full. Each unauthenticated request holds its slot
  only for its token check, but no test measures the rate that would keep it full.
- That `unauthenticatedRefusals` tells a caller nothing of a scope it does not reach. No request it
  counts was tied to a scope, but the cap's refusals rise with every scope's arrivals while it is
  full.
- That the configured values fit a key service's quota. The operator sizes them, across instances.
- The MCP front's calls. No in-process acquisition path from `go/mcp*.go` was found, so they are taken
  to reach the engine through `/acquire` and to be counted there. The maintainer should confirm this.

## Open questions for the maintainer

The acceptance settled the earlier questions on counting per instance and on `/verify`. These stay
open.

1. **`Retry-After` for a full cap: `1` (recommended) or none.** ADR-0029 sends none where the wait is
   unknowable, but the issue asks for `Retry-After` on every `429`.
2. **The posture `limits` member: give it (recommended) or keep the line alone.** It names the
   caller's own scopes and their values, never another scope's.
3. **The callers' cap: fixed at 4096 (recommended) or configurable.**
4. **The specification side: one sentence (recommended).** judgment-pack-spec's `/act` text could say
   that `/act` may answer `429` `limit_reached`, as text only in the next patch. Otherwise nothing.
5. **Count per request (recommended) or weight by signing calls.**
6. **A per-caller bound across scopes, before the body: not in this record (recommended).** It would
   count requests refused before their scope is known.
7. **Per-scope refusal counts for operators: none in this record (recommended).** The count of
   unauthenticated refusals is given (decision 5). A count per scope would be the later refusal
   journal's, with no stderr line per refusal.
8. **The gateway-wide cap's form: a `beforeScope` member, 1024 when left out (recommended), a member
   that must be given, or a fixed constant.**
9. **A `/verify` from a caller of several scopes: held by the gateway-wide cap (recommended), or
   charged to each scope it reaches.** Its verdict is of every scope, and charging one of them alone
   would be arbitrary.
10. **The unauthenticated refusals: the cap's and authentication's together (recommended), or the
    cap's alone.**
11. **`unauthenticatedRefusals`: given to every caller that reads the line (recommended), or only to a
    caller that reaches every source.**

## Acceptance

Accepted by the maintainer on 2026-11-23, with these conditions, each folded into the decision it
settles:

1. **Per-instance counting, for this release.** N instances admit up to N times each limit, and an
   operator running several instances sets each limit divided by N. Shared counting is gateway #593
   (v0.41.0). The configuration (decision 1), several instances (decision 6), the release notes
   (decision 7) and the build plan's engine-config section (decision 8) say so.
2. **The in-flight cap stands in for connections,** with one gateway-wide cap for the requests not
   yet tied to a scope: before the token is read, and unauthenticated requests. The count of
   unauthenticated refusals is shown in `/posture`, and a later refusal journal relies on it
   (decisions 1, 2, 4 and 5).
3. **`/act` and its dry-runs are counted at steps 3a and 8a,** before any lookup, lock, signing or
   delivery (ADR-0054's acceptance, its second condition). This stands (decision 2).
4. **`/verify` is counted,** under the caller's scope, or under the gateway-wide cap when it is
   reached unauthenticated (decision 2).
5. **The honest statement stays:** the limiter bounds one scope's effect on another; it does not
   remove it (the summary, decision 4, and what is not established).
6. **`/act` is `501` on the PostgreSQL kind;** its count applies there once `/act` is served (context,
   fact 2, and decision 2).
7. **A limiter refusal is `429` with a fixed sentence** that names no other scope and gives no other
   scope's state. `Retry-After` comes from the caller's own scope, or from the gateway-wide cap where
   that refused, alone. The build plan names a test for it (decisions 3 and 8).

## The maintainer's rulings for the build (2026-11-23)

These rulings were made for the second build pull request. Each one is folded into the decision it
changes above, and where this list and earlier text differ, this list holds.

1. **The gateway-wide slot is held only until the token is read,** never across the body or the run.
   The listener's read-header timeout (`listenerReadHeaderTimeout`, 10 seconds) and read timeout
   (`listenerReadTimeout`, 30 seconds, headers and body) already bound a slow client, so no
   configuration member is added for them. A request whose headers have not arrived has no handler
   and holds no slot. One middleware takes the slot and releases what the request holds when its
   handler returns, however it ends; a route gives the slot back at the token (`leaveBefore`). This
   supersedes "holds its gateway-wide slot until it is answered" for a request with a token, and the
   body-unread hold of a caller of several scopes.
2. **`limits.beforeScope`** is the gateway-wide cap, 1024 when left out (open question 8).
3. **`/verify` from a caller of several scopes is charged to every scope it reaches, all or
   nothing** (open question 9). If any one refuses, the request is refused and none is charged.
   `charge` takes every scope and gives back what the others took where one refuses. A gateway with
   no identity reaches every source, and its `/verify` is charged so too.
4. **Every `401` counts as an unauthenticated refusal,** beside the cap's own (open question 10).
5. **The unauthenticated count is given to every `/posture` caller.** It names no scope (open
   question 11).
6. **Every route is under the gateway-wide cap but `/publickey` and `/publickey/history`,** so
   verifiers still answer while the cap is full. `/registry` is under the cap: it serves the whole
   registry log on an open route, the cheapest to flood. The gateway has no `/healthz`.
7. **The engine configuration version is 44** (`requestLimitsVersion`), the newest of
   `engineVersions`.

The review of the limiter added three changes: a second charge of one request is an error the route
answers (`500`, nothing served), not a panic; a full callers' table is swept at most once a second;
and the `callers` sentence says "or a spent bucket".

## More information

Gateway #507; ADR-0054 decision 6 and its acceptance; ADR-0026, ADR-0029, ADR-0035, ADR-0036,
ADR-0037, ADR-0041, ADR-0049, ADR-0050; SPEC.md §6 ("Caller scope identifiers", `/acquire`, `/act`,
`/seal`, `/posture`), §11.5, §11.8; `go/serve.go` (`listenerServer`, the `/acquire`, `/act` and
`/seal` handlers, `fail`), `go/caller_scopes.go` (`reachOf`, `callerScopesLine`), `go/posture.go`
(`reachedSources`), `go/engine.go` (`engineVersions`, `engineMembers`).

This record supersedes nothing. It amends nothing: ADR-0054 decision 6 asked for it.
