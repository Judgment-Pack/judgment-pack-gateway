---
status: proposed
date: 2026-11-23
deciders: maintainer
---

# Each scope, and each caller within it, has a request rate and an in-flight limit, counted by each instance at the first step that knows the scope

> **Number.** 0057 is a placeholder, assigned at merge. An open pull request holds 0056.

> **Summary.**
>
> - **Chosen:** a top-level `limits` member (engine configuration version
>   `<engine-version: assigned at merge>`), keyed by scope identifier, with `"unscoped"` for the
>   sources of none, and a `default` for every scope it does not name. Each entry gives a token bucket
>   (`requestsPerMinute` and `burst`), an in-flight cap (`inFlight`), and the same three for each
>   caller within the scope (`perCaller`). Without the member, nothing changes, byte for byte.
> - **Counted:** every `/acquire`, `/act` and `/seal` request, `/act` dry-runs included (ADR-0054
>   decision 6). Each request is counted once, to one scope its caller reaches, at the first step that
>   knows that scope. That step comes before the body is read when the caller's token reaches one scope
>   alone. Otherwise it comes right after the route's own scope step. It is always before any session
>   lookup, key lock, source run, signing or delivery.
> - **Answered:** `429`, `Retry-After`, `{"error", "code": "limit_reached", "limit"}`, and
>   `"refusedAt": "limit"` on `/act`. Nothing is minted, journaled, stored, admitted or sent to the
>   receipt sink.
> - **Isolated:** each scope's state is its own, in an immutable map built at start, and is taken with
>   atomics and that scope's own mutex. No request waits on a limit. At most 4096 callers are held for
>   each scope, and a new caller is refused, never served uncounted, when every held caller is busy.
> - **Per instance:** each instance counts its own requests (ADR-0035). Under N instances, a scope may
>   send up to N times its configured values. `/posture` says so.
> - **Reported:** a `request-limits` line, and a `limits` member listing the effective values, both
>   judged over the scopes of the sources the caller reaches alone (ADR-0041).

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

Four facts in the code shape the answer:

1. **A connection has no scope.** The gateway learns the caller from its token. It learns the scope
   from the token only when the token reaches one scope alone. A caller that reaches several, the
   installation's caller among them, names the scope in the body: in `/acquire`'s `source` and
   `scope`, in `/act`'s `scope` (ADR-0054), and in `/seal`'s `scope` or its session. An idle
   keep-alive connection is of no scope. Go's HTTP/1.1 server serves one request at a time on a
   connection. A "connection limit" per scope is therefore a limit on the scope's requests **in
   flight**, and this record calls it that.
2. **`/act` is not served on the PostgreSQL kind.** It is refused `501` at `refusedAt: "storage"`
   before the body is read (`go/serve.go:2801`). Under ADR-0035's several instances, the routes that
   sign are therefore `/acquire` and `/seal`, until `/act` is served there.
3. **A delegated request reaches the sources of none alone** (`go/caller_scopes.go:192`, `reachOf`),
   and so does a reservation sender (§11.8). A delegated scoped write waits for the RFC 0030 scope
   binding (ADR-0054 decision 1).
4. **A limit bounds a share; it removes no shared point.** Within its limit, a scope's admitted
   requests still take the gateway's lock, the store's append and the signer, as today. The limiter
   adds no shared point of its own (decision 4), and it bounds how many of one scope's requests can
   be queued at the existing ones.

## Decision drivers

1. **Unchanged by default.** A configuration without the member answers, starts and reports as it
   does today, byte for byte.
2. **Isolation.** A scope at its limit adds no lock, no wait and no state to another scope's request.
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

From engine configuration version `<engine-version: assigned at merge>`, a configuration may carry a
top-level `limits` member:

```json
"limits": {
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
- **The defaults.** Without `limits`, nothing is counted, and every answer, start line and posture
  report is as today, byte for byte. Without `default`, a scope that `scopes` does not name is
  unlimited. A member an entry leaves out is unlimited.
- **The load-time refusals.** Each one names the member and the form and quotes no value. The gateway
  will not start on any of the following:
  - the member under an earlier version: `limits is a version-<n> member; engineVersion <m> has no
    limits`;
  - a `limits` with neither `default` nor `scopes`, or with any other member;
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

- **Counted:** `/acquire`, `/act` and `/seal`. Each one runs a source, signs a receipt or a seal, or
  walks the decision-record directory and signs. `/act` is counted whether it writes or is a dry-run
  (ADR-0054 decision 6).
- **Not counted:**
  - `/posture`, which reads the configuration and signs nothing.
  - `/verify`, whose verdict covers the whole store and which is served only to a caller that reaches
    every source (ADR-0036 decision 7, ADR-0037). It is of no one scope.
  - The open routes, `/registry`, `/publickey` and `/publickey/history`, which have no caller and no
    scope. They are bounded by `openRouteWriteTimeout`.
  - The issuing host's endpoints, `/delegation/credential` and `/delegation/revoke`, whose caller is a
    host, not a scope.
  - A witness's `/witness/*`.
- **Not requests:** an `/act`'s read-back is part of its `/act` and is counted once with it. Start-time
  sealing (`sealOpenAtStart`) and the commands run while the gateway is stopped (`seal-open`,
  `retain`, `store rotate`, `remove-scope`) are not requests.

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
  would let a caller spend a scope it does not reach.

**The step, on each route.**

| Route | Caller reaches one scope | Caller reaches several, or every source |
|---|---|---|
| `/acquire` | after authentication, before the body is read | after the source's scope check (§6: "before the trail, the publisher policy, the grant, the admission, a delegation's count or the source"), and before them |
| `/act` | step 3a: after `storage`, before step 4 reads the members | step 8a: after step 8 holds `scope` to the caller's reach, before step 9 looks up the label. A request naming no scope is charged to `"unscoped"` only where the caller reaches none |
| `/seal` | after authentication, before the body is read | after the members are read, where the request names `scope` (held to the reach by `narrowedTo`). Otherwise after the session is found and held to the reach, before the seal is signed or delivered |

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
- A request refused **before** the limit step is not counted. That covers a `401`, a `404` method,
  `/act`'s pre-body `scope-identifier` and `storage`, and a malformed body.
- A request refused **after** the limit step stays counted. It took its token and holds its slot until
  its answer is written. Examples are a session refusal, a decision-policy refusal, a dry-run's
  outcome, and a throttled source.

**The slot is released** when the handler returns, after the answer is written, whatever the answer.
It is released by a deferred call, so a panic that the server recovers releases it too.

### 3. The `429` answer

- **Status:** `429`.
- **`Retry-After`:** delta-seconds.
  - For a refused bucket, the whole seconds until the bucket that refused holds one request, rounded
    up. That is at least 1, and at most 60 under the smallest rate allowed.
  - For a full in-flight cap, `1`. A slot frees when any of the scope's answers is written, which the
    gateway cannot foresee, so `1` is a hint and not a promise.
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
    in flight; send it again after Retry-After` (decision 4).
  No sentence names a scope identifier, a caller or a number.
- **On `/act`,** the body adds `"refusedAt": "limit"`, at step 3a or 8a.
- **The order of the checks:** the callers' table (decision 4), the caller's cap, the scope's cap, the
  caller's bucket, then the scope's bucket. The first one that refuses answers. Everything taken before it is given back, so a caller
  over its own share does not spend its scope's tokens.
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
- **No global lock on the path.** A request of scope A touches only A's map entry, A's atomics and A's
  mutex. It never touches B's state.
- **Bounded memory.** A scope holds at most 4096 callers (`maxLimitedCallers`), roughly 100 bytes each.
  - A caller whose bucket is full and who has nothing in flight is **idle**. A fresh entry would be
    the same, so dropping it loses nothing.
  - A new caller that finds the table full sweeps the idle entries.
  - If none is idle, the request is refused `429` with `limit: "callers"` and `Retry-After: 1`. It is
    not served uncounted (driver 6). Only that scope, which has `perCaller` set, is affected.
- **What isolation does not give.** A scope within its limit still shares the gateway's lock, the
  store's append and the signer with every scope, as today (context, fact 4). The limit bounds how many
  of one scope's requests can wait at them: at most its `inFlight`.

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
- **The filtering.** The line and the member change with nothing of a scope the caller does not reach:
  not its existence, not its key, not its values, and not whether `default` covers it. That is SPEC.md
  §6's rule for `/posture` (served to a caller that does not reach every source). The installation's
  caller, `"unchecked"` and no identity reach every source and read every scope. `gateway posture`, run
  by the operator, reports every scope.

### 6. Several instances (ADR-0035)

- **Per instance.** Each instance counts the requests it serves. Its state is in its memory, and each start
  begins with every bucket full and nothing in flight. A caller cannot cause a start, so it cannot reset its own share.
- **Under N instances,** a scope may send up to N times each configured value. An operator who wants a
  ceiling C across N instances configures C / N, and accepts two costs:
  - under session affinity (ADR-0035: each session is held by the instance that minted it), one
    instance may refuse a scope while another has room;
  - during a hand-over, both instances serve for a while, and each has its full share.
- **Signing quota.** The instances on one database sign with one key (ADR-0035). The signing calls
  that the limits allow add up across instances, and an operator sizes the sum against the key
  service's quota.
- **I2 was not taken.** Counting in the shared database would put a round trip, and a row lock, on
  every counted request of every scope. That is the coupling decision 4 forbids. It would also give
  every scope a new refusal whenever the database is slow, whether the limiter then failed open or
  closed. A shared count stays possible as a later record, alongside the live rotation across
  instances (#537).

### 7. Compatibility, rollback and the release notes

- **Compatibility.**
  - Without `limits`, every answer, start line and posture report is unchanged.
  - An earlier engine refuses the member by name (`exactlyMembers`), and the version gates it.
  - No receipt, seal, registry line, journal entry or store row changes form. There is no corpus
    family, and neither verifier changes.
  - SPEC.md §6 gains the `429` of `/acquire`, `/act` and `/seal`, `/act`'s steps 3a and 8a, and the
    `request-limits` line and the `limits` member of `/posture`.
- **Rollback.** Remove `limits` and set the version back. The limits keep nothing in the store, so
  there is nothing to undo.
- **What the release notes must say.**
  - From engine version `<engine-version: assigned at merge>`, a top-level `limits` member sets, for
    each scope identifier, for `"unscoped"`, or by `default`, a request rate (`requestsPerMinute`,
    `burst`), a cap on requests in flight (`inFlight`), and the same for each caller within the scope
    (`perCaller`). Without it, nothing changes.
  - `/acquire`, `/act` (dry-runs included) and `/seal` may answer `429` with `Retry-After` and
    `{"error", "code": "limit_reached", "limit"}`, and `/act` with `"refusedAt": "limit"`. Nothing is
    minted, journaled or forwarded for such an answer.
  - The limits are counted by each instance alone. Under several instances, a scope may send up to the
    number of instances times its configured values.
  - A delegated request, and a reservation sender, are counted in `"unscoped"`, each by its own sender.
  - `/posture` adds `request-limits` and `limits`, judged over the caller's own scopes.
  - `perCaller` needs an identity, and a `scopes` key must name a configured scope.

### 8. The build plan

There are two pull requests. Each runs its touched tests only, and CI does the full run. The member is
readable only in the pull request that enforces it, so no inert configuration ever ships. A
security-focused review is done on the second pull request. At most nine mutants are run, each on a
safeguard and in a scratch copy, and each must make a named test fail.

1. **L1, the limiter** (`go/limits.go`, unexported, with no configuration and no route).
   - It holds the GCRA bucket, the cap, the callers' table, give-back on a later refusal, the idle
     sweep and the refusal when the table is full, all with an injected monotonic clock.
   - Tests:
     - rate and burst;
     - `Retry-After` rounding and its bounds;
     - a refused take leaves the state unchanged;
     - a caller refused by the scope gets its token back;
     - idle entries are dropped, and a full table of busy callers refuses;
     - concurrent take and release under `-race`, which ends with every counter at zero.
   - Mutants:
     - (1) a refused take still counted, caught by the unchanged-state test;
     - (2) the give-back dropped, caught by the token-back test;
     - (3) a full table admits the caller uncounted, caught by the full-table test.
2. **L2, the member, the routes and the report.**
   - The engine version, the parse and every load-time refusal of decision 1, and the start line.
   - The charge points of decision 2, the answer of decision 3, and the line and member of decision 5.
   - SPEC.md §6, and a section in `docs/design/engine-config.md`.
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
     - **What counts.** A `401` is not counted. A request refused after the limit step is counted.
     - **Posture.** A caller of scope A reads the same `request-limits` line and `limits` member, byte
       for byte, whether B's entry exists, changes or is removed.
   - Mutants:
     - (4) one limiter shared by every scope, caught by the isolation test;
     - (5) a process-wide mutex held across the request around the limiter, caught by the isolation
       test;
     - (6) the dry-run skipping the limit step, caught by the decision 6 test;
     - (7) step 8a charging a scope the caller does not reach, caught by the reach test;
     - (8) the posture member judged over every scope, caught by the posture test;
     - (9) the `perCaller` load refusal without an identity removed, caught by the load test.

### Consequences

- **Good:** one scope's callers can no longer take every other scope's share of the gateway, or of a
  key service's signing quota. ADR-0054's dry-run is bounded as decision 6 requires.
- **Good:** without the member nothing changes, and no record or verifier changes with it.
- **Good:** the limiter adds no shared lock and no wait. Its memory is bounded per scope.
- **Bad:** a caller of several scopes has its body read before it is counted.
- **Bad:** under several instances, the configured values are per instance, and the operator divides.
- **Bad:** a request is counted once whatever it costs. An `/act` with a read-back signs twice and
  counts once.
- **Bad:** a scope within its limit still waits at the shared points it waits at today.
- **Revisit when** `/act` is served on the PostgreSQL kind, when a shared count across instances is
  asked for, or when a cost weight per request (signing calls) is needed.

### What is not established

- That one scope within its limit adds no delay to another at the gateway's lock, the store's append
  or the signer. The limits bound that delay; they do not remove it. No test with a slow signer is in
  this plan.
- That the configured values fit a key service's quota. The operator sizes them, across instances.
- The MCP front's calls. No in-process acquisition path from `go/mcp*.go` was found, so they are taken
  to reach the engine through `/acquire` and to be counted there. The maintainer should confirm this.

## Open questions for the maintainer

1. **Per instance (recommended) or shared.** I1 now. A shared count, if wanted, would be its own record,
   beside #537.
2. **`Retry-After` for a full cap: `1` (recommended) or none.** ADR-0029 sends none where the wait is
   unknowable, but the issue asks for `Retry-After` on every `429`.
3. **The posture `limits` member: give it (recommended) or keep the line alone.** It names the
   caller's own scopes and their values, never another scope's.
4. **The callers' cap: fixed at 4096 (recommended) or configurable.**
5. **`/verify`: not counted (recommended).** It is served only to a caller that reaches every source.
   It could have its own bound in a later record.
6. **The specification side: one sentence (recommended).** judgment-pack-spec's `/act` text could say
   that `/act` may answer `429` `limit_reached`, as text only in the next patch. Otherwise nothing.
7. **Count per request (recommended) or weight by signing calls.**
8. **A per-caller bound across scopes, before the body: not in this record (recommended).** It would
   count requests refused before their scope is known.
9. **A count of refusals for operators: none in this record (recommended).** It would be a later
   metrics surface, with no stderr line per refusal.

## More information

Gateway #507; ADR-0054 decision 6 and its acceptance; ADR-0026, ADR-0029, ADR-0035, ADR-0036,
ADR-0037, ADR-0041, ADR-0049, ADR-0050; SPEC.md §6 ("Caller scope identifiers", `/acquire`, `/act`,
`/seal`, `/posture`), §11.5, §11.8; `go/serve.go` (`listenerServer`, the `/acquire`, `/act` and
`/seal` handlers, `fail`), `go/caller_scopes.go` (`reachOf`, `callerScopesLine`), `go/posture.go`
(`reachedSources`), `go/engine.go` (`engineVersions`, `engineMembers`).

This record supersedes nothing. It amends nothing: ADR-0054 decision 6 asked for it.
