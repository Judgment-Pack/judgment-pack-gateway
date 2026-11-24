---
status: accepted, 2026-11-24 (E1 to E4 decided by the maintainer on gateway #593; the batch rule, the window bound and the fallback start accepted at review on gateway #621)
date: 2026-11-24
deciders: maintainer
---

# The instances of one PostgreSQL database may count the request limits together: the rate leased from the database in batches, in flight and per caller split by the live instances

> **Summary.**
>
> - **Chosen (ADR-0057's option I2, as the maintainer decided it on gateway #593):** an opt-in
>   `limits.shared: true`, a member of engine configuration version `51` (`sharedLimitsVersion`),
>   valid only on the PostgreSQL kind with `storage.instances: "several"`. Schema version 11 adds
>   `gateway.limit_rates`, one row per limited scope.
> - **Rate:** each scope's bucket is one row of the database, on the database's clock. Each instance
>   leases a batch of up to b requests from it with one statement and admits from what it holds.
>   The refill runs in the background once a batch is down to half. No request sends a statement or
>   takes a row lock, and one scope's refill never waits for another scope's row.
> - **In flight and per caller:** each instance counts alone at ceil(limit/N), where N is the number
>   of live rows of the start lease, read again every 10 seconds and never on a request.
> - **Database unreachable:** each instance counts the rate alone too, at ceil(limit/N). `/posture`
>   says the shared count is unavailable. The first refill that succeeds returns the instance to the
>   shared count.
> - **Without the member, and at engine version 50 and below,** nothing changes, byte for byte, and
>   the `/posture` line is included in that. The gateway-wide cap (`beforeScope`) stays each
>   instance's own.

## Context

ADR-0057 counts each scope's limits per instance (its option I1). N instances on one database
(ADR-0035) therefore admit up to N times each limit, and an operator divides each limit by N.
ADR-0057 turned down counting in the database (I2) for that release because it would put a round
trip and a row lock on every counted request of every scope (decision 4). Gateway #593 asked for a
shared count that adds neither. The maintainer decided its four open questions (E1 to E4) and the
rate's design before the build.

## Decision

### 1. The member (E4)

- `limits.shared` is `true` or `false`. It is a version-51 member. Below 51 it is refused by name,
  true or false: `limits.shared is a version-51 member; engineVersion <m> has no limits.shared`.
- Set `true`, it is refused by name on the filesystem kind and on PostgreSQL with one instance
  (`storage.instances` `"one"` or left out). Those configurations have no count to share.
- `false`, or the member left out, keeps ADR-0057's per-instance count, byte for byte. That covers
  the start line and the `/posture` line.

### 2. The rate

- **The row.** `gateway.limit_rates(scope, tat)`: the scope as the store's scoped tables hold it
  (`none` or `scope:<id>`), and the bucket's theoretical arrival time, in whole microseconds of the
  database's clock since the epoch. The instances share no other clock. Row security is enabled
  and forced, under the store's one scope policy, so a transaction reads and writes only its own
  scope's row. The run-time role holds SELECT, INSERT and UPDATE on the table, and no DELETE.
- **The lease.** One statement holds the scope's row `FOR NO KEY UPDATE NOWAIT`, then reads
  `clock_timestamp()` once the row is held, as the start lease's renewal does. It takes
  k = min(wanted, ⌊(B·T − (max(tat, now) − now)) / T⌋) requests and sets
  `tat = max(tat, now) + k·T`. T is the configured interval, rounded up to the microsecond. B is the
  configured burst. A lease of k is k requests at once against the one bucket ADR-0057 describes,
  and it is taken only where they conform. The statement returns k and how far the bucket's time
  stood ahead of the clock. The refusal's `Retry-After` comes from that answer.
- **The batch rule.** b = ⌈requestsPerMinute / 600⌉, the requests of 100 ms of the rate, kept
  between 1 and 64 and never above the burst. A refill tops the instance's batch up to b, so an
  instance never holds more than b of a scope. The rule is a parameter of this design, not part of
  the configuration: a later release may change it without an engine version only where every
  bound stated below still holds as written.
- **The request path** (`scopeLimiter.take` in `go/limits.go`, `sharedScope.take` in
  `go/limits_shared.go`) decrements an atomic counter of leased requests. When the batch reaches
  half, it hands the scope to the refill with a flag and a send on a buffered channel that never
  waits. With nothing left, it refuses `scope-rate`, as one bucket does. It sends no statement and
  takes no row lock.
- **The refill** runs on one goroutine and a connection of its own, never one of the kind's pool,
  one statement at a time. A row that another transaction holds fails its lease at once with
  55P03. That scope is tried again after 50 ms, and the next scope's refill goes on. A bucket with
  less room than wanted is tried again once it has room. Refill writes are fenced on the instance's
  row of the start lease, as every write of the kind is.

### 3. The bounds

Write N for the live instances, B for the burst, T for the interval, and b for the batch.

- **The rate is never exceeded over time.** Every admitted request spends a request leased from
  the row, and the row admits what one bucket of the configured rate and burst admits. So since any
  moment at which the instances held nothing, they have admitted no more than that bucket would.
- **Over any window of length W,** the instances admit at most B + ceil(W/T) + N·b. The first two terms
  are what the bucket leases over the window. N·b is what the instances held when the window began.
  For example, a scope of 6000 requests a minute (T = 10 ms, so b = 10) with a burst B of 50, on
  N = 3 instances, admits at most 50 + 100 + 3·10 = 180 requests in any one second; one instance
  counting alone admits at most 50 + 100 = 150.
- **Burst.** The shared bucket's burst is the configured B, unchanged, and a batch is part of it.
  At one instant the instances together admit at most B + N·b: the bucket's room plus the batches
  they hold.
- **Under-admission.** One scope's rate may go unadmitted by up to (N−1)·b: the requests the other
  instances leased and have not spent.
- **In flight (E2).** Each instance caps a scope's in-flight requests at ⌈cap/N⌉, so at most
  cap + N − 1 are in flight in all.
- **Per caller (E3).** Each instance counts each caller's rate, burst and in-flight cap at
  ⌈limit/N⌉, so in all at most limit + N − 1 of each member.
- **N is read every 10 seconds** (`sharedInstancesInterval`, the start lease's renewal interval).
  A starting instance counts itself. The others see a new instance, or one whose row expired, at
  their next count. Until then the in-flight and per-caller sums may stand at the earlier N's
  shares for up to 10 seconds.
- **The gateway-wide cap** (`beforeScope`) stays each instance's own. It bounds requests that no
  scope is known for yet, which no shared row could hold.

### 4. The database unreachable (E1)

- **Unreachable** means that a refill, or a count of the instances, failed other than by its row's
  lock. That covers no connection, an error from the database, and no answer within 2 seconds
  (`sharedRefillBound`). The 2 seconds bound the connection, the statements and the commit; the
  statement and lock timeouts are 2 seconds as well. A refill after the instance lost its start
  lease fails its fence, and is unreachable too.
- **While unreachable,** each instance counts the scope's rate alone, from a full bucket at
  ⌈requestsPerMinute/N⌉ and ⌈burst/N⌉. In flight and per caller stay at ⌈limit/N⌉, with N the last
  count. A batch the instance still holds is kept for the shared count's return and is not spent
  meanwhile.
- **`/posture`** says the shared count is unavailable (section 5).
- **Recovery.** A probe every second (`sharedProbeInterval`) counts the instances and refills the
  scopes whose batch is low. Once it succeeds, the instance counts from the shared row again.

### 5. Start lines and `/posture`

- The configuration's start line reads `request limits: <n> of <m> scopes are limited, counted
  together by the instances of this database (limits.shared)`.
- Once the start lease is held and the first batches are leased, a second line reads
  `request limits: counted together by the <N> live instances of this database (limits.shared): …`.
  Where the database did not answer, that line instead says that the shared count is unavailable.
- The `request-limits` posture line keeps its state and its counts. Where ADR-0057 ends it with
  `counted by this instance alone; under several instances each one counts its own`, it ends with
  the bounds of section 3 instead, starting `counted together by the instances of this database
  (limits.shared)`. The serving instance adds `N=<n> live instances`. While the database does not
  answer, the line opens that part with `the shared count is unavailable: the database did not
  answer a refill within 2s, so this instance counts alone at ceil(limit/N) of N=<n>, …`.
  `gateway posture` has no live state and gives the bounds alone.

### 6. The schema and the store's commands

- **Migration.** Schema version 11 (`0011_limit_rates.sql`) makes the table, its check, its key,
  row security and the scope policy, and grants.sql gives the run-time role SELECT, INSERT and
  UPDATE. Like every migration, it is applied by `gateway store migrate` while no instance serves.
  A v0.41.0 instance refuses a database at schema 10, as it refuses one behind any of its
  migrations.
- **Rows.** A row is made, if missing, when an instance shares its count, and is moved only by
  leases. `gateway store remove-scope` removes a scope's row with the scope's other rows. The row
  holds a bucket's time and nothing a record names.
- **The database's clock.** The lease is the one statement besides the start lease's that reads
  the database's clock (`TestThePostgresKindReadsNoDatabaseClock` holds both). Receipt and seal
  times stay the gateway's (ADR-0031, decision 9).

## Consequences

- An operator running several instances sets each limit once, for all of them.
- A refill costs one statement per scope for every b/2 requests admitted on an instance. That is
  at most about 20 statements a second per scope at the highest rate, all off the request path.
- A held or slow row delays only its own scope's refill. That scope refuses `scope-rate` from its
  own batch and never waits.

## What is not established

- The bounds assume that each instance's monotonic clock runs at the database clock's rate.
  Neither drift nor a database clock that steps is modelled.
- A fallback does not divide what is left of the shared bucket. Each instance starts its own bucket
  full at ⌈B/N⌉, so the first second of a fallback may admit up to about B beside what the batches
  had admitted.

## Tests

`TestThePostgresInstancesUnderLimitsSharedHoldOneLimitTogether` starts two gateway services on
one database and drives them together over 1.5 s. With the member they stay within
B + ceil(W/T) + N·b; without it they admit about twice that. The other tests are:

- `TestASharedScopeAdmitsFromItsBatchWithNoRoundTrip`: no request-path round trip.
- `TestAPostgresScopesHeldRowAddsNoWaitToAnotherScope`: a held row.
- `TestAPostgresInFlightCapIsSplitByTheLiveInstances`: 3 each of two, then 5.
- `TestAPostgresSharedCountFallsBackToLimitOverNAndReturns`: the database cut by a proxy, the
  fallback, the posture line and the return.
- `TestLimitsSharedIsRefusedByNameBelow51OnTheFilesystemAndWithOneInstance` and
  `TestLimitsWithoutSharedSayWhatTheySaidAt50`: the configuration and engine version 50.
- `TestAPostgresStoreAtSchemaTenMigratesToTheSharedRates`: the migration.
