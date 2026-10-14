---
status: accepted, 2026-10-14
date: 2026-10-14
deciders: maintainer
---

# A decision policy may fix an argument to a value and close the argument set, at engine configuration version 9, so that a dispatcher write tool is held to the write its decision means; the engine compares and never fills a value in, and the receipt names the policy by its digest as before

Issue #258. A decision policy's `bind` ([ADR-0011](0011-hold-a-write-to-its-decision.md))
compares an argument with a fact of the record; it has no value of its own and refuses no argument
it does not name. The write-back platforms (#248, #257) brought a tool that this leaves open. This
record states the design the pull request for #258 builds; the maintainer accepts or amends it.

**Checked against** gateway `main` at `73cd57d` (v0.13.1).

## Context and problem statement

**What exists.** A policy holds a write to its record: an outcome among `outcomes`, no handoff,
`packs`, `reviewed`, `requireSignedRecord` ([ADR-0012](0012-hold-a-write-to-a-signed-record.md)),
and `bind`, pairs of RFC 6901 pointers whose two values, one in the request's `arguments` and one
in the record's `inputs.facts`, must be equal as JSON values with their types (`policy-bind`,
[executor.md](../design/executor.md) step 11). An argument no pair names is the requester's.

**What that leaves open.** The remote Azure DevOps MCP server's write tools are grouped
dispatchers, steered by an `action` argument: `wit_work_item_write` creates, updates
(`update`), updates several items at once (`update_batch`) and adds children
([catalog/README.md](../../catalog/README.md)). A policy that binds the work item's `id` and its
revision alone leaves the `action` to the request. `update_batch` writes the items its
`batchUpdates` name, whatever `id` says. A request may also add an operation to `updates` that
changes another field. The decision was about one item at one revision. The write is whatever the
request chose.

**The stopgap.** #257 holds such a tool by binding the whole arguments, the empty pointer, to a
fact in which the record states the whole write (`writeBack`, in
[engine-config.md](../design/engine-config.md), "The write-back platforms", before this record).
That works and stays possible. It costs this: the pack's facts must carry the write member for
member, the state the outcome maps to among them; a pack's author writes the request; and every
change of the vendor's argument shape is a change of the pack.

## Decision drivers

- The request is the party being checked. What it is held to is the operator's configuration
  (ADR-0011).
- The receipt records what the requester asked. The engine sends what was committed to, and
  nothing else (executor.md step 4).
- A policy without the new members, and every configuration file written before, mean exactly
  what they meant.
- The receipt format, the verifier and the corpus stay as they are: the receipt names the policy
  by digest, and a verifier holds no configuration.
- A refusal names the check and a pointer, never a value.

## Considered options

- **A. Two policy members.** `fix`, pairs of a pointer and a value the argument must equal, and
  `closed`, a flag that refuses any argument no pointer of `bind` or `fix` reaches. Compared as
  `bind` compares, at the same step.
- **B. The engine filling values in.** A policy member that sets an argument, or supplies one the
  request left out. Declined. The commitments a receipt carries, `argumentsCommitment` and
  `action.request`, are over what is sent. A request the policy rewrote would have the receipt
  say that the requester asked for what the policy wrote. A requester could also leave a value
  out and have it supplied, and nothing signed would show which was which.
- **C. A schema per tool.** A JSON Schema in the policy, or the server's captured input schema
  enforced at `/act`. Declined. A schema language in the engine is a large surface, with dialects
  and a validator of its own to trust. The captured schema is the vendor's: it changes with the
  server, and it states which shapes the tool accepts, not which write the decision approved.
  Pointers and canonical equality are what `bind` already uses.
- **D. Keep the stopgap alone.** Not declined: binding the whole arguments stays valid, and a
  closed policy with a root binding is exactly it. It is not enough: it puts the write in the
  pack.

## Decision outcome

Chosen: A. It holds a dispatcher to one action and one set of operations, with the request's own
bytes sent unchanged, through the parser and the comparison the policy already has.

### 1. The members

- **`fix`**, optional: an array of `{"argument": <pointer>, "value": <any JSON value>}`. The
  pointer is into the request's `arguments`, an RFC 6901 pointer held as `bind`'s are. The value
  is any value the engine's strict parser reads: integers only, a name given twice refused, so
  every fixed value is in the canonical domain of `SPEC.md` §1.1. An entry with a member beyond
  its two, or without one of them, is refused. So is a pointer that is not a pointer, a pointer
  fixed twice (to one value or to two), and a pointer both fixed and bound, which would hold one
  argument to a value and to a fact at once. Only the identical pointer is refused. A fixed
  pointer under a bound one, or the reverse, is the operator's to write.
- **`closed`**, optional: a boolean, false when absent.
- **The version.** Both are members of engine configuration version 9, under the rule that a
  member change moves `engineVersion`. A file of an earlier version that carries either is
  refused by name (`fix is a version-9 member; engineVersion 8 has no fix`), `"closed": false`
  included. A version-9 file without them loads as before. `connect` writes no policy: it keeps
  the policy of an entry it replaces as written, never lowers a version, and raises none for
  these members.

### 2. The check

At the existing `policy-bind` step, after the bindings and before anything is sent. Nothing else
about the executor's order changes.

- **Each fixed value.** The request's argument at the pointer must exist and be equal to the value
  as a JSON value with its type: the same bytes in the canonical form, as `bind` compares. So the
  string `"2"` never equals the number `2`, the string `"update"` never equals the array
  `["update"]`, and an object's members may come in any order. An absent argument is not the
  value. The refusal: `argument "<pointer>" is not the fixed value`.
- **`closed`.** Every member of the request's `arguments`, at every depth, must be reached by a
  pointer some `bind` or `fix` entry names. A pointer **covers** the value it names and everything
  under it; the empty pointer covers the whole arguments. The arguments object itself is walked
  and never refused. Below it, each value is judged by its pointer:
  - a value a named pointer covers is admitted whole;
  - an object, or an array, whose pointer is a proper prefix, token by token, of a named pointer
    is on the way to it, and is admitted when each of its members, or each of its elements, is
    admitted in turn;
  - any other value is refused: a member or an element no named pointer reaches, and a value on
    the way to a named pointer that is neither an object nor an array.

  **Arrays, exactly.** An element of an array is reached by a pointer to it, its index written in
  decimal with no leading zero (`/updates/0`), or by a pointer that covers the array (`/updates`,
  or any pointer the array lies under). `-` and an index with a leading zero name no element
  (RFC 6901 §4), so they reach none. An array on the way to a named pointer has each element held
  in turn, so an element past those the pointers name is refused: a request cannot add an
  operation. A member's token is its name with `~` written `~0` and `/` written `~1`, the one
  spelling RFC 6901 gives it, so a pointer reaches a member exactly when it resolves to it, and a
  member named `01` or `-` of an object is a member like any other. The refusal names the first
  value refused, in the order the request wrote its members:
  `argument "<pointer>" is reached by no binding`, the pointer made printable and bounded as other
  request text a refusal quotes.

  A closed policy with neither `bind` nor `fix` is valid, and admits only an empty `arguments`
  object, or none.
- **Never a value.** Neither refusal states a value: not the policy's, not the request's, not the
  record's.

### 3. The engine never fills a value in

A request that leaves out a fixed argument, or changes it, is refused, and nothing is sent. The
engine sends the request's arguments as they were committed to. The reason: the receipt records
what the requester asked, and a policy that rewrote the request would make the receipt say the
requester asked for what the policy wrote.

### 4. The digest

`action.policy` is `"sha256:"` and the SHA-256 of the canonical form (`SPEC.md` §1.1) of the
policy object as configured, so `fix` and `closed` change it as any member does. The same policy
spelled in another order has the same digest. Fixed entries in another order, or `"closed": false`
written where the member could be left out, give another digest for the same checks, as
ADR-0011's `"reviewed": false` and ADR-0012's keys do. ADR-0011 determination 3 said the
canonical form of a policy is its RFC 8785 form too, since it holds no number and only fixed ASCII
names. A fixed value may hold integers and member names of any script. The digest stays `canon`'s,
whose order for names outside the Basic Multilingual Plane is not RFC 8785's. `SPEC.md` §1.2a says
so. The receipt carries the digest only, so `verify`'s reading of `action.policy` is unchanged;
`gateway conform` and the released vectors are unchanged.

### 5. What it establishes, and what it does not

With a policy that sets `closed`, an action receipt that names it establishes, in addition to the
policy's other checks, that the request's arguments were exactly those the policy names, each bound
to the record or fixed by the policy, at the moment of the check. With `fix` alone, it establishes
that each argument the policy fixes was the value the policy states, at that moment.

It does not establish that the target interpreted them as intended: what an `action` or an
operation means is the server's, and a server may supply a default for an argument the request
left out, which no check of the request can see. It establishes nothing of anything a policy does
not name when `closed` is false. A closed policy holds the values it names and that nothing else
is present; it does not hold the container type of an ancestor, so an object whose member names
are an array's indexes is read as that array's elements (RFC 6901 reads a numeric token on an
object as a member's name), and a closed policy admits more than one shape of request. As before, nothing here closes the interval between the check and
the commit: a precondition on the target, Azure DevOps' `test` of `/rev`, is what does.

### 6. The worked example

The Azure DevOps policy in [engine-config.md](../design/engine-config.md), "The write-back
platforms", is rewritten on the members. `fix` holds `action` to `update`, the revision test's
`op` and `path`, and the operation that sets the state the outcome maps to. `bind` holds the work
item's `id` and the tested revision to the record's facts. `closed: true` refuses any member or
element no pointer reaches; the request the example shows is one the policy admits, not the only
one (§5).
The record states the item it judged and no write. The whole-arguments binding is replaced there.
It is still valid.

### Consequences

- Good, because a dispatcher tool is held to one action and one set of operations without the
  record stating the write, and the state an outcome maps to can be stated by the operator's
  policy rather than the pack's facts.
- Good, because the request's bytes are what is sent and what the receipt commits to, and the
  receipt, the verifier and the corpus are unchanged.
- Good, because a policy without the members, and every earlier configuration file, mean what they
  meant.
- Bad, because a closed policy must name every argument a client sends. A client that adds a
  harmless member, such as `project`, is refused until the operator names it, and a vendor's new
  argument is refused until the policy names it.
- Bad, because a server that gains an argument with a default changes what a write does without
  any request naming it; `closed` sees only the request.
- Bad, because a policy fixes one value for every outcome it allows, and a platform holds each
  tool to one policy: a tool that is to write one state on approval and another on rejection
  needs a second platform entry, with its own user and credentials.
- Bad, because the fixed values are in the configuration, which the receipt names only by digest:
  a reader needs the configuration to know what an action was held to, as before.
- Bad, because the configuration's version moves again, and a file that uses the members is
  refused by every engine before this one.
- Bad, because a closed refusal quotes a pointer built from the request's member names, bounded
  and made printable as other request text is.
- Revisit when a tool needs an argument held to a set of values, or to a value that depends on the
  outcome; when a policy is to hold a container's shape, an array at a pointer and its length
  (#267); when the engine reads a server's captured input schema at `/act`; or when the receipt
  is to carry the policy rather than its digest.

### How this sits with earlier records

- Of [ADR-0011](0011-hold-a-write-to-its-decision.md), determinations 1 and 2 are extended, and
  nothing is superseded. The closed set of a policy's members gains `fix` and `closed`, both
  version-9 members. The `policy-bind` step also holds the arguments to the values the policy
  fixes and, when it is closed, to the pointers it names. Determination 3's decision stands, the
  digest of the canonical form of the policy as configured; its remark that this form is the
  policy's RFC 8785 form too holds for a policy without `fix` (determination 4 above).
  Determination 5 stands as written: with a policy, `decision` establishes exactly the policy's checks, which now
  may include these. ADR-0011 carries an amendment paragraph beside its `bind` determination that
  points here.
- [ADR-0012](0012-hold-a-write-to-a-signed-record.md)'s member and step are unchanged.
- [ADR-0007](0007-the-engine-serves-the-adapters-it-ships.md)'s `services` still takes the next
  version when it is built.

## More information

- `SPEC.md` §1.2a (`policy`); [the engine's configuration](../design/engine-config.md) and
  [the executor](../design/executor.md), step 11; [SECURITY.md](../../SECURITY.md).
- `go/decision_policy.go` (`parseDecisionPolicy`, `holdToPolicy`, `unreachedArgument`); the tests
  in `go/act_policy_fix_test.go` and `go/write_platforms_test.go`.
- Issues #258, #248; pull request #257.
- Material-decision categories: public-surface, documented-claim, security.
