---
status: accepted, 2026-10-17
date: 2026-10-17
deciders: maintainer
---

# A decision policy may hold the value at a pointer to an array or an object, and an array to a length (`shape`), at engine configuration version 10, so that a closed policy admits one shape of request; a shaped pointer reaches its container for `closed` and covers nothing under it

Issue #267, decided A by the maintainer on 2026-10-17. A closed policy
([ADR-0016](0016-a-policy-fixes-a-value-and-closes-the-argument-set.md)) holds the values it names
and that nothing else is present; it does not hold the container type of an ancestor, so it can
admit more than one shape of request. This record states the design the pull request for #267
builds; the maintainer accepts or amends it.

**Checked against** gateway `main` at `1cfc3fd` (v0.16.0).

## Context and problem statement

**What exists.** A policy's `bind` and `fix` name arguments by RFC 6901 pointers, and `closed`
refuses every member and element no such pointer reaches. A pointer is resolved as RFC 6901
resolves it: a token on an object names a member, so `/updates/0` resolves in an array to its
first element and in an object to its member named `"0"`. `closed` walks an object or an array on
the way to a named pointer, either one.

**What that leaves open.** The review of #265 found that the worked Azure DevOps policy, which binds
`/updates/0/value` and fixes `/updates/0/op`, `/updates/0/path` and `/updates/1`, admits the
request with `updates` as an array and the same request with `updates` as an object of members
`"0"` and `"1"`. Both pass `bind`, `fix` and `closed`, and both are sent. ADR-0016 §5 states the
limit, the worked policy states it, and a regression test records the admission. On 2026-10-14 the
maintainer deferred a member to the output dialects of the Judgment Exchange
(judgment-pack-spec#142), which need exact request shapes. On 2026-10-17 the maintainer decided A:
a `shape` member.

## Decision drivers

- A closed policy can admit exactly one shape of request, and the operator states that shape.
- The request's bytes are what is sent. The engine compares and fills nothing in (ADR-0016 §3).
- A policy without the new member, and every configuration file written before, mean exactly
  what they meant.
- The receipt format, the verifier and the corpus stay as they are.
- A refusal names the check and a pointer, never a value.
- No schema language in the engine (ADR-0016, option C).

## Considered options

- **A. A `shape` member beside `fix` and `bind`.** At a pointer, the value is an array or an
  object, and for an array a maximum length.
- **B. A form of `fix`.** `fix` gains a value form that names a container type without its
  members (`{"type": "array", "maxLength": 2}`). Declined. It has fewer members, but `fix` would
  mean two things, a fixed value and a held shape, and a fixed value that happens to be such an
  object could no longer be fixed.
- **C. Not at all.** Keep the documented limit and its regression test. A policy that must hold a
  container binds or fixes the whole value. Declined. It puts the whole write back into the pack
  or the policy, which ADR-0016 set out to avoid.
- **D. `closed` infers the type.** A container through which every named pointer continues with
  a decimal index would be held to an array. Declined. It changes what version-9 policies admit,
  and it guesses an intention the operator did not write.

## Decision outcome

Chosen: A, as the maintainer decided. It is one more check of the same kind, through the pointers
and the parser the policy already has, and it leaves the meaning of `fix` alone.

### 1. The member

- **`shape`**, optional: an array of entries. Each entry is one of exactly two forms:

  | Form | Members |
  | --- | --- |
  | an object | `{"pointer": <pointer>, "type": "object"}` |
  | an array | `{"pointer": <pointer>, "type": "array", "maxLength": <integer from 0 to 524288>}` |

  `pointer` is an RFC 6901 pointer into the request's `arguments`, held as `bind`'s and `fix`'s
  are. `type` is the string `array` or `object`, in that spelling. An array's entry always carries
  `maxLength`, and an object's never does, so each type has one form. `maxLength` is an integer
  from 0 to 524288. 524288 is the value budget an action's arguments are parsed within
  (`maxArgumentValues`), so no array longer than that can arrive and a larger bound would hold
  nothing more. A policy has no other count to bound it by. An entry with a member beyond its form,
  or without one of its members, is refused. So is a pointer that is not a pointer, a `type` of any
  other value, an array without its bound, a bound out of range or not an integer, and an object
  with a bound.
- **One pointer, one rule.** A pointer shaped twice is refused, to one form or to two. A pointer
  both fixed and shaped is refused: the fixed value holds its own type and length, so a shape
  beside it adds nothing or admits nothing. A pointer both bound and shaped is the operator's to
  write: the fact's type is the record's, and the shape holds it. A shaped pointer under a fixed or
  a bound one, or the reverse, is the operator's to write, as in ADR-0016. `"shape": []` holds
  nothing.
- **The version.** `shape` is a member of engine configuration version 10, under the rule that a
  member change moves `engineVersion`. A file of an earlier version that carries it is refused by
  name (`shape is a version-10 member; engineVersion 9 has no shape`), `"shape": []` included. A
  version-10 file without it loads as before. A version-9 policy means in a version-10 file what
  it means in a version-9 one, and has the same digest, since the digest is over the policy object
  and not over the file. `connect` writes no policy. It keeps the policy of an entry it replaces as
  written, never lowers a version, and raises none for this member.

### 2. The check

At the existing `policy-bind` step, after the bindings and the fixed values and before `closed`:
bind, fix, shape, closed. The first that fails is the refusal, and nothing is sent.

- **Each entry.** The value at the pointer must be there and be an array for `array`, or an object
  for `object`. For an array, its number of elements must be at most `maxLength`. An absent value
  is not the container, by `fix`'s rule that an absent argument is not the value: the engine fills
  nothing in, and a policy that shapes a container requires it. The refusals are
  `argument "<pointer>" is not of the shape the policy holds it to` and
  `argument "<pointer>" holds more elements than the policy's shape allows`. Neither states a
  value: not the type, not the bound, not the length, not anything of the request's.
- **The value at the pointer, and nothing above it.** The pointer is resolved as `fix`'s is, by
  RFC 6901. An entry holds the container its pointer names. A container above it is held only by
  an entry of its own. A container needs one when every pointer through it continues with a
  decimal index token. A container that some `bind`, `fix` or `shape` pointer continues through with
  any other token is already an object, since each of those pointers must resolve.

### 3. What `closed` does with a shaped pointer

A shaped pointer **reaches** its container and **covers** nothing.

- The container at a shaped pointer is not refused, and the objects and arrays on the way to it
  are walked as they are on the way to a pointer of `bind` or `fix`.
- No member or element under it is reached by the shape. Each one is reached only as ADR-0016's
  rule reaches it: covered by a pointer of `bind` or `fix`, or on the way to one, or itself a
  container another entry of `shape` names. A pointer of `bind` or `fix` that names the shaped
  container covers it and everything under it, as before.

So a closed policy whose only pointers are shapes admits only arguments in which every value is a
container a shape names, of its type, or a container on the way to one, and nothing else: with one
entry, `/updates` an array, it admits `{"updates": []}` alone, since an element under it is reached
by nothing and an absent `updates` is not the container. A closed policy with neither `bind`, `fix`
nor `shape` admits only an empty `arguments` object, or none, as ADR-0016 states.

### 4. The digest

`action.policy` is the digest of the policy as configured, `shape` in it as any member is. Entries
in another order, or `"shape": []` written where the member could be left out, give another digest
for the same checks, as ADR-0016's `fix` and `"closed": false` do. ADR-0016 §4, and `SPEC.md`
§1.2a after it, gave a reason why the canonical form of a policy without `fix` is its RFC 8785
form too: such a policy "holds no number". A shape's `maxLength` is a number. Each one is an
integer from 0 to 524288, which RFC 8785 writes as `canon` does, in decimal digits, so the
conclusion stands and the reason is now that the policy's only numbers are such bounds. The
receipt carries the digest only, so `verify`, `gateway conform` and the released vectors are
unchanged.

### 5. What it establishes, and what it does not

With a closed policy, an action receipt that names it establishes, in addition to ADR-0016 §5,
that each value a shape names was a container of its type, and each shaped array no longer than its
bound, at the moment of the check. A closed policy that shapes each container through which its
pointers continue only by an index admits one shape of request: the values it names, in containers
of the types it names, and nothing else.

ADR-0016 §5's limit, that a closed policy does not hold the container type of an ancestor, now
holds for a container no entry of `shape` names, and only for that. A shape holds a container's
type and an array's length. It does not hold an object's members or their number, nor an
element's value: `bind`, `fix` and `closed` do that. As before, nothing here establishes how the
target interprets a request it is sent.

### 6. The worked example

The Azure DevOps policy in [engine-config.md](../design/engine-config.md), "The write-back
platforms", gains one entry: `/updates`, an array of at most two elements. With `/updates/1` fixed,
and so required, `updates` is an array of exactly two. `/updates/0` is an object, since `op`,
`path` and `value` resolve in it. The arguments are an object by the executor's rule. The policy
then admits one request for a given record: the request the example shows, up to the order of an
object's members and the spelling of its JSON. The object with members `"0"` and `"1"` in place of
the array is refused at `policy-bind`, and nothing is sent. The test that recorded its admission
keeps it under ADR-0016's policy without a shape, in a version-9 file, and shows its refusal under
the policy with one.

### Consequences

- Good, because a closed policy can admit exactly one shape of request, and the worked Azure
  DevOps policy does.
- Good, because the request's bytes are what is sent and committed to, and the receipt, the
  verifier and the corpus are unchanged.
- Good, because a policy without the member, and every earlier configuration file, mean what they
  meant, with the same digest.
- Bad, because the operator names each container whose type is to be held. The engine infers
  none (option D), so a closed policy without a shape still admits either container where its
  pointers continue only by an index.
- Bad, because in a closed policy an array's elements are already held by the pointers that reach
  them, so `maxLength` adds a bound mostly where the array is covered whole or the policy is not
  closed. The form requires it all the same, so that an array has one form.
- Bad, because the configuration's version moves again, and a file that uses the member is refused
  by every engine before this one.
- Bad, because a shape refusal says that the pointer is shaped, as a fix refusal says that the
  pointer is fixed.
- Revisit when the output dialects of the Judgment Exchange (judgment-pack-spec#142) need a shape
  this cannot state: an object's number of members, a scalar's type, a least length. Also revisit
  when the engine reads a server's captured input schema at `/act`, or when the receipt is to carry
  the policy rather than its digest.

### How this sits with earlier records

- Of [ADR-0016](0016-a-policy-fixes-a-value-and-closes-the-argument-set.md), determinations 1
  and 2 are extended, and nothing is superseded. The closed set of a policy's members gains
  `shape`, a version-10 member. `policy-bind` also holds the shapes, after the fixed values and
  before `closed`. `closed`'s reach gains the shaped pointers, which reach their containers and
  cover nothing. §5's limit holds for a container no shape names, and only for that: a closed
  policy that shapes each container its pointers continue through only by an index admits one
  shape of request. §2's closed policy with neither `bind` nor `fix` admits only an empty
  `arguments`, or none, when it has no `shape` either (§3 above). §4's "holds no number" becomes
  "its only numbers are a shape's `maxLength`" (§4 above). §6's worked example is rewritten in
  engine-config.md, and its admission of the object spelling is kept as a regression under the
  policy without a shape. ADR-0016 itself is not edited: an accepted record is immutable
  ([README](README.md#adding-a-record)), and its index row carries the annotation naming this
  record.
- [ADR-0011](0011-hold-a-write-to-its-decision.md) and
  [ADR-0012](0012-hold-a-write-to-a-signed-record.md) are unchanged beyond what ADR-0016 records.
- [ADR-0007](0007-the-engine-serves-the-adapters-it-ships.md)'s `services` still takes the next
  version when it is built.

## More information

- `SPEC.md` §1.2a (`policy`); [the engine's configuration](../design/engine-config.md) and
  [the executor](../design/executor.md), step 11; [SECURITY.md](../../SECURITY.md).
- `go/decision_policy.go` (`parseDecisionPolicy`, `holdToPolicy`, `unreachedArgument`); the tests
  in `go/act_policy_shape_test.go` and `go/write_platforms_test.go`.
- Issue #267; pull request #265 and its review; judgment-pack-spec#142.
- Material-decision categories: public-surface (the policy grammar, engine configuration version
  10).
