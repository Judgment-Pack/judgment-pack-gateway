# Contributing

This repository is the reference implementation of the gateway **and** the home of
`SPEC.md`, which is normative. When the binary and the specification disagree, the
specification is right and the binary has a bug — including when the binary is the
older of the two.

That inversion is the reason for most of what follows: a change here can alter what
a receipt means to someone who never runs this code.

## Before opening a pull request

```bash
cd go
gofmt -l .            # must print nothing
go vet ./...
go test ./...
go build -trimpath -o gateway . && ./gateway conform   # the frozen corpus is the arbiter
```

CI runs the same four on Linux, macOS and Windows against Go 1.26. `gateway conform`
matters most: `corpus/` is frozen, and a change that makes it pass differently has
changed the format, whatever the diff looks like.

Tests here are grouped by what they defend, and a change should land in the group it
belongs to rather than in whichever file is nearest:

- `conformance_test.go` — the corpus vectors
- `service_test.go` — the HTTP surface's ordinary behaviour
- `probes_test.go` — malformed, hostile and boundary input
- `ceremony_test.go` — SPEC.md §5a's consumer ceremony, executable: each step a
  consumer performs between a verdict and acting on the bytes, refusal legs
  included
- `teeth_test.go` — the properties the format exists to have, tested by trying to
  violate them

A change to canonicalization, signing, sealing or verification wants a test in the
last group, written as an attack rather than as an example. "It still works" is not
evidence that tampering still fails.

## Changing SPEC.md

Describe the change in an issue first, and say which of these it is:

- **A clarification** — the implementations already agree and the text did not say
  so. Cheap, and welcome.
- **A normative change** — a conforming implementation would have to change. Say
  what a receipt signed before the change means afterwards, and whether an existing
  verifier keeps working.

Do not change `SPEC.md` and the implementation in the same commit without saying
which one led. A specification edited to match a binary is a changelog, not a
specification.

`go/AMBIGUITIES.md` is closed and stays closed: it is the record of what a
clean-room second implementation could not determine from the text alone. If you
find a new ambiguity, it is an issue and a `SPEC.md` fix, not a new entry there.

## The signing path

`store.go`, `serve.go` and `verify.go` hold the seed, the receipt chain and the
verifier. A subtle mistake in any of them is silent: signatures still verify,
sessions still seal, and the guarantee is gone.

- Never commit a seed, a private key, or a store containing either. `corpus/TEST-SEED`
  and `corpus/TEST-PUBLIC-KEY` are test vectors and are the only key material that
  belongs in the tree.
- A change that touches what is signed, or the order it is canonicalized in, is a
  normative change to `SPEC.md` §1 whether or not the text moves.
- The verifier must keep grading a store it did not produce. Anything that makes
  verification depend on state only the serving process holds has removed the point
  of the verifier.

Vulnerabilities go to the process in [SECURITY.md](SECURITY.md), not to a public
issue or pull request.

## Tags

A tag (`v0.1.0`, …) names a reviewed state of this repository — the binary,
the specification, and the corpus that arbitrates between them — so a
consumer pinning the gateway by digest can name the tagged state its digest
was built from, instead of a moving branch or a local checkout. Tags are
never moved or reused. `receiptVersion` is the *format's* version and moves
independently: a tag names a snapshot of everything, the format version
names what a verifier accepts.

## Scope

This repository stays one Go binary and its specification. The gateway serves,
verifies, canonicalizes and mints identities; it does not decide anything, and it
does not grow a client library — a consumer's helper belongs in that consumer's
language and repository, reaching this one over the wire.

What the gateway attests is deliberately narrow: byte lineage from a named key
holder. A change that would let a receipt assert that its contents are *true*, or
that an action was *authorized*, is out of scope no matter how convenient.

## Sign-off and license

Contributions must be signed off with `git commit --signoff`, certifying the
Developer Certificate of Origin 1.1: <https://developercertificate.org/>.
Contributions are licensed under Apache-2.0.
