# Security policy

## Support status

This is a **reference gateway**, not a hardened deployment. It is pre-1.0, provides no security,
compatibility, or support service-level guarantee, binds localhost, has no authentication or
authorization on its HTTP surface, and runs as a single operator holding a single signing identity.
It must not be used as the sole control for consequential production decisions, and a `/verify` that
answers `ok` must not be read as a statement that the underlying facts are true — see
[Security boundary](#security-boundary).

## Reporting a vulnerability

Do not open a public issue for a vulnerability that could forge a receipt or a seal, cause
verification to miss a session the gateway actually attested, escape the receipt or artifact store,
disclose or recover the signing key, bypass a fail-closed refusal, or otherwise make the gateway
answer `ok` for a store that is not faithful.

Use this repository's [private vulnerability reporting](https://github.com/Judgment-Pack/judgment-pack-gateway/security/advisories/new)
(Security → Report a vulnerability). If that is unavailable, open a minimal non-sensitive issue
asking a maintainer to establish a private channel. Include:

- a minimal synthetic reproduction;
- the affected endpoint or module and the commit;
- expected and actual behaviour;
- likely impact; and
- any suggested mitigation.

Never include real keys, receipts, source responses, credentials, or proprietary data in a report.
Synthetic fixtures only.

## Security boundary

The ceiling is **byte-lineage, not truth**. Everything below describes what the gateway proves and,
more importantly, what it does not.

**The key is the trust root.** The signing key lives in the service. Its disclosure forges
everything — every receipt, every seal, retroactively. There is no defence against a compromised
gateway, and none is claimed.

**Verification is asymmetric** (receipt versions 2 and 3). Receipts and seals are Ed25519 signatures, so
checking one requires only the **public** key. A verifier gains no power to forge by being able to
verify, and needs no trust relationship with the operator beyond holding the right public key. This
replaced an HMAC format in which anyone who could verify could also forge; that format is gone rather
than deprecated, so the symmetric caveat does not survive in a legacy path.

**But the public key itself must arrive out of band.** Fetching a gateway's public key from that same
gateway and then verifying its store proves *internal consistency*, not authenticity — an impostor
serves its own key and its own store, and both agree. The public key has to be pinned through a
channel that does not depend on the party being audited. Nothing in this repository establishes that
channel; a receipt carries a `keyId`, never a key, precisely so that an implementation cannot
accidentally trust the key a store hands it.

**Signing uses Go's standard library `crypto/ed25519`** — vetted and constant-time. An earlier
revision carried a hand-written pure-Python Ed25519 that was explicitly *not* constant time and was
documented as unfit to hold a real key. Retiring the Python removed that caveat rather than
mitigating it, which is the largest security improvement in this repository's history.
`corpus/ed25519-vectors.json` still checks the signature layer against vectors produced by an
independent implementation.

**A seed and a public key are both 32 bytes**, so no length check distinguishes them. Passing one
where the other belongs is not refused — it silently becomes a *different identity*, whose receipts
fail verification with `key-mismatch`. The gateway prints its `keyId` on startup so an operator can
confirm which identity is live.

**An attestation is not an authentication of the source.** A receipt proves the bytes the gateway
retained are the bytes it attested, under a *caller-configured authority label*. It does not prove
that a genuinely-named upstream produced them. A validly attested but fabricated, incomplete, stale,
or misleading source response yields a valid receipt.

**The caller is outside the trust boundary.** A client supplies a session id, a source name, and
arguments — never a receipt. The gateway produces every receipt, which is what keeps a model or agent
structurally out of the proof path: a caller can assert anything, but it cannot manufacture the
gateway's signature.

Because the caller is untrusted, its inputs are constrained where they reach the filesystem. A session
id names a directory under the store and a verifier **discovers** sessions by enumerating that
directory, so session ids are restricted to a flat token
([`SPEC.md` §2a](SPEC.md)) at the HTTP boundary, at `Registry.seal`, and again at `Store.stamp`. A
value that escaped the receipts root would produce genuinely signed receipts that verification could
never enumerate — `/verify` would answer `ok` for a store missing sessions the gateway itself signed,
silently voiding the coverage guarantee in [`SPEC.md` §3](SPEC.md). Treat any input that can steer
where the gateway writes as a vulnerability in this class, not as a configuration mistake.

**Version 3 receipts, the default, commit to arguments under a per-receipt salt** that is returned
in the acquire response and never retained (SPEC.md §1.2a). A party holding only the store learns
nothing about the arguments from the commitment and cannot compare it with another receipt's;
revealing a committed value takes its salt, so whoever holds the salt can reveal that one value
and nobody else can. Who holds it is a matter of transport and custody: this reference delivers
the response over unauthenticated plaintext HTTP on localhost, so the holder is whoever can read
that exchange, and exclusivity to the caller is not something the reference provides. What the
retained artifact itself discloses is the source's affair. `--receipt-version 2` keeps the
version 2 form for a consumer not yet updated, and with it the oracle described next.

**A version 3 acquisition record names the source by the digest of the file the command's first
word resolved to**, resolved once and read before anything is started. It is that file at that
moment: a replacement between the read and the start is not detected, and a file that is not a
regular file is refused rather than opened. A directly executed script is digested as the script;
`python3 fetch.py` is digested as the interpreter, and the script, like every further argument of
the command, is operator configuration the record does not repeat. What the record says is which
program the operator configured, not that the program is honest.

**Version 2's arguments commitment is an equality oracle to callers.** `argumentsDigest` is a deterministic
keyed digest of the canonical arguments, with no per-receipt salt. The keying stops a party that only
holds receipts from brute-forcing a small argument space; it does not stop a party that can also
invoke `/acquire` under the same key, which — since the acquire response carries the complete
receipt — is every caller: such a party can recover another caller's low-entropy arguments by
submitting candidates and comparing digests. Treat arguments as non-secret against the gateway's
caller set. A salted commitment would close this and is a receipt-format change, out of scope for
version 2.

**Sources are operator-configured subprocesses.** The gateway executes what the operator configures
and attests whatever bytes come back. It attaches no transport, authentication, or schema of its own.
Configuring an untrusted command is equivalent to running it.

**A source is started with the environment declared for it, plus `PATH`, and nothing else of the
gateway's.** `--source-env` sets a variable or copies one by name from the gateway's environment
at spawn time; `PATH` is copied unless declared, because it carries no secret and a source that
cannot find a shell is not a source. On Windows, os/exec adds `SYSTEMROOT` to any explicit
environment that lacks it, and that one variable reaches a source there undeclared. The copy-by-
name form is for passing a path through, not a secret: a credential placed in the gateway's
environment is in the signer's memory whatever is declared, and this design does not cover that
configuration — give a source a path to a file its own identity can read.

**On Unix a source runs in a process group led by an anchor**, a process the gateway starts before
the source and reaps only after the group has been killed. A group is addressed by its leader's
pid, and a leader that has been reaped frees a pid another process can take; the anchor holds the
group id until the last kill has been sent, so no kill reaches an unrelated process. Cancelling a
source — on the thirty-second timeout, on overflow, or on the gateway's own shutdown — kills the
source and every descendant still in the group, and the group is killed again after the source is
waited for, since an overflow a descendant writes after the source has exited cancels nothing
os/exec still watches. A descendant that has left the group is not reached: it gets a bounded wait
for its pipe, not the acquisition. On Windows there is no process group; the direct child is
killed and any descendant gets the same bounded wait. The gateway carries its own interrupt to
every source in flight, because a source in its own group no longer receives the terminal's, and
it answers every request in flight before it exits — or, if a request is still open when the
grace (the pipe wait plus ten seconds) expires, aborts it and exits non-zero saying so. The anchor
is this executable's own running image where the kernel exposes it (`/proc/self/exe`); elsewhere
the executable's path is re-opened for each acquisition, so replacing or removing the binary
while the gateway runs is not supported — stop and restart it. The anchor mode is selected by an
internal marker variable and an argument together and requires a pipe on stdin; an ordinary
invocation that inherits the marker refuses to run rather than silently succeed. On Linux a root
gateway asked to run a source as another user must hold `CAP_SETUID`, `CAP_SETGID` and
`CAP_KILL`, and refuses to start without them: a process that can switch but cannot kill could
start the source and never stop it. **`--source-user`** runs a source as another OS
user where the platform has one, with that user's own supplementary groups and none of the
gateway's, and `serve` refuses to start rather than fall back to running the source as the signer
when it cannot switch; a root process stripped of the capability to switch passes the startup
check and fails at its first acquisition, where the operating system's reason is reported. **A
source's stdout is bounded** (`--source-max-output`, one mebibyte by default) and its stderr is
bounded and truncated: a source that crosses the stdout bound is killed, its acquisition fails, and
nothing it wrote is retained. **The seed is opened once and judged as the file that was opened** —
a regular file, on Unix also owned by the gateway's own user and readable by nobody else — before
it is read through that same descriptor, so the file checked is the file loaded, and a file larger
than a seed file can be is refused rather than read in part. A Unix seed that fails is refused at
startup with the `chmod` to run. What owner and mode do not see: an access-control list that
grants another user read access, which macOS honours before the mode bits; an operator who grants
one has opened the seed, and nothing here notices. Windows checks that the seed is a regular file
and says the rest is the filesystem's. **On Unix, descriptors the launcher left open are marked
close-on-exec at startup**, enumerated exactly where the kernel lists them (`/proc/self/fd` on
Linux, `/dev/fd` on macOS and the BSDs), so a seed passed as `3<gateway.seed` reaches no source
whatever user or mode protects the file. Where neither listing exists the sweep runs by number up
to the hard limit, capped, and misses a descriptor opened above a limit that was lowered
afterwards — a last resort on platforms this reference does not test. os/exec on Windows hands a
child only the handles it is told to.

What none of this gives: a source that runs as the gateway's own user, because no `--source-user`
was given, can read what that user can read, including the seed; and a gateway that runs as root,
which `--source-user` requires today, can read the files a source user holds. The separation is
only as strong as the identities the operator gives the two sides. Closing the second gap — a
non-root signer beside per-source users — is the engine's job
([docs/adr/0001](docs/adr/0001-one-engine-four-processes.md),
[docs/design/engine-image.md](docs/design/engine-image.md)), not this reference's.

**The registry closes replay and rollback only relative to a verifier that trusts the gateway's
registry over the store.** The anchor must be fetched from the key holder, not from the store being
checked. A verifier that reads both from the same untrusted place gets no guarantee.

**Not in scope for this reference:** availability or HA, authenticated transport, access control,
multi-tenancy, key rotation or custody, rate limiting, and resistance to a local attacker who can
concurrently rename or replace store ancestors. Run it from a directory whose ownership and write
permissions you control.
