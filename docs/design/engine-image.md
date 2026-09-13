# Design note: the engine image

**Status: design note, not normative.** How the release described in
[ADR-0001](../adr/0001-one-engine-four-processes.md) is assembled and what runs inside it.

## What the image contains

The `Dockerfile` at the repository root builds it: both modules with CGO disabled, so the
binaries are static, on a base that carries no shell and no libc (distroless static), every
base pinned by the digest of its manifest index as the catalog pins what it names. The three
capabilities the signer needs to switch each adapter to its platform's user and stop it
afterwards — `CAP_SETUID`, `CAP_SETGID`, `CAP_KILL` ([engine-config.md](engine-config.md)) — are
file capabilities on the gateway binary, written in the builder stage by `build/setcap.go` as
the kernel's own attribute, and nothing more: none that reads past permissions, none ambient or
inheritable. Build with BuildKit, Docker's builder since 23.0: the legacy builder copies the
binary between stages without that attribute, and the image it makes cannot switch a user,
which is what CI's capability check exists to catch.

| Path | What | Pinned how |
|---|---|---|
| `/usr/local/bin/gateway` | the core binary from `go/`: `serve`, `verify`, `canon`, `conform`, `keygen`, and the engine's `connect`; owned by `engine`, mode 0700, since it carries file capabilities | built from this repository at the tagged commit |
| `/usr/local/bin/adapter-airbyte` | runs a connector image and reads its record stream | built from `adapters/` at the same commit |
| `/usr/local/bin/adapter-mcp` | an MCP client: live reads and tool calls | same |
| `/usr/share/engine/catalog/` | the binding files ([catalog/](../../catalog/README.md)) | by content; each is referenced by digest from the configuration |
| `/usr/share/engine/corpus/` | the frozen corpus, so `gateway conform` runs inside the image | by content |
| `/etc/passwd` | the signer's user `engine` (uid 65532) and eight platform users `engine-1` … `engine-8` (uids 65601 … 65608), each with a home of its own alone | written at build |

Not yet in the image, and said so here rather than promised: `adapter-http` (the generic
fallback the envelope contract names; not shipped by this release), an `executor` (nothing
performs an action yet), the runtime `jpack` (no runtime pin exists yet), and a container
runtime for the Airbyte connectors and MCP server images (the section below); the adapters
find `docker` or `podman` on the engine's `PATH` or at the path the configuration names, which
in this image means a runtime the deployment provides beside it.

The image carries **no seed, no store, no registry, and no configuration**. All four live on a
volume the operator mounts; the image's command is `serve --config /etc/engine/engine.json`,
and it refuses to start until that file is there. A first run with no seed at the configured
path is the operator's `keygen`, so pinning out of band stays the operator's explicit act. The
platform users are a convention of the image: a configuration names one per platform, and an
operator who needs more derives an image with more; the engine refuses a platform whose user is
root, the signer's, or another platform's, whatever the image carries.

CI builds the image from every commit and never pushes it: what it checks is that it builds
from the pinned bases, that the core inside it agrees with the corpus it carries, and that the
filesystem a container created from the image unpacks to — `docker export`, the runtime's own
unpacking, not a model of the layers, so that what is judged is what runs and a bypass would have
to be the unpacker's own — is what this note states: the gateway binary with exactly its three capabilities (read from the v2
or the v3 attribute, not compared as bytes), mode 0700 and the signer's, reached through
directories that are root's and that nobody else may write, with no link on the way; nothing
else carrying a capability or a set-user-id or set-group-id bit, hard links included; every
home its user's alone at 0700; the adapters, the catalog and the corpus root's, unwritable by
others, reached the same way, the last two byte for byte the checkout's; every home under a root-owned
`/home` that nobody else may write, so no home can be renamed away; every such path passable and
readable by everyone, since the signer and the platform users are not root; the catalog and the
corpus trees exactly the checkout's, nothing more; the users and groups as the engine reads them
— by the first line naming them, a name or an id twice refused, each user's own group primary
and its home under `/home`; the helper that made the homes gone; and the entrypoint and command
from the image's configuration. Two things an export cannot show are held otherwise: the root
directory, which the exporter omits, by the act — neither a platform user nor the signer may
create a top-level path — and the capability attribute's revision and root id, which the exporter
normalises to revision 2, by a scan of the saved image's layer headers for that one attribute:
every entry carrying it, in any layer, must be the gateway with exactly the stated capabilities,
which needs no model of how layers combine, since a later layer cannot make an earlier attribute
more than it was. The
check's own tests hold each invariant with a negative case of its own, one thing wrong per case,
so that no other refusal can mask the one under test. The image is unpacked and run on a
case-sensitive filesystem: a case-folding one, under which two spellings name one directory, is
not supported, and the check does not model it. It then starts the image as built, with no
override, and holds the two launch overrides below to what is stated here.

**Launch overrides.** With every capability dropped (`--cap-drop ALL`) the kernel refuses to
execute the gateway at all — the binary's attribute has the effective bit set, which demands its
permitted set in full, and the bounding set no longer allows it — so the engine never starts and
no refusal of its own is reached; the supported minimum is `--cap-drop ALL --cap-add SETUID
--cap-add SETGID --cap-add KILL`, under which it starts as it does by default. Run as root
(`--user 0`) the engine refuses to start unless the configuration sets `rootSigner: "accepted"`
([engine-config.md](engine-config.md)), and an accepted root signer is not confined to the three
capabilities: it holds whatever the container runtime gives root, which is a deployment outside
this note's claim.

**What is pinned is the inputs, not the bytes.** Two clean builds of the same commit are the
same in content and differ in digest: built files, the account files and the homes carry the
build's timestamps, and the image metadata is not normalised. A release publishes the digest of
one build; the pins are what make a rebuild comparable in content, not identical in bytes. Making
the image reproducible byte for byte — a fixed `SOURCE_DATE_EPOCH` and an exporter that rewrites
timestamps — is a limit accepted here, not a defect: the default builder does not rewrite
timestamps, and the claim this image makes rests on its contents.

## The processes

The container's first process is `gateway serve`, reading the engine configuration
([engine-config.md](engine-config.md)). It is the only process that ever holds the seed.

Adapters are **spawned, never linked**. When a request names a platform, the gateway resolves
its binding to an adapter binary and starts it over the source contract of SPEC.md §6:
canonical arguments on stdin, one JSON result on stdout, thirty seconds. Today's `serve` bounds
the incoming HTTP body at one mebibyte and does not bound a source's output; a bound on adapter
output is part of the next phase, not a property of the current code. The spawn differs from
today's in three ways that the isolation claim depends on: the environment is **empty** except
for the credentials path, the adapter runs under a **distinct OS identity** where the platform
provides one, and the engine has already refused to start if the seed file is readable by that
identity. The adapter reads its secret in its own process and the gateway never sees it. A
connector image for a history read is run by the Airbyte adapter, not by the gateway.

The runtime runs on request as its own process, for evaluation and for the decision-record
half of `verify`. It holds no seed and no credential.

`gateway verify` reads the store and the registry and, with the engine configuration, the
decision records. It needs the public key and nothing else, and it runs the same way outside the
image, on a copy of the store, which is the only way its verdict is evidence
([SPEC.md §5a.3](../../SPEC.md)).

## The container runtime problem

Airbyte connectors are container images. An engine that runs in a container cannot start
another container without help, and the choices are all operational:

1. **A mounted container-runtime socket.** The Airbyte adapter runs connectors as sibling
   containers through the host's runtime. Simple and standard — and it hands the adapter
   process the authority to start any container on the host, with any mount, which is
   authority to read the seed. An adapter holding a rootful daemon socket holds everything the
   signer holds, and a volume mount described as "into the adapter's process only" is a
   description, not a restriction.
2. **A rootless runtime inside the image.** Heavier image; the adapter's own OS identity runs
   connector images nested, with no authority beyond its own.
3. **The connector protocol without containers.** Some connectors are plain Python packages
   and run in-process under a Python interpreter shipped with the image; the Java connectors
   for databases do not.

None of the three ships in the image, and the image is built for **2** arranged beside it,
since it is the only one of the three under which the boundary this design claims survives.
What that arrangement is, stated as the contract it is rather than as a default: a runtime
client binary (`docker` or `podman`, static) at the path the configuration's `runtime` names,
executable by the platform users; a runtime socket that client reaches, belonging to a daemon
that runs **as that platform user** — a rootless daemon started as a service outside the
adapter, since a switched adapter is held to `no_new_privs` and cannot itself gain privilege
through helpers such as `newuidmap` ([engine-config.md](engine-config.md)), whose socket that
platform user alone may reach, and whose subordinate uid and gid ranges — the identities its
containers may take — are disjoint from every other platform's and exclude the signer's, since
a rootless daemon's authority is its user's plus those ranges and a range that overlapped
another platform's identity would reach that platform's credentials; and the adapter's
temporary directory visible to that daemon at the same absolute path, because the adapter
stages a connector's credentials under it and names that path in the mount it asks for — a
daemon in another mount namespace would mount nothing, or something else. The adapter's
temporary directory is its own `TMPDIR`, or `/tmp` when the platform's declared environment
sets none; the engine forwards nothing of its own environment, so a deployment either shares
`/tmp` between the engine and each daemon or sets each platform's `environment.TMPDIR` to the
path it shares. A deployment that provides a client and a socket and not the rest has not
provided a runtime. **1** is available, and it is outside the isolation claim: the engine refuses
a host-socket configuration unless the operator sets `hostRuntime: "accepted"` in the engine
configuration, the startup log says in one line that the Airbyte adapter now holds host
authority equivalent to the signer's, and the deployment is then one in which the seed's
protection rests on the host, not on this design — a seed held in a hardware module or a key
service the host cannot read is what makes that acceptable. **3** is not pursued: it would make
the adapter's behaviour depend on which connector language it met.

MCP servers are pulled the same way, as pinned container images run as sibling processes, and
the adapter speaks to them over stdio — a container's or a command's; a remote server reached
over HTTPS with a token the adapter holds is not in this release, and is future work. `npx`-style
installation at run time is refused: nothing runs that was not pinned by digest.

## What `verify` reads

Inside or outside the image, one command:

```
gateway verify <store> <registry> <authority> --decision-records <dir> < publickey.raw
```

It performs the version 2 verification unchanged, then the version 3 findings
([receipt-v3.md](receipt-v3.md)): every action receipt's citations resolve to receipts in the
store, and for every action receipt some file under the decision-record directory re-digests
to its `decision.recordDigest`. It hashes those bytes and interprets none of them; a
digest-shaped filename satisfies nothing. The verdict is the JSON, never the exit code, as
§5a.2 requires.

## Provenance

No release workflow publishes the image yet: CI builds it from every commit and never pushes it.
When one does, it is to publish the image digest, a software bill of materials for both modules,
and the runtime pin, in the same `checksums.txt` that names the binaries, so that an operator pins
the image by digest and can name the tagged state it was built from, as
[CONTRIBUTING.md](../../CONTRIBUTING.md#tags) already says of the binary. Until then the digest of
a build is what a deployment pins, and this note is what it means.

## What is deliberately not in the image

- No identity provider. The engine verifies tokens against a key file the operator supplies;
  it issues none.
- No connector code. Connector images and MCP servers are pulled at run time by digest.
- No policy, pack, or decision. Packs live in the application's own project; the runtime
  evaluates what it is handed.
- No network listener beyond the configured `listen` address, which is loopback unless an
  identity provider is configured.
