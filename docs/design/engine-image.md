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
from the pinned bases, that the core inside it agrees with the corpus it carries, that the
gateway binary holds exactly its three capabilities, and that the adapters and the catalog are
where the configuration expects them.

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

The default is **2**: it is the only one of the three under which the boundary this design
claims survives. **1** is available, and it is outside the isolation claim: the engine refuses
a host-socket configuration unless the operator sets `hostRuntime: "accepted"` in the engine
configuration, the startup log says in one line that the Airbyte adapter now holds host
authority equivalent to the signer's, and the deployment is then one in which the seed's
protection rests on the host, not on this design — a seed held in a hardware module or a key
service the host cannot read is what makes that acceptable. **3** is not pursued: it would make
the adapter's behaviour depend on which connector language it met.

MCP servers are pulled the same way, as pinned container images run as sibling processes, or
reached as remote servers over HTTPS with a token the adapter holds. `npx`-style installation
at run time is refused: nothing runs that was not pinned by digest.

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

The release workflow publishes the image digest, a software bill of materials for both modules,
and the runtime pin, in the same `checksums.txt` that names the binaries. An operator pins the
image by digest and can name the tagged state it was built from, as [CONTRIBUTING.md](../../CONTRIBUTING.md#tags)
already says of the binary.

## What is deliberately not in the image

- No identity provider. The engine verifies tokens against a key file the operator supplies;
  it issues none.
- No connector code. Connector images and MCP servers are pulled at run time by digest.
- No policy, pack, or decision. Packs live in the application's own project; the runtime
  evaluates what it is handed.
- No network listener beyond the configured `listen` address, which is loopback unless an
  identity provider is configured.
