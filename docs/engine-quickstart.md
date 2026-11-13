# Quickstart: a running engine from the published image

This takes the engine image a release publishes ([releasing.md](releasing.md)) to a running
engine with one platform, and shows what `gateway posture` says about the source sandbox. All of
it is synthetic: the platform `records` has one live source, an `http` binding to
`records.example`, a name reserved for examples, with a placeholder token, and no source is
called. It needs a Linux host on `amd64` or `arm64` with Docker and `sudo`, since the files the
engine reads must belong to the image's users.

## The image

Pin the image by the digest the release states. The release notes' "Engine image" section gives
it, and it is the SHA-256 of the release's `judgment-pack-gateway_<version>_engine-image.index.json`,
which `checksums.txt` names and the release attests ([releasing.md](releasing.md#verifying-a-download)):

```sh
IMAGE='ghcr.io/judgment-pack/judgment-pack-gateway:0.28.0@sha256:<digest>'
```

The tag is for the reader; Docker pulls by the digest and refuses other bytes. `0.28.0` is the
first release that publishes the image.

## The files

The engine reads one configuration, a catalog entry for each binding it names, a credentials file
for each operation, and a state directory that holds the seed, the store and the registry. Each
is a host directory mounted into the container:

```sh
mkdir -p engine/etc engine/catalog engine/secrets engine/state
cd engine
cat > catalog/records.json <<'EOF'
{"bindingVersion":"1","platform":"records","operations":{"live":{"shape":"http","endpoint":"https://records.example/api","paths":["/health"],"methods":["GET"],"bearer":"API_TOKEN","checkPath":"/health","licence":"MIT"}}}
EOF
printf '%s' '{"API_TOKEN":"example-token"}' > secrets/records.json
binding="records@sha256:$(sha256sum catalog/records.json | cut -d ' ' -f 1)"
cat > etc/engine.json <<EOF
{
  "engineVersion": "23",
  "authority": "gateway:quickstart",
  "seed": "/var/lib/engine/gateway.seed",
  "store": "/var/lib/engine/store",
  "registry": "/var/lib/engine/registry.jsonl",
  "decisionRecords": "/var/lib/engine/decisions",
  "listen": "127.0.0.1:8787",
  "catalog": "/srv/catalog",
  "adapters": "/usr/local/bin",
  "measureSandboxAtStart": true,
  "platforms": {
    "records": {
      "binding": "${binding}",
      "credentials": {"live": {"file": "/run/secrets/records.json"}},
      "user": "engine-1"
    }
  }
}
EOF
```

The binding is named by the digest of its catalog entry, as every binding is
([engine-config.md](design/engine-config.md#bindings)). `measureSandboxAtStart` (engine version
23) makes the start refuse a host on which the source's sandbox cannot be enforced, which the
next steps show.

Then the owners the engine holds each file to. The signer runs as `engine` (uid 65532) and owns
the state directory alone. The platform's source runs as `engine-1` (uid 65601), the user the
configuration names, and owns its credential alone, in a directory that is root's. The
configuration and the catalog are root's:

```sh
chmod 0600 secrets/records.json
chmod 0700 state
sudo chown -R root:root etc catalog secrets
sudo chown 65601:65601 secrets/records.json
sudo chown 65532:65532 state
mounts=(-v "$PWD/state:/var/lib/engine" -v "$PWD/etc:/etc/engine:ro" -v "$PWD/catalog:/srv/catalog:ro" -v "$PWD/secrets:/run/secrets:ro")
```

The seed is made once, by the operator, and its public key is what a verifier pins:

```sh
docker run --rm "${mounts[@]}" "$IMAGE" keygen /var/lib/engine/gateway.seed
```

## Posture under Docker's default seccomp profile

```sh
docker run --rm "${mounts[@]}" "$IMAGE" posture --config /etc/engine/engine.json
```

Each line is one protection: its name, its state, and the reason. A source's line gives the
source, its class, the sandbox mode its policy selects, the backend and the state. Under Docker's
default profile:

```
operator-program-confinement  not-enforced   the gateway does not confine the programs it starts: …
records/live adapter workspace-write none not-enforced preset=custom sandbox-not-enforced: no usable filesystem sandbox backend
```

The image carries bubblewrap at `/usr/bin/bwrap` ([design/engine-image.md](design/engine-image.md),
"The source sandbox"), and it needs to make a user namespace as the source's user. Docker's
default profile refuses that to a container without `CAP_SYS_ADMIN`. On the Docker this was
written against (28.1), the profile also refuses Landlock's calls, so neither backend can be had.
With `measureSandboxAtStart` on, the engine says so and does not start:

```sh
docker run --rm --init "${mounts[@]}" "$IMAGE"
```

```
start: measureSandboxAtStart: source records/live: workspace-write is not enforced under none: sandbox-not-enforced: no usable filesystem sandbox backend; the engine does not start (gateway posture --config, given this configuration, reports each source)
```

Without the member, or at engine version 22 or earlier, the engine starts here and serves.
`gateway posture` then reads as above, and each launch of the source refuses with
`sandbox-not-enforced` ([engine-config.md](design/engine-config.md), "When the sandbox cannot be
had").

## A running engine

The sandbox needs a syscall filter that lets the source's user make a user namespace. The
broadest choice is no filter, `--security-opt seccomp=unconfined`. That also lifts the filter from
the signer: its boundary is its own user and its three capabilities, not seccomp, but the
container then has no syscall filter at all. A narrower choice is a profile of your own: Docker's
default with `clone`, `clone3` and `unshare` allowed to make a user namespace, and the `mount`,
`umount2` and `pivot_root` bubblewrap makes inside it. This guide ships no such profile and has
not tested one, and what a profile allows is the operator's to review. `--init` gives the engine
an init, which reaps an orphaned descendant of a source ([SECURITY.md](../SECURITY.md)).

```sh
docker run -d --name engine --init --security-opt seccomp=unconfined "${mounts[@]}" "$IMAGE"
docker logs engine
```

```
start: measureSandboxAtStart: measured records/live workspace-write bubblewrap enforced
gateway on http://127.0.0.1:8787 (authority gateway:quickstart, key …)
```

The engine serves. Its posture, from inside the container, as the user it runs as:

```sh
docker exec engine /usr/local/bin/gateway posture --config /etc/engine/engine.json
```

```
operator-program-confinement  enforced       filesystem write-policy checks ran as the configured source users; …
records/live adapter workspace-write bubblewrap enforced preset=custom filesystem mounts are read-only outside the declared writable directories (launcher /usr/bin/bwrap); …
```

`listen` is a loopback address inside the container, so a published port does not reach it.
Reaching the engine from another host takes engine version 19's `listen`, an `identity` and a
TLS-terminating front ([design/engine-image.md](design/engine-image.md), "What is deliberately not
in the image").

## Reading the sandbox's state

- **`enforced`**: bubblewrap holds the filesystem write boundary the policy selects. Network
  access is unchanged, and a local service reached over a Unix socket is outside the boundary.
- **`partial`**: a backend runs, with measured limits the reason names. Under Landlock,
  file-content writes, truncation and directory changes are restricted; metadata changes such as
  `chmod`, and connections to local sockets, are not. Under bubblewrap, a listening socket was
  seen that no mask hides. A source in this state launches, and `measureSandboxAtStart` lets the
  engine start. A host whose security module restricts unprivileged user namespaces (Ubuntu's
  AppArmor setting from 24.04, for one) may pass bubblewrap over for Landlock even under
  `seccomp=unconfined`. That case is not shown here.
- **`not-enforced`**: no backend holds the selected mode. Every restricted launch of the source
  refuses, before anything is started, and with `measureSandboxAtStart` the engine does not
  start. The one exception is a policy that selects `danger-full-access`: the operator chose no
  boundary, and the source launches unrestricted.

`/posture` over HTTP answers the same entries with a fixed sentence in place of the helper's
words ([engine-config.md](design/engine-config.md#what-the-engine-reports-posture)).

## Stopping it

```sh
docker stop engine && docker rm engine
```

The state directory keeps the seed, the store and the registry for the next start. The
configuration's other members are in [design/engine-config.md](design/engine-config.md), and the
bindings the image carries are in [catalog/](../catalog/README.md).
