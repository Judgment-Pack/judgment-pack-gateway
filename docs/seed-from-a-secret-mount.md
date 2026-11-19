# A seed from a read-only secret mount

`serve` refuses a seed file that isn't a regular file owned by the gateway's own user and
readable by it alone ([README](../README.md), [SECURITY.md](../SECURITY.md)). Some container
platforms deliver a secret as a file on a read-only mount, owned by another user and readable by
everyone in the container (mode `0444`). The gateway refuses such a seed: "seed file is not owned
by the gateway's own user". The refusal is deliberate. A seed any process in the container can read
is a seed any source running there can read too.

The supported practice is to **copy the seed at start into a private file the gateway's user owns**,
and point the configuration's `seed` at that copy.

## The copy step

Run it in the container's entrypoint, as the gateway's own user, before `serve`:

```sh
#!/bin/sh
set -eu
umask 077
install -d -m 0700 /run/gateway                      # a memory-backed directory (tmpfs)
install -m 0600 /secrets/gateway.seed /run/gateway/gateway.seed
exec gateway serve --config /etc/gateway/engine.json # "seed": "/run/gateway/gateway.seed"
```

- **Where the copy goes.** Put it in a directory on a memory-backed filesystem that only the
  gateway's user can enter, so the seed is never written to the image or to a persistent disk.
  `umask 077` makes every file the script creates private from the moment it exists, so the copy
  is never readable by others, even briefly, and `install -m 0600` states the final mode.
- **Who runs the step.** The gateway's user runs it, so the copy is owned by that user without a
  `chown`. Never run it as root and hand the file over afterwards.
- **The mounted file.** Leave the mounted file where it is, and never point `seed` at it. Where
  the platform lets you, make the mount readable only by the gateway's user, and don't give a
  source's user access to the directory it is mounted in.
- **Rotation.** A new secret version reaches the gateway at its next start. A rotation of the
  signing key itself is `gateway rotate-key`, as for any seed.

## Fetching the seed instead of mounting it

Where the platform's secret store has an API, the entrypoint can read the secret into the same
private file instead of copying a mounted one. Write it through `install` or under `umask 077` in
the same directory, with the same rules. The gateway's user needs read access to that one secret
and nothing else.

## What this does not change

The seed is still a file on the gateway's host, readable by the gateway's user, and every rule
SECURITY.md states for it still holds. A signer that never holds the private key, where an
external key service signs, is a separate change (#431).
