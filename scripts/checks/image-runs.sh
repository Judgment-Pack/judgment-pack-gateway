#!/usr/bin/env bash
# CI step: The image runs the adapters and the runtime, and starts the engine as built
set -e
docker run --rm --entrypoint /usr/local/bin/adapter-mcp engine:ci --check 2>&1 | grep -q 'usage: adapter-mcp' || { echo "adapter-mcp does not run"; exit 1; }
docker run --rm --entrypoint /usr/local/bin/adapter-airbyte engine:ci 2>&1 | grep -q 'usage: adapter-airbyte' || { echo "adapter-airbyte does not run"; exit 1; }
docker run --rm --entrypoint /usr/local/bin/adapter-http engine:ci 2>&1 | grep -q 'usage: adapter-http' || { echo "adapter-http does not run"; exit 1; }
docker run --rm --entrypoint /usr/local/bin/adapter-document engine:ci positional 2>&1 | grep -q 'usage: adapter-document' || { echo "adapter-document does not run"; exit 1; }
# The runtime reports the pinned release's version, as the signer
# and as a platform user: it is everyone's to run. The first line
# of its output is compared literally, and the run must succeed.
version=$(sed -n 's/^FROM ghcr\.io\/judgment-pack\/judgment-pack:\([0-9][0-9.]*[0-9]\)@sha256:[0-9a-f]\{64\} AS runtime$/\1/p' Dockerfile)
[ -n "$version" ] || { echo "the Dockerfile's runtime pin names no version"; exit 1; }
for user in 65532 65601; do
  out=$(docker run --rm --user $user --entrypoint /usr/local/bin/jpack engine:ci version) || { echo "the runtime does not run as uid $user"; exit 1; }
  [ "$(printf '%s\n' "$out" | head -n 1)" = "jpack $version" ] || { echo "uid $user: the runtime is not $version: $out"; exit 1; }
done
# The engine, as built and as its own user, reports the image's custody
# and the reaping of a source's descendants as enforced (gateway posture),
# and its report is one line for each of the five protections.
out=$(docker run --rm engine:ci posture) || { echo "gateway posture does not run in the image"; exit 1; }
[ "$(printf '%s\n' "$out" | wc -l)" -eq 5 ] || { echo "gateway posture does not report five protections: $out"; exit 1; }
printf '%s\n' "$out" | grep -Eq '^container-custody +enforced ' || { echo "the image does not report its own custody: $out"; exit 1; }
printf '%s\n' "$out" | grep -Eq '^descendant-reaping +enforced ' || { echo "the image does not report a source's descendants reaped: $out"; exit 1; }
