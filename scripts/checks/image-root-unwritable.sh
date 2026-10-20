#!/usr/bin/env bash
# CI step: Nobody but root may write the root directory
# The root directory is not in an export; what it must be -- root's,
# writable by nobody else -- is held by the act, with a probe every
# identity can run (build/probe.go, built here with the image's own
# pinned builder, mounted read-only, never part of the image): the
# signer and each of the eight platform users are refused at the
# root, and root, as the control, is not.
set -e
docker run --rm --user "$(id -u):$(id -g)" -e HOME=/tmp -e GOCACHE=/tmp/gocache -e GOPATH=/tmp/gopath -v "$PWD":/src -w /src docker.io/library/golang:1.26-bookworm@sha256:9fdc884aacc3bec89b20ffc69f4bb369c78210e3e4f600387b5128b12c199f81 sh -c 'CGO_ENABLED=0 go build -o /src/probe build/probe.go'
# The probe's refusal is its exit 3; under the runner's bash -e a
# failing substitution would end the step first, so it is caught.
for user in 65532 65601 65602 65603 65604 65605 65606 65607 65608; do
  code=0; out=$(docker run --rm --user $user -v "$PWD/probe:/probe:ro" --entrypoint /probe engine:ci /created-$user 2>&1) || code=$?
  echo "uid $user: exit $code: $out"
  if [ "$code" != "3" ] || ! echo "$out" | grep -q 'permission denied'; then echo "uid $user was not refused at the root as stated"; exit 1; fi
done
out=$(docker run --rm --user 0 -v "$PWD/probe:/probe:ro" --entrypoint /probe engine:ci /created-root 2>&1)
echo "root: $out"
echo "$out" | grep -q 'created' || { echo "the probe could not create even as root; it proves nothing"; exit 1; }
# The root directory itself: root's, its group root's, passable by
# everyone and writable by nobody else -- what a refusal alone
# cannot show, since a platform user that owned it could chmod it.
echo "$out" | grep -q 'root uid=0 gid=0 mode=0755' || { echo "the root directory is not root's at 0755"; exit 1; }
