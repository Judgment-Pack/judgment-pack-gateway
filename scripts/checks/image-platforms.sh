#!/usr/bin/env bash
# CI step: The release's own build of the image: both platforms, pushed by digest, run as pulled
# build/engine-image.sh is what the release runs (release.yml). Here it
# builds linux/amd64 and linux/arm64 from this commit, as the release
# does, and pushes the archive, every manifest by its digest, to a
# registry on this runner's loopback -- never a public one -- reading the
# tag back as the release does. The amd64 image is then pulled by that
# digest and run: it reports the version it was stamped with, and its
# custody, which needs the gateway's file capabilities to have come
# through the archive and the push. The arm64 image is built and its
# entry in the index held to its platform; it is not run here. Each
# platform's filesystem, arm64's with amd64's, is held to what the design
# states by the check the release runs before its push
# (build/engine-image.sh check, .github/image_checks.py): pulled by its
# manifest's digest, created and exported, never executed.
set -e
out="$(mktemp -d)"
registry=""
cleanup() {
  [ -z "${registry}" ] || docker rm -f "${registry}" >/dev/null
  rm -rf "${out}"
}
trap cleanup EXIT
RELEASE_VERSION=v0.0.0-ci build/engine-image.sh build "${out}"
build/engine-image.sh check "${out}"
registry="$(docker run -d -p 127.0.0.1::5000 docker.io/library/registry:3.0.0@sha256:6c5666b861f3505b116bb9aa9b25175e71210414bd010d92035ff64018f9457e)"
port="$(docker port "${registry}" 5000/tcp | head -n 1 | sed 's/.*://')"
for _ in $(seq 1 30); do
  curl -fsS "http://127.0.0.1:${port}/v2/" >/dev/null 2>&1 && break
  sleep 1
done
build/engine-image.sh push "${out}" "127.0.0.1:${port}/engine:ci"
digest="$(cat "${out}/engine-image.digest")"
pulled="127.0.0.1:${port}/engine@${digest}"
reported="$(docker run --rm --platform linux/amd64 "${pulled}" version)"
[ "${reported}" = "gateway v0.0.0-ci" ] || { echo "the pushed image reports ${reported}, not gateway v0.0.0-ci"; exit 1; }
posture="$(docker run --rm --platform linux/amd64 "${pulled}" posture)"
printf '%s\n' "${posture}" | grep -Eq '^container-custody +enforced ' || { echo "the pushed image does not report its own custody: ${posture}"; exit 1; }
docker image rm "${pulled}" >/dev/null
echo "the release's build of ${digest} pushes by digest and runs as pulled"
