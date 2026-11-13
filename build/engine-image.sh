#!/usr/bin/env bash
# The engine image as a release publishes it (docs/design/engine-image.md,
# Provenance; docs/releasing.md; docs/adr/0030): one build of the Dockerfile
# for every platform the release names, into an OCI archive, and the push
# of that archive, every manifest by its digest. The release workflow and
# CI (scripts/checks/image-platforms.sh) run this same script, so that what
# CI builds before a release is built by the invocation the release uses.
#
#   build/engine-image.sh build <dir>
#       builds from the working tree into <dir>/engine-image.tar (an OCI
#       archive) and writes <dir>/engine-image.index.json, the bytes of the
#       image index, whose SHA-256 is the image digest, and
#       <dir>/engine-image.digest, that digest as sha256:<hex>. Refuses an
#       index that is not one manifest for each platform, and nothing else.
#       RELEASE_VERSION, when set, is the tag the gateway reports and the
#       index's version annotation.
#   build/engine-image.sh push <dir> <repository>:<tag>
#       copies every manifest of <dir>/engine-image.tar to the registry with
#       its digest unchanged, then reads the tag back and refuses unless it
#       names <dir>/engine-image.digest. REGISTRY_AUTH_FILE, when set, is a
#       containers-auth.json file the copy reads its credential from; the
#       credential is never an argument. TLS is verified for every registry
#       but one on this host's loopback, which CI pushes to.
set -euo pipefail

# Each pinned by the digest of its manifest index, as the Dockerfile's bases
# are, so that a builder or copier is never a tag's latest. The builder
# carries its own emulators for the stages that run on the target
# platform, so a host needs no binfmt_misc registration of its own.
BUILDKIT=docker.io/moby/buildkit:v0.23.2@sha256:ddd1ca44b21eda906e81ab14a3d467fa6c39cd73b9a39df1196210edcb8db59e
SKOPEO=quay.io/skopeo/stable:v1.20.0@sha256:47853bb9fb24202af9110531ebd6e43c5f97701254ca290596640290d17942f4
# The platforms a release publishes, and the only ones: the Dockerfile's
# bases and the runtime pin each carry both.
PLATFORMS=linux/amd64,linux/arm64
SOURCE=https://github.com/Judgment-Pack/judgment-pack-gateway
HERE="$(cd "$(dirname "$0")" && pwd)"

refuse() {
  echo "engine-image: $*" >&2
  exit 1
}

build() {
  [ "$#" -eq 1 ] || refuse "usage: engine-image.sh build <dir>"
  local out=$1 revision builder
  mkdir -p "${out}"
  out="$(cd "${out}" && pwd)"
  revision="$(git rev-parse HEAD)"
  # A builder of this build's own, on the pinned BuildKit, removed after:
  # the docker driver writes neither an OCI archive nor more than one
  # platform.
  builder="engine-image-$$"
  docker buildx create --name "${builder}" --driver docker-container --driver-opt "image=${BUILDKIT}" --bootstrap >/dev/null
  trap 'docker buildx rm --force "'"${builder}"'" >/dev/null 2>&1 || true' EXIT
  local annotations=(
    --annotation "index:org.opencontainers.image.source=${SOURCE}"
    --annotation "index:org.opencontainers.image.revision=${revision}"
  )
  if [ -n "${RELEASE_VERSION:-}" ]; then
    annotations+=(--annotation "index:org.opencontainers.image.version=${RELEASE_VERSION}")
  fi
  # No provenance or SBOM attestation manifests in the index: the release
  # attests the index digest itself, as it attests the archives
  # (release.yml), and the index holds the platforms' images and nothing else.
  docker buildx build --builder "${builder}" \
    --platform "${PLATFORMS}" \
    --provenance=false --sbom=false \
    --build-arg "RELEASE_VERSION=${RELEASE_VERSION:-}" \
    "${annotations[@]}" \
    --metadata-file "${out}/engine-image.metadata.json" \
    --output "type=oci,dest=${out}/engine-image.tar" \
    .
  python3 -I "${HERE}/engine_image.py" "${out}" "${PLATFORMS}"
}

push() {
  [ "$#" -eq 2 ] || refuse "usage: engine-image.sh push <dir> <repository>:<tag>"
  local out ref digest tls pushed
  out="$(cd "$1" && pwd)"
  ref=$2
  digest="$(cat "${out}/engine-image.digest")"
  [[ "${digest}" =~ ^sha256:[0-9a-f]{64}$ ]] || refuse "${out}/engine-image.digest is not a digest"
  [ "sha256:$(sha256sum "${out}/engine-image.index.json" | cut -d ' ' -f 1)" = "${digest}" ] || refuse "engine-image.index.json is not the index ${digest} names"
  case "${ref}" in
    *@*) refuse "${ref} names a digest; the push is to a tag" ;;
    127.0.0.1:*/*:*) tls=false ;;
    */*:*) tls=true ;;
    *) refuse "${ref} is not <registry>/<repository>:<tag>" ;;
  esac
  local mounts=(-v "${out}:/image:ro") auth=()
  if [ -n "${REGISTRY_AUTH_FILE:-}" ]; then
    mounts+=(-v "${REGISTRY_AUTH_FILE}:/auth.json:ro")
    auth=(--authfile /auth.json)
  fi
  # Every manifest as it is, by its digest: a copy that would have to
  # change one (recompress, convert) fails rather than push another image.
  docker run --rm --network host "${mounts[@]}" "${SKOPEO}" \
    copy --all --preserve-digests --dest-tls-verify="${tls}" "${auth[@]}" \
    oci-archive:/image/engine-image.tar "docker://${ref}"
  # What the tag now names, as the registry serves it.
  pushed="sha256:$(docker run --rm --network host "${mounts[@]}" "${SKOPEO}" \
    inspect --raw --tls-verify="${tls}" "${auth[@]}" "docker://${ref}" | sha256sum | cut -d ' ' -f 1)"
  [ "${pushed}" = "${digest}" ] || refuse "${ref} names ${pushed}, not the image built, ${digest}"
  echo "pushed ${ref}@${digest}"
}

command=${1:-}
[ "$#" -gt 0 ] && shift
case "${command}" in
  build) build "$@" ;;
  push) push "$@" ;;
  *) refuse "usage: engine-image.sh build <dir> | push <dir> <repository>:<tag>" ;;
esac
