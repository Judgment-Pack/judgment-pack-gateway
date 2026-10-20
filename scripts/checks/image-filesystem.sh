#!/usr/bin/env bash
# CI step: The image's unpacked filesystem is what the design states, and its layers give the attribute as stated
# The runtime the image carries is the released binary the Dockerfile
# pins, byte for byte: the same binary is taken from the pinned image
# here, by the digest the Dockerfile names, and handed to the check.
set -e
# Exactly one pin line, spelled as a version tag and a digest.
[ "$(grep -c '^FROM ghcr\.io/judgment-pack/judgment-pack:' Dockerfile)" = 1 ] || { echo "the Dockerfile must name the runtime pin exactly once"; exit 1; }
pin=$(sed -n 's/^FROM \(ghcr\.io\/judgment-pack\/judgment-pack:[0-9][0-9.]*[0-9]@sha256:[0-9a-f]\{64\}\) AS runtime$/\1/p' Dockerfile)
[ -n "$pin" ] || { echo "the Dockerfile's runtime pin is not <version>@sha256:<digest>"; exit 1; }
docker create --name runtime-pinned "$pin"
docker cp runtime-pinned:/jpack runtime-jpack
docker rm runtime-pinned
docker create --name engine-export engine:ci
docker export engine-export > engine-export.tar
docker rm engine-export
docker image inspect engine:ci > engine-config.json
mkdir -p image && docker save engine:ci | tar -x -C image
python3 .github/image_checks.py engine-export.tar engine-config.json . image runtime-jpack
