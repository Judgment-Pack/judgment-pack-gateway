#!/usr/bin/env bash
# CI steps: the pinned runtime, taken from its image by digest; the build; the scenario.
# ADR-0014's acceptance scenario (determination 6), as the test: a witness run from this commit's
# binary on loopback with a test issuer, a trail registered there, an operator's gateway naming it
# in witnessedBy, an acquisition and an action for the trail, and a verifier that starts from the
# record and its receipts alone -- `gateway verify`, then `gateway witness fetch` against the
# released runtime's reader -- and reads the countersigned coverage; then a key the witness does
# not hold, another origin than the statements came from, and the witness stopped
# (go/witness_scenario_test.go). Run from go/.
set -e
# A second runtime pin, beside the Dockerfile's: the image carries 0.21.0, which predates
# `audit verify --witness`, and moving that pin is a release of the image of its own. This one is
# the released binary the scenario reads a witness's chain with, by digest.
WITNESS_READER_RUNTIME=ghcr.io/judgment-pack/judgment-pack:0.30.0@sha256:7e5576e7a515e16568480aa00e60a89deb97f7f3552b23aeda5355a0946da450
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
echo 'witness-scenario: the pinned runtime, taken from its image by digest'
docker create --name witness-reader "$WITNESS_READER_RUNTIME"
docker cp witness-reader:/jpack "$tmp/jpack"
docker rm witness-reader
version=$(printf '%s' "$WITNESS_READER_RUNTIME" | sed -n 's/^ghcr\.io\/judgment-pack\/judgment-pack:\([0-9][0-9.]*[0-9]\)@sha256:[0-9a-f]\{64\}$/\1/p')
[ -n "$version" ] || { echo "the runtime pin is not <version>@sha256:<digest>"; exit 1; }
out=$("$tmp/jpack" version) || { echo "the pinned runtime does not run"; exit 1; }
[ "$(printf '%s\n' "$out" | head -n 1)" = "jpack $version" ] || { echo "the pinned runtime is not $version: $out"; exit 1; }
echo 'witness-scenario: build'
go build -buildvcs=false -o "$tmp/gateway" .
echo 'witness-scenario: a verifier that starts from the record reads the countersigned coverage'
GATEWAY_SCENARIO_RUNTIME="$tmp/jpack" GATEWAY_SCENARIO_GATEWAY="$tmp/gateway" go test -count=1 -run '^TestReceiptNamesTheWitnessScenario$' -v .
