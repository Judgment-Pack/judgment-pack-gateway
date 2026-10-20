#!/usr/bin/env bash
# CI step: A rendering agrees with its published schemas
# A record the rendering adapter writes in this run, and the examples
# beside the schemas, are what the schemas describe, and the schemas
# refuse a list of broken variants of each (docs/design/rendering.md).
# The record of a PDF is made with the stand-in for a rendering program
# that lies beside the examples, since the runner has none. The
# validator is the one the setup step installs (testdata/attachments/schema-requirements.txt).
set -e
export GOWORK=off
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
go build -buildvcs=false -o "$tmp/adapter-render" ./cmd/adapter-render
"$tmp/adapter-render" < ../testdata/rendering/examples/refund-decision.request.json > "$tmp/render-record.json"
"$tmp/adapter-render" --renderer ../testdata/rendering/standin-renderer < ../testdata/rendering/examples/refund-decision.pdf.request.json > "$tmp/render-pdf-record.json"
python3 ../testdata/rendering/check_schema.py "$tmp/render-record.json" "$tmp/render-pdf-record.json"
