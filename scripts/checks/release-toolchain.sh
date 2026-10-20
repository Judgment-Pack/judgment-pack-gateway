#!/usr/bin/env bash
# CI step: This is the toolchain the release workflow names
set -e
export GOWORK=off
named="$(sed -n "s/^ *go-version: *['\"]\{0,1\}\([0-9][0-9.]*\)['\"]\{0,1\} *\$/\1/p" .github/workflows/release.yml)"
[ -n "$named" ] && [ "go$named" = "$(go env GOVERSION)" ] || { echo "release.yml names Go ${named:-nothing}, and this job runs $(go env GOVERSION)"; exit 1; }
