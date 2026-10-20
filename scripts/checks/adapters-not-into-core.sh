#!/usr/bin/env bash
# CI step: No adapters dependency resolves into the core
# The mirror of the core's rule: an adapter may take dependencies the core
# never will, but no dependency may resolve into the core's directory,
# under any import name, and nothing may redirect resolution.
set -e
export GOWORK=off
find .. -name go.work -not -path '*/.git/*' | grep -q . && { echo "a go.work file is present"; exit 1; } || true
grep -nE '^\s*replace\b' go.mod && { echo "go.mod carries a replace directive"; exit 1; } || true
core="$(cd ../go && pwd)"
go list -deps -f '{{.ImportPath}} {{.Dir}}' ./... \
  | awk -v core="$core" '$2 == core || index($2, core "/") == 1 { print "resolves into the core: " $0; bad = 1 } END { exit bad }'
go list -deps ./... | grep -qx plugin && { echo "an adapter imports plugin"; exit 1; } || true
