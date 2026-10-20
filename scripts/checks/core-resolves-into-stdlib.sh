#!/usr/bin/env bash
# CI step: Every core dependency resolves into the standard library
# The process boundary is the security claim (docs/adr/0001): the module
# that holds the seed is never linked to the module that holds platform
# credentials. The check no-third-party-modules judges import spelling, and spelling is
# not provenance: a workspace file or a replace directive can make any
# name resolve anywhere. So this step asks the toolchain where every
# dependency actually resolved (`.Standard`), with workspaces disabled,
# and refuses the files and directives that would redirect resolution.
set -e
export GOWORK=off
find .. -name go.work -not -path '*/.git/*' | grep -q . && { echo "a go.work file is present"; exit 1; } || true
grep -nE '^\s*(require|replace|exclude)\b' go.mod && { echo "go.mod declares a dependency, replacement, or exclusion"; exit 1; } || true
go list -deps -f '{{.ImportPath}} {{.Standard}} {{.Dir}}' . \
  | awk '$1 != "gateway" && $2 != "true" { print "resolves outside the standard library: " $0; bad = 1 } END { exit bad }'
go list -deps . | grep -qx plugin && { echo "the core imports plugin"; exit 1; } || true
