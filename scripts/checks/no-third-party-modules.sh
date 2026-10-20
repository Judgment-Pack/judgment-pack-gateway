#!/usr/bin/env bash
# CI step: No third-party modules
set -e
if [ -f go.sum ]; then echo "go.sum exists: a dependency crept in"; exit 1; fi
go list -deps . | grep -v '^gateway$' | grep -vE '^(internal/|[a-z]+(/|$))' && exit 1 || true
