#!/usr/bin/env bash
# CI step (job postgresql): the storage kinds through the binary (go/storage_scenario_test.go).
# This commit's binary on the PostgreSQL kind: `gateway store migrate` as the migration login, and
# refused as the run-time login; then, after a start on the kind with one acquisition and its seal
# (in the test's process: serve --config takes a platform, whose source runs as a user of its own
# that only a start as root switches to), `gateway export --config` from the kind, `gateway export
# --check` and `gateway verify` on the export, and no output or file of the run holding either
# login's password. Then a store a configuration without storage wrote, exported by this binary
# and by main's: the two exports alike byte for byte, each holding the store's own bytes. Run from
# go/, with GATEWAY_TEST_POSTGRES_DSN naming the job's server.
set -euo pipefail
tmp=$(mktemp -d)
trap 'git worktree remove --force "$tmp/main-tree" >/dev/null 2>&1 || true; rm -rf "$tmp"' EXIT
echo 'storage-scenario: build this commit'
go build -buildvcs=false -o "$tmp/gateway" .
echo "storage-scenario: build main's"
git fetch --no-tags --depth=1 origin main
git worktree add --detach "$tmp/main-tree" FETCH_HEAD
(cd "$tmp/main-tree/go" && go build -buildvcs=false -o "$tmp/gateway-main" .)
echo 'storage-scenario: the scenario, none skipped'
GATEWAY_SCENARIO_GATEWAY="$tmp/gateway" GATEWAY_SCENARIO_MAIN_GATEWAY="$tmp/gateway-main" GATEWAY_TEST_POSTGRES_REQUIRED=1 \
  go test -count=1 -timeout 10m -v -run '^TestStorageScenario' . | tee "$tmp/scenario.log"
if grep -q -- '--- SKIP' "$tmp/scenario.log"; then
  grep -- '--- SKIP' "$tmp/scenario.log"
  echo 'storage-scenario: a case skipped'
  exit 1
fi
