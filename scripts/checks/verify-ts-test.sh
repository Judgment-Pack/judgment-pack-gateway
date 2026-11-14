#!/usr/bin/env bash
# CI step: the verify-ts tests (`npm test`, the Node test runner, whose output is TAP when it is not
# written to a terminal). Run from verify-ts/. The summary of a failed step keeps only the start of
# its output, so on a failure the failing tests are printed first: each `not ok` line with the lines
# indented under it (its diagnostic block, blank lines in a message included), nested tests
# included; the whole output follows, unchanged. On a pass the output is the test runner's alone.
# The exit status is the runner's.
set -e
out="$(mktemp)"
trap 'rm -f "$out"' EXIT
status=0
npm test >"$out" 2>&1 || status=$?
if [ "$status" -ne 0 ]; then
  echo "verify-ts-test: the failing tests, then the whole output"
  awk '
    keep && (/^ *$/ || (match($0, /^ */) && RLENGTH > depth)) { print; next }
    { keep = 0 }
    /^ *not ok / { match($0, /^ */); depth = RLENGTH; keep = 1; print }
  ' "$out"
  echo "verify-ts-test: the whole output"
fi
cat "$out"
exit "$status"
