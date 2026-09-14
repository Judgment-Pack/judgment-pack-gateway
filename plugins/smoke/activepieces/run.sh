#!/bin/sh
# Executes the piece's actions as the framework calls them against an engine.
#   plugins/smoke/activepieces/run.sh [engine url]
set -eu
here=$(cd "$(dirname "$0")" && pwd)
node "$here/run.mjs" "$here/../../activepieces/judgment-pack" "${1:-http://127.0.0.1:8787}"
