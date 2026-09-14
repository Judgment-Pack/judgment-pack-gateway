#!/bin/sh
# Runs the community node inside the official n8n image against an engine on
# the host: installs the built package as n8n's own installer would, imports
# the credential and the workflow, executes the workflow headless, and checks
# what each node produced against n8n's own record of the execution.
#
#   plugins/smoke/n8n/run.sh <package tarball> [engine url]
set -eu
here=$(cd "$(dirname "$0")" && pwd)
tarball=$(cd "$(dirname "$1")" && pwd)/$(basename "$1")
engine=${2:-http://127.0.0.1:8787}
# the image these checks were written against, by digest; N8N_IMAGE runs
# another on purpose (the refusal text check.py expects is this version's)
image=${N8N_IMAGE:-docker.n8n.io/n8nio/n8n:2.38.7@sha256:a8c95f75c6fdf65f5f2b7a7b354744eaa1c62bb911b5c00af6499c3f38e4cd32}
if [ -n "${N8N_SMOKE_DATA:-}" ]; then data=$N8N_SMOKE_DATA; keep=1; else data=$(mktemp -d); keep=${N8N_SMOKE_KEEP:-0}; fi
cleanup() { if [ "$keep" = 1 ]; then echo "n8n smoke: data kept at $data"; else rm -rf "$data"; fi; }
trap cleanup EXIT
mkdir -p "$data/nodes"
# the package as n8n's community-node installer lays it out: a package.json
# under ~/.n8n/nodes naming it, and node_modules beside. The package's peer,
# n8n-workflow, is not installed here: the image's own copy is the one n8n
# hands a community node, and a second copy pulled by npm would float
# independently of the pinned image
(cd "$data/nodes" && npm init -y >/dev/null && npm install --ignore-scripts --legacy-peer-deps --no-audit --no-fund "$tarball" >/dev/null && test ! -e node_modules/n8n-workflow)
# the container runs as this user, so the directory stays this user's alone
chmod 700 "$data"
sed "s#http://127.0.0.1:8787#$engine#" "$here/credentials.json" > "$data/credentials.json"
# one session per run, the same literal in every node: a session the engine
# has sealed refuses another receipt, and a fresh n8n database numbers its
# executions from one again
nonce=$(date +%s)-$$
sed "s#RUN_NONCE#$nonce#g" "$here/workflow.json" > "$data/workflow.json"
echo "n8n smoke: data $data, session smoke-n8n-$nonce"
run() {
  docker run --rm --network host --user "$(id -u):$(id -g)" \
    -v "$data:/data/.n8n" \
    -e N8N_USER_FOLDER=/data -e N8N_ENCRYPTION_KEY=smoke-only-not-a-secret \
    -e N8N_COMMUNITY_PACKAGES_ALLOW_TOOL_USAGE=true -e N8N_LOG_LEVEL=warn \
    -e N8N_DIAGNOSTICS_ENABLED=false -e N8N_VERSION_NOTIFICATIONS_ENABLED=false -e N8N_RUNNERS_ENABLED=false \
    "$image" "$@"
}
run import:credentials --input=/data/.n8n/credentials.json
run import:workflow --input=/data/.n8n/workflow.json
run execute --id=jpsmokewf000001
python3 "$here/check.py" "$data/database.sqlite" "smoke-n8n-$nonce"
