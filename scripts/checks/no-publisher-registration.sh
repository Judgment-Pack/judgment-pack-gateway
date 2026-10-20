#!/usr/bin/env bash
# CI step: The tree carries no publisher registration
# No publisher's application registration in the connection companion
# (docs/design/publisher-google-oauth.md).
set -e
export GOWORK=off
[ "$(tr -d '[:space:]' < adapters/cmd/gateway-connections/publisher-google.json)" = "{}" ] || { echo "publisher-google.json is not the empty registration"; exit 1; }
