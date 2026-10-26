#!/usr/bin/env bash
# CI step: Every shipped adapter passes gateway adapter-conform
# The tests named below write the envelope each envelope source of the
# connection local plan writes, its own code against its tests' stand-in for
# the provider. testdata/adapter-conform then builds the gateway and the
# programs of adapters/cmd, runs gateway adapter-conform over every program
# that writes an envelope (adapter-airbyte, adapter-mcp and adapter-http to
# accepted envelopes against stand-ins, the connection programs to a refusal of
# their own (source-failed) before any provider), and hands it each envelope
# written. The envelopes written are held to the published schema as well,
# with the validator the setup step installs
# (testdata/attachments/schema-requirements.txt).
set -e
export GOWORK=off
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
JPACK_TEST_ENVELOPES="$tmp" go test ./connections ./websource -count=1 -run '^(TestDriveRecordForPublishedSchema|TestGmailSearchSelectAndVerifiedTextExport|TestNotionOAuthSearchSelectedSnapshot|TestSearchResultsForPublishedSchema|TestDatabricksStatementIsOneInlineRequest|TestDatabricksMCPUnityGatewayServiceIsReadAsTheOthers|TestAzureDevOpsEachReadIsItsDocumentedRequest|TestAzureDevOpsMCPReadsTheRemoteServer|TestWebSnapshotAndRedirect|TestDiscoverScopeRobotsAndDepth)$'
ADAPTER_CONFORM_ENVELOPES="$tmp" go test ./testdata/adapter-conform -count=1 -v
python3 ../schema/check_adapter_envelope.py "$tmp"/*.json
