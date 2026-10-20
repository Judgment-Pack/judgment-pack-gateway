#!/usr/bin/env bash
# CI step: Actual provider output agrees with its published attachment schema
set -e
export GOWORK=off
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
JPACK_TEST_DRIVE_RECORD="$tmp/drive-record.json" go test ./connections -run '^TestDriveRecordForPublishedSchema$' -count=1
python3 ../testdata/attachments/check_schema.py "$tmp/drive-record.json"
JPACK_TEST_GMAIL_RECORD="$tmp/gmail-record.json" go test ./connections -run '^TestGmailSearchSelectAndVerifiedTextExport$' -count=1
python3 ../testdata/attachments/check_gmail_schema.py "$tmp/gmail-record.json"
JPACK_TEST_NOTION_RECORD="$tmp/notion-record.json" JPACK_TEST_OBSIDIAN_RECORD="$tmp/obsidian-record.json" go test ./connections -run '^Test(NotionOAuthSearchSelectedSnapshot|ObsidianSelectedSnapshotAndBoundary)$' -count=1
python3 ../testdata/attachments/check_connected_schema.py "$tmp/notion-record.json" "$tmp/obsidian-record.json"
JPACK_TEST_WEB_RECORD="$tmp/web-record.json" go test ./websource -run '^TestWebSnapshotAndRedirect$' -count=1
python3 ../testdata/attachments/check_web_schema.py "$tmp/web-record.json"
JPACK_TEST_WEB_OCR_RECORD="$tmp/web-ocr-record.json" go test ./websource -run '^TestWebPDFUsesSelectedOCRAndKeepsOriginalSource$' -count=1
python3 ../testdata/attachments/check_web_schema.py "$tmp/web-ocr-record.json"
JPACK_TEST_WEB_REDIRECT_RECORD="$tmp/web-redirect-record.json" go test ./websource -run '^TestGroundingRedirectIsFollowedOnceWhenTheOperatorEnablesIt$' -count=1
python3 ../testdata/attachments/check_web_schema.py "$tmp/web-redirect-record.json"
JPACK_TEST_RESOURCE_RECORD="$tmp/resource-record.json" go test ./connections -run '^TestResourceProducerSupportsUnknownProviderAndBindsRetainedBytes$' -count=1
python3 ../testdata/attachments/check_resource_schema.py "$tmp/resource-record.json"
JPACK_TEST_RESOURCE_PDF="$tmp/resource-pdf.json" go test ./connections -run '^TestGenericResourcePDFUsesSharedRecord$' -count=1
python3 ../testdata/attachments/check_resource_schema.py "$tmp/resource-pdf.json"
