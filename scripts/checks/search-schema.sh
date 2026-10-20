#!/usr/bin/env bash
# CI step: A search result agrees with its published schema
# A result of each kind the search source writes in this run, and the
# examples beside the schemas, are what the schemas describe, and the
# schemas refuse a list of broken variants of each (docs/web-search.md).
# No provider is asked: the answers are the test's own. The validator
# is the one the setup step installs.
set -e
export GOWORK=off
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
JPACK_TEST_SEARCH_RESULT="$tmp/search-result.json" JPACK_TEST_GROUNDED_RESULT="$tmp/grounded-result.json" go test ./connections -run '^TestSearchResultsForPublishedSchema$' -count=1
python3 ../testdata/search/check_schema.py "$tmp/search-result.json" "$tmp/grounded-result.json"
