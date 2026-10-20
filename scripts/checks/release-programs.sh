#!/usr/bin/env bash
# CI step: Every program under adapters/cmd is named in the release build
# The names in a file, compared with the directories: a first notice
# only. A build under the right name from the wrong package passes
# it, and is refused by the release workflow, which reads the
# archives.
set -e
export GOWORK=off
want="$(ls adapters/cmd | sort)"
have="$(sed -n 's/^    binary: //p' .goreleaser.yml | grep -vx gateway | sort)"
[ "$want" = "$have" ] || { echo "adapters/cmd and .goreleaser.yml name different programs:"; diff <(echo "$want") <(echo "$have"); exit 1; }
