#!/usr/bin/env bash
# CI step: The stated launch overrides behave as stated
# The launch overrides the design note states: every capability
# dropped is an exec the kernel refuses, since the binary's effective
# bit demands its permitted set in full; the three added back is the
# supported minimum.
set -e
if docker run --rm --cap-drop ALL engine:ci >out.txt 2>&1; then echo "started with every capability dropped"; cat out.txt; exit 1; fi
grep -qi 'operation not permitted\|permission denied' out.txt || { echo "refused for another reason:"; cat out.txt; exit 1; }
docker run --rm --cap-drop ALL --cap-add SETUID --cap-add SETGID --cap-add KILL engine:ci 2>&1 | grep -q 'engine configuration: open /etc/engine/engine.json' || { echo "the three capabilities alone do not start the engine"; exit 1; }
