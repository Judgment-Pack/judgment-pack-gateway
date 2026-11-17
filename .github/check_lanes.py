#!/usr/bin/env python3
"""check_lanes.py --lane LANE [--manifest dev.json]: the checks scripts/dev/check.sh skips in one lane.

CI runs dev.json's checks in two lanes side by side. `go-tests` holds the checks named in GO_TESTS:
those that build and run the Go tests of the core and of the adapters, which share one build of
each module's test binaries. `rest` holds every other check of the manifest, so a check added to
dev.json later runs in `rest` without a change here. Each lane skips the other's checks, so every
check runs in exactly one lane, and check.sh's own --changed selection still applies within a lane.
A name in GO_TESTS that the manifest no longer has is refused, as is a lane that would skip nothing
or everything. Prints skip=NAME,NAME, for GITHUB_OUTPUT. Standard library only.
"""
import argparse
import json
import sys

GO_TESTS = (
    'go-vet', 'go-test', 'verify-ts-witness-chain', 'witness-scenario',
    'adapters-vet', 'adapters-vet-windows', 'sandbox-boundary', 'adapters-test',
    'acquisition-fixture', 'attachment-schemas', 'search-schema', 'adapter-conform',
)
LANES = ('go-tests', 'rest')


class Refusal(Exception):
    pass


def checks(manifest):
    """The step names check.sh runs, in its order: the checks, and parity where there is one."""
    names = [check['name'] for check in manifest['checks']] + (['parity'] if 'parity' in manifest else [])
    if len(names) != len(set(names)):
        raise Refusal('the manifest names a check twice')
    return names


def skipped(lane, names, go_tests=GO_TESTS):
    """The checks lane skips: the other lane's, in the manifest's order."""
    if len(go_tests) != len(set(go_tests)):
        raise Refusal('GO_TESTS names a check twice')
    missing = sorted(set(go_tests) - set(names))
    if missing:
        raise Refusal('GO_TESTS names checks dev.json does not have: %s' % ', '.join(missing))
    if lane == 'go-tests':
        result = [name for name in names if name not in go_tests]
    elif lane == 'rest':
        result = [name for name in names if name in go_tests]
    else:
        raise Refusal('no lane %r; the lanes are %s' % (lane, ', '.join(LANES)))
    if not result or len(result) == len(names):
        raise Refusal('lane %s would skip %d of %d checks' % (lane, len(result), len(names)))
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(prog='check_lanes.py', description=__doc__.splitlines()[0])
    parser.add_argument('--lane', required=True)
    parser.add_argument('--manifest', default='dev.json')
    args = parser.parse_args(argv)
    try:
        with open(args.manifest, encoding='utf-8') as handle:
            names = checks(json.load(handle))
        result = skipped(args.lane, names)
    except (Refusal, OSError, ValueError, KeyError, TypeError) as error:
        print('check-lanes: refuse: %s' % error, file=sys.stderr)
        return 1
    print('skip=' + ','.join(result))
    print('check-lanes: lane %s runs %d of %d checks' % (args.lane, len(names) - len(result), len(names)),
          file=sys.stderr)
    return 0


if __name__ == '__main__':
    sys.exit(main())
