#!/usr/bin/env python3
"""go_test_shard.py --shard K --of N [--dir DIR] [--dry-run]: one shard of `go test ./...`.

The partition is of the top-level names `go test -list .` gives for every package of the module
in DIR (tests, examples, fuzz targets and benchmarks; a subtest goes with its parent): shard K of
N holds the names whose length is K-1 modulo N. Go selects them with one short expression,
`-run '^(?:.{N})*.{K-1}$'`, whatever the number of tests (a list of names would not fit a Windows
command line), and a test added later joins a shard by itself. The module here is one package, so
the shards cannot be lists of packages.

Before anything runs, the script refuses unless the N shards are disjoint and together hold the
whole listing, its own shard is not empty, and Go's selection of the expression (`go test -list
EXPR ./...`) is, package by package, exactly the names the rule gives the shard. Then
`go test -run EXPR ./...`, whose exit status is the script's. Standard library only.
"""
import argparse
import re
import subprocess
import sys

NAME = re.compile(r'(Test|Example|Fuzz|Benchmark)[A-Za-z0-9_]*')
PASSED = re.compile(r'ok\s+(\S+)(\s.*)?')
NO_TESTS = re.compile(r'\?\s+(\S+)\s+\[no test files\]')


class Refusal(Exception):
    pass


def shard_of(name, count):
    """The shard (1 to count) a top-level name belongs to."""
    return len(name) % count + 1


def expression(shard, count):
    """The expression `-run` and `-list` select shard of count with: the names whose length is
    shard - 1 modulo count, anchored at both ends."""
    if not 1 <= shard <= count:
        raise Refusal('shard %d of %d' % (shard, count))
    rest = shard - 1
    return '^(?:.{%d})*%s$' % (count, '.{%d}' % rest if rest else '')


def parse_listing(text):
    """{package: [top-level names]} from the output of `go test -list EXPR ./...`. Any line that
    is not a name, a package's "ok" line or its "no test files" line is refused, as is a name
    before no package."""
    packages, pending = {}, []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        passed, empty = PASSED.fullmatch(line), NO_TESTS.fullmatch(line)
        if passed or empty:
            package = (passed or empty).group(1)
            if package in packages:
                raise Refusal('package %s is listed twice' % package)
            if empty and pending:
                raise Refusal('names before %s, which has no test files' % package)
            packages[package], pending = pending, []
        elif NAME.fullmatch(line):
            pending.append(line)
        else:
            raise Refusal('a line of the listing that is not a name or a package: %r' % line)
    if pending:
        raise Refusal('names after the last package: %s' % pending[:3])
    for package, names in packages.items():
        if len(names) != len(set(names)):
            raise Refusal('a name is listed twice in %s' % package)
    return packages


def check_partition(listing, selected, shard, count):
    """The names of shard, after checking that the count shards are disjoint and hold every name
    of listing, that shard holds some, and that Go selected exactly them."""
    every = {(package, name) for package, names in listing.items() for name in names}
    shards = [{(package, name) for package, name in every if shard_of(name, count) == k}
              for k in range(1, count + 1)]
    union = set().union(*shards)
    if union != every or sum(len(part) for part in shards) != len(every):
        raise Refusal('the %d shards do not hold every name exactly once' % count)
    own = shards[shard - 1]
    if not own:
        raise Refusal('shard %d of %d holds no test' % (shard, count))
    if set(selected) != set(listing):
        raise Refusal('the listing of the shard names other packages: %s' % sorted(
            set(selected) ^ set(listing)))
    chosen = {(package, name) for package, names in selected.items() for name in names}
    if chosen != own:
        raise Refusal('go selects %d names the rule does not give shard %d, and leaves %d it does: %s' % (
            len(chosen - own), shard, len(own - chosen), sorted(chosen ^ own)[:5]))
    return own, len(every)


def go(arguments, directory):
    """`go ARGUMENTS` in directory, its standard output as text; a failure is a refusal."""
    result = subprocess.run(['go'] + arguments, cwd=directory, stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, text=True)
    if result.returncode:
        sys.stdout.write(result.stdout)
        raise Refusal('go %s exited %d' % (' '.join(arguments), result.returncode))
    return result.stdout


def main(argv=None, run=go):
    parser = argparse.ArgumentParser(prog='go_test_shard.py', description=__doc__.splitlines()[0])
    parser.add_argument('--shard', type=int, required=True)
    parser.add_argument('--of', type=int, required=True, dest='count')
    parser.add_argument('--dir', default='.')
    parser.add_argument('--dry-run', action='store_true', help='check the partition, run no test')
    args = parser.parse_args(argv)
    try:
        if args.count < 2:
            raise Refusal('a split needs two shards or more, not %d' % args.count)
        pattern = expression(args.shard, args.count)
        listing = parse_listing(run(['test', '-list', '.', './...'], args.dir))
        selected = parse_listing(run(['test', '-list', pattern, './...'], args.dir))
        own, total = check_partition(listing, selected, args.shard, args.count)
    except Refusal as refusal:
        print('go-test-shard: refuse: %s' % refusal, file=sys.stderr)
        return 1
    print('go-test-shard: shard %d of %d: %d of %d top-level names in %d package(s), -run %s; '
          'the %d shards are disjoint and hold every name' % (
              args.shard, args.count, len(own), total, len(listing), pattern, args.count), flush=True)
    if args.dry_run:
        return 0
    return subprocess.run(['go', 'test', '-run', pattern, './...'], cwd=args.dir,
                          stdin=subprocess.DEVNULL).returncode


if __name__ == '__main__':
    sys.exit(main())
