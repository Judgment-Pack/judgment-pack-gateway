#!/usr/bin/env python3
"""Write THIRD_PARTY_NOTICES: the licence of everything a released binary links.

Usage: python3 build/third_party_notices.py [--check]

A release archive carries binaries, and a binary carries the code of every
module it was linked with. This asks the toolchain which packages those are,
for every platform a release is built for, and copies each module's licence
and notice files from the module cache, as downloaded and verified against
go.sum: the ones at the module's root, and the ones in a linked package's
own directory or any directory above it, since a package taken from
elsewhere keeps its own terms beside it. Nothing is fetched here that
`go list` does not fetch, and no licence is named from memory.

The Go toolchain's own licence is copied from the toolchain that runs this,
so the file is written, and checked before a release is packaged, with the
toolchain release.yml names.

With --check nothing is written: the file in the tree is compared with what
would be written, and a difference is a failure. CI runs it so, which is
what keeps the file true when a dependency is added, removed or moved.
"""
import argparse
import os
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / 'THIRD_PARTY_NOTICES'
TITLE = 'judgment-pack-gateway third-party notices'
# The modules that build released binaries, and the packages released from
# each. The core, go/, is listed so that the day it links anything but the
# standard library, the file says so; CI refuses that day on its own account.
MODULES = [('go', '.'), ('adapters', './cmd/...')]
# Every platform .goreleaser.yml builds for: a module linked on one of them
# alone is still a module a release carries.
TARGETS = [(goos, goarch) for goos in ('darwin', 'linux', 'windows') for goarch in ('amd64', 'arm64')]
LICENCE_FILE = re.compile(r'^(LICEN[SC]E|NOTICE|COPYING|PATENTS)([.-].*)?$', re.IGNORECASE)
RULE = '=' * 72
THIN = '-' * 72


def go(args, cwd, **env):
    environment = dict(os.environ, GOWORK='off', GOFLAGS='-buildvcs=false -mod=readonly', CGO_ENABLED='0', **env)
    return subprocess.run(['go', *args], cwd=cwd, env=environment, check=True, capture_output=True, text=True).stdout


def linked_modules():
    """Every module but the main ones, as (path, version) -> (root, directories of its linked packages)."""
    found = {}
    template = '{{with .Module}}{{if not .Main}}{{.Path}}\t{{.Version}}\t{{.Dir}}\t{{$.Dir}}{{end}}{{end}}'
    for directory, packages in MODULES:
        for goos, goarch in TARGETS:
            for line in go(['list', '-deps', '-f', template, packages], ROOT / directory, GOOS=goos, GOARCH=goarch).splitlines():
                if not line.strip():
                    continue
                path, version, where, package = line.split('\t')
                if not where or not package:
                    raise SystemExit(f'{path} {version} is not in the module cache; run `go mod download` in {directory}/')
                root, linked = found.setdefault((path, version), (Path(where), set()))
                linked.add(Path(package))
    return found


def licence_files(root, linked, what):
    """The licence files at the module's root, then those beside or above a linked package."""
    directories = {root}
    for package in linked:
        while package != root:
            if root not in package.parents:
                raise SystemExit(f'{what}: the package directory {package} is not under the module root {root}')
            directories.add(package)
            package = package.parent
    files = []
    for directory in sorted(directories, key=lambda d: d.relative_to(root).as_posix()):
        files += sorted(entry for entry in directory.iterdir() if entry.is_file() and LICENCE_FILE.match(entry.name))
    if not any(entry.parent == root and entry.name.upper().startswith(('LICENSE', 'LICENCE', 'COPYING')) for entry in files):
        raise SystemExit(f'{what} carries no licence file in {root}; it cannot be released until its terms are known')
    return [(entry.relative_to(root).as_posix(), entry) for entry in files]


def text_of(path):
    lines = path.read_bytes().decode('utf-8').replace('\r\n', '\n').replace('\r', '\n').split('\n')
    return '\n'.join(line.rstrip() for line in lines).strip('\n') + '\n'


def render():
    modules = linked_modules()
    out = [TITLE, '=' * len(TITLE), '']
    out += [
        'The binaries in a release are linked with the Go standard library and',
        'runtime and with the Go modules listed below. The gateway itself, built',
        'from go/, links the standard library alone; every module listed is linked',
        'by an adapter, built from adapters/. Each is given below with the licence',
        'and notice files it is distributed with, unedited: those at the module\'s',
        'root, and those a linked package carries in its own directory.',
        '',
        'This file is written by build/third_party_notices.py from the module',
        'cache, for every platform a release is built for. Do not edit it: change',
        'the dependency and run the script. CI refuses a tree where the two differ.',
        '',
        'Linked',
        '------',
        '',
        '- The Go programming language: standard library and runtime',
    ]
    out += [f'- {path} {version}' for path, version in sorted(modules)]
    out.append('')
    goroot = Path(go(['env', 'GOROOT'], ROOT).strip())
    sections = [('The Go programming language: standard library and runtime', goroot, set())]
    sections += [(f'{path} {version}', *modules[(path, version)]) for path, version in sorted(modules)]
    for name, root, linked in sections:
        for shown, entry in licence_files(root, linked, name):
            out += [RULE, name, shown, THIN, '', text_of(entry)]
    return '\n'.join(out)


def main():
    parser = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    parser.add_argument('--check', action='store_true', help='compare with the file in the tree and write nothing')
    args = parser.parse_args()
    wanted = render()
    if not args.check:
        OUTPUT.write_bytes(wanted.encode('utf-8'))
        print(f'wrote {OUTPUT.relative_to(ROOT)}')
        return 0
    held = OUTPUT.read_bytes().decode('utf-8') if OUTPUT.exists() else ''
    if held != wanted:
        print(f'{OUTPUT.relative_to(ROOT)} is not what build/third_party_notices.py writes; run it and commit the result', file=sys.stderr)
        return 1
    print(f'{OUTPUT.relative_to(ROOT)} is what the linked modules say')
    return 0


if __name__ == '__main__':
    sys.exit(main())
