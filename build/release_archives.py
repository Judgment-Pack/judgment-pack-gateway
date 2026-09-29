#!/usr/bin/env python3
"""Hold the archives of a release to the commit they were built from.

Usage: python3 build/release_archives.py --dist dist --version 0.5.0 [--tree .]

The release workflow runs this on what GoReleaser wrote, before anything is
attested: it is held of the archives themselves, and not of the
configuration that was meant to make them. For every platform a release is
built for, the archive of that name must hold exactly:

  - the documents, each a file, byte for byte the tree's;
  - the corpus and the catalog, every file the tree tracks and no other,
    byte for byte: the corpus arbitrates, so it travels as it is;
  - the programs, each a file and nothing but a file, built from the
    package of its name, for the archive's operating system and
    architecture and at the processor level a release promises, as the
    executable's own build record says, and executable where the system
    has the bit.

Nothing else may be in it: no other file, no link, no device. Every fault
found is reported, and any fault is a failure.

What this does not establish: that a program behaves. A build record says
what an executable was built from and for; it is read here and not run.
"""
import argparse
import io
import os
from pathlib import Path, PurePosixPath
import stat
import subprocess
import sys
import tarfile
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[1]
PROJECT = 'judgment-pack-gateway'
TARGETS = [f'{goos}_{goarch}' for goos in ('darwin', 'linux', 'windows') for goarch in ('amd64', 'arm64')]
DOCUMENTS = ['LICENSE', 'README.md', 'SECURITY.md', 'SPEC.md', 'THIRD_PARTY_NOTICES']
DIRECTORIES = ['catalog', 'corpus']
# The level of each architecture a release is built at, which is the lowest:
# an archive named for an architecture runs on every processor of it.
LEVELS = {'amd64': ('GOAMD64', 'v1'), 'arm64': ('GOARM64', 'v8.0')}


def programs(tree):
    """Name -> the package it is built from: the core, and every program under adapters/cmd."""
    found = {'gateway': 'gateway'}
    for entry in sorted((tree / 'adapters' / 'cmd').iterdir()):
        if entry.is_dir():
            found[entry.name] = f'adapters/cmd/{entry.name}'
    return found


def tracked(tree, directory):
    """Relative path -> bytes, for every file the tree tracks under the directory."""
    listed = subprocess.run(['git', '-C', str(tree), 'ls-files', '-z', '--', directory], check=True, capture_output=True).stdout
    names = [name for name in listed.decode('utf-8').split('\0') if name]
    if not names:
        raise SystemExit(f'the tree tracks no file under {directory}/')
    return {name: (tree / name).read_bytes() for name in names}


def members(archive):
    """Every member of an archive as (name, kind, mode, bytes); kind is 'file', 'dir' or what else it is."""
    if archive.suffix == '.zip':
        with zipfile.ZipFile(archive) as opened:
            for info in opened.infolist():
                mode = info.external_attr >> 16
                if info.is_dir():
                    yield info.filename, 'dir', mode, b''
                elif stat.S_ISLNK(mode):
                    yield info.filename, 'link', mode, b''
                else:
                    yield info.filename, 'file', mode, opened.read(info)
        return
    with tarfile.open(archive, 'r:gz') as opened:
        for info in opened.getmembers():
            if info.isdir():
                yield info.name, 'dir', info.mode, b''
            elif info.isreg():
                yield info.name, 'file', info.mode, opened.extractfile(info).read()
            else:
                yield info.name, 'link' if info.issym() or info.islnk() else 'special', info.mode, b''


def build_record(data, scratch):
    """What `go version -m` says of an executable: (package, os, architecture, level), or why it says nothing usable."""
    held = scratch / 'program'
    held.write_bytes(data)
    ran = subprocess.run(['go', 'version', '-m', str(held)], capture_output=True, text=True)
    if ran.returncode != 0:
        return None, 'it carries no build record: ' + (ran.stderr.strip().splitlines() or ['go version -m failed'])[-1]
    packages, settings = [], {}
    for line in ran.stdout.splitlines():
        fields = line.split()
        if len(fields) >= 2 and fields[0] == 'path':
            packages.append(fields[1])
        if len(fields) >= 2 and fields[0] == 'build' and '=' in fields[1]:
            key, _, value = fields[1].partition('=')
            settings.setdefault(key, []).append(value)
    if len(packages) != 1:
        return None, f'its build record names {len(packages)} packages'
    for key in ('GOOS', 'GOARCH'):
        if len(settings.get(key, [])) != 1:
            return None, f'its build record states {key} {len(settings.get(key, []))} times'
    arch = settings['GOARCH'][0]
    key = LEVELS.get(arch, ('', ''))[0]
    level = settings.get(key, [])
    if len(level) != 1:
        return None, f'its build record states {key or "a level"} {len(level)} times'
    return (packages[0], settings['GOOS'][0], arch, level[0]), ''


def check(archive, target, tree, scratch):
    """Every fault of one archive, as sentences; none is a pass."""
    faults = []
    goos, _, goarch = target.partition('_')
    suffix = '.exe' if goos == 'windows' else ''
    wanted_programs = {name + suffix: package for name, package in programs(tree).items()}
    wanted_files = {name: (tree / name).read_bytes() for name in DOCUMENTS}
    for directory in DIRECTORIES:
        wanted_files.update(tracked(tree, directory))

    seen = {}
    for name, kind, mode, data in members(archive):
        path = PurePosixPath(name)
        clean = path.as_posix()
        if clean in ('.', ''):
            continue
        if path.is_absolute() or '..' in path.parts:
            faults.append(f'{name}: a path that leaves the archive')
            continue
        if kind == 'dir':
            if clean not in DIRECTORIES and not any(clean.startswith(directory + '/') for directory in DIRECTORIES):
                faults.append(f'{clean}/: a directory a release does not hold')
            continue
        if kind != 'file':
            faults.append(f'{clean}: a {kind}, and a release holds files')
            continue
        if clean in seen:
            faults.append(f'{clean}: in the archive twice')
            continue
        seen[clean] = (mode, data)

    for name in sorted(set(wanted_files) | set(wanted_programs)):
        if name not in seen:
            faults.append(f'{name}: not in the archive')
    for name in sorted(set(seen) - set(wanted_files) - set(wanted_programs)):
        faults.append(f'{name}: a file a release does not hold')

    for name, wanted in sorted(wanted_files.items()):
        if name in seen and seen[name][1] != wanted:
            faults.append(f'{name}: not the bytes the tree holds')

    level_key, level = LEVELS[goarch]
    for name, package in sorted(wanted_programs.items()):
        if name not in seen:
            continue
        mode, data = seen[name]
        record, why = build_record(data, scratch)
        if record is None:
            faults.append(f'{name}: {why}')
            continue
        if record != (package, goos, goarch, level):
            faults.append(f'{name}: built from {record[0]} for {record[1]}_{record[2]} at {record[3]}, and not from {package} for {target} at {level_key}={level}')
        if not suffix and not mode & 0o111:
            faults.append(f'{name}: not executable')
    return faults


def main():
    parser = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    parser.add_argument('--dist', type=Path, required=True, help='the directory GoReleaser wrote')
    parser.add_argument('--version', required=True, help='the version in the archive names, without the leading v')
    parser.add_argument('--tree', type=Path, default=ROOT, help='the tree the archives were built from')
    parser.add_argument('--target', action='append', help='check these targets only (for the tests of this script)')
    args = parser.parse_args()
    tree = args.tree.resolve()
    failed = False
    with tempfile.TemporaryDirectory(prefix='release-archives-') as scratch:
        for target in args.target or TARGETS:
            extension = 'zip' if target.startswith('windows_') else 'tar.gz'
            archive = args.dist / f'{PROJECT}_{args.version}_{target}.{extension}'
            if not archive.is_file():
                print(f'{target}: {archive.name} is not there', file=sys.stderr)
                failed = True
                continue
            faults = check(archive, target, tree, Path(scratch))
            for fault in faults:
                print(f'{target}: {fault}', file=sys.stderr)
            if faults:
                failed = True
            else:
                print(f'{target}: {archive.name} holds what a release holds')
    return 1 if failed else 0


if __name__ == '__main__':
    sys.exit(main())
