#!/usr/bin/env python3
"""Hold the archives of a release to the commit they were built from.

Usage: python3 build/release_archives.py --dist dist --version 0.5.0 [--tree .] [--commit HEAD]

The release workflow runs this on what GoReleaser wrote, before anything is
attested: it is held of the archives themselves, and not of the
configuration that was meant to make them. For every platform a release is
built for, the archive of that name must hold exactly:

  - the documents, byte for byte the commit's;
  - the corpus and the catalog, every file the commit holds and no other,
    byte for byte: the corpus arbitrates, so it travels as it is;
  - the programs, each one program and not a file of several, built from
    the package of its name, for the archive's operating system and
    architecture and at the processor level a release promises, as the
    executable's own build record says, and readable and executable by
    everyone, which the packer records of a program for Windows too.

An archive holds files and nothing else: no directory of its own, no link,
no device, no name twice, and no name written any way but the plain one
(no "./", no trailing slash, no backslash). A member's header must be of the
one form the packer writes, and any other is refused, though it may be a
lawful archive: in a tar archive a plain regular file with no extended
header; in a zip archive a regular file as a Unix system records one, its
name given once and whole, with no field beside it but a time. The
members' headers are read first and their contents after, one at a time,
and only of members a release holds; a member larger than any a release has
is refused unread. Every fault found is reported, and any fault is a
failure.

What is compared is the commit, not the working tree: a file changed or
removed in the tree after the commit changes nothing here.

What this is for, and what it is not. It is a check of the workflow's own
packaging: that a pattern did not pass a file over, that a build was made
from the package and for the platform its name says. It reads an archive as
Python's standard library reads one. It is not a defence against an archive
made to be read one way by one program and another way by the next: whoever
could put such an archive where this looks could change this script too.

What this does not establish: that a program behaves. A build record says
what an executable was built from and for; it is read here, by whatever
`go` is first on the path, and the program is not run. The release workflow
and CI run this with the toolchain a release is built with.
"""
import argparse
from pathlib import Path
import stat
import struct
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
# No member of a release is a tenth of this.
LIMIT = 512 << 20
# How a file that holds several programs begins (a universal Mach-O, in either
# byte order and either width). The toolchain reads the first program in one
# and says nothing of the rest.
SEVERAL = (b'\xca\xfe\xba\xbe', b'\xbe\xba\xfe\xca', b'\xca\xfe\xba\xbf', b'\xbf\xba\xfe\xca')
# What a zip entry of the packer's carries beside its name: a time (0x5455),
# and the flags for a size written after the contents (0x8) and a name in
# UTF-8 (0x800).
ZIP_FIELDS = {0x5455}
ZIP_FLAGS = 0x8 | 0x800


def git(tree, *args):
    return subprocess.run(['git', '-C', str(tree), *args], check=True, capture_output=True).stdout


def programs(tree, commit):
    """Name -> the package it is built from: the core, and every program the commit holds under adapters/cmd."""
    found = {'gateway': 'gateway'}
    listed = git(tree, 'ls-tree', '-d', '-z', '--name-only', commit, 'adapters/cmd/').decode('utf-8')
    for name in sorted(path.rsplit('/', 1)[1] for path in listed.split('\0') if path):
        found[name] = f'adapters/cmd/{name}'
    return found


def committed(tree, commit):
    """Path -> bytes, as the commit holds them: the documents, and every file under the directories."""
    paths = list(DOCUMENTS)
    for directory in DIRECTORIES:
        listed = git(tree, 'ls-tree', '-r', '-z', '--name-only', commit, '--', directory).decode('utf-8')
        under = [path for path in listed.split('\0') if path]
        if not under:
            raise SystemExit(f'the commit holds no file under {directory}/')
        paths += under
    return {path: git(tree, 'cat-file', 'blob', f'{commit}:{path}') for path in paths}


def zip_fields(extra):
    """The identifiers of the fields a zip entry carries beside its name, or None where they cannot be read."""
    found, place = [], 0
    while place < len(extra):
        if place + 4 > len(extra):
            return None
        identifier, size = struct.unpack('<HH', extra[place:place + 4])
        found.append(identifier)
        place += 4 + size
    return found if place == len(extra) else None


def zip_kind(info):
    """What a zip entry is, by everything its header says of it."""
    mode = info.external_attr >> 16
    form = stat.S_IFMT(mode)
    if info.orig_filename.endswith('/') or form == stat.S_IFDIR or info.external_attr & 0x10:
        return 'directory'
    if form == stat.S_IFLNK:
        return 'link'
    if form != stat.S_IFREG or info.create_system != 3:
        return 'member of no kind the packer writes'
    fields = zip_fields(info.extra)
    if fields is None or set(fields) - ZIP_FIELDS or len(fields) != len(set(fields)) \
            or info.flag_bits & ~ZIP_FLAGS or info.external_attr & 0xffff or info.comment:
        return 'member whose header says more than a name, a mode and a time'
    return 'file'


def tar_kind(info):
    """What a tar member is, by everything its header says of it."""
    if info.isdir():
        return 'directory'
    if info.issym() or info.islnk():
        return 'link'
    if info.type != tarfile.REGTYPE:
        return 'member of no kind the packer writes'
    if info.pax_headers:
        return 'member whose header says more than a name, a mode and a time'
    return 'file'


def headers(archive):
    """Every member's header as (name, kind, mode, size), the name as the archive writes it. Nothing is read."""
    if archive.suffix == '.zip':
        with zipfile.ZipFile(archive) as opened:
            for info in opened.infolist():
                yield info.orig_filename, zip_kind(info), (info.external_attr >> 16) & 0o7777, info.file_size
        return
    with tarfile.open(archive, 'r:gz') as opened:
        for info in opened:
            # An extended header may give the name, and the reader has tidied it by then.
            yield info.pax_headers.get('path', info.name), tar_kind(info), info.mode & 0o7777, info.size


def contents(archive, names):
    """(name, bytes) for the named members, one at a time, in the archive's order. The names are of sound members."""
    if archive.suffix == '.zip':
        with zipfile.ZipFile(archive) as opened:
            for info in opened.infolist():
                if info.orig_filename in names:
                    yield info.orig_filename, opened.read(info)
        return
    with tarfile.open(archive, 'r:gz') as opened:
        for info in opened:
            if info.name in names:
                yield info.name, opened.extractfile(info).read()


def plain(name):
    """Whether a name is written the one plain way: parts joined by single slashes, none empty, none a dot.

    No name a release holds is written any other way, so a name that fails this is refused without it, as a
    file a release does not hold. This says why.
    """
    return '\\' not in name and '\0' not in name and all(part not in ('', '.', '..') for part in name.split('/'))


def parse_record(text):
    """What a build record says: (package, os, architecture, level), or why it says nothing usable."""
    packages, settings = [], {}
    for line in text.splitlines():
        fields = line.split()
        if len(fields) < 2:
            continue
        if fields[0] == 'path':
            packages.append(fields[1])
        if fields[0] == 'build':
            key, _, value = fields[1].partition('=')
            settings.setdefault(key, []).append(value)
    if len(packages) != 1:
        return None, f'its build record names {len(packages)} packages'
    for key in ('GOOS', 'GOARCH'):
        if len(settings.get(key, [])) != 1:
            return None, f'its build record states {key} {len(settings.get(key, []))} times'
    arch = settings['GOARCH'][0]
    if arch not in LEVELS:
        return None, f'its build record states an architecture no release is built for: {arch}'
    key = LEVELS[arch][0]
    if len(settings.get(key, [])) != 1:
        return None, f'its build record states {key} {len(settings.get(key, []))} times'
    return (packages[0], settings['GOOS'][0], arch, settings[key][0]), ''


def build_record(data, scratch):
    """What `go version -m` says of an executable's bytes."""
    if data[:4] in SEVERAL:
        return None, 'it holds several programs, and a release holds one under each name'
    held = scratch / 'program'
    held.write_bytes(data)
    try:
        ran = subprocess.run(['go', 'version', '-m', str(held)], capture_output=True, text=True)
    finally:
        held.unlink()
    if ran.returncode != 0 or not ran.stdout.strip():
        return None, 'it carries no build record: ' + (ran.stderr.strip().splitlines() or ['go version -m said nothing'])[-1]
    return parse_record(ran.stdout)


def check(archive, target, wanted_files, wanted_programs, scratch):
    """Every fault of one archive, as sentences; none is a pass."""
    faults = []
    goos, _, goarch = target.partition('_')
    suffix = '.exe' if goos == 'windows' else ''
    wanted_programs = {name + suffix: package for name, package in wanted_programs.items()}
    shared = sorted(set(wanted_files) & set(wanted_programs))
    if shared:
        # One name cannot be held to a document's bytes and to a program's record.
        return [f'{name}: the name of a document and of a program' for name in shared]
    wanted = set(wanted_files) | set(wanted_programs)

    unread = (tarfile.TarError, zipfile.BadZipFile, OSError, EOFError)
    try:
        listed = list(headers(archive))
    except unread as refused:
        return [f'the archive cannot be read through: {refused}']
    sound = {}
    seen = set()
    for name, kind, mode, size in listed:
        shown = repr(name)[1:-1]
        if name in seen:
            faults.append(f'{shown}: in the archive twice')
            # Neither is read: there is no saying which one an unpacking would leave.
            sound.pop(name, None)
            continue
        seen.add(name)
        if kind != 'file':
            faults.append(f'{shown}: a {kind}, and a release holds files')
        elif not plain(name):
            faults.append(f'{shown}: a name not written the plain way')
        elif name not in wanted:
            faults.append(f'{shown}: a file a release does not hold')
        elif size > LIMIT:
            faults.append(f'{shown}: {size} bytes, more than any file of a release')
        else:
            sound[name] = mode
    for name in sorted(wanted - seen):
        faults.append(f'{name}: not in the archive')

    try:
        # One member at a time; a fault in reading ends the reading.
        for name, data in contents(archive, set(sound)):
            faults += member_faults(name, data, sound[name], wanted_files, wanted_programs, target, scratch)
    except unread as refused:
        # As when the two places a zip archive names a member in disagree.
        faults.append(f'the archive cannot be read through: {refused}')
    return faults


def member_faults(name, data, mode, wanted_files, wanted_programs, target, scratch):
    """The faults of one sound member's contents and mode."""
    if name in wanted_files:
        return [] if data == wanted_files[name] else [f'{name}: not the bytes the commit holds']
    faults = []
    goos, _, goarch = target.partition('_')
    level_key, level = LEVELS[goarch]
    package = wanted_programs[name]
    record, why = build_record(data, scratch)
    if record is None:
        faults.append(f'{name}: {why}')
    elif record != (package, goos, goarch, level):
        faults.append(f'{name}: built from {record[0]} for {record[1]}_{record[2]} at {record[3]}, and not from {package} for {target} at {level_key}={level}')
    if mode & 0o555 != 0o555:
        faults.append(f'{name}: mode {mode:04o}, which not everyone can read and execute')
    return faults


def main():
    parser = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    parser.add_argument('--dist', type=Path, required=True, help='the directory GoReleaser wrote')
    parser.add_argument('--version', required=True, help='the version in the archive names, without the leading v')
    parser.add_argument('--tree', type=Path, default=ROOT, help='the repository the archives were built from')
    parser.add_argument('--commit', default='HEAD', help='the commit the archives were built from')
    parser.add_argument('--target', action='append', help='check these targets only (for the tests of this script)')
    args = parser.parse_args()
    tree = args.tree.resolve()
    commit = git(tree, 'rev-parse', '--verify', f'{args.commit}^{{commit}}').decode('ascii').strip()
    wanted_files, wanted_programs = committed(tree, commit), programs(tree, commit)
    failed = False
    with tempfile.TemporaryDirectory(prefix='release-archives-') as scratch:
        for target in args.target or TARGETS:
            extension = 'zip' if target.startswith('windows_') else 'tar.gz'
            archive = args.dist / f'{PROJECT}_{args.version}_{target}.{extension}'
            if not archive.is_file():
                print(f'{target}: {archive.name} is not there', file=sys.stderr)
                failed = True
                continue
            faults = check(archive, target, wanted_files, wanted_programs, Path(scratch))
            for fault in faults:
                print(f'{target}: {fault}', file=sys.stderr)
            if faults:
                failed = True
            else:
                print(f'{target}: {archive.name} holds what commit {commit[:12]} says a release holds')
    return 1 if failed else 0


if __name__ == '__main__':
    sys.exit(main())
