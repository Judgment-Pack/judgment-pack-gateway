#!/usr/bin/env python3
"""The archive check refuses what it says it refuses: sound archives, then one fault at a time.

Usage: python3 build/test_release_archives.py

A repository is made in a temporary directory, with the shape of this one
where the check reads it: the documents, a corpus and a catalog, and two
programs under adapters/cmd beside the core, all committed. The programs
are real ones, built by the toolchain, since what the check reads is the
record the toolchain writes. Archives of that commit pass; then each is
spoiled in one way, and the check must refuse it and say why.

The cases are not a proof that nothing else gets through.
"""
import io
import os
from pathlib import Path
import shutil
import stat
import struct
import subprocess
import sys
import tarfile
import tempfile
import unittest
import zipfile
import zlib

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
import release_archives as checked  # noqa: E402

PROGRAM = 'package main\n\nfunc main() {}\n'
TARGETS = ['linux_amd64', 'windows_arm64']
RECORD = 'program: go1.26.5\n\tpath\tgateway\n\tmod\tgateway\t(devel)\t\n\tbuild\tGOARCH=amd64\n\tbuild\tGOOS=linux\n\tbuild\tGOAMD64=v1\n'


def go_build(module, package, output, goos, goarch, **settings):
    # The levels are set here and not taken from whoever runs the tests.
    levels = {'GOAMD64': 'v1', 'GOARM64': 'v8.0'}
    levels.update(settings)
    environment = dict(os.environ, GOOS=goos, GOARCH=goarch, CGO_ENABLED='0', GOWORK='off', GOFLAGS='-buildvcs=false', **levels)
    subprocess.run(['go', 'build', '-trimpath', '-ldflags', '-s -w', '-o', str(output), package], cwd=module, env=environment, check=True)


class ArchiveChecks(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.scratch = Path(tempfile.mkdtemp(prefix='release-archives-test-'))
        cls.addClassCleanup(shutil.rmtree, cls.scratch, ignore_errors=True)
        tree = cls.tree = cls.scratch / 'tree'
        tree.mkdir()
        for name in checked.DOCUMENTS:
            (tree / name).write_bytes(f'{name}\n'.encode())
        (tree / 'corpus' / 'stores').mkdir(parents=True)
        (tree / 'corpus' / 'canon.json').write_bytes(b'{"a":1}\r\n')
        (tree / 'corpus' / 'stores' / 'one.json').write_bytes(b'{}\n')
        (tree / 'catalog').mkdir()
        (tree / 'catalog' / 'postgres.json').write_bytes(b'{}\n')
        (tree / 'go').mkdir()
        (tree / 'go' / 'go.mod').write_text('module gateway\n\ngo 1.26\n')
        (tree / 'go' / 'main.go').write_text(PROGRAM)
        for name in ('adapter-one', 'adapter-two'):
            (tree / 'adapters' / 'cmd' / name).mkdir(parents=True)
            (tree / 'adapters' / 'cmd' / name / 'main.go').write_text(PROGRAM)
        (tree / 'adapters' / 'go.mod').write_text('module adapters\n\ngo 1.26\n')
        (tree / '.gitattributes').write_text('corpus/** -text\n')
        git = ['git', '-C', str(tree), '-c', 'user.name=test', '-c', 'user.email=test@invalid', '-c', 'commit.gpgsign=false']
        subprocess.run(['git', 'init', '-q', str(tree)], check=True)
        subprocess.run(git + ['add', '.'], check=True)
        subprocess.run(git + ['commit', '-q', '-m', 'tree'], check=True)
        cls.files = checked.committed(tree, 'HEAD')
        cls.programs = checked.programs(tree, 'HEAD')

        cls.built = {}
        for target in TARGETS + ['linux_arm64', 'darwin_amd64']:
            goos, _, goarch = target.partition('_')
            where = cls.scratch / 'built' / target
            where.mkdir(parents=True)
            go_build(tree / 'go', '.', where / 'gateway', goos, goarch)
            for name in ('adapter-one', 'adapter-two'):
                go_build(tree / 'adapters', f'./cmd/{name}', where / name, goos, goarch)
            cls.built[target] = where
        go_build(tree / 'go', '.', cls.scratch / 'built' / 'gateway-amd64-v3', 'linux', 'amd64', GOAMD64='v3')
        go_build(tree / 'go', '.', cls.scratch / 'built' / 'gateway-arm64-v8.1', 'windows', 'arm64', GOARM64='v8.1')
        go_build(tree / 'go', '.', cls.scratch / 'built' / 'gateway-darwin-arm64', 'darwin', 'arm64')

    def contents(self, target):
        """What a sound archive of the target holds: name -> (mode, bytes)."""
        suffix = '.exe' if target.startswith('windows_') else ''
        held = {name: (0o644, data) for name, data in self.files.items()}
        for name in ('gateway', 'adapter-one', 'adapter-two'):
            held[name + suffix] = (0o755, (self.built[target] / name).read_bytes())
        return held

    def archive(self, target, held, extra=()):
        """Write the archive of the target; extra is tar members or zip entries added after, as given."""
        dist = Path(tempfile.mkdtemp(dir=self.scratch))
        if target.startswith('windows_'):
            path = dist / f'{checked.PROJECT}_1.0.0_{target}.zip'
            with zipfile.ZipFile(path, 'w') as opened:
                for name, (mode, data) in held.items():
                    opened.writestr(self.zip_entry(name, stat.S_IFREG, mode), data)
                for info, data in extra:
                    opened.writestr(info, data)
            return dist
        path = dist / f'{checked.PROJECT}_1.0.0_{target}.tar.gz'
        with tarfile.open(path, 'w:gz') as opened:
            for name, (mode, data) in held.items():
                info = tarfile.TarInfo(name)
                info.mode, info.size = mode, len(data)
                opened.addfile(info, io.BytesIO(data))
            for info, data in extra:
                opened.addfile(info, io.BytesIO(data) if data is not None else None)
        return dist

    def faults(self, target, held, extra=()):
        dist = self.archive(target, held, extra)
        return checked.check(next(dist.iterdir()), target, self.files, self.programs, dist)

    def refused(self, target, held, saying, extra=()):
        faults = self.faults(target, held, extra)
        self.assertTrue(any(saying in fault for fault in faults), f'no fault says {saying!r}: {faults}')

    def tar_member(self, name, kind, mode=0o644, link=''):
        info = tarfile.TarInfo(name)
        info.type, info.mode, info.linkname = kind, mode, link
        return info

    def zip_entry(self, name, form, mode=0o644, system=3, low=0, extra=b'', written=None):
        """A zip entry as a Unix system records a member, unless told otherwise; written is the name as the header has it."""
        info = zipfile.ZipInfo(name)
        info.create_system, info.external_attr, info.extra = system, ((form | mode) << 16) | low, extra
        if written is not None:
            info.filename = written
        return info

    # Sound archives.

    def test_sound_archives_pass(self):
        for target in TARGETS:
            self.assertEqual(self.faults(target, self.contents(target)), [], target)

    def test_a_zip_entry_with_a_time_beside_its_name_passes(self):
        # As the packer writes every entry: one field, a time.
        time = struct.pack('<HHBI', 0x5455, 5, 1, 1790000000)
        held = self.contents('windows_arm64')
        entries = [(self.zip_entry(name, stat.S_IFREG, mode, extra=time), data) for name, (mode, data) in held.items()]
        self.assertEqual(self.faults('windows_arm64', {}, extra=entries), [])

    def test_the_commit_is_what_is_compared_and_not_the_tree(self):
        changed, removed = self.tree / 'SPEC.md', self.tree / 'corpus' / 'canon.json'
        kept = changed.read_bytes(), removed.read_bytes()
        try:
            changed.write_bytes(b'changed after the commit\n')
            removed.unlink()
            files = checked.committed(self.tree, 'HEAD')
            self.assertEqual(files, self.files)
            held = self.contents('linux_amd64')
            held['SPEC.md'] = (0o644, b'changed after the commit\n')
            dist = self.archive('linux_amd64', held)
            faults = checked.check(next(dist.iterdir()), 'linux_amd64', files, self.programs, dist)
            self.assertEqual(faults, ['SPEC.md: not the bytes the commit holds'])
        finally:
            changed.write_bytes(kept[0])
            removed.write_bytes(kept[1])

    # What is missing, and what is too much.

    def test_a_missing_program(self):
        held = self.contents('linux_amd64')
        del held['adapter-two']
        self.refused('linux_amd64', held, 'adapter-two: not in the archive')

    def test_a_missing_corpus_file(self):
        held = self.contents('linux_amd64')
        del held['corpus/canon.json']
        self.refused('linux_amd64', held, 'corpus/canon.json: not in the archive')

    def test_a_file_a_release_does_not_hold(self):
        held = self.contents('windows_arm64')
        held['notes.txt'] = (0o644, b'stray\n')
        self.refused('windows_arm64', held, 'notes.txt: a file a release does not hold')

    def test_a_file_too_many_in_the_corpus(self):
        held = self.contents('linux_amd64')
        held['corpus/more.json'] = (0o644, b'{}\n')
        self.refused('linux_amd64', held, 'corpus/more.json: a file a release does not hold')

    def test_a_document_under_another_case(self):
        held = self.contents('linux_amd64')
        held['license'] = held['LICENSE']
        self.refused('linux_amd64', held, 'license: a file a release does not hold')

    def test_a_member_twice(self):
        # With other bytes the second time: neither is read, so nothing is said of bytes.
        held = self.contents('linux_amd64')
        again = tarfile.TarInfo('LICENSE')
        again.size = 5
        faults = self.faults('linux_amd64', held, extra=[(again, b'other')])
        self.assertEqual(faults, ['LICENSE: in the archive twice'])

    def test_a_member_larger_than_any_of_a_release(self):
        kept = checked.LIMIT
        size = len(self.files['LICENSE'])
        try:
            checked.LIMIT = size - 1
            faults = self.faults('linux_amd64', self.contents('linux_amd64'))
        finally:
            checked.LIMIT = kept
        self.assertIn(f'LICENSE: {size} bytes, more than any file of a release', faults)
        self.assertFalse(any('not the bytes' in fault or 'build record' in fault for fault in faults), faults)

    def test_a_commit_without_a_directory_a_release_holds(self):
        bare = self.scratch / 'bare'
        bare.mkdir()
        for name in checked.DOCUMENTS:
            (bare / name).write_bytes(b'x\n')
        (bare / 'corpus').mkdir()
        (bare / 'corpus' / 'canon.json').write_bytes(b'{}\n')
        git = ['git', '-C', str(bare), '-c', 'user.name=test', '-c', 'user.email=test@invalid', '-c', 'commit.gpgsign=false']
        subprocess.run(['git', 'init', '-q', str(bare)], check=True)
        subprocess.run(git + ['add', '.'], check=True)
        subprocess.run(git + ['commit', '-q', '-m', 'no catalog'], check=True)
        with self.assertRaises(SystemExit) as refused:
            checked.committed(bare, 'HEAD')
        self.assertEqual(str(refused.exception), 'the commit holds no file under catalog/')

    # Bytes.

    def test_a_corpus_file_with_its_line_ending_converted(self):
        held = self.contents('linux_amd64')
        held['corpus/canon.json'] = (0o644, b'{"a":1}\n')
        self.refused('linux_amd64', held, 'corpus/canon.json: not the bytes the commit holds')

    def test_a_changed_document(self):
        held = self.contents('windows_arm64')
        held['SPEC.md'] = (0o644, b'another specification\n')
        self.refused('windows_arm64', held, 'SPEC.md: not the bytes the commit holds')

    # Names.

    def test_a_name_with_a_leading_dot(self):
        held = self.contents('linux_amd64')
        held['./LICENSE'] = held.pop('LICENSE')
        faults = self.faults('linux_amd64', held)
        self.assertIn('./LICENSE: a name not written the plain way', faults)
        self.assertIn('LICENSE: not in the archive', faults)

    def test_a_program_named_with_a_trailing_slash(self):
        held = self.contents('linux_amd64')
        held['gateway/'] = held.pop('gateway')
        faults = self.faults('linux_amd64', held)
        self.assertIn('gateway/: a name not written the plain way', faults)
        self.assertIn('gateway: not in the archive', faults)

    def test_a_path_that_leaves_the_archive(self):
        held = self.contents('linux_amd64')
        held['../outside'] = (0o644, b'x')
        self.refused('linux_amd64', held, '../outside: a name not written the plain way')

    def test_a_name_with_a_backslash(self):
        held = self.contents('windows_arm64')
        held['corpus\\canon.json'] = held.pop('corpus/canon.json')
        faults = self.faults('windows_arm64', held)
        self.assertIn('corpus\\\\canon.json: a name not written the plain way', faults)
        self.assertIn('corpus/canon.json: not in the archive', faults)

    def test_a_member_with_no_name(self):
        faults = self.faults('windows_arm64', self.contents('windows_arm64'), extra=[(self.zip_entry('x', stat.S_IFREG, written=''), b'x')])
        self.assertEqual(faults, [': a name not written the plain way'])

    def test_a_zip_name_that_a_reader_would_cut_short(self):
        # The reader ends a name at its first zero byte; another program need not.
        held = self.contents('windows_arm64')
        data = held.pop('LICENSE')[1]
        faults = self.faults('windows_arm64', held, extra=[(self.zip_entry('LICENSE', stat.S_IFREG, written='LICENSE\0x'), data)])
        self.assertEqual(sorted(faults), ['LICENSE: not in the archive', 'LICENSE\\x00x: a name not written the plain way'])

    def test_a_zip_entry_that_gives_its_name_a_second_time(self):
        # The field for a name in Unicode, which some programs take in place of the name.
        other = 'not-a-release-file.txt'.encode()
        field = struct.pack('<BI', 1, zlib.crc32(b'LICENSE')) + other
        held = self.contents('windows_arm64')
        data = held.pop('LICENSE')[1]
        faults = self.faults('windows_arm64', held, extra=[(self.zip_entry('LICENSE', stat.S_IFREG, extra=struct.pack('<HH', 0x7075, len(field)) + field), data)])
        self.assertEqual(faults, ['LICENSE: a member whose header says more than a name, a mode and a time, and a release holds files'])

    def test_a_zip_entry_that_says_more_than_the_packer_writes(self):
        time = struct.pack('<HHBI', 0x5455, 5, 1, 1790000000)
        said = {
            'a field that is not a time': dict(extra=struct.pack('<HH', 0x7875, 0)),
            'a time twice': dict(extra=time + time),
            'an attribute of another system': dict(low=0x20),
        }
        for what, how in said.items():
            held = self.contents('windows_arm64')
            data = held.pop('SPEC.md')[1]
            faults = self.faults('windows_arm64', held, extra=[(self.zip_entry('SPEC.md', stat.S_IFREG, **how), data)])
            self.assertEqual(faults, ['SPEC.md: a member whose header says more than a name, a mode and a time, and a release holds files'], what)
        held = self.contents('windows_arm64')
        data = held.pop('SPEC.md')[1]
        entry = self.zip_entry('SPEC.md', stat.S_IFREG)
        entry.comment = b'x'
        faults = self.faults('windows_arm64', held, extra=[(entry, data)])
        self.assertEqual(faults, ['SPEC.md: a member whose header says more than a name, a mode and a time, and a release holds files'], 'a comment')

    def test_the_flags_of_a_zip_entry(self):
        # Read from the entry and not from an archive: the writer at hand keeps no flag it is given.
        for flags, kind in ((0, 'file'), (0x8, 'file'), (0x800, 'file'), (0x808, 'file'), (0x1, None), (0x2000, None), (0x809, None)):
            entry = self.zip_entry('SPEC.md', stat.S_IFREG)
            entry.flag_bits = flags
            self.assertEqual(checked.zip_kind(entry), kind or 'member whose header says more than a name, a mode and a time', hex(flags))

    def test_a_zip_entry_with_a_field_cut_short(self):
        held = self.contents('windows_arm64')
        data = held.pop('SPEC.md')[1]
        time = struct.pack('<HHBI', 0x5455, 5, 1, 1790000000)
        faults = self.faults('windows_arm64', held, extra=[(self.zip_entry('SPEC.md', stat.S_IFREG, extra=time[:6]), data)])
        self.assertEqual(len(faults), 1, faults)
        self.assertTrue(faults[0].startswith('the archive cannot be read through: '), faults)

    def test_the_fields_of_a_zip_entry(self):
        time = struct.pack('<HHBI', 0x5455, 5, 1, 1790000000)
        self.assertEqual(checked.zip_fields(b''), [])
        self.assertEqual(checked.zip_fields(time), [0x5455])
        self.assertEqual(checked.zip_fields(time + struct.pack('<HH', 0x7075, 0)), [0x5455, 0x7075])
        self.assertIsNone(checked.zip_fields(time[:3]))
        self.assertIsNone(checked.zip_fields(time[:6]))
        self.assertIsNone(checked.zip_fields(time + b'\0'))

    def test_a_zip_whose_two_namings_of_a_member_differ(self):
        dist = self.archive('windows_arm64', self.contents('windows_arm64'))
        archive = next(dist.iterdir())
        raw = archive.read_bytes()
        first = raw.index(b'SECURITY.md')
        self.assertNotEqual(raw.index(b'SECURITY.md', first + 1), -1)
        archive.write_bytes(raw[:first] + b'SECURITY.mx' + raw[first + 11:])
        faults = checked.check(archive, 'windows_arm64', self.files, self.programs, dist)
        self.assertEqual(len(faults), 1, faults)
        self.assertTrue(faults[0].startswith('the archive cannot be read through: '), faults)

    # Kinds.

    def test_a_directory_even_one_a_release_s_files_lie_in(self):
        self.refused('linux_amd64', self.contents('linux_amd64'), 'corpus: a directory, and a release holds files',
                     extra=[(self.tar_member('corpus', tarfile.DIRTYPE, 0o755), None)])

    def test_a_directory_under_the_name_of_a_file_already_there(self):
        # Unpacked, the directory would take the file's place.
        faults = self.faults('linux_amd64', self.contents('linux_amd64'),
                             extra=[(self.tar_member('corpus/canon.json', tarfile.DIRTYPE, 0o755), None)])
        self.assertEqual(faults, ['corpus/canon.json: in the archive twice'])

    def test_a_directory_of_programs_under_a_program_s_name(self):
        # `go version -m` reads a directory through, and the last record in it is a sound one.
        held = self.contents('windows_arm64')
        del held['gateway.exe']
        held['gateway.exe/a'] = (0o755, (self.built['linux_amd64'] / 'gateway').read_bytes())
        held['gateway.exe/z.exe'] = (0o755, (self.built['windows_arm64'] / 'gateway').read_bytes())
        faults = self.faults('windows_arm64', held)
        self.assertIn('gateway.exe: not in the archive', faults)
        self.assertIn('gateway.exe/z.exe: a file a release does not hold', faults)

    def test_a_link_in_place_of_a_file(self):
        held = self.contents('linux_amd64')
        del held['LICENSE']
        self.refused('linux_amd64', held, 'LICENSE: a link, and a release holds files',
                     extra=[(self.tar_member('LICENSE', tarfile.SYMTYPE, link='/etc/hostname'), None)])

    def test_a_hard_link_in_place_of_a_file(self):
        held = self.contents('linux_amd64')
        del held['adapter-two']
        self.refused('linux_amd64', held, 'adapter-two: a link, and a release holds files',
                     extra=[(self.tar_member('adapter-two', tarfile.LNKTYPE, 0o755, link='adapter-one'), None)])

    def test_a_tar_member_of_no_kind_the_packer_writes(self):
        for kind in (tarfile.FIFOTYPE, tarfile.CHRTYPE, tarfile.BLKTYPE, tarfile.CONTTYPE, tarfile.AREGTYPE):
            held = self.contents('linux_amd64')
            data = held.pop('gateway')[1]
            member = self.tar_member('gateway', kind, 0o755)
            carried = data if kind in (tarfile.CONTTYPE, tarfile.AREGTYPE) else None
            member.size = len(data) if carried else 0
            self.assertEqual(self.faults('linux_amd64', held, extra=[(member, carried)]),
                             ['gateway: a member of no kind the packer writes, and a release holds files'], kind)

    def pax_archive(self, held, name, headers):
        """The archive of linux_amd64 in the format of extended headers, one member carrying the given ones."""
        dist = Path(tempfile.mkdtemp(dir=self.scratch))
        with tarfile.open(dist / f'{checked.PROJECT}_1.0.0_linux_amd64.tar.gz', 'w:gz', format=tarfile.PAX_FORMAT) as opened:
            for member, (mode, data) in held.items():
                info = tarfile.TarInfo(member)
                info.mode, info.size = mode, len(data)
                if member == name:
                    info.pax_headers = dict(headers)
                opened.addfile(info, io.BytesIO(data))
        return dist

    def test_a_tar_member_named_by_an_extended_header(self):
        # The reader drops a trailing slash from such a name; unpacked, it makes a directory and no program.
        for written in ('gateway/', 'gateway//', 'other'):
            dist = self.pax_archive(self.contents('linux_amd64'), 'gateway', {'path': written})
            faults = checked.check(next(dist.iterdir()), 'linux_amd64', self.files, self.programs, dist)
            self.assertIn('gateway: not in the archive', faults, written)
            self.assertIn(f'{written}: a member whose header says more than a name, a mode and a time, and a release holds files', faults, written)

    def test_a_tar_member_with_any_extended_header(self):
        dist = self.pax_archive(self.contents('linux_amd64'), 'LICENSE', {'comment': 'x'})
        faults = checked.check(next(dist.iterdir()), 'linux_amd64', self.files, self.programs, dist)
        self.assertEqual(faults, ['LICENSE: a member whose header says more than a name, a mode and a time, and a release holds files'])

    def test_a_zip_entry_that_says_it_is_a_link(self):
        held = self.contents('windows_arm64')
        del held['LICENSE']
        self.refused('windows_arm64', held, 'LICENSE: a link, and a release holds files',
                     extra=[(self.zip_entry('LICENSE', stat.S_IFLNK), b'/etc/hostname')])

    def test_a_zip_entry_that_says_it_is_not_a_file(self):
        program = (self.built['windows_arm64'] / 'gateway').read_bytes()
        kinds = {
            'a pipe': (dict(form=stat.S_IFIFO), 'member of no kind the packer writes'),
            'a device': (dict(form=stat.S_IFCHR), 'member of no kind the packer writes'),
            'a socket': (dict(form=stat.S_IFSOCK), 'member of no kind the packer writes'),
            'no form at all': (dict(form=0), 'member of no kind the packer writes'),
            'a file of another system': (dict(form=stat.S_IFREG, system=0), 'member of no kind the packer writes'),
            'a directory by its form': (dict(form=stat.S_IFDIR), 'directory'),
            'a directory by the attribute of another system': (dict(form=stat.S_IFREG, low=0x10), 'directory'),
            'a directory by that attribute alone': (dict(form=0, system=0, low=0x10), 'directory'),
        }
        for what, (how, kind) in kinds.items():
            held = self.contents('windows_arm64')
            del held['gateway.exe']
            how = dict(how)
            faults = self.faults('windows_arm64', held, extra=[(self.zip_entry('gateway.exe', how.pop('form'), 0o755, **how), program)])
            self.assertEqual(faults, [f'gateway.exe: a {kind}, and a release holds files'], what)

    def test_a_zip_directory_by_its_name(self):
        faults = self.faults('windows_arm64', self.contents('windows_arm64'), extra=[(self.zip_entry('corpus/', stat.S_IFREG, 0o755), b'')])
        self.assertEqual(faults, ['corpus/: a directory, and a release holds files'])

    # Programs.

    def test_a_program_built_from_another_package(self):
        held = self.contents('linux_amd64')
        held['adapter-one'] = held['adapter-two']
        self.refused('linux_amd64', held, 'adapter-one: built from adapters/cmd/adapter-two')

    def test_a_program_built_for_another_system_and_the_same_architecture(self):
        held = self.contents('linux_amd64')
        held['gateway'] = (0o755, (self.built['darwin_amd64'] / 'gateway').read_bytes())
        self.refused('linux_amd64', held, 'gateway: built from gateway for darwin_amd64 at v1')

    def test_a_program_built_for_another_architecture_and_the_same_system(self):
        held = self.contents('linux_amd64')
        held['adapter-one'] = (0o755, (self.built['linux_arm64'] / 'adapter-one').read_bytes())
        self.refused('linux_amd64', held, 'adapter-one: built from adapters/cmd/adapter-one for linux_arm64')

    def test_a_program_built_above_the_level_a_release_promises(self):
        held = self.contents('linux_amd64')
        held['gateway'] = (0o755, (self.scratch / 'built' / 'gateway-amd64-v3').read_bytes())
        self.refused('linux_amd64', held, 'gateway: built from gateway for linux_amd64 at v3, and not from gateway for linux_amd64 at GOAMD64=v1')
        held = self.contents('windows_arm64')
        held['gateway.exe'] = (0o755, (self.scratch / 'built' / 'gateway-arm64-v8.1').read_bytes())
        self.refused('windows_arm64', held, 'gateway.exe: built from gateway for windows_arm64 at v8.1, and not from gateway for windows_arm64 at GOARM64=v8.0')

    def test_a_program_that_is_not_a_program(self):
        held = self.contents('linux_amd64')
        held['adapter-one'] = (0o755, b'#!/bin/sh\nexit 0\n')
        self.refused('linux_amd64', held, 'adapter-one: it carries no build record')

    def test_a_program_not_everyone_can_run(self):
        # Each of the six bits by itself, then some modes as they are met.
        for mode in (0o355, 0o655, 0o715, 0o745, 0o751, 0o754, 0o644, 0o641, 0o700, 0o311):
            held = self.contents('linux_amd64')
            held['adapter-two'] = (mode, held['adapter-two'][1])
            self.assertEqual(self.faults('linux_amd64', held), [f'adapter-two: mode {mode:04o}, which not everyone can read and execute'])
        # The packer records the mode of a program for Windows as of any other.
        held = self.contents('windows_arm64')
        held['gateway.exe'] = (0o644, held['gateway.exe'][1])
        self.assertEqual(self.faults('windows_arm64', held), ['gateway.exe: mode 0644, which not everyone can read and execute'])

    def test_a_universal_program(self):
        # A true one: two programs for macOS, of two architectures, in the container that holds both.
        parts = [(0x01000007, 3, (self.built['darwin_amd64'] / 'gateway').read_bytes()),
                 (0x0100000c, 0, (self.scratch / 'built' / 'gateway-darwin-arm64').read_bytes())]
        step, place, table, body = 1 << 14, 1 << 14, b'', b''
        for kind, sub, data in parts:
            table += struct.pack('>iiIII', kind, sub, place, len(data), 14)
            padded = data + b'\0' * (-len(data) % step)
            body += padded
            place += len(padded)
        whole = struct.pack('>II', 0xcafebabe, len(parts)) + table
        whole += b'\0' * (step - len(whole)) + body
        ran = subprocess.run(['go', 'version', '-m', '/dev/stdin'], input=whole, capture_output=True)
        held = self.contents('linux_amd64')
        held['gateway'] = (0o755, whole)
        self.assertEqual(self.faults('linux_amd64', held), ['gateway: it holds several programs, and a release holds one under each name'], ran)

    def test_a_name_of_a_document_and_of_a_program(self):
        dist = self.archive('linux_amd64', self.contents('linux_amd64'))
        faults = checked.check(next(dist.iterdir()), 'linux_amd64', self.files, dict(self.programs, LICENSE='adapters/cmd/LICENSE'), dist)
        self.assertEqual(faults, ['LICENSE: the name of a document and of a program'])

    def with_toolchain(self, script, data=b'#!/bin/sh\n'):
        """What is said of a file's build record when `go` is the given script."""
        tool = Path(tempfile.mkdtemp(dir=self.scratch))
        (tool / 'go').write_text(script)
        (tool / 'go').chmod(0o755)
        kept = os.environ['PATH']
        try:
            os.environ['PATH'] = f'{tool}{os.pathsep}{kept}'
            return checked.build_record(data, self.scratch)
        finally:
            os.environ['PATH'] = kept

    def test_a_toolchain_that_says_nothing_of_a_file_and_does_not_fail(self):
        self.assertEqual(self.with_toolchain('#!/bin/sh\nexit 0\n'), (None, 'it carries no build record: go version -m said nothing'))

    def test_a_toolchain_that_gives_a_record_and_fails(self):
        script = "#!/bin/sh\nprintf '%s' '" + RECORD + "'\necho 'could not read the whole file' >&2\nexit 1\n"
        self.assertEqual(self.with_toolchain(script), (None, 'it carries no build record: could not read the whole file'))

    def test_a_toolchain_that_gives_a_record(self):
        script = "#!/bin/sh\nprintf '%s' '" + RECORD + "'\n"
        self.assertEqual(self.with_toolchain(script), (('gateway', 'linux', 'amd64', 'v1'), ''))

    def test_a_file_that_holds_several_programs(self):
        # As a universal Mach-O begins, in either byte order and either width;
        # the toolchain would read the first program in it.
        program = (self.built['darwin_amd64'] / 'gateway').read_bytes()
        for start in (b'\xca\xfe\xba\xbe', b'\xbe\xba\xfe\xca', b'\xca\xfe\xba\xbf', b'\xbf\xba\xfe\xca'):
            held = self.contents('linux_amd64')
            held['gateway'] = (0o755, start + program)
            self.refused('linux_amd64', held, 'gateway: it holds several programs')

    def test_each_part_of_the_record_is_compared_by_itself(self):
        # The levels of two architectures share no name, so no real program
        # differs from another in its architecture alone: the record is given.
        held = {name: value for name, value in self.contents('linux_amd64').items() if not name.startswith('adapter-')}
        sound = ('gateway', 'linux', 'amd64', 'v1')
        kept = checked.build_record
        try:
            for place, other in enumerate(('adapters/cmd/adapter-one', 'darwin', 'arm64', 'v2')):
                given = sound[:place] + (other,) + sound[place + 1:]
                checked.build_record = lambda data, scratch, given=given: (given, '')
                dist = self.archive('linux_amd64', held)
                faults = checked.check(next(dist.iterdir()), 'linux_amd64', self.files, {'gateway': 'gateway'}, dist)
                self.assertEqual(faults, [f'gateway: built from {given[0]} for {given[1]}_{given[2]} at {given[3]}, and not from gateway for linux_amd64 at GOAMD64=v1'])
            checked.build_record = lambda data, scratch: (sound, '')
            dist = self.archive('linux_amd64', held)
            self.assertEqual(checked.check(next(dist.iterdir()), 'linux_amd64', self.files, {'gateway': 'gateway'}, dist), [])
        finally:
            checked.build_record = kept

    # The build record, as text.

    def test_a_sound_record(self):
        self.assertEqual(checked.parse_record(RECORD), (('gateway', 'linux', 'amd64', 'v1'), ''))

    def test_a_record_of_two_programs(self):
        self.assertEqual(checked.parse_record(RECORD + RECORD), (None, 'its build record names 2 packages'))

    def test_a_record_that_names_no_package(self):
        self.assertEqual(checked.parse_record(RECORD.replace('\tpath\tgateway\n', '')), (None, 'its build record names 0 packages'))

    def test_a_record_without_its_system(self):
        self.assertEqual(checked.parse_record(RECORD.replace('\tbuild\tGOOS=linux\n', '')), (None, 'its build record states GOOS 0 times'))

    def test_a_record_with_its_architecture_twice(self):
        self.assertEqual(checked.parse_record(RECORD + '\tbuild\tGOARCH=arm64\n'), (None, 'its build record states GOARCH 2 times'))

    def test_a_record_without_its_level(self):
        self.assertEqual(checked.parse_record(RECORD.replace('\tbuild\tGOAMD64=v1\n', '')), (None, 'its build record states GOAMD64 0 times'))

    def test_a_record_with_lines_of_one_word(self):
        self.assertEqual(checked.parse_record(RECORD + '\tpath\n\tbuild\n\n'), (('gateway', 'linux', 'amd64', 'v1'), ''))

    def test_a_record_with_a_setting_on_a_line_that_is_not_a_build_line(self):
        self.assertEqual(checked.parse_record(RECORD + '\tdep\tGOOS=plan9\n'), (('gateway', 'linux', 'amd64', 'v1'), ''))

    def test_a_record_for_an_architecture_no_release_is_built_for(self):
        self.assertEqual(checked.parse_record(RECORD.replace('GOARCH=amd64', 'GOARCH=riscv64')), (None, 'its build record states an architecture no release is built for: riscv64'))

    # The script, as the workflow runs it.

    def run_script(self, dist, *targets, commit='HEAD'):
        arguments = [sys.executable, str(Path(checked.__file__)), '--dist', str(dist), '--version', '1.0.0', '--tree', str(self.tree), '--commit', commit]
        for target in targets:
            arguments += ['--target', target]
        return subprocess.run(arguments, capture_output=True, text=True)

    def test_an_archive_that_is_not_there(self):
        dist = self.archive('linux_amd64', self.contents('linux_amd64'))
        ran = self.run_script(dist, 'linux_amd64', 'windows_arm64')
        self.assertEqual(ran.returncode, 1, ran.stderr)
        self.assertIn('linux_amd64: judgment-pack-gateway_1.0.0_linux_amd64.tar.gz holds what commit', ran.stdout)
        self.assertIn('windows_arm64: judgment-pack-gateway_1.0.0_windows_arm64.zip is not there', ran.stderr)

    def test_a_fault_is_a_failure_of_the_script(self):
        held = self.contents('linux_amd64')
        held['notes.txt'] = (0o644, b'stray\n')
        ran = self.run_script(self.archive('linux_amd64', held), 'linux_amd64')
        self.assertEqual(ran.returncode, 1, ran.stdout)
        self.assertIn('linux_amd64: notes.txt: a file a release does not hold', ran.stderr)
        self.assertEqual(self.run_script(self.archive('linux_amd64', self.contents('linux_amd64')), 'linux_amd64').returncode, 0)

    def test_a_commit_that_is_not_there(self):
        ran = self.run_script(self.archive('linux_amd64', self.contents('linux_amd64')), 'linux_amd64', commit='no-such-commit')
        self.assertNotEqual(ran.returncode, 0)


if __name__ == '__main__':
    unittest.main(verbosity=2)
