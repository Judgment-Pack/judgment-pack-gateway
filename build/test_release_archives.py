#!/usr/bin/env python3
"""The archive check holds each thing it says it holds: one negative case each.

Usage: python3 build/test_release_archives.py

A tree is made in a temporary directory, with the shape of this repository
where the check reads it: the documents, a corpus and a catalog that git
tracks, and two programs under adapters/cmd beside the core. The programs
are real ones, built by the toolchain for two platforms, since what the
check reads is the record the toolchain writes. Archives of that tree pass;
then each is spoiled in one way, and the check must refuse it and say why.
"""
import io
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parent))
import release_archives as checked  # noqa: E402

PROGRAM = 'package main\n\nfunc main() {}\n'
TARGETS = ['linux_amd64', 'windows_arm64']


def go_build(module, package, output, goos, goarch, **settings):
    environment = dict(os.environ, GOOS=goos, GOARCH=goarch, CGO_ENABLED='0', GOWORK='off', GOFLAGS='-buildvcs=false', **settings)
    subprocess.run(['go', 'build', '-trimpath', '-ldflags', '-s -w', '-o', str(output), package], cwd=module, env=environment, check=True)


class ArchiveChecks(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.scratch = Path(tempfile.mkdtemp(prefix='release-archives-test-'))
        tree = cls.tree = cls.scratch / 'tree'
        for name in checked.DOCUMENTS:
            (tree / name).parent.mkdir(parents=True, exist_ok=True)
            (tree / name).write_text(f'{name}\n')
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
        git = ['git', '-C', str(tree), '-c', 'user.name=test', '-c', 'user.email=test@invalid', '-c', 'commit.gpgsign=false']
        subprocess.run(['git', 'init', '-q', str(tree)], check=True)
        subprocess.run(git + ['add', '.'], check=True)
        subprocess.run(git + ['commit', '-q', '-m', 'tree'], check=True)

        cls.built = {}
        for target in TARGETS + ['linux_arm64']:
            goos, _, goarch = target.partition('_')
            where = cls.scratch / 'built' / target
            where.mkdir(parents=True)
            go_build(tree / 'go', '.', where / 'gateway', goos, goarch)
            for name in ('adapter-one', 'adapter-two'):
                go_build(tree / 'adapters', f'./cmd/{name}', where / name, goos, goarch)
            cls.built[target] = where
        go_build(tree / 'go', '.', cls.scratch / 'built' / 'gateway-v3', 'linux', 'amd64', GOAMD64='v3')

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.scratch, ignore_errors=True)

    def contents(self, target):
        """What a sound archive of the target holds: name -> (mode, bytes)."""
        suffix = '.exe' if target.startswith('windows_') else ''
        held = {name: (0o644, (self.tree / name).read_bytes()) for name in checked.DOCUMENTS}
        for name in ('corpus/canon.json', 'corpus/stores/one.json', 'catalog/postgres.json'):
            held[name] = (0o644, (self.tree / name).read_bytes())
        for name in ('gateway', 'adapter-one', 'adapter-two'):
            held[name + suffix] = (0o755, (self.built[target] / name).read_bytes())
        return held

    def archive(self, target, held, extra=()):
        """Write the archive of the target; extra is tar members or zip entries added as given."""
        dist = Path(tempfile.mkdtemp(dir=self.scratch))
        if target.startswith('windows_'):
            path = dist / f'{checked.PROJECT}_1.0.0_{target}.zip'
            with zipfile.ZipFile(path, 'w') as opened:
                for name, (mode, data) in held.items():
                    info = zipfile.ZipInfo(name)
                    info.external_attr = (0o100000 | mode) << 16
                    opened.writestr(info, data)
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
        archive = next(dist.iterdir())
        return checked.check(archive, target, self.tree, dist)

    def refused(self, target, held, saying, extra=()):
        faults = self.faults(target, held, extra)
        self.assertTrue(any(saying in fault for fault in faults), f'no fault says {saying!r}: {faults}')

    def test_sound_archives_pass(self):
        for target in TARGETS:
            self.assertEqual(self.faults(target, self.contents(target)), [], target)

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

    def test_a_corpus_file_with_its_line_ending_converted(self):
        held = self.contents('linux_amd64')
        held['corpus/canon.json'] = (0o644, b'{"a":1}\n')
        self.refused('linux_amd64', held, 'corpus/canon.json: not the bytes the tree holds')

    def test_a_changed_document(self):
        held = self.contents('windows_arm64')
        held['SPEC.md'] = (0o644, b'another specification\n')
        self.refused('windows_arm64', held, 'SPEC.md: not the bytes the tree holds')

    def test_a_program_built_from_another_package(self):
        held = self.contents('linux_amd64')
        held['adapter-one'] = held['adapter-two']
        self.refused('linux_amd64', held, 'adapter-one: built from adapters/cmd/adapter-two')

    def test_a_program_built_for_another_system(self):
        held = self.contents('linux_amd64')
        held['gateway'] = (0o755, (self.built['windows_arm64'] / 'gateway').read_bytes())
        self.refused('linux_amd64', held, 'gateway: built from gateway for windows_arm64')

    def test_a_program_built_for_another_architecture(self):
        held = self.contents('linux_amd64')
        held['adapter-one'] = (0o755, (self.built['linux_arm64'] / 'adapter-one').read_bytes())
        self.refused('linux_amd64', held, 'adapter-one: built from adapters/cmd/adapter-one for linux_arm64')

    def test_a_program_built_above_the_level_a_release_promises(self):
        held = self.contents('linux_amd64')
        held['gateway'] = (0o755, (self.scratch / 'built' / 'gateway-v3').read_bytes())
        self.refused('linux_amd64', held, 'at v3, and not from gateway for linux_amd64 at GOAMD64=v1')

    def test_a_program_that_is_not_a_program(self):
        held = self.contents('linux_amd64')
        held['adapter-one'] = (0o755, b'#!/bin/sh\nexit 0\n')
        self.refused('linux_amd64', held, 'adapter-one: it carries no build record')

    def test_a_program_without_its_executable_bit(self):
        held = self.contents('linux_amd64')
        held['adapter-two'] = (0o644, held['adapter-two'][1])
        self.refused('linux_amd64', held, 'adapter-two: not executable')

    def test_a_directory_of_programs_under_a_program_s_name(self):
        # Two real programs in a directory named for one: `go version -m`
        # reads a directory through, and the last record in it is a sound one.
        held = self.contents('windows_arm64')
        del held['gateway.exe']
        held['gateway.exe/a'] = (0o755, (self.built['linux_amd64'] / 'gateway').read_bytes())
        held['gateway.exe/z.exe'] = (0o755, (self.built['windows_arm64'] / 'gateway').read_bytes())
        faults = self.faults('windows_arm64', held)
        self.assertIn('gateway.exe: not in the archive', faults)
        self.assertTrue(any('gateway.exe/z.exe: a file a release does not hold' in fault for fault in faults), faults)

    def test_a_link_in_place_of_a_file(self):
        held = self.contents('linux_amd64')
        del held['LICENSE']
        link = tarfile.TarInfo('LICENSE')
        link.type, link.linkname = tarfile.SYMTYPE, '/etc/hostname'
        self.refused('linux_amd64', held, 'LICENSE: a link, and a release holds files', extra=[(link, None)])

    def test_a_path_that_leaves_the_archive(self):
        held = self.contents('linux_amd64')
        held['../outside'] = (0o644, b'x')
        self.refused('linux_amd64', held, 'a path that leaves the archive')

    def test_an_archive_that_is_not_there(self):
        dist = self.archive('linux_amd64', self.contents('linux_amd64'))
        ran = subprocess.run([sys.executable, str(Path(checked.__file__)), '--dist', str(dist), '--version', '1.0.0', '--tree', str(self.tree), '--target', 'linux_amd64', '--target', 'windows_arm64'], capture_output=True, text=True)
        self.assertEqual(ran.returncode, 1, ran.stderr)
        self.assertIn('linux_amd64: judgment-pack-gateway_1.0.0_linux_amd64.tar.gz holds what a release holds', ran.stdout)
        self.assertIn('windows_arm64: judgment-pack-gateway_1.0.0_windows_arm64.zip is not there', ran.stderr)


if __name__ == '__main__':
    unittest.main(verbosity=2)
