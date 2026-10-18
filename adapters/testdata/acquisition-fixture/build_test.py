"""Refusal tests for the separate fixture builder; no network or Go builds."""
import importlib.util
from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import subprocess
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location('fixture_builder', Path(__file__).with_name('build.py'))
builder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder)


class FixtureBuilderTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.output_temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.output_temporary.cleanup)
        self.output = Path(self.output_temporary.name) / 'fixture-output'
        self.archive = self.root / 'judgment-pack-gateway_0.18.0_linux_amd64.tar.gz'
        self.checksums = self.root / 'checksums.txt'
        self.provenance = self.root / 'component-artifacts.json'
        self.commit = '5' * 40
        self.files = {name: ('released-' + name).encode() for name in builder.PROGRAMS}
        self.files.update({name: name.encode() for name in builder.LICENSES})
        self.write_archive()
        self.record = {
            'repository': 'Judgment-Pack/judgment-pack-gateway',
            'version': 'v0.18.0', 'revision': self.commit,
            'archive': self.archive.name, 'archiveSha256': builder.digest(self.archive.read_bytes()),
            'signerWorkflow': 'Judgment-Pack/judgment-pack-gateway/.github/workflows/release.yml',
            'files': {('gateway-licenses/' if name in builder.LICENSES else '') + name: builder.digest(data)
                      for name, data in self.files.items()},
        }
        self.checksums.write_text(self.record['archiveSha256'] + '  ' + self.archive.name + '\n')
        self.provenance.write_text(json.dumps({'gateway': self.record}))

    def write_archive(self, extra=None):
        with tarfile.open(self.archive, 'w:gz') as archive:
            for name, data in self.files.items():
                member = tarfile.TarInfo(name)
                member.size = len(data)
                archive.addfile(member, io.BytesIO(data))
            if extra is not None:
                archive.addfile(extra, io.BytesIO(b'other'))

    def approve(self):
        return builder.approved_base(self.archive, self.checksums, self.provenance, 'v0.18.0', self.commit)

    def test_base_pins_exact_archive_and_every_copied_file(self):
        record, checksums = self.approve()
        retained = builder.base_files(self.archive, record)
        self.assertEqual(set(retained), set(record['files']))
        self.assertEqual(checksums, self.checksums.read_bytes())
        for name, data in retained.items():
            self.assertEqual(builder.digest(data), record['files'][name])
        self.record['files']['gateway'] = '0' * 64
        with self.assertRaises(ValueError):
            builder.base_files(self.archive, self.record)

    def test_archive_checksum_or_release_provenance_changes_refuse(self):
        self.checksums.write_text('0' * 64 + '  ' + self.archive.name + '\n')
        with self.assertRaises(ValueError):
            self.approve()
        self.checksums.write_text(self.record['archiveSha256'] + '  ' + self.archive.name + '\n')
        self.record['revision'] = '0' * 40
        self.provenance.write_text(json.dumps({'gateway': self.record}))
        with self.assertRaises(ValueError):
            self.approve()

    def test_duplicate_archive_member_and_unpinned_copy_refuse(self):
        member = tarfile.TarInfo('gateway')
        member.size = 5
        self.write_archive(member)
        with self.assertRaises(ValueError):
            builder.base_files(self.archive, self.record)
        self.write_archive()
        self.record['files']['unexpected'] = '0' * 64
        with self.assertRaises(ValueError):
            builder.base_files(self.archive, self.record)

    def test_archive_link_never_becomes_a_program(self):
        del self.files['gateway']
        member = tarfile.TarInfo('gateway')
        member.type = tarfile.SYMTYPE
        member.linkname = '/operator/private/gateway'
        self.write_archive(member)
        with self.assertRaises(ValueError):
            builder.base_files(self.archive, self.record)

    def source_tree(self):
        module = self.root / 'adapters'
        (module / 'websource').mkdir(parents=True)
        (module / 'websource' / 'adapter.go').write_text('package websource\n')
        (module / 'connections').mkdir()
        (module / 'connections' / 'presentation.json').write_text('{"en":"before"}')
        (module / 'testdata' / 'acquisition-fixture').mkdir(parents=True)
        (module / 'testdata' / 'acquisition-fixture' / 'build.py').write_text('frozen builder\n')
        (module / 'go.mod').write_text('module adapters\n')
        return module

    def test_source_inventory_refuses_symlinked_production_package_and_non_go_file(self):
        module = self.source_tree()
        external = self.root / 'external-package'
        (module / 'websource').rename(external)
        (module / 'websource').symlink_to(external, target_is_directory=True)
        with mock.patch.object(builder, 'ROOT', self.root), self.assertRaises(ValueError):
            builder.source_files()
        (module / 'websource').unlink()
        external.rename(module / 'websource')
        (module / 'connections' / 'presentation.json').unlink()
        (module / 'connections' / 'presentation.json').symlink_to(self.provenance)
        with mock.patch.object(builder, 'ROOT', self.root), self.assertRaises(ValueError):
            builder.source_files()

    def test_source_inventory_hashes_embedded_assets_and_builder(self):
        module = self.source_tree()
        with mock.patch.object(builder, 'ROOT', self.root):
            before = builder.source_files()
            asset = module / 'connections' / 'presentation.json'
            self.assertEqual(before['adapters/connections/presentation.json'], builder.digest(asset.read_bytes()))
            self.assertIn('adapters/testdata/acquisition-fixture/build.py', before)
            asset.write_text('{"en":"changed embed"}')
            self.assertNotEqual(before, builder.source_files())

    def fake_build(self, change=None, output=None, allow_dirty=True, status=b' M fixture source',
                   tag_commit=None, failing=None):
        args = SimpleNamespace(output=output or self.output, base_archive=self.archive,
                               base_checksums=self.checksums, base_provenance=self.provenance,
                               base_tag='v0.18.0', base_commit=self.commit,
                               allow_dirty_fixture_source=allow_dirty)

        def git(*arguments):
            # The refs are the signed tag's own, not HEAD or another name.
            if arguments[0] == 'verify-tag':
                self.assertEqual(arguments, ('verify-tag', 'refs/tags/v0.18.0'))
            elif arguments[0] == 'cat-file':
                self.assertEqual(arguments, ('cat-file', 'tag', 'refs/tags/v0.18.0'))
            elif arguments[0] == 'rev-parse':
                self.assertIn(arguments, [('rev-parse', '--verify', 'refs/tags/v0.18.0^{commit}'), ('rev-parse', 'HEAD')])
            if arguments[0] == failing:
                raise subprocess.CalledProcessError(1, ['git', *arguments])
            output = b'signed tag evidence'
            if arguments[0] == 'rev-parse':
                output = (tag_commit or self.commit).encode() if arguments[1] == '--verify' else self.commit.encode()
            elif arguments[0] == 'status':
                output = status
            return SimpleNamespace(stdout=output, stderr=b'')

        def go(command, **options):
            if command[:2] == ['go', 'env']:
                return SimpleNamespace(stdout=b'linux\namd64\n')
            self.assertEqual(command[:2], ['go', 'build'])
            Path(command[command.index('-o') + 1]).write_bytes(b'compiled fixture')
            if change is not None:
                change()
            return SimpleNamespace(stdout=b'')

        with mock.patch.object(builder, 'ROOT', self.root), mock.patch.object(builder, 'git', side_effect=git), mock.patch.object(builder.subprocess, 'run', side_effect=go), mock.patch.dict(builder.os.environ, {'GOOS': '', 'GOARCH': ''}), redirect_stdout(io.StringIO()):
            builder.build(args)
        return args.output

    def test_embedded_asset_or_builder_change_during_build_refuses_output(self):
        module = self.source_tree()
        for relative in ['connections/presentation.json', 'testdata/acquisition-fixture/build.py']:
            with self.subTest(relative=relative):
                path = module / relative
                with self.assertRaisesRegex(ValueError, 'source changed during the build'):
                    self.fake_build(lambda: path.write_bytes(path.read_bytes() + b'changed'))
                self.assertFalse(self.output.exists())

    def test_builder_hash_is_bound_to_frozen_complete_inventory(self):
        module = self.source_tree()
        with mock.patch.object(builder, 'ROOT', self.root):
            before = builder.source_files()
        output = self.fake_build()
        provenance = json.loads((output / 'fixture-provenance.json').read_bytes())
        self.assertEqual(provenance['fixture']['sourceFiles'], before)
        self.assertEqual(provenance['fixture']['builderSha256'], before['adapters/testdata/acquisition-fixture/build.py'])
        self.assertEqual(provenance['fixture']['sourceFiles']['adapters/connections/presentation.json'], builder.digest((module / 'connections' / 'presentation.json').read_bytes()))

    def test_a_tag_that_does_not_verify_refuses_before_any_output(self):
        self.source_tree()
        with self.assertRaises(subprocess.CalledProcessError):
            self.fake_build(failing='verify-tag')
        self.assertFalse(self.output.exists())

    def test_a_tag_naming_another_commit_refuses(self):
        self.source_tree()
        with self.assertRaisesRegex(ValueError, 'names another commit'):
            self.fake_build(tag_commit='6' * 40)
        self.assertFalse(self.output.exists())

    def test_uncommitted_source_refuses_without_the_review_flag(self):
        self.source_tree()
        with self.assertRaisesRegex(ValueError, 'source is dirty'):
            self.fake_build(allow_dirty=False)
        self.assertFalse(self.output.exists())
        # The same tree, clean, builds without the flag and is not marked dirty.
        output = self.fake_build(allow_dirty=False, status=b'')
        provenance = json.loads((output / 'fixture-provenance.json').read_bytes())
        self.assertFalse(provenance['fixture']['dirty'])
        self.assertEqual(provenance['fixture']['version'], 'fixture.' + self.commit[:12])

    def test_an_output_in_the_checkout_or_already_there_refuses(self):
        self.source_tree()
        existing = self.output_temporary_path('existing')
        existing.mkdir()
        (existing / 'keep').write_text('kept')
        for name, output in {'existing': existing, 'the checkout': self.root,
                             'inside the checkout': self.root / 'new-output'}.items():
            with self.subTest(name):
                with self.assertRaisesRegex(ValueError, 'new directory outside the source checkout'):
                    self.fake_build(output=output)
        self.assertEqual((existing / 'keep').read_text(), 'kept')
        self.assertFalse((self.root / 'new-output').exists())

    def output_temporary_path(self, name):
        return self.output.parent / name


if __name__ == '__main__':
    unittest.main()
