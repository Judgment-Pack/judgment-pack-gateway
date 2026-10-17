"""Smoke admission refusals must precede every signer/control subprocess."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location('fixture_smoke', Path(__file__).with_name('smoke.py'))
smoke = importlib.util.module_from_spec(spec)
spec.loader.exec_module(smoke)


class FixtureSmokeAdmissionTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.bundle = Path(self.temporary.name)
        base = {}
        files = {}
        replacement = b'compiled fixture'
        for name in smoke.PROGRAMS:
            original = ('official-' + name).encode()
            base[name] = smoke.hashlib.sha256(original).hexdigest()
            data = replacement if name in ('adapter-sources', 'adapter-web') else original
            (self.bundle / name).write_bytes(data)
            files[name] = smoke.hashlib.sha256(data).hexdigest()
        for name in smoke.LICENSES:
            base['gateway-licenses/' + name] = '0' * 64
        self.manifest = {'fixture': True, 'version': 'fixture.test', 'revision': '5' * 40, 'files': files}
        self.provenance = {'kind': 'gateway-acquisition-fixture', 'officialRelease': False,
                           'base': {'files': base},
                           'fixture': {'programSha256': smoke.hashlib.sha256(replacement).hexdigest(),
                                       'version': 'fixture.test', 'revision': '5' * 40,
                                       'replacedPrograms': ['adapter-sources', 'adapter-web']}}
        self.save()

    def save(self):
        (self.bundle / 'gateway-bundle.json').write_text(json.dumps(self.manifest))
        (self.bundle / 'fixture-provenance.json').write_text(json.dumps(self.provenance))

    def refused_without_execution(self):
        with mock.patch.object(smoke.subprocess, 'run') as run, mock.patch.object(smoke.subprocess, 'Popen') as popen:
            with self.assertRaises(ValueError):
                smoke.smoke(self.bundle)
            run.assert_not_called()
            popen.assert_not_called()

    def test_complete_inventory_can_be_admitted_without_execution(self):
        with mock.patch.object(smoke.subprocess, 'run') as run, mock.patch.object(smoke.subprocess, 'Popen') as popen:
            self.assertEqual(smoke.admit_bundle(self.bundle), self.manifest)
            run.assert_not_called()
            popen.assert_not_called()

    def test_omitted_signer_control_companion_or_adapter_refuses_before_execution(self):
        for name in smoke.PROGRAMS:
            with self.subTest(program=name):
                digest = self.manifest['files'].pop(name)
                self.save()
                self.refused_without_execution()
                self.manifest['files'][name] = digest

    def test_incomplete_base_or_replacement_provenance_refuses_before_execution(self):
        del self.provenance['base']['files']['gateway']
        self.save()
        self.refused_without_execution()
        self.provenance['base']['files']['gateway'] = self.manifest['files']['gateway']
        self.provenance['fixture']['programSha256'] = '0' * 64
        self.save()
        self.refused_without_execution()

    def test_changed_signer_cannot_be_approved_by_only_its_manifest(self):
        (self.bundle / 'gateway').write_bytes(b'changed signer')
        self.manifest['files']['gateway'] = smoke.hashlib.sha256(b'changed signer').hexdigest()
        self.save()
        self.refused_without_execution()


if __name__ == '__main__':
    unittest.main()
