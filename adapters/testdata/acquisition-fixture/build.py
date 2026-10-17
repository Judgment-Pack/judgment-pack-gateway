#!/usr/bin/env python3
"""Build a separate, explicitly approved acquisition fixture bundle; no downloads."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parents[3]
TAG = 'gateway_acquisition_fixture'
PROGRAMS = ('gateway', 'adapter-document', 'gateway-connections', 'adapter-drive',
            'adapter-gmail', 'adapter-sources', 'adapter-web', 'adapter-render',
            'ocr-tesseract', 'ocr-cloud')
LICENSES = ('LICENSE', 'THIRD_PARTY_NOTICES')


def digest(data):
    return hashlib.sha256(data).hexdigest()


def git(*args):
    return subprocess.run(['git', '-C', str(ROOT), *args], check=True,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def approved_base(archive, checksums, provenance, tag, commit):
    if not re.fullmatch(r'v[0-9]+\.[0-9]+\.[0-9]+', tag) or not re.fullmatch(r'[a-f0-9]{40}', commit):
        raise ValueError('requires an explicit release tag and exact commit')
    record = json.loads(provenance.read_bytes())['gateway']
    if (record['repository'] != 'Judgment-Pack/judgment-pack-gateway'
            or record['version'] != tag or record['revision'] != commit
            or record['archive'] != archive.name
            or record['signerWorkflow'] != 'Judgment-Pack/judgment-pack-gateway/.github/workflows/release.yml'):
        raise ValueError('base provenance differs from the requested release')
    checksum_bytes = checksums.read_bytes()
    matching = [line.split() for line in checksum_bytes.decode('ascii').splitlines()
                if len(line.split()) == 2 and line.split()[1].lstrip('*') == archive.name]
    if len(matching) != 1 or not re.fullmatch(r'[a-f0-9]{64}', matching[0][0]):
        raise ValueError('base archive needs one exact published checksum')
    archive_hash = digest(archive.read_bytes())
    if matching[0][0] != archive_hash or record['archiveSha256'] != archive_hash:
        raise ValueError('base archive checksum differs')
    return record, checksum_bytes


def base_files(archive, record):
    # Only the explicitly pinned bundle programs and license files are copied.
    # Archive paths are never used as filesystem destinations.
    suffix = '.exe' if record['archive'].endswith('_windows_amd64.zip') else ''
    if suffix:
        raise ValueError('this fixture builder currently supports native tar.gz archives only')
    names = {name: name for name in PROGRAMS}
    names.update({'gateway-licenses/' + name: name for name in LICENSES})
    if set(record['files']) != set(names):
        raise ValueError('base provenance must pin every copied program and license')
    found = {}
    with tarfile.open(archive, 'r:gz') as source:
        for member in source:
            if member.name not in names.values():
                continue
            if member.name in found or not member.isfile() or member.size > 256 << 20:
                raise ValueError('base archive has duplicate, nonregular or oversized bundle files')
            found[member.name] = source.extractfile(member).read()
    result = {}
    for target, name in names.items():
        if name not in found or digest(found[name]) != record['files'][target]:
            raise ValueError('base bundle file differs from verified provenance: ' + name)
        result[target] = found[name]
    return result


def source_files():
    source = ROOT / 'adapters'
    if source.is_symlink() or not source.is_dir():
        raise ValueError('fixture module must be a regular source directory')
    files = {}

    def unreadable(error):
        raise ValueError('fixture module content could not be inventoried') from error

    # Inventory the whole module, including embedded assets, tests, scripts and
    # the builder itself. Refuse symlink directories before os.walk could skip
    # them, and refuse symlink files regardless of their name or extension.
    for directory, names, filenames in os.walk(source, followlinks=False, onerror=unreadable):
        for name in sorted(names):
            path = Path(directory) / name
            if path.is_symlink() or not path.is_dir():
                raise ValueError('fixture module directories must not be symlinks')
        for name in sorted(filenames):
            path = Path(directory) / name
            if path.is_symlink() or not path.is_file():
                raise ValueError('fixture module inputs must be regular files without symlinks')
            files[str(path.relative_to(ROOT))] = digest(path.read_bytes())
    return files


def build(args):
    target = args.output.resolve()
    if target.exists() or target == ROOT or ROOT in target.parents:
        raise ValueError('fixture output must be a new directory outside the source checkout')
    record, checksums = approved_base(args.base_archive, args.base_checksums,
                                     args.base_provenance, args.base_tag, args.base_commit)
    if git('rev-parse', '--verify', 'refs/tags/' + args.base_tag + '^{commit}').stdout.decode().strip() != args.base_commit:
        raise ValueError('signed base tag names another commit')
    verification = git('verify-tag', 'refs/tags/' + args.base_tag)
    signed_tag = git('cat-file', 'tag', 'refs/tags/' + args.base_tag).stdout
    retained = base_files(args.base_archive, record)
    revision = git('rev-parse', 'HEAD').stdout.decode().strip()
    dirty = bool(git('status', '--porcelain', '--untracked-files=all').stdout)
    if dirty and not args.allow_dirty_fixture_source:
        raise ValueError('fixture source is dirty; review builds require --allow-dirty-fixture-source')
    inputs = source_files()
    version = 'fixture.' + revision[:12] + ('.dirty' if dirty else '')
    environment = dict(os.environ, CGO_ENABLED='0', GOWORK='off', GOPROXY='off', GOSUMDB='off', GOFLAGS='')
    if environment.get('GOOS') or environment.get('GOARCH'):
        raise ValueError('fixture builds are native; unset GOOS and GOARCH')
    native = subprocess.run(['go', 'env', 'GOOS', 'GOARCH'], cwd=ROOT / 'adapters',
                            env=environment, check=True, stdout=subprocess.PIPE).stdout.decode().split()
    if record['archive'] != 'judgment-pack-gateway_' + args.base_tag[1:] + '_' + '_'.join(native) + '.tar.gz':
        raise ValueError('base archive does not match the native fixture platform')
    with tempfile.TemporaryDirectory(prefix='gateway-acquisition-fixture-') as temporary:
        executable = Path(temporary) / 'acquisition-fixture'
        subprocess.run(['go', 'build', '-buildvcs=false', '-trimpath', '-tags=' + TAG,
                        '-ldflags=-X adapters/document.Version=' + version,
                        '-o', str(executable), './testdata/acquisition-fixture'],
                       cwd=ROOT / 'adapters', env=environment, check=True)
        if inputs != source_files() or revision != git('rev-parse', 'HEAD').stdout.decode().strip():
            raise ValueError('fixture source changed during the build')
        fixture_bytes = executable.read_bytes()
    # The release signer and all other companions remain exact archive bytes.
    retained['adapter-web'] = fixture_bytes
    retained['adapter-sources'] = fixture_bytes
    target.mkdir(parents=True)
    try:
        for name, data in retained.items():
            path = target / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
            path.chmod(0o755 if name in PROGRAMS else 0o644)
        provenance = {
            'format': 1, 'kind': 'gateway-acquisition-fixture', 'officialRelease': False,
            'base': record, 'baseChecksumsSha256': digest(checksums),
            'baseTagObjectSha256': digest(signed_tag),
            'fixture': {'revision': revision, 'dirty': dirty, 'version': version,
                        'buildTag': TAG, 'sourceFiles': inputs,
                        'builderSha256': inputs['adapters/testdata/acquisition-fixture/build.py'],
                        'programSha256': digest(fixture_bytes),
                        'replacedPrograms': ['adapter-sources', 'adapter-web']},
        }
        (target / 'fixture-provenance.json').write_text(json.dumps(provenance, indent=2) + '\n')
        evidence = target / 'fixture-provenance'
        evidence.mkdir()
        (evidence / 'base-checksums.txt').write_bytes(checksums)
        (evidence / 'base-signed-tag.txt').write_bytes(signed_tag)
        (evidence / 'base-tag-verification.txt').write_bytes(verification.stdout + verification.stderr)
        manifest = {'version': version, 'revision': revision, 'fixture': True,
                    'files': {name: digest(retained[name]) for name in PROGRAMS}}
        manifest_bytes = (json.dumps(manifest, indent=2) + '\n').encode()
        (target / 'gateway-bundle.json').write_bytes(manifest_bytes)
    except BaseException:
        shutil.rmtree(target)
        raise
    print('TEST FIXTURE ONLY:', target)
    print('Manifest SHA256:', digest(manifest_bytes))
    print('Fixture program SHA256:', digest(fixture_bytes))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base-archive', type=Path, required=True)
    parser.add_argument('--base-checksums', type=Path, required=True)
    parser.add_argument('--base-provenance', type=Path, required=True,
                        help='Explicit independently verified component-artifacts.json; this builder does not verify GitHub attestations.')
    parser.add_argument('--base-tag', required=True)
    parser.add_argument('--base-commit', required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--allow-dirty-fixture-source', action='store_true',
                        help='Review-only build: records dirty source and every regular module content hash.')
    args = parser.parse_args()
    try:
        build(args)
    except (KeyError, ValueError, OSError, subprocess.CalledProcessError, tarfile.TarError) as error:
        parser.exit(1, 'Fixture build refused: ' + str(error) + '\n')


if __name__ == '__main__':
    main()
