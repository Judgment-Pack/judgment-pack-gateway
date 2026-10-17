#!/usr/bin/env python3
"""Opt-in fixture bundle smoke: two real acquisitions, sealed and verified by Gateway."""
import argparse
import hashlib
import json
from pathlib import Path
import select
import shlex
import socket
import subprocess
import sys
import tempfile
import urllib.request

# Reading the shared inventory must not create new module input files.
sys.dont_write_bytecode = True
from build import LICENSES, PROGRAMS


def checked(command, **options):
    return subprocess.run(command, check=True, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, timeout=15, **options).stdout


def admit_bundle(bundle):
    manifest = json.loads((bundle / 'gateway-bundle.json').read_bytes())
    provenance = json.loads((bundle / 'fixture-provenance.json').read_bytes())
    if (manifest.get('fixture') is not True or provenance.get('officialRelease') is not False
            or provenance.get('kind') != 'gateway-acquisition-fixture'
            or not manifest.get('version', '').startswith('fixture.')):
        raise ValueError('requires an explicitly labeled fixture bundle')
    if (set(manifest['files']) != set(PROGRAMS)
            or set(provenance['base']['files']) != set(PROGRAMS) | {'gateway-licenses/' + name for name in LICENSES}
            or provenance['fixture']['replacedPrograms'] != ['adapter-sources', 'adapter-web']
            or provenance['fixture']['version'] != manifest['version']
            or provenance['fixture']['revision'] != manifest['revision']):
        raise ValueError('fixture bundle needs the complete known program inventory and matching provenance')
    for name, expected in manifest['files'].items():
        path = bundle / name
        if path.is_symlink() or not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            raise ValueError('fixture bundle checksum differs')
        if name in ('adapter-web', 'adapter-sources'):
            if expected != provenance['fixture']['programSha256']:
                raise ValueError('fixture program differs from recorded provenance')
        elif expected != provenance['base']['files'][name]:
            raise ValueError('unmodified base companion differs from recorded provenance')
    return manifest


def smoke(bundle):
    # Complete admission precedes even connection configuration and keygen.
    manifest = admit_bundle(bundle)
    gateway = str(bundle / 'gateway')
    with tempfile.TemporaryDirectory(prefix='gateway-fixture-smoke-') as temporary:
        root = Path(temporary)
        root.chmod(0o700)
        state = root / 'connections'
        state.mkdir(mode=0o700)
        commands = [
            {'id': 'configure', 'method': 'configure', 'params': {'id': 'fixture', 'name': 'Synthetic fixture', 'provider': 'tavily', 'credential': 'tvly-fixture-only', 'dailyLimit': 1}},
            {'id': 'status', 'method': 'status', 'params': {}},
        ]
        replies = checked([str(bundle / 'gateway-connections'), '--state-dir', str(state), '--principal', 'desk-local', '--provider', 'web-search'],
                          input=('\n'.join(json.dumps(command) for command in commands) + '\n').encode())
        replies = [json.loads(line) for line in replies.splitlines()]
        if len(replies) != 2 or any(reply.get('error') for reply in replies):
            raise ValueError('disposable search configuration refused')
        connection = replies[1]['result']['connections'][0]
        seed = root / 'fixture.seed'
        keygen = checked([gateway, 'keygen', str(seed)]).decode().splitlines()
        public = next(line.split()[1] for line in keygen if line.startswith('publicKey '))
        # Reserve a native loopback port only for the startup handoff. The
        # smoke never retries an acquisition if a request fails or is uncertain.
        with socket.socket() as reservation:
            reservation.bind(('127.0.0.1', 0))
            port = reservation.getsockname()[1]
        store, registry = root / 'store', root / 'registry.json'
        search_command = shlex.join([str(bundle / 'adapter-sources'), '--provider', 'web-search', '--principal', 'desk-local'])
        command = [gateway, 'serve', str(store), str(seed), 'fixture-smoke', str(registry),
                   '--port', str(port), '--source', 'web=' + shlex.quote(str(bundle / 'adapter-web')),
                   '--source-shape', 'web=http', '--source', 'web-search=' + search_command,
                   '--source-shape', 'web-search=http',
                   '--source-env', 'web-search=JPACK_CONNECTIONS_DIR=' + str(state)]
        process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        try:
            ready, _, _ = select.select([process.stderr], [], [], 5)
            if not ready or not process.stderr.readline().startswith(b'gateway on http://127.0.0.1:'):
                raise ValueError('disposable Gateway did not announce readiness')
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

            def post(path, value):
                request = urllib.request.Request('http://127.0.0.1:' + str(port) + path,
                                                 data=json.dumps(value).encode(),
                                                 headers={'Content-Type': 'application/json'})
                with opener.open(request, timeout=10) as response:
                    return json.loads(response.read())

            acquisitions = [
                post('/acquire', {'session': 'fixture-smoke', 'source': 'web-search', 'arguments': {'connection': 'fixture', 'revision': connection['revision'], 'query': 'synthetic source fixtures', 'maxResults': 3}}),
                post('/acquire', {'session': 'fixture-smoke', 'source': 'web', 'arguments': {'url': 'https://example.com/fixtures/start?submitted=unchanged%2Fbytes'}}),
            ]
            for response, role, source in zip(acquisitions, ['adapter-sources', 'adapter-web'], ['web-search', 'web']):
                receipt = response['receipt']
                identity = receipt['acquisition']['adapter']
                if (not receipt['signature'] or receipt['source'] != source
                        or identity['name'] != role or identity['version'] != manifest['version']
                        or identity['digest'] != 'sha256:' + manifest['files'][role]):
                    raise ValueError('receipt does not name the actual fixture executable')
            if (acquisitions[0]['result']['kind'] != 'search-results'
                    or acquisitions[1]['result']['attachmentVersion'] != '1'
                    or acquisitions[1]['result']['provenance']['source']['requestedUrl'] != 'https://example.com/fixtures/start?submitted=unchanged%2Fbytes'):
                raise ValueError('real search/page acquisition record missing')
            post('/seal', {'session': 'fixture-smoke'})
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
            process.stderr.close()
        report = json.loads(checked([gateway, 'verify', str(store), str(registry), 'fixture-smoke'], input=public.encode()))
        findings = report.get('findings', [])
        if report.get('ok') is not True or len(findings) != 2 or any(item.get('status') != 'ok' for item in findings):
            raise ValueError('genuine Gateway receipt verification refused')
    print('PASS: one real search and one real page acquisition; genuine Gateway signatures and fixture identities verified; zero model calls/decisions')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bundle', type=Path, required=True)
    args = parser.parse_args()
    try:
        smoke(args.bundle.resolve())
    except (KeyError, ValueError, OSError, subprocess.SubprocessError) as error:
        parser.exit(1, 'Fixture smoke refused: ' + str(error) + '\n')


if __name__ == '__main__':
    main()
