#!/usr/bin/env python3
"""Focused semantic mutations. Run against both reviewed, complete source trees.

python3 mutations.py /path/to/gateway /path/to/desk /tmp/results.json
Requires Go, Node 22 and Desk's installed web/node_modules. No provider credentials.
Each mutation uses an isolated copy; originals are never edited. Output includes
exact replacements and test commands. This is not independent review or coverage
of every foundation guard.
"""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


def run():
    gateway, desk, output = map(Path, sys.argv[1:])
    go_test = ['go', 'test', './connections', './cmd/gateway-connections', '-run', 'Test(ResourcePageBoundsAndAvailability|DisconnectDoesNotInventRemoteRevocation|ControlReplyRefusesOversizeWithoutLeakingPartialResult)$', '-count=1']
    web_test = ['npm', 'test', '--', '--maxWorkers=2', 'src/connections/resourceProtocol.test.ts', 'src/connections/ConnectionsPane.test.tsx']
    cases = [
        ('gateway', 'remote-revocation-default', 'adapters/connections/broker.go', 'revoked := false', 'revoked := true'),
        ('gateway', 'control-line-budget', 'adapters/cmd/gateway-connections/main.go', 'len(raw)+1 > connections.ControlLineBytes', 'false'),
        ('gateway', 'resource-page-budget', 'adapters/connections/resource_controls.go', 'len(raw) > ResourcePageBytes', 'len(raw) < 0'),
        ('gateway', 'resource-page-count', 'adapters/connections/resource_controls.go', 'len(page.Items) > ResourcePageItems', 'len(page.Items) < 0'),
        ('gateway', 'resource-page-cursor', 'adapters/connections/resource_controls.go', 'page.More != (page.NextPageToken != "")', 'false'),
        ('desk', 'resource-status-ceiling', 'web/src/connections/resourceProtocol.ts', '(value.maxFileBytes as number)>RESOURCE_MAX_BYTES', 'false'),
        ('desk', 'resource-page-budget', 'web/src/connections/resourceProtocol.ts', 'encode.encode(JSON.stringify(value)).length>48<<10', 'false'),
        ('desk', 'resource-scope-change', 'web/src/connections/ConnectionsPane.tsx', ', status?.data?.resource?.id]', ']'),
        ('desk', 'unavailable-row-affordance', 'web/src/connections/ConnectionsPane.tsx', 'working || Boolean(row.unavailable) ||', 'working ||'),
        ('desk', 'cursor-loop-refusal', 'web/src/connections/ConnectionsPane.tsx', 'answer.nextPageToken === pageToken || visitedPages.current.has(answer.nextPageToken)', 'false'),
        ('desk', 'disconnect-confirmation', 'web/src/connections/ConnectionsPane.tsx', 'descriptor?.protocol && result.disconnected !== true', 'false'),
    ]
    results = []
    with tempfile.TemporaryDirectory(prefix='jp-foundation-mutations-') as temp:
        roots = {}
        for name, source in [('gateway', gateway), ('desk', desk)]:
            root = Path(temp) / name
            shutil.copytree(source, root, ignore=shutil.ignore_patterns('.git', 'node_modules', '__pycache__', 'dist'), symlinks=True)
            if name == 'desk':
                (root / 'web/node_modules').symlink_to((source / 'web/node_modules').resolve(), target_is_directory=True)
            roots[name] = root
            cmd = go_test if name == 'gateway' else web_test
            cwd = root / ('adapters' if name == 'gateway' else 'web')
            result = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
            if result.returncode:
                raise RuntimeError(f'{name} baseline failed: {result.stdout[-3000:]}{result.stderr[-3000:]}')
        for repo, name, filename, before, after in cases:
            path = roots[repo] / filename
            original = path.read_text()
            if original.count(before) != 1:
                raise RuntimeError(f'{name}: expected unique mutation target')
            cmd = go_test if repo == 'gateway' else web_test
            cwd = roots[repo] / ('adapters' if repo == 'gateway' else 'web')
            try:
                path.write_text(original.replace(before, after))
                result = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
            finally:
                path.write_text(original)
            transcript = result.stdout + result.stderr
            # A build/import failure is not a killed behavioral mutant.
            behavioral_failure = '--- FAIL:' in transcript if repo == 'gateway' else 'AssertionError:' in transcript or 'TestingLibraryElementError:' in transcript
            verdict = 'killed' if result.returncode and behavioral_failure else 'invalid' if result.returncode else 'survived'
            row = dict(repo=repo, name=name, file=filename, before=before, after=after, command=cmd, verdict=verdict, exitCode=result.returncode)
            results.append(row)
            print(f'{repo}/{name}: {verdict}', flush=True)
            output.with_name(output.stem + '-' + repo + '-' + name + '.log').write_text(transcript)
    output.write_text(json.dumps({'kind':'focused semantic mutations','independentReview':False,'baseline':'both passed','results':results}, indent=2) + '\n')
    return 0 if all(row['verdict'] == 'killed' for row in results) else 1


if __name__ == '__main__':
    sys.exit(run())
