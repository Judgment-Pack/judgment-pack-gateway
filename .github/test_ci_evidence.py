"""The release evidence gate's configuration (.github/ci-evidence.json), held to the workflows it
describes, so that the three cannot drift apart unnoticed until a release refuses:

- every job and matrix leg ci.yml runs is a required job of the configuration, by the display
  name the API reports, on the labels it runs on, with a profile of its platform; and none more;
- each of them records its evidence on a push to main, under the job key the configuration
  gives it, and uploads it under the artifact name the gate reads;
- the Go each leg and the check job run is the one release.yml names, and each profile pins it;
- every input path is a tracked file, and a change to it selects the step that runs this file;
- every file of the tree that pins what a run fetches or resolves (an image by digest, a module or
  package lock, a requirements file, the manifest, the packer's configuration, a file ci.yml reads)
  is an input, so a new pin file fails here until it is recorded;
- release.yml takes the evidence and calls no workflow: the gate runs on the tagged commit, with
  the check job's toolchains set up by the same actions, and keeps its decision record;
- scripts/dev/release_evidence.py is the development kit's lib/release_evidence.py of the kit
  release its line 2 names, byte for byte after that line, and that release is the one the other
  vendored scripts name.

Standard library only; the workflows are read by the YAML subset below, which refuses anything
it does not know. Run from the repository root: python3 .github/test_ci_evidence.py"""
import hashlib
import importlib.util
import json
import os
import re
import subprocess
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONFIG = '.github/ci-evidence.json'
HELPER = 'scripts/dev/release_evidence.py'
RELEASE = '.github/workflows/release.yml'
TEST = '.github/test_ci_evidence.py'
# The SHA-256 of the kit's lib/release_evidence.py at each kit release this repository has
# vendored. A re-vendor adds the new release's digest, taken from the kit's tag.
KIT_DIGESTS = {
    'v0.10.0': 'd44af3df07f64036013ba9967a54cf799cec678068f0937395d6a2eef370e0e8',
    'v0.11.0': 'f272b7a43272bac31bb9b0c37a583d9c40d376972b04c812e576bd82c1ef18e3',
}
CAPTURE_GUARD = "github.ref == 'refs/heads/main' && github.event_name == 'push'"
# A reference by digest, as an image pull or run names one (the name may be assembled apart).
IMAGE_PIN = re.compile(r'@sha256:[0-9a-f]{64}')
# Lock, requirements and module files, by name, wherever they are.
LOCK_FILE = re.compile(r'(^|/)(go\.(mod|sum|work)|package-lock\.json|npm-shrinkwrap\.json|yarn\.lock|'
                       r'pnpm-lock\.yaml|[^/]*requirements[^/]*\.txt|Pipfile\.lock|poetry\.lock|uv\.lock|'
                       r'Cargo\.lock)$')
# Read by their tools under these names: the image definition, the runner's manifest and mapping, the
# packer's configuration.
NAMED = re.compile(r'(^|/)(Dockerfile[^/]*|Containerfile|\.dockerignore|dev\.json|jpdev\.json|'
                   r'\.goreleaser\.ya?ml)$')
# Files that name an image by digest and that no reused check pulls or starts: data, a placeholder,
# or a script only an on-demand workflow runs. Each says why; any other such file is a pin.
NOT_PULLED = {
    'adapters/internal/containers/containers_test.go': 'a placeholder digest the reference parser is tested on',
    'adapters/mcp/descriptors_test.go': 'a placeholder binding in a descriptor test',
    'adapters/mcp/testdata/stdio-golden/check-descriptors.json': 'a recorded descriptor, compared as bytes',
    'adapters/testdata/adapter-conform/conform_test.go': 'a placeholder image in a conformance fixture',
    'go/catalog_test.go': 'the catalog read as data, never started',
    'go/descriptors_test.go': 'a placeholder binding in a descriptor test',
    'go/taxonomy_producer_test.go': 'a placeholder binding in a taxonomy fixture',
    'plugins/smoke/n8n/run.sh': 'run by smoke.yml on demand, not by ci.yml',
    'plugins/smoke/testing/make_flatted_fixtures.cjs': 'a comment naming the image the fixtures came from',
    'testdata/catalog-v1/postgres.json': 'a catalog of an earlier version, read as data',
    'testdata/tool-descriptors/rendered.json': 'a recorded rendering, compared as bytes',
    'testdata/tool-taxonomy/v2.json': 'a taxonomy fixture, read as data',
}
UPLOAD = 'actions/upload-artifact@'
LABEL_OS = {'ubuntu': 'Linux', 'macos': 'macOS', 'windows': 'Windows'}
GOOS = {'Linux': 'linux', 'macOS': 'darwin', 'Windows': 'windows'}
GOARCH = {'X64': 'amd64', 'ARM64': 'arm64'}


# --- a YAML subset: block mappings and sequences, plain and quoted scalars, literal blocks, flow
# sequences of scalars, {} and []. Enough for the workflows; anything else raises ValueError.

class _Reader:
    def __init__(self, text):
        self.lines = text.split('\n')
        self.i = 0

    def fail(self, why):
        raise ValueError('line %d: %s' % (self.i + 1, why))

    def peek(self):
        while self.i < len(self.lines):
            line = self.lines[self.i]
            stripped = line.strip()
            if stripped and not stripped.startswith('#'):
                indent = len(line) - len(line.lstrip(' '))
                if line[indent] == '\t':
                    self.fail('a tab')
                return indent, line[indent:]
            self.i += 1
        return None

    def node(self, indent):
        content = self.peek()[1]
        return self.sequence(indent) if _item(content) else self.mapping(indent)

    def sequence(self, indent):
        items = []
        while True:
            at = self.peek()
            if at is None or at[0] < indent:
                return items
            if at[0] > indent:
                self.fail('unexpected indentation')
            if not _item(at[1]):
                return items
            rest = at[1][1:].lstrip(' ')
            if not rest:
                self.i += 1
                following = self.peek()
                if following is None or following[0] <= indent:
                    self.fail('an empty sequence item')
                items.append(self.node(following[0]))
            elif _KEY.match(rest):
                # "- key: value" opens a mapping at the column of its key.
                column = len(self.lines[self.i]) - len(rest)
                self.lines[self.i] = ' ' * column + rest
                items.append(self.mapping(column))
            else:
                self.i += 1
                items.append(self.scalar(rest))

    def mapping(self, indent):
        result = {}
        while True:
            at = self.peek()
            if at is None or at[0] < indent:
                return result
            if at[0] > indent:
                self.fail('unexpected indentation')
            if _item(at[1]):
                return result
            match = _KEY.match(at[1])
            if not match:
                self.fail('not a key: %r' % at[1])
            key, rest = _unquote(match.group(1)), _uncomment(match.group(2) or '')
            if key in result:
                self.fail('a repeated key: %s' % key)
            self.i += 1
            if rest in ('|', '|-'):
                result[key] = self.literal(indent, rest == '|-')
            elif rest:
                result[key] = self.scalar(rest)
            else:
                following = self.peek()
                if following is None or following[0] < indent or (
                        following[0] == indent and not _item(following[1])):
                    result[key] = None
                else:
                    result[key] = self.node(following[0])

    def literal(self, indent, strip):
        lines, column = [], None
        while self.i < len(self.lines):
            line = self.lines[self.i]
            if line.strip():
                here = len(line) - len(line.lstrip(' '))
                if here <= indent:
                    break
                column = here if column is None else column
                if here < column:
                    self.fail('a literal block line left of its block')
                lines.append(line[column:])
            else:
                lines.append('')
            self.i += 1
        while lines and not lines[-1]:
            lines.pop()
        text = '\n'.join(lines)
        return text if strip else text + '\n'

    def scalar(self, text):
        text = text.strip()
        if text == '{}':
            return {}
        if text.startswith('[') and text.endswith(']'):
            inner = text[1:-1].strip()
            return [self.scalar(part) for part in inner.split(',')] if inner else []
        if text[0] in '\'"':
            end = _closing(text)
            if end is None or _uncomment(text[end + 1:]).strip():
                self.fail('a quoted scalar with text after it: %r' % text)
            return _unquote(text[:end + 1])
        if text[0] in '{[&*!|>%@`':
            self.fail('an unsupported scalar: %r' % text)
        return _uncomment(text).strip()


_KEY = re.compile(r'''([A-Za-z0-9_][A-Za-z0-9_.-]*|"[^"\\]*"|'[^']*'):(?:\s+(.*))?$''')


def _item(content):
    return content == '-' or content.startswith('- ')


def _uncomment(text):
    found = re.search(r'(^|\s)#', text)
    return (text[:found.start()] if found else text).rstrip()


def _closing(text):
    quote, index = text[0], 1
    while index < len(text):
        if quote == '"' and text[index] == '\\':
            index += 2
            continue
        if text[index] == quote:
            if quote == "'" and text[index + 1:index + 2] == "'":
                index += 2
                continue
            return index
        index += 1
    return None


def _unquote(text):
    if text[:1] == "'":
        return text[1:-1].replace("''", "'")
    if text[:1] == '"':
        body = text[1:-1]
        if re.search(r'\\[^"\\]', body):
            raise ValueError('an escape this reader does not know: %r' % text)
        return body.replace('\\"', '"').replace('\\\\', '\\')
    return text


def load_yaml(text):
    reader = _Reader(text)
    result = reader.mapping(0)
    if reader.peek() is not None:
        reader.fail('text after the document')
    return result


# --- the repository ------------------------------------------------------------------------------

def read(path):
    with open(os.path.join(ROOT, path), encoding='utf-8') as handle:
        return handle.read()


def tracked():
    output = subprocess.run(['git', 'ls-files', '-z'], cwd=ROOT, check=True,
                            stdout=subprocess.PIPE).stdout.decode('utf-8')
    return set(output.split('\0')) - {''}


def pin_files(files):
    """The files of the tree that pin what a run of ci.yml fetches or resolves."""
    found = {path for path in files if LOCK_FILE.search(path) or NAMED.search(path)}
    for path in files:
        if path.endswith('.md') or path in NOT_PULLED:
            continue
        with open(os.path.join(ROOT, path), 'rb') as handle:
            if IMAGE_PIN.search(handle.read().decode('utf-8', 'replace')):
                found.add(path)
    # Every tracked file ci.yml's steps name (its comments aside), such as release.yml, whose Go
    # the check job sets up.
    workflow = '\n'.join(line for line in read('.github/workflows/ci.yml').splitlines()
                         if not line.lstrip().startswith('#'))
    found |= {token for token in re.findall(r'[A-Za-z0-9_./-]+', workflow) if token in files}
    return found


def vendored(name, path):
    spec = importlib.util.spec_from_file_location(name, os.path.join(ROOT, path))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def gate():
    return vendored('release_evidence', HELPER)


def selects(path, check):
    """Whether a change to path alone selects check under jpdev.json, as the vendored selection
    reads it: the checks of every rule that matches it, or the whole list for an unmapped path or a
    selection input."""
    selection = vendored('changed_checks', 'scripts/dev/changed_checks.py')
    if path in ('jpdev.json', 'dev.json', 'scripts/dev/check.sh', 'scripts/dev/changed_checks.py'):
        return True
    rules = [(rule['paths'], rule['checks']) for rule in json.loads(read('jpdev.json'))['changed']]
    matched = [checks for globs, checks in rules
               if any(selection.glob_regex(glob).fullmatch(path) for glob in globs)]
    return not matched or any(check in checks for checks in matched)


def expand(text, values):
    """Each ${{ matrix.KEY }} of a workflow expression replaced by the leg's value; a key the leg
    does not have is refused, and any other expression is left as it is."""
    def one(match):
        if match.group(1) not in values:
            raise ValueError('matrix.%s is not a value of the leg' % match.group(1))
        return values[match.group(1)]
    return re.sub(r'\$\{\{\s*matrix\.([A-Za-z0-9_-]+)\s*\}\}', one, text)


def legs(job):
    """One dict of matrix values per leg of a job (one empty dict for a job without a matrix)."""
    strategy = job.get('strategy') or {}
    matrix = strategy.get('matrix')
    if matrix is None:
        return [{}]
    if set(matrix) != {'include'}:
        raise ValueError('only a matrix of include entries is read here')
    return [dict(entry) for entry in matrix['include']]


def option(command, name):
    found = re.findall(r'(?:^|\s)%s\s+("[^"]*"|\S+)' % re.escape(name), command)
    return [value.strip('"') for value in found]


def release_go():
    named = re.findall(r'''^ *go-version: *['"]?([0-9][0-9.]*)['"]? *$''', read(RELEASE), re.M)
    if len(named) != 1:
        raise ValueError('release.yml names %d Go versions' % len(named))
    return named[0]


def kit_release(path):
    line = read(path).split('\n')[1]
    found = re.fullmatch(r'# from judgment-pack-devkit (v[0-9]+\.[0-9]+\.[0-9]+) \(([^)]+)\)', line)
    return found.groups() if found else (None, None)


class YamlSubsetTest(unittest.TestCase):
    """The reader reads what the workflows hold and refuses what it does not know."""

    def test_reads_the_forms_the_workflows_use(self):
        text = ('a: plain # a comment\n'
                'b: "quoted: yes"\n'
                "c: 'it''s'\n"
                'd: [main, "x"]\n'
                'e: {}\n'
                'f:\n'
                '  - one\n'
                '  - name: two\n'
                '    with:\n'
                '      k: v\n'
                'g:\n'
                '- seq at the key\'s column\n'
                'h: |\n'
                '  line one\n'
                '\n'
                '    indented # kept\n'
                'i:\n')
        self.assertEqual(load_yaml(text), {
            'a': 'plain', 'b': 'quoted: yes', 'c': "it's", 'd': ['main', 'x'], 'e': {},
            'f': ['one', {'name': 'two', 'with': {'k': 'v'}}], 'g': ["seq at the key's column"],
            'h': 'line one\n\n  indented # kept\n', 'i': None})

    def test_refuses_what_it_does_not_know(self):
        for text in ('a: b\n  c: d\n', 'a: &anchor x\n', 'a: >\n  folded\n', 'a: {b: c}\n',
                     'a: 1\na: 2\n', 'a: "x" y\n', 'a: "\\t"\n', 'just text\n'):
            with self.subTest(text=text), self.assertRaises(ValueError):
                load_yaml(text)

    def test_reads_both_workflows(self):
        for path in ('.github/workflows/ci.yml', RELEASE):
            with self.subTest(path=path):
                self.assertIn('jobs', load_yaml(read(path)))


class ConfigurationTest(unittest.TestCase):
    """.github/ci-evidence.json against ci.yml, release.yml, jpdev.json and the tree."""

    @classmethod
    def setUpClass(cls):
        cls.config = json.loads(read(CONFIG))
        cls.workflow_key, = cls.config['workflows']
        cls.spec = cls.config['workflows'][cls.workflow_key]
        cls.ci = load_yaml(read(cls.spec['path']))
        cls.release = load_yaml(read(RELEASE))

    def ci_legs(self):
        """(display name, job id, job, matrix values) for every job and leg ci.yml runs."""
        result = []
        for job_id, job in self.ci['jobs'].items():
            for values in legs(job):
                result.append((expand(job.get('name', job_id), values), job_id, job, values))
        return result

    def test_the_gate_accepts_the_configuration(self):
        gate().check_config(self.config)

    def test_the_workflow_is_ci_on_a_push_to_main(self):
        self.assertEqual(self.config['repository'], 'Judgment-Pack/judgment-pack-gateway')
        self.assertEqual(self.spec['name'], self.ci['name'])
        self.assertEqual(self.spec['events'], ['push'])
        self.assertEqual(self.ci['on']['push'], {'branches': [self.config['branch']]})
        self.assertNotIn('workflow_dispatch', self.ci['on'])

    def test_every_job_and_leg_is_required_and_no_other(self):
        names = [name for name, _, _, _ in self.ci_legs()]
        self.assertEqual(len(names), len(set(names)))
        required = {job['name'] for job in self.spec['jobs'].values()}
        self.assertEqual(set(names), required | set(self.spec.get('skipped_jobs', [])))
        self.assertEqual(self.spec.get('skipped_jobs', []), [])
        # The go matrix is three native legs, never one.
        self.assertEqual(sorted(values['os'] for values in legs(self.ci['jobs']['go'])),
                         ['macos-latest', 'ubuntu-latest', 'windows-latest'])

    def test_each_leg_has_its_job_id_labels_and_platform(self):
        by_name = {job['name']: (key, job) for key, job in self.spec['jobs'].items()}
        for name, job_id, job, values in self.ci_legs():
            key, spec = by_name[name]
            with self.subTest(job=key):
                self.assertEqual(spec['job_id'], job_id)
                self.assertEqual(spec['labels'], [expand(job['runs-on'], values)])
                platform = self.config['profiles'][spec['profile']]['platform']
                family = spec['labels'][0].split('-')[0]
                self.assertEqual(platform['RUNNER_OS'], LABEL_OS[family])

    def test_each_leg_records_and_uploads_its_evidence_on_a_push_to_main(self):
        by_name = {job['name']: (key, job) for key, job in self.spec['jobs'].items()}
        for name, _, job, values in self.ci_legs():
            key, spec = by_name[name]
            with self.subTest(job=key):
                steps = job['steps']
                captures = [index for index, step in enumerate(steps)
                            if 'release_evidence.py capture' in (step.get('run') or '')]
                self.assertEqual(len(captures), 1)
                capture, upload = steps[captures[0]], steps[captures[0] + 1]
                command = capture['run']
                env = {name: expand(value, values) for name, value in (capture.get('env') or {}).items()}
                command = re.sub(r'\$\{(\w+)\}', lambda m: env.get(m.group(1), m.group(0)), command)
                self.assertEqual(capture.get('if'), CAPTURE_GUARD)
                self.assertEqual(option(command, '--workflow'), [self.workflow_key])
                self.assertEqual(option(command, '--job'), [key])
                self.assertEqual(option(command, '--output'), ['${RUNNER_TEMP}/evidence.json'])
                self.assertEqual(bool(option(command, '--setup-log')), bool(spec.get('setup')))
                self.assertEqual(bool(option(command, '--check-log')), spec['checks'] != [])
                self.assertEqual(capture.get('working-directory', '.'), '.')
                self.assertTrue(upload['uses'].startswith(UPLOAD))
                self.assertEqual(upload.get('if'), CAPTURE_GUARD)
                self.assertEqual(expand(upload['with']['name'], values),
                                 'ci-evidence-%s-%s-${{ github.run_attempt }}' % (self.workflow_key, key))
                self.assertEqual(upload['with']['path'], '${{ runner.temp }}/evidence.json')
                self.assertEqual(upload['with']['if-no-files-found'], 'error')
                # The summaries capture reads are the ones the job's steps write, the job failing
                # with a failed step (pipefail), so a summary is never of a step that failed.
                for log in option(command, '--setup-log') + option(command, '--check-log'):
                    writers = [step for step in steps[:captures[0]]
                               if '| tee "%s"' % log in (step.get('run') or '')]
                    self.assertEqual(len(writers), 1, log)
                    self.assertIn('set -o pipefail', writers[0]['run'])

    def test_every_leg_runs_the_go_release_yml_names_and_its_profile_pins_it(self):
        version = release_go()
        go = self.ci['jobs']['go']
        setup = [step for step in go['steps'] if step.get('uses', '').startswith('actions/setup-go@')]
        self.assertEqual(len(setup), 1)
        self.assertEqual(setup[0]['with']['go-version'], version)
        for key, spec in self.spec['jobs'].items():
            profile = self.config['profiles'][spec['profile']]
            platform = profile['platform']
            with self.subTest(job=key):
                self.assertEqual(profile['tools'].get('go'), ['go', 'version'])
                self.assertEqual(profile['pins'].get('go'), 'go version go%s %s/%s' % (
                    version, GOOS[platform['RUNNER_OS']], GOARCH[platform['RUNNER_ARCH']]))
                # Only the release job's own platform is compared with the release runner.
                expected = 'release-runner' if (platform['RUNNER_OS'], platform['RUNNER_ARCH']) == (
                    'Linux', 'X64') else 'pins'
                self.assertEqual(profile['compare'], expected)

    def test_every_input_is_tracked_and_its_change_runs_this_test(self):
        files = tracked()
        self.assertIn('ci-evidence', [check['name'] for check in json.loads(read('dev.json'))['checks']])
        for path in self.config['inputs'] + [CONFIG, HELPER, TEST]:
            with self.subTest(path=path):
                self.assertIn(path, files)
                self.assertTrue(selects(path, 'ci-evidence'), 'a change to %s does not run ci-evidence' % path)

    def test_every_pin_file_of_the_tree_is_an_input(self):
        files = tracked()
        recorded = set(self.config['inputs']) | {CONFIG, HELPER, 'dev.json', self.spec['path']}
        missing = sorted(pin_files(files) - recorded)
        self.assertEqual(missing, [], 'pin files the evidence does not record: add them to inputs')
        for path, why in NOT_PULLED.items():
            with self.subTest(path=path):
                self.assertTrue(why)
                self.assertIn(path, files, 'a stale entry of NOT_PULLED')
                with open(os.path.join(ROOT, path), 'rb') as handle:
                    self.assertRegex(handle.read().decode('utf-8', 'replace'), IMAGE_PIN)
                self.assertNotIn(path, recorded)

    def test_release_takes_the_evidence_and_calls_no_workflow(self):
        jobs = self.release['jobs']
        for key, job in jobs.items():
            with self.subTest(job=key):
                self.assertNotIn('uses', job)
                for step in job.get('steps', []):
                    self.assertNotIn('continue-on-error', step)
        verify = jobs['verify']
        self.assertEqual(verify['name'], 'CI at the tag')
        self.assertEqual(verify['needs'], 'admit')
        self.assertEqual(verify['runs-on'], 'ubuntu-latest')
        self.assertEqual(verify['permissions'], {'contents': 'read', 'actions': 'read'})
        self.assertEqual(jobs['package']['needs'], ['admit', 'verify'])
        self.assertNotIn('if', jobs['package'])
        steps = verify['steps']
        self.assertEqual(steps[0]['with'], {'persist-credentials': 'false', 'ref': '${{ github.sha }}'})
        runs = [index for index, step in enumerate(steps)
                if 'release_evidence.py verify' in (step.get('run') or '')]
        self.assertEqual(len(runs), 1)
        run, keep = steps[runs[0]], steps[runs[0] + 1]
        self.assertEqual(run['run'], 'python3 %s verify --output "${RUNNER_TEMP}/release-evidence.json"' % HELPER)
        self.assertNotIn('if', run)
        self.assertEqual(run['env'], {'GH_TOKEN': '${{ github.token }}'})
        self.assertEqual(keep['if'], '${{ !cancelled() }}')
        self.assertTrue(keep['uses'].startswith(UPLOAD))
        self.assertEqual(keep['with'], {'name': 'release-evidence-${{ github.run_attempt }}',
                                        'path': '${{ runner.temp }}/release-evidence.json',
                                        'if-no-files-found': 'error'})

    def test_release_sets_up_the_check_jobs_toolchains_as_ci_does(self):
        def setups(steps):
            return {step['uses'].split('@')[0]: step for step in steps
                    if step.get('uses', '').startswith(('actions/setup-go@', 'actions/setup-node@',
                                                        'actions/setup-python@'))}
        check = self.ci['jobs']['check']['steps']
        verify = self.release['jobs']['verify']['steps']
        ours, theirs = setups(verify), setups(check)
        self.assertEqual(sorted(ours), ['actions/setup-go', 'actions/setup-node', 'actions/setup-python'])
        for action in ours:
            with self.subTest(action=action):
                self.assertEqual(ours[action]['uses'], theirs[action]['uses'])
                ours_with, theirs_with = dict(ours[action]['with']), dict(theirs[action]['with'])
                # The module cache is the one difference: it does not touch the toolchain.
                ours_with.pop('cache', None)
                theirs_with.pop('cache-dependency-path', None)
                self.assertEqual(ours_with, theirs_with)
        named = [step for step in verify if step.get('id') == 'dev']
        self.assertEqual(len(named), 1)
        self.assertEqual(named[0], [step for step in check if step.get('id') == 'dev'][0])
        # The gate runs after the toolchains are set up, so it resolves them.
        order = [step.get('uses', '').split('@')[0] or step.get('run', '') for step in verify]
        gate_at = [index for index, text in enumerate(order) if 'release_evidence.py verify' in text][0]
        for action in ours:
            self.assertLess(order.index(action), gate_at)


class VendoredGateTest(unittest.TestCase):
    """scripts/dev/release_evidence.py is the kit's library, line 2 naming the kit release."""

    def test_the_vendored_gate_is_the_kits_library_after_line_2(self):
        with open(os.path.join(ROOT, HELPER), 'rb') as handle:
            data = handle.read()
        lines = data.split(b'\n')
        self.assertEqual(lines[0], b'#!/usr/bin/env python3')
        release, source = kit_release(HELPER)
        self.assertEqual(source, 'lib/release_evidence.py')
        self.assertIn(release, KIT_DIGESTS, 'record the digest of the kit release this copy names')
        library = b'\n'.join(lines[:1] + lines[2:])
        self.assertEqual(hashlib.sha256(library).hexdigest(), KIT_DIGESTS[release])

    def test_the_vendored_scripts_name_one_kit_release(self):
        releases = {path: kit_release(path)[0] for path in (
            HELPER, 'scripts/dev/check.sh', 'scripts/dev/changed_checks.py', 'scripts/dev/handover_check.sh')}
        self.assertEqual(len(set(releases.values())), 1, releases)


if __name__ == '__main__':
    unittest.main(verbosity=2)
