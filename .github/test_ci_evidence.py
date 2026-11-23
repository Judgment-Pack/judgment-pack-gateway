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
  vendored scripts name;
- the matrix legs each event runs, and the Windows leg's shards: each top-level test of the core
  in exactly one (.github/go_test_shard.py, held here too);
- the check lanes: every check of dev.json in exactly one (.github/check_lanes.py, held here too),
  and the check job, which fails unless both lanes succeeded and records every check's result from
  their summaries.

Standard library only; the workflows are read by the YAML subset below, which refuses anything
it does not know. Run from the repository root: python3 .github/test_ci_evidence.py"""
import hashlib
import importlib.util
import json
import os
import re
import subprocess
import tempfile
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
    'testdata/tool-taxonomy/v3.json': 'a customer taxonomy fixture, read as data',
    'testdata/tool-taxonomy/v4.json': 'a customer command taxonomy fixture, read as data',
}
UPLOAD = 'actions/upload-artifact@'
DOWNLOAD = 'actions/download-artifact@'
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


# The one expression a matrix value may be: a value for runs of the events named, 'none' (which
# matches no leg) for every other event.
EVENT_VALUE = re.compile(r"\$\{\{\s*(\(\s*(?P<several>[^()]*)\s*\)|(?P<one>[^()&|]*?))\s*&&\s*"
                         r"'(?P<value>[A-Za-z0-9_.-]+)'\s*\|\|\s*'none'\s*\}\}")
EVENT_TEST = re.compile(r"github\.event_name == '([a-z_]+)'")


def matrix_value(value, event):
    """A matrix value as GitHub evaluates it for a run of event: a literal, or
    `${{ (github.event_name == 'a' || github.event_name == 'b') && 'value' || 'none' }}`; any other
    expression is refused."""
    if '${{' not in value:
        return value
    found = EVENT_VALUE.fullmatch(value.strip())
    if not found:
        raise ValueError('a matrix expression this reader does not know: %r' % value)
    tests = [part.strip() for part in (found.group('several') or found.group('one')).split('||')]
    events = []
    for test in tests:
        one = EVENT_TEST.fullmatch(test)
        if not one:
            raise ValueError('a matrix condition this reader does not know: %r' % test)
        events.append(one.group(1))
    return found.group('value') if event in events else 'none'


def legs(job, event='push'):
    """One dict of matrix values per leg of a job for a run of event (one empty dict for a job
    without a matrix), as GitHub expands a matrix: the product of the base values, without the
    combinations an exclude entry matches, then each include entry added to every original
    combination it overwrites no base value of, or made a leg of its own where there is none. A
    key some leg has and another does not is '' in the other, as the expression reads it there."""
    strategy = job.get('strategy') or {}
    matrix = strategy.get('matrix')
    if matrix is None:
        return [{}]
    unknown = set(matrix) - {'include', 'exclude'} - {key for key, values in matrix.items()
                                                     if isinstance(values, list)}
    if unknown:
        raise ValueError('matrix keys this reader does not know: %s' % sorted(unknown))
    base = {key: values for key, values in matrix.items() if key not in ('include', 'exclude')}
    for key, values in base.items():
        if not values or not all(isinstance(value, str) for value in values):
            raise ValueError('matrix.%s: a list of scalars is required' % key)
    originals = [{}] if base else []
    for key, values in base.items():
        originals = [dict(leg, **{key: value}) for leg in originals for value in values]
    for entry in matrix.get('exclude') or []:
        if not isinstance(entry, dict) or not entry or not set(entry) <= set(base):
            raise ValueError('an exclude entry names a key of no base: %r' % entry)
        values = {key: matrix_value(value, event) for key, value in entry.items()}
        originals = [leg for leg in originals if any(leg[key] != value for key, value in values.items())]
    added = []
    for entry in matrix.get('include') or []:
        if not isinstance(entry, dict) or not entry:
            raise ValueError('an include entry is not a mapping: %r' % entry)
        if any('${{' in value for value in entry.values()):
            raise ValueError('an include entry holds an expression: %r' % entry)
        matched = [leg for leg in originals if all(leg[key] == value for key, value in entry.items()
                                                   if key in base)]
        for leg in matched:
            leg.update(entry)
        if not matched:
            added.append(dict(entry))
    result = originals + added
    keys = {key for leg in result for key in leg}
    return [{key: leg.get(key, '') for key in sorted(keys)} for leg in result]


LEG_TEST = re.compile(r"matrix\.([A-Za-z0-9_-]+) (==|!=) '([^']*)'")


def runs_on_leg(condition, values):
    """Whether a step's `if` lets it run on a leg: no condition, or matrix tests joined by || or by
    && (not both); a condition on anything but the matrix is refused here."""
    if condition is None:
        return True
    for joiner, combine in ((' || ', any), (' && ', all)):
        if joiner in condition:
            if (' && ' if joiner == ' || ' else ' || ') in condition:
                raise ValueError('a condition mixing || and &&: %r' % condition)
            return combine(runs_on_leg(part, values) for part in condition.split(joiner))
    found = LEG_TEST.fullmatch(condition.strip())
    if not found or found.group(1) not in values:
        raise ValueError('a leg condition this reader does not know: %r' % condition)
    return (values[found.group(1)] == found.group(3)) == (found.group(2) == '==')


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


class MatrixTest(unittest.TestCase):
    """The matrix reader expands a matrix as GitHub does, per event, and refuses what it does not
    know."""

    QUEUE = "${{ (github.event_name == 'pull_request' || github.event_name == 'merge_group') && 'b' || 'none' }}"

    def test_base_exclude_and_include(self):
        job = {'strategy': {'matrix': {
            'os': ['a', 'b', 'c'], 'n': ['1', '2'],
            'exclude': [{'os': 'a', 'n': '2'}, {'os': 'b', 'n': '2'}, {'os': self.QUEUE}],
            'include': [{'os': 'c', 'n': '1', 'part': 'x'}, {'os': 'c', 'n': '2', 'part': 'y'}]}}}
        self.assertEqual(legs(job, 'push'), [
            {'n': '1', 'os': 'a', 'part': ''}, {'n': '1', 'os': 'b', 'part': ''},
            {'n': '1', 'os': 'c', 'part': 'x'}, {'n': '2', 'os': 'c', 'part': 'y'}])
        for event in ('pull_request', 'merge_group'):
            with self.subTest(event=event):
                self.assertEqual([leg['os'] for leg in legs(job, event)], ['a', 'c', 'c'])

    def test_an_include_that_matches_nothing_is_a_leg_of_its_own(self):
        # Includes are applied after excludes: an include for an excluded leg would bring it back.
        job = {'strategy': {'matrix': {'os': ['a', 'b'], 'exclude': [{'os': self.QUEUE}],
                                       'include': [{'os': 'b', 'k': 'v'}]}}}
        self.assertEqual(legs(job, 'pull_request'), [{'k': '', 'os': 'a'}, {'k': 'v', 'os': 'b'}])
        self.assertEqual(legs({'strategy': {'matrix': {'include': [{'os': 'a'}, {'os': 'b'}]}}}),
                         [{'os': 'a'}, {'os': 'b'}])

    def test_refuses_expressions_it_does_not_know(self):
        for value in ("${{ github.ref == 'refs/heads/main' && 'b' || 'none' }}",
                      "${{ github.event_name != 'push' && 'b' || 'none' }}",
                      "${{ github.event_name == 'push' && 'b' || 'a' }}",
                      "${{ matrix.os }}"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                legs({'strategy': {'matrix': {'os': ['a', 'b'], 'exclude': [{'os': value}]}}})
        for matrix in ({'os': 'a'}, {'os': ['a'], 'exclude': [{'go': 'x'}]},
                       {'os': ['a'], 'include': [{'os': '${{ matrix.os }}'}]}):
            with self.subTest(matrix=matrix), self.assertRaises(ValueError):
                legs({'strategy': {'matrix': matrix}})


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
        # The go matrix is three native operating systems, never one, Windows in shards.
        self.assertEqual(sorted(values['os'] for values in legs(self.ci['jobs']['go'])),
                         ['macos-latest', 'ubuntu-latest', 'windows-latest', 'windows-latest'])

    def test_the_windows_shards_test_the_core_once_and_the_other_legs_whole(self):
        """Each leg runs the core's tests by one step: `go test ./...`, or on Windows one shard of
        the script's split, the shards being 1 to N of its --of N. The sandbox boundary tests run
        once on each operating system."""
        go = self.ci['jobs']['go']
        steps = {step['name']: step for step in go['steps']}
        whole, shard = steps['Tests'], steps['Tests, one shard of two']
        self.assertEqual(whole['run'], 'go test ./...')
        command = shard['run']
        self.assertEqual(option(command, '--dir'), ['go'])
        self.assertEqual(option(command, '--shard'), ['${SHARD}'])
        self.assertEqual(shard['env'], {'SHARD': '${{ matrix.shard }}'})
        self.assertEqual(shard.get('working-directory'), '.')
        self.assertTrue(command.startswith('python .github/go_test_shard.py '))
        count = int(option(command, '--of')[0])
        windows = [values for values in legs(go) if values['os'] == 'windows-latest']
        self.assertEqual(sorted(values['shard'] for values in windows), [str(k) for k in range(1, count + 1)])
        sandbox = {}
        for values in legs(go):
            with self.subTest(leg=expand(go['name'], values)):
                ran = [step['name'] for step in (whole, shard) if runs_on_leg(step.get('if'), values)]
                self.assertEqual(ran, ['Tests, one shard of two' if values['os'] == 'windows-latest' else 'Tests'])
                if runs_on_leg(steps['Native sandbox boundary tests'].get('if'), values):
                    sandbox[values['os']] = sandbox.get(values['os'], 0) + 1
        self.assertEqual(sandbox, {'ubuntu-latest': 1, 'macos-latest': 1, 'windows-latest': 1})

    def test_the_macos_leg_runs_on_main_and_nightly_and_no_leg_else_drops_out(self):
        """A pull request and a merge group run without the macOS leg; a push to main, whose run
        the release takes, and the nightly run have it. Every other leg runs on every event, and
        on the nightly run only the go matrix runs."""
        go = self.ci['jobs']['go']
        on_push = sorted(expand(go['name'], values) for values in legs(go, 'push'))
        macos = [name for name in on_push if name.startswith('macos-latest')]
        self.assertEqual(len(macos), 1)
        for event, has_macos in (('push', True), ('schedule', True), ('pull_request', False),
                                 ('merge_group', False)):
            with self.subTest(event=event):
                names = sorted(expand(go['name'], values) for values in legs(go, event))
                self.assertEqual(names, on_push if has_macos else sorted(set(on_push) - set(macos)))
        self.assertEqual(set(self.ci['on']), {'pull_request', 'merge_group', 'push', 'schedule',
                                              'workflow_call'})
        for key, job in self.ci['jobs'].items():
            with self.subTest(job=key):
                if key == 'go':
                    self.assertNotIn('if', job)
                else:
                    self.assertIn("github.event_name != 'schedule'", job['if'])

    def test_the_check_job_passes_only_when_both_lanes_did_and_reads_both(self):
        """`check` needs the lanes, runs when one failed or the run was cancelled, and fails unless both succeeded; on a push
        to main its evidence reads the summary of every lane. Each lane runs check.sh skipping
        what .github/check_lanes.py says, on every event."""
        lanes_job, check = self.ci['jobs']['check-lanes'], self.ci['jobs']['check']
        lanes = [values['lane'] for values in legs(lanes_job)]
        self.assertEqual(tuple(lanes), vendored('check_lanes', '.github/check_lanes.py').LANES)
        self.assertEqual(check['needs'], 'check-lanes')
        # always(), not !cancelled(): a run cancelled while the lanes ran must leave `check` failed,
        # not skipped, since a skipped required check counts as passed.
        self.assertEqual(check['if'], "${{ always() && github.event_name != 'schedule' }}")
        self.assertNotIn('cancelled()', check['if'])
        gate = check['steps'][0]
        self.assertEqual(gate['env'], {'LANES': '${{ needs.check-lanes.result }}'})
        self.assertIn('if [ "${LANES}" != success ]; then', gate['run'])
        self.assertIn('exit 1', gate['run'])
        self.assertNotIn('if', gate)
        capture = [step for step in check['steps'] if 'release_evidence.py capture' in (step.get('run') or '')][0]
        self.assertEqual(sorted(option(capture['run'], '--check-log')),
                         sorted('${RUNNER_TEMP}/%s/checks.log' % lane for lane in lanes))
        self.assertEqual(option(capture['run'], '--setup-log'), [])
        steps = {step['name']: step for step in lanes_job['steps']}
        choose = steps["The lane's checks"]
        self.assertEqual(choose['id'], 'lane')
        self.assertEqual(choose['env'], {'LANE': '${{ matrix.lane }}'})
        self.assertEqual(choose['run'], 'python3 .github/check_lanes.py --lane "${LANE}" >> "$GITHUB_OUTPUT"')
        run = steps['Checks']
        self.assertEqual(run['env']['SKIP'], '${{ steps.lane.outputs.skip }}')
        calls = re.findall(r'scripts/dev/check\.sh [^|]*', run['run'])
        self.assertEqual(len(calls), 3)
        for call in calls:
            with self.subTest(call=call):
                self.assertEqual(option(call, '--skip'), ['$SKIP'])
                self.assertNotIn('--only', call)

    def test_the_postgresql_passes_run_once_each_in_legs_of_their_own(self):
        """The superuser pass and the pass as an administrator that is no superuser each run in
        one leg, against the leg's own server, over the same tests; the storage scenario once."""
        job = self.ci['jobs']['postgresql']
        self.assertIn('postgres', job['services'])
        steps = {step['name']: step for step in job['steps']}
        passes = ("The PostgreSQL kind's tests, none skipped",
                  "The PostgreSQL kind's tests as an administrator that is no superuser")
        runs = {name: [values['role'] for values in legs(job) if runs_on_leg(steps[name].get('if'), values)]
                for name in passes + ('The storage kinds through the binary',)}
        self.assertEqual(runs, {passes[0]: ['superuser'], passes[1]: ['non-superuser'],
                                'The storage kinds through the binary': ['superuser']})
        selections = [re.findall(r"go test [^|]* -run '([^']+)' \.", steps[name]['run']) for name in passes]
        self.assertEqual(len(selections[0]), 1)
        self.assertEqual(selections[0], selections[1])

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
                # The summaries capture reads are the ones the job's steps write, or a job it needs
                # wrote and uploaded in this attempt, the job failing with a failed step
                # (pipefail), so a summary is never of a step that failed.
                for log in option(command, '--setup-log') + option(command, '--check-log'):
                    writer = self.summary_writer(job, steps[:captures[0]], log)
                    self.assertIn('set -o pipefail', writer['run'])

    def summary_writer(self, job, before, log):
        """The step that wrote log: one of the job's steps before the capture, or, for a summary
        the job downloads, the step of the job it needs that wrote the file that job uploads under
        that name on a push to main, in the same attempt."""
        writers = [step for step in before if '| tee "%s"' % log in (step.get('run') or '')]
        downloads = [step for step in before if step.get('uses', '').startswith(DOWNLOAD)
                     and log == step['with']['path'].replace('${{ runner.temp }}', '${RUNNER_TEMP}') +
                     '/' + log.rsplit('/', 1)[1]]
        self.assertEqual(len(writers) + len(downloads), 1, log)
        if writers:
            return writers[0]
        download = downloads[0]
        self.assertEqual(download.get('if'), CAPTURE_GUARD)
        name = download['with']['name']
        self.assertTrue(name.endswith('-${{ github.run_attempt }}'), name)
        found = []
        for upstream in [job['needs']] if isinstance(job.get('needs'), str) else job.get('needs', []):
            for values in legs(self.ci['jobs'][upstream]):
                steps = self.ci['jobs'][upstream]['steps']
                for index, step in enumerate(steps):
                    if step.get('uses', '').startswith(UPLOAD) and expand(step['with']['name'], values) == name:
                        self.assertEqual(step.get('if'), CAPTURE_GUARD)
                        self.assertEqual(step['with']['if-no-files-found'], 'error')
                        path = step['with']['path'].replace('${{ runner.temp }}', '${RUNNER_TEMP}')
                        self.assertEqual(path.rsplit('/', 1)[1], log.rsplit('/', 1)[1])
                        wrote = [earlier for earlier in steps[:index]
                                 if '| tee "%s"' % path in (earlier.get('run') or '')]
                        self.assertEqual(len(wrote), 1, path)
                        found.append(wrote[0])
        self.assertEqual(len(found), 1, '%s is uploaded by %d legs of the jobs this one needs' % (name, len(found)))
        return found[0]

    def test_the_image_builder_runs_the_go_release_yml_names(self):
        """The engine image's builder image is held to release.yml's setup-go pin: its build stage
        stops unless `go version` names that release, with toolchain switching off, and the image
        check that runs the builder names the same image."""
        dockerfile = read('Dockerfile')
        stages = re.split(r'^FROM ', dockerfile, flags=re.M)
        build = [stage for stage in stages if re.match(r'\S+ +\S+ +AS +build\s*$', stage.split('\n', 1)[0])]
        self.assertEqual(len(build), 1, 'the Dockerfile has one build stage')
        image = re.match(r'(\S+) +(\S+)', build[0]).group(2)
        self.assertRegex(image, r'@sha256:[0-9a-f]{64}$')
        checks = re.findall(r"^RUN go version \| grep -q '\^go version go([0-9.]+) '$", build[0], re.M)
        self.assertEqual(checks, [release_go()])
        body = build[0].split('\n')
        first_build = next(i for i, line in enumerate(body) if 'go build' in line)
        check = next(i for i, line in enumerate(body) if line.startswith('RUN go version'))
        self.assertLess(check, first_build, 'the check runs before the first go build')
        env = [line for line in body[:check] if line.startswith('ENV ')]
        self.assertTrue(any(re.search(r'(^| )GOTOOLCHAIN=local( |$)', line) for line in env),
                        'the build stage sets GOTOOLCHAIN=local before the check')
        short = re.sub(r'^docker\.io/library/', '', image)
        self.assertEqual(re.findall(r'golang:[^\s"]+', read('scripts/checks/image-root-unwritable.sh')), [short])

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
                # Every leg is held to its pins: GitHub serves several builds of one runner image
                # at once, so the image version is not something a release can match.
                self.assertEqual(profile['compare'], 'pins')

    def test_the_check_profile_pins_the_exact_node_and_python_dev_json_names(self):
        toolchains = json.loads(read('dev.json'))['toolchains']
        pins = self.config['profiles']['check']['pins']
        self.assertRegex(toolchains['node']['version'], r'^\d+\.\d+\.\d+$')
        # check.sh (the kit's) finds python<version> on PATH, so the version stays major.minor and
        # the workflows set up the exact one.
        self.assertRegex(toolchains['python']['version'], r'^\d+\.\d+$')
        self.assertRegex(toolchains['python']['exact'], r'^\d+\.\d+\.\d+$')
        self.assertTrue(toolchains['python']['exact'].startswith(toolchains['python']['version'] + '.'))
        self.assertEqual(pins['node'], 'v' + toolchains['node']['version'])
        self.assertEqual(pins['python'], 'Python ' + toolchains['python']['exact'])

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
        def toolchain(step):
            # The module cache is the one difference: it does not touch the toolchain.
            return {key: value for key, value in step['with'].items()
                    if key not in ('cache', 'cache-dependency-path')}
        verify = self.release['jobs']['verify']['steps']
        ours = setups(verify)
        self.assertEqual(sorted(ours), ['actions/setup-go', 'actions/setup-node', 'actions/setup-python'])
        named = [step for step in verify if step.get('id') == 'dev']
        self.assertEqual(len(named), 1)
        # Every job whose evidence is held to the check profile: the check job and its lanes.
        held = sorted({spec['job_id'] for spec in self.spec['jobs'].values() if spec['profile'] == 'check'})
        self.assertEqual(held, ['check', 'check-lanes'])
        for job_id in held:
            check = self.ci['jobs'][job_id]['steps']
            theirs = setups(check)
            self.assertEqual(sorted(theirs), sorted(ours))
            for action in ours:
                with self.subTest(job=job_id, action=action):
                    self.assertEqual(ours[action]['uses'], theirs[action]['uses'])
                    self.assertEqual(toolchain(ours[action]), toolchain(theirs[action]))
            with self.subTest(job=job_id):
                self.assertEqual(named[0], [step for step in check if step.get('id') == 'dev'][0])
        self.assertEqual(setups(self.ci['jobs']['check']['steps'])['actions/setup-go']['with'],
                         ours['actions/setup-go']['with'])
        # The gate runs after the toolchains are set up, so it resolves them.
        order = [step.get('uses', '').split('@')[0] or step.get('run', '') for step in verify]
        gate_at = [index for index, text in enumerate(order) if 'release_evidence.py verify' in text][0]
        for action in ours:
            self.assertLess(order.index(action), gate_at)


class CheckLanesTest(unittest.TestCase):
    """.github/check_lanes.py: every check of dev.json in exactly one lane, a new one in rest, and
    a stale name refused."""

    @classmethod
    def setUpClass(cls):
        cls.lanes = vendored('check_lanes', '.github/check_lanes.py')
        cls.names = cls.lanes.checks(json.loads(read('dev.json')))

    def runs(self, lane, names):
        skipped = self.lanes.skipped(lane, names)
        self.assertEqual(len(skipped), len(set(skipped)))
        return [name for name in names if name not in skipped]

    def test_every_check_runs_in_exactly_one_lane(self):
        self.assertEqual(sorted(set(self.lanes.GO_TESTS) - set(self.names)), [])
        ran = [name for lane in self.lanes.LANES for name in self.runs(lane, self.names)]
        self.assertEqual(sorted(ran), sorted(self.names))
        self.assertEqual(self.runs('go-tests', self.names),
                         [name for name in self.names if name in self.lanes.GO_TESTS])
        for heavy in ('go-test', 'adapters-test'):
            self.assertIn(heavy, self.lanes.GO_TESTS)
        for light in ('image-build', 'image-platforms', 'release-archives'):
            self.assertIn(light, self.runs('rest', self.names))

    def test_a_check_added_to_dev_json_runs_in_rest(self):
        names = self.names + ['a-new-check']
        self.assertIn('a-new-check', self.runs('rest', names))
        self.assertNotIn('a-new-check', self.runs('go-tests', names))

    def test_refuses_a_stale_name_an_unknown_lane_and_a_lane_of_everything(self):
        gone = [name for name in self.names if name != 'adapters-test']
        for lane in self.lanes.LANES:
            with self.subTest(lane=lane), self.assertRaises(self.lanes.Refusal):
                self.lanes.skipped(lane, gone)
        with self.assertRaises(self.lanes.Refusal):
            self.lanes.skipped('images', self.names)
        for go_tests in ((), tuple(self.names), ('go-test', 'go-test')):
            with self.subTest(go_tests=len(go_tests)), self.assertRaises(self.lanes.Refusal):
                self.lanes.skipped('go-tests', self.names, go_tests)

    def test_the_script_prints_the_skip_list_or_refuses(self):
        for lane in self.lanes.LANES:
            with self.subTest(lane=lane):
                done = subprocess.run(['python3', '-I', '.github/check_lanes.py', '--lane', lane], cwd=ROOT,
                                      stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
                self.assertEqual(done.returncode, 0)
                self.assertEqual(done.stdout, 'skip=%s\n' % ','.join(self.lanes.skipped(lane, self.names)))
        manifest = json.loads(read('dev.json'))
        manifest['checks'] = [check for check in manifest['checks'] if check['name'] != 'go-test']
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, 'dev.json')
            with open(path, 'w', encoding='utf-8') as handle:
                json.dump(manifest, handle)
            done = subprocess.run(['python3', '-I', '.github/check_lanes.py', '--lane', 'rest', '--manifest', path],
                                  cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        self.assertEqual((done.returncode, done.stdout), (1, ''))
        self.assertIn('go-test', done.stderr)


class GoTestShardTest(unittest.TestCase):
    """.github/go_test_shard.py: the rule, its expression, the listing it reads and the refusals."""

    @classmethod
    def setUpClass(cls):
        cls.shard = vendored('go_test_shard', '.github/go_test_shard.py')

    LISTING = ('TestA\nTestBb\r\nExampleCcc\nBenchmarkDd\nok  \tgateway\t0.009s\n'
               '?   \tgateway/cmd\t[no test files]\nFuzzEe\nTestFff\nok  \tgateway/x\t(cached)\n')

    def fake(self, listing, selected):
        def run(arguments, directory):
            self.assertEqual(directory, 'go')
            self.assertEqual(arguments[:2], ['test', '-list'])
            self.assertEqual(arguments[3:], ['./...'])
            return listing if arguments[2] == '.' else selected
        return run

    def test_the_expression_selects_the_rules_names(self):
        for count in (2, 3, 4):
            for k in range(1, count + 1):
                pattern = re.compile(self.shard.expression(k, count))
                for length in range(1, 60):
                    name = 'T' * length
                    with self.subTest(count=count, shard=k, length=length):
                        self.assertEqual(bool(pattern.fullmatch(name)), self.shard.shard_of(name, count) == k)
        self.assertEqual(self.shard.expression(1, 2), '^(?:.{2})*$')
        self.assertEqual(self.shard.expression(2, 2), '^(?:.{2})*.{1}$')
        for k in (0, 3):
            with self.assertRaises(self.shard.Refusal):
                self.shard.expression(k, 2)

    def test_reads_a_listing_package_by_package(self):
        self.assertEqual(self.shard.parse_listing(self.LISTING), {
            'gateway': ['TestA', 'TestBb', 'ExampleCcc', 'BenchmarkDd'], 'gateway/cmd': [],
            'gateway/x': ['FuzzEe', 'TestFff']})
        for text in ('TestA\nsomething printed\nok  \tp\t0.1s\n', 'TestA\n', 'TestA\n?   \tp\t[no test files]\n',
                     'ok  \tp\t0.1s\nok  \tp\t0.1s\n', 'TestA\nTestA\nok  \tp\t0.1s\n',
                     'FAIL\tp [build failed]\n'):
            with self.subTest(text=text), self.assertRaises(self.shard.Refusal):
                self.shard.parse_listing(text)

    def test_runs_when_go_selects_exactly_the_shard(self):
        # Shard 1 of 2 holds the even lengths: TestBb (6), ExampleCcc (10) and FuzzEe (6); shard 2
        # TestA (5), BenchmarkDd (11) and TestFff (7).
        own = 'TestBb\nExampleCcc\nok  \tgateway\t0.1s\n?   \tgateway/cmd\t[no test files]\nFuzzEe\nok  \tgateway/x\t0.1s\n'
        self.assertEqual(self.shard.main(['--dir', 'go', '--shard', '1', '--of', '2', '--dry-run'],
                                         run=self.fake(self.LISTING, own)), 0)
        other = ('TestA\nBenchmarkDd\nok  \tgateway\t0.1s\n?   \tgateway/cmd\t[no test files]\n'
                 'TestFff\nok  \tgateway/x\t0.1s\n')
        self.assertEqual(self.shard.main(['--dir', 'go', '--shard', '2', '--of', '2', '--dry-run'],
                                         run=self.fake(self.LISTING, other)), 0)

    def test_refuses_a_selection_that_is_not_the_shard(self):
        wrong = {
            'a name missing': 'TestBb\nok  \tgateway\t0.1s\n?   \tgateway/cmd\t[no test files]\nFuzzEe\nok  \tgateway/x\t0.1s\n',
            'a name more': 'TestA\nTestBb\nExampleCcc\nok  \tgateway\t0.1s\n?   \tgateway/cmd\t[no test files]\n'
                           'FuzzEe\nok  \tgateway/x\t0.1s\n',
            'a package missing': 'TestBb\nExampleCcc\nok  \tgateway\t0.1s\nFuzzEe\nok  \tgateway/x\t0.1s\n',
            'everything': self.LISTING,
        }
        for why, selected in wrong.items():
            with self.subTest(why=why):
                self.assertEqual(self.shard.main(['--dir', 'go', '--shard', '1', '--of', '2', '--dry-run'],
                                                 run=self.fake(self.LISTING, selected)), 1)

    def test_refuses_an_empty_shard_and_a_split_of_one(self):
        listing = 'TestAb\nok  \tgateway\t0.1s\n'
        self.assertEqual(self.shard.main(['--dir', 'go', '--shard', '2', '--of', '2', '--dry-run'],
                                         run=self.fake(listing, 'ok  \tgateway\t0.1s\n')), 1)
        self.assertEqual(self.shard.main(['--dir', 'go', '--shard', '1', '--of', '1', '--dry-run'],
                                         run=self.fake(listing, listing)), 1)


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
