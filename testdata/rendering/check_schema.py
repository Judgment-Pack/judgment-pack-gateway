#!/usr/bin/env python3
"""Hold the rendering schemas to the examples and to a record an adapter
wrote, and hold them to refuse what the contract refuses.

usage: check_schema.py RECORD.json

RECORD.json is a record adapter-render wrote in this run. The examples are
read from the directory beside this script."""
import copy
import json
from pathlib import Path
import sys

from jsonschema import Draft202012Validator

here = Path(__file__).parent
arguments_schema = json.loads((here / 'arguments-v1.schema.json').read_text())
record_schema = json.loads((here / 'render-v1.schema.json').read_text())
Draft202012Validator.check_schema(arguments_schema)
Draft202012Validator.check_schema(record_schema)
arguments = Draft202012Validator(arguments_schema)
record = Draft202012Validator(record_schema)

written = json.loads(Path(sys.argv[1]).read_text())
record.validate(written)
example = json.loads((here / 'examples' / 'refund-decision.record.json').read_text())
record.validate(example)
request = json.loads((here / 'examples' / 'refund-decision.request.json').read_text())
arguments.validate(request)

refused = 0


def refuse(validator, value, change, why):
    global refused
    broken = copy.deepcopy(value)
    change(broken)
    assert not validator.is_valid(broken), f'accepted: {why}'
    refused += 1


def member(value, *path):
    for name in path:
        value = value[name]
    return value


def put(*path_and_value):
    *path, name, new = path_and_value
    return lambda v: member(v, *path).__setitem__(name, new)


def drop(*path):
    *path, name = path
    return lambda v: member(v, *path).pop(name)


blocks = request['document']['blocks']
kinds = [b['type'] for b in blocks]
paragraph, heading = kinds.index('paragraph'), kinds.index('heading')
listing, table = kinds.index('list'), kinds.index('table')

for change, why in [
    (put('format', 'html'), 'a format the contract does not name'),
    (put('format', 'DOCX'), 'a format of another case'),
    (drop('format'), 'no format'),
    (drop('document'), 'no document'),
    (put('save', 'drive'), 'a member the contract does not name'),
    (put('document', 'title', ''), 'an empty title'),
    (put('document', 'title', 'a\nb'), 'a title with a line feed'),
    (put('document', 'title', 'a\x7fb'), 'a title with a delete'),
    (put('document', 'title', 'a￾b'), 'a title with U+FFFE'),
    (put('document', 'title', 't' * 256), 'a title of 256 characters'),
    (put('document', 'language', 'en us'), 'a language that is no tag'),
    (put('document', 'language', 'en\n'), 'a language with a line feed after it'),
    (put('document', 'language', 'e'), 'a language of one letter'),
    (put('document', 'author', 'a'), 'a member of document the contract does not name'),
    (put('document', 'blocks', []), 'no block'),
    (put('document', 'blocks', {}), 'blocks that is an object'),
    (put('cites', {}), 'cites with no decision'),
    (put('cites', 'decision', 'sha256:abc'), 'a decision that is no digest'),
    (put('cites', 'decision', 'sha256:' + 'A' * 64), 'a decision in capitals'),
    (put('cites', 'receipt', 'x'), 'a member of cites the contract does not name'),
    (put('document', 'blocks', paragraph, 'type', 'image'), 'a type the contract does not define'),
    (put('document', 'blocks', paragraph, 'level', 1), 'a paragraph with a level'),
    (drop('document', 'blocks', paragraph, 'runs'), 'a paragraph with no runs'),
    (drop('document', 'blocks', paragraph, 'type'), 'a block with no type'),
    (put('document', 'blocks', paragraph, 'runs', [{'text': 'x'}] * 513), '513 runs'),
    (put('document', 'blocks', paragraph, 'runs', 0, 'text', 1), 'a text that is a number'),
    (put('document', 'blocks', paragraph, 'runs', 0, 'text', 'a\rb'), 'a text with a carriage return'),
    (put('document', 'blocks', paragraph, 'runs', 0, 'text', 'a\x00b'), 'a text with a null character'),
    (put('document', 'blocks', paragraph, 'runs', 0, 'text', 'a\x7fb'), 'a text with a delete'),
    (put('document', 'blocks', paragraph, 'runs', 0, 'text', 'a￿b'), 'a text with U+FFFF'),
    (put('document', 'blocks', paragraph, 'runs', 0, 'bold', 'true'), 'bold that is a string'),
    (put('document', 'blocks', paragraph, 'runs', 0, 'color', 'red'), 'a member of a run the contract does not name'),
    (drop('document', 'blocks', paragraph, 'runs', 0, 'text'), 'a run with no text'),
    (put('document', 'blocks', paragraph, 'runs', 0, 'link', ''), 'an empty target'),
    (put('document', 'blocks', paragraph, 'runs', 0, 'link', 'example.com'), 'a target with no scheme'),
    (put('document', 'blocks', paragraph, 'runs', 0, 'link', 'file:///etc/passwd'), 'a target that is a file'),
    (put('document', 'blocks', paragraph, 'runs', 0, 'link', 'javascript:alert(1)'), 'a target that is a script'),
    (put('document', 'blocks', paragraph, 'runs', 0, 'link', 'https://example.com/a b'), 'a target with a space'),
    (put('document', 'blocks', paragraph, 'runs', 0, 'link', 'https://example.com/\n'), 'a target with a line feed after it'),
    (put('document', 'blocks', paragraph, 'runs', 0, 'link', 'https://example.com/' + 'a' * 2048), 'a target past its length'),
    (put('document', 'blocks', heading, 'level', 0), 'a heading of level 0'),
    (put('document', 'blocks', heading, 'level', 7), 'a heading of level 7'),
    (put('document', 'blocks', heading, 'level', '1'), 'a level that is a string'),
    (put('document', 'blocks', heading, 'level', 1.5), 'a level with a fraction'),
    (drop('document', 'blocks', heading, 'level'), 'a heading with no level'),
    (put('document', 'blocks', listing, 'ordered', 1), 'ordered that is a number'),
    (drop('document', 'blocks', listing, 'ordered'), 'a list with no ordered'),
    (put('document', 'blocks', listing, 'items', []), 'a list with no item'),
    (put('document', 'blocks', listing, 'items', [{'runs': []}] * 1001), '1001 items'),
    (put('document', 'blocks', listing, 'items', 0, 'items', []), 'a list within a list'),
    (put('document', 'blocks', listing, 'items', 0, 'x'), 'an item that is a string'),
    (put('document', 'blocks', table, 'rows', []), 'a table with no row'),
    (put('document', 'blocks', table, 'rows', [[]]), 'a table with an empty row'),
    (put('document', 'blocks', table, 'rows', [[{'runs': []}] * 65]), '65 columns'),
    (put('document', 'blocks', table, 'rows', [[{'runs': []}]] * 1001), '1001 rows'),
    (put('document', 'blocks', table, 'header', []), 'an empty header'),
    (put('document', 'blocks', table, 'caption', 'x'), 'a table with a caption'),
    (put('document', 'blocks', table, 'rows', 0, 0, 'rows', []), 'a cell that holds a table'),
]:
    refuse(arguments, request, change, why)

for change, why in [
    (put('renderVersion', '2'), 'a version that is not 1'),
    (put('saved', True), 'a member the record does not have'),
    (drop('provenance'), 'no provenance'),
    (put('request', 'format', 'pdf'), 'a format this release does not write'),
    (put('request', 'title', ''), 'an empty title'),
    (put('request', 'language', 'en us'), 'a language that is no tag'),
    (drop('request', 'language'), 'no language member'),
    (drop('request', 'cites'), 'no cites member'),
    (put('request', 'contentDigest', 'sha256:abc'), 'a content digest that is not one'),
    (put('request', 'blocks', 0), 'no block'),
    (put('request', 'textBytes', -1), 'a negative count of text'),
    (put('request', 'textBytes', 1.5), 'a count with a fraction'),
    (put('request', 'cites', {}), 'cites with no decision'),
    (put('request', 'cites', {'decision': 'x'}), 'a decision that is no digest'),
    (put('file', 'mediaType', 'application/pdf'), 'a media type of another format'),
    (put('file', 'size', 0), 'a size of nothing'),
    (put('file', 'size', '1'), 'a size that is a string'),
    (put('file', 'sha256', 'abc'), 'a digest that is not one'),
    (put('file', 'encoding', 'hex'), 'another encoding'),
    (put('file', 'bytes', ''), 'no bytes'),
    (put('file', 'bytes', 'AAA'), 'base64 without its padding'),
    (put('file', 'bytes', 'AAAA\n'), 'base64 with a line feed after it'),
    (put('file', 'bytes', 'AB=='), 'base64 whose unused bits are not zero'),
    (put('file', 'name', 'a.docx'), 'a member of file the record does not have'),
    (put('rendering', 'status', 'partial'), 'a status that is not complete'),
    (put('rendering', 'renderer', 'kind', 'program'), 'a renderer that is a program'),
    (put('rendering', 'renderer', 'name', 'adapter-render/docx/2'), 'a renderer of another name'),
    (put('rendering', 'renderer', 'digest', 'sha256:' + '0' * 64), 'a renderer with a digest'),
    (put('rendering', 'bounds', 'maxBlocks', 0), 'a bound of nothing'),
    (drop('rendering', 'bounds', 'timeoutMs'), 'bounds without the timeout'),
    (put('rendering', 'durationMs', -1), 'a negative duration'),
    (put('rendering', 'durationMs', 9007199254740992), 'a duration past the domain'),
    (put('provenance', 'adapter', 'name', 'adapter-document'), 'an adapter of another name'),
    (put('provenance', 'adapter', 'version', ''), 'an adapter with no version'),
    (put('provenance', 'adapter', 'digest', 'abc'), 'an adapter whose digest is not one'),
    (put('provenance', 'observedAt', '2026-09-28T12:00:00+02:00'), 'an instant with a zone'),
    (put('provenance', 'observedAt', '2026-09-28T12:00:00.000Z'), 'an instant to the millisecond'),
    (put('provenance', 'observedAt', '2026-09-28T12:00:00Z\n'), 'an instant with a line feed after it'),
    (put('provenance', 'source', None), 'a member of provenance the record does not have'),
]:
    refuse(record, written, change, why)

# What the schemas admit at the edges of each rule.
for change, why in [
    (drop('cites'), 'a request that cites nothing'),
    (drop('document', 'language'), 'a request that names no language'),
    (put('format', 'pdf'), 'a request for a PDF'),
    (put('document', 'language', 'zh-Hant-HK'), 'a language with a script and a region'),
    (put('document', 'blocks', paragraph, 'runs', []), 'a paragraph with no run'),
    (put('document', 'blocks', paragraph, 'runs', 0, 'text', ''), 'an empty text'),
    (put('document', 'blocks', paragraph, 'runs', 0, 'text', 'a\nb\tc'), 'a text with a line feed and a tab'),
    (put('document', 'blocks', paragraph, 'runs', 0, 'link', 'HTTPS://example.com/'), 'a scheme in capitals'),
    (put('document', 'blocks', paragraph, 'runs', 0, 'link', 'mailto:a@example.com'), 'an address'),
    (drop('document', 'blocks', table, 'header'), 'a table with no header'),
]:
    admitted = copy.deepcopy(request)
    change(admitted)
    assert arguments.is_valid(admitted), f'refused: {why}'

print(f'PASS: the examples and the written record match the rendering schemas; {refused} broken variants refused')
