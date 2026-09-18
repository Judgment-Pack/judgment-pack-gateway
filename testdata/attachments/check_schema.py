#!/usr/bin/env python3
"""Validate real Drive producer output and reject broken source variants."""
import copy
import json
from pathlib import Path
import sys
from jsonschema import Draft202012Validator

schema = json.loads(Path(__file__).with_name('attachment-v1.schema.json').read_text())
Draft202012Validator.check_schema(schema)
validator = Draft202012Validator(schema)
record = json.loads(Path(sys.argv[1]).read_text())
validator.validate(record)
for key in ('fileId', 'version', 'mediaType'):
    broken = copy.deepcopy(record)
    del broken['provenance']['source'][key]
    assert not validator.is_valid(broken), f'missing {key} accepted'
for value in ('', 'bad/file', 'a' * 201):
    broken = copy.deepcopy(record)
    broken['provenance']['source']['fileId'] = value
    assert not validator.is_valid(broken), 'invalid fileId accepted'
broken = copy.deepcopy(record)
broken['provenance']['source']['token'] = 'must-not-be-present'
assert not validator.is_valid(broken), 'unexpected source credential member accepted'
for key, values in (
    ('version', ('', 'v' * 33)),
    ('mediaType', ('', 'TEXT/PLAIN', 'text/plain\n', 'not-a-mime-type', 'text/plain; charset=utf-8')),
):
    for value in values:
        broken = copy.deepcopy(record)
        broken['provenance']['source'][key] = value
        assert not validator.is_valid(broken), f'invalid source {key} accepted: {value!r}'
for media_type in ('text/plain', 'application/pdf', 'application/vnd.google-apps.document'):
    boundary = copy.deepcopy(record)
    boundary['document']['version'] = 'v' * 32
    boundary['provenance']['source'].update(version='v' * 32, mediaType=media_type)
    validator.validate(boundary)
print('PASS: actual Drive record and lexical boundaries match producer schema; 14 invalid variants refused')
