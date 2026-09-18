#!/usr/bin/env python3
"""Check real Gmail producer output and its source-specific lexical boundaries."""
import copy
import json
from pathlib import Path
import sys
from jsonschema import Draft202012Validator
schema = json.loads(Path(__file__).with_name('attachment-v1.schema.json').read_text())
validator = Draft202012Validator(schema)
record = json.loads(Path(sys.argv[1]).read_text())
validator.validate(record)
for key in ('messageId', 'threadId', 'version', 'format'):
    invalid = copy.deepcopy(record)
    del invalid['provenance']['source'][key]
    assert not validator.is_valid(invalid), f'missing {key} accepted'
for key, values in (
    ('messageId', ('../token', 'A', 'a' * 65, 'abc\n')),
    ('threadId', ('', 'unknown', 'a' * 65)),
    ('version', ('', '1' * 33, '1\n', 'one')),
    ('format', ('raw', 'html')),
):
    for value in values:
        invalid = copy.deepcopy(record)
        invalid['provenance']['source'][key] = value
        assert not validator.is_valid(invalid), f'invalid {key} accepted'
invalid = copy.deepcopy(record)
invalid['provenance']['source']['accessToken'] = 'must-not-be-present'
assert not validator.is_valid(invalid), 'extra source token accepted'
print('PASS: actual Gmail export matches schema; 18 invalid variants refused')
