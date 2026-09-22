"""Check an actual generic producer snapshot against the published schema."""
import copy
import json
from pathlib import Path
import sys
from jsonschema import Draft202012Validator
schema = json.loads(Path(__file__).with_name('attachment-v1.schema.json').read_text())
validator = Draft202012Validator(schema)
record = json.loads(Path(sys.argv[1]).read_text())
validator.validate(record)
for key in ('provider', 'resourceId', 'url', 'version', 'format'):
    bad = copy.deepcopy(record)
    del bad['provenance']['source'][key]
    assert not validator.is_valid(bad), 'missing source member accepted'
for key, value in [('provider', '../private'), ('resourceId', ''), ('version', 'unversioned'), ('format', 'raw')]:
    bad = copy.deepcopy(record)
    bad['provenance']['source'][key] = value
    assert not validator.is_valid(bad), 'invalid source identity accepted'
bad = copy.deepcopy(record)
bad['provenance']['source']['accessToken'] = 'must-not-be-present'
assert not validator.is_valid(bad), 'credential member accepted'
print('PASS: generic resource producer record and source members')
