"""Validate actual public-web producer output and required source members."""
import copy
import json
from pathlib import Path
import sys
from jsonschema import Draft202012Validator
schema = json.loads(Path(__file__).with_name('attachment-v1.schema.json').read_text())
validator = Draft202012Validator(schema)
record = json.loads(Path(sys.argv[1]).read_text())
validator.validate(record)
for key in ('requestedUrl', 'url', 'version', 'responseDigest', 'mediaType', 'format'):
    bad = copy.deepcopy(record)
    del bad['provenance']['source'][key]
    assert not validator.is_valid(bad), 'missing source member accepted'
for key, value in [('version', 'unversioned'), ('responseDigest', 'bad'), ('format', 'rendered-html'), ('mediaType', 'application/json')]:
    bad = copy.deepcopy(record)
    bad['provenance']['source'][key] = value
    assert not validator.is_valid(bad), 'unknown source variant accepted'
bad = copy.deepcopy(record)
bad['provenance']['source']['cookie'] = 'must-not-be-present'
assert not validator.is_valid(bad), 'credential member accepted'
# redirectPolicy is optional and closed: present only when a redirect policy
# was followed, and then a policy the schema names.
for value in ('', 'any-origin', None):
    bad = copy.deepcopy(record)
    bad['provenance']['source']['redirectPolicy'] = value
    assert not validator.is_valid(bad), 'unknown redirect policy accepted'
print('PASS: web producer record and required source members')
