#!/usr/bin/env python3
"""Hold the adapter envelope schema to its vectors, to the table of remote
endpoints, and to the differences its description states.

usage: check_adapter_envelope.py [ENVELOPE.json ...]

Every vector under vectors/adapter-envelope/valid must be accepted and every
one under vectors/adapter-envelope/invalid refused; go/adapter_envelope_test.go
holds the gateway's own reading to the same files. Each endpoint of
testdata/remote-endpoints/cases.json, put in an envelope from a remote server,
is accepted or refused as the table says. Each ENVELOPE.json named on the
command line is one a source's code wrote in this run (the adapter-conform
step names them), and must be accepted. The validator is the one the setup
step installs (testdata/attachments/schema-requirements.txt)."""
import copy
import json
from pathlib import Path
import sys

from jsonschema import Draft202012Validator
from jsonschema.exceptions import best_match

here = Path(__file__).parent
schema = json.loads((here / 'adapter-envelope.v1.json').read_text(encoding='utf-8'))
Draft202012Validator.check_schema(schema)
validator = Draft202012Validator(schema)
vectors = here / 'vectors' / 'adapter-envelope'


def read(path):
    return json.loads(Path(path).read_text(encoding='utf-8'))


def accepted(value, what):
    error = best_match(validator.iter_errors(value))
    assert error is None, f'refused, against the vectors: {what}: {error.message}'


def refused(value, what):
    assert not validator.is_valid(value), f'accepted, against the vectors: {what}'


valid = sorted((vectors / 'valid').glob('*.json'))
invalid = sorted((vectors / 'invalid').glob('*.json'))
assert valid and invalid, 'no vectors'
for path in valid:
    accepted(read(path), path.name)
for path in invalid:
    refused(read(path), path.name)

# The remote form, case by case: an https endpoint with the identity of a
# TLS peer, an http one with none, as a remote server's envelope carries.
table = read(here.parent / 'testdata' / 'remote-endpoints' / 'cases.json')
remote = read(vectors / 'valid' / 'remote-over-tls.json')
tls = remote['acquisition']['peerIdentity']
endpoints = 0
for side, check in (('accepted', accepted), ('refused', refused)):
    for case in table[side]:
        endpoint = case['endpoint']
        if 'padTo' in case:
            endpoint += 'a' * (case['padTo'] - len(endpoint))
        envelope = copy.deepcopy(remote)
        envelope['acquisition']['endpoint'] = endpoint
        envelope['acquisition']['peerIdentity'] = tls if endpoint.startswith('https://') else None
        check(envelope, f'{side} {case["rule"]}: {endpoint[:80]!r}')
        endpoints += 1

# What the description leaves to the gateway, admitted here: a schema reads
# parsed JSON, and the shape is the operator's.
base = (vectors / 'valid' / 'one-row.json').read_text(encoding='utf-8')


def edited(old, new):
    text = base.replace(old, new, 1)
    assert text != base, old
    return text


stated = 0
for text, why in [
    (edited('"id": 101', '"id": 101.0'), 'an integer written with a fraction'),
    (edited('"id": 101', '"id": 1.01e2'), 'an integer written with an exponent'),
    (edited('"id": 101', '"id": 1, "id": 101'), 'a member named twice'),
    (edited('"approved"', '"\\ud800"'), 'a lone surrogate'),
    ((vectors / 'valid' / 'remote-loopback.json').read_text(encoding='utf-8'), 'transport and server, whatever shape the source was declared with'),
]:
    accepted(json.loads(text), f'a stated difference: {why}')
    stated += 1

written = sys.argv[1:]
for path in written:
    accepted(read(path), path)

print(f'PASS: the adapter envelope schema accepts {len(valid)} valid vectors and refuses {len(invalid)} invalid ones; '
      f'{endpoints} remote endpoints as the table says; {stated} stated differences admitted; {len(written)} written envelopes accepted')
