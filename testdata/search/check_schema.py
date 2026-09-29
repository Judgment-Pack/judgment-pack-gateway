#!/usr/bin/env python3
"""Hold the search schemas to the examples and to results the source wrote,
and hold them to refuse what the contract refuses.

usage: check_schema.py RESULT.json GROUNDED-RESULT.json

RESULT.json is the result of a search of a Tavily connection that the source
wrote in this run, and GROUNDED-RESULT.json one of a Google connection. No
provider was asked for either: the answers are the tests' own
(adapters/connections/web_search_record_test.go). The examples are read from
the directory beside this script."""
import copy
import json
from pathlib import Path
import sys

from jsonschema import Draft202012Validator

here = Path(__file__).parent
arguments_schema = json.loads((here / 'arguments-v1.schema.json').read_text())
result_schema = json.loads((here / 'result-v1.schema.json').read_text())
Draft202012Validator.check_schema(arguments_schema)
Draft202012Validator.check_schema(result_schema)
arguments = Draft202012Validator(arguments_schema)
result = Draft202012Validator(result_schema)

written = json.loads(Path(sys.argv[1]).read_text())
grounded = json.loads(Path(sys.argv[2]).read_text())
result.validate(written)
result.validate(grounded)
assert written['provider'] == 'tavily' and written['kind'] == 'search-results', 'the first file is not a result of a Tavily connection'
assert grounded['provider'] == 'google-grounding' and grounded['kind'] == 'grounded-answer', 'the second file is not a grounded answer'
assert written['hits'] and grounded['hits'], 'a written result has no hit to change'
for name in ('generatedAnswer', 'attributionHtml', 'queries'):
    assert name in grounded, f'the written grounded answer has no {name} to change'

request = json.loads((here / 'examples' / 'tavily.request.json').read_text())
arguments.validate(request)
result.validate(json.loads((here / 'examples' / 'tavily.result.json').read_text()))
result.validate(json.loads((here / 'examples' / 'grounded.result.json').read_text()))

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


for change, why in [
    (drop('connection'), 'no connection'),
    (drop('revision'), 'no revision'),
    (drop('query'), 'no query'),
    (drop('maxResults'), 'no maxResults'),
    (put('endpoint', 'https://example.org/search'), 'an endpoint from the caller'),
    (put('provider', 'tavily'), 'a provider from the caller'),
    (put('credential', 'secret'), 'a credential from the caller'),
    (put('QUERY', 'public policy guidance'), 'a member named in capitals, beside the member'),
    (lambda v: v.__setitem__('Query', v.pop('query')), 'a member named with a capital'),
    (put('connection', 'Research'), 'a connection in capitals'),
    (put('connection', '1research'), 'a connection that begins with a digit'),
    (put('connection', 'a/b'), 'a connection that is a path'),
    (put('connection', 'a' * 49), 'a connection of 49 characters'),
    (put('connection', 'research\n'), 'a connection with a line feed after it'),
    (put('revision', 'abc'), 'a revision that is not one'),
    (put('revision', 'A' * 64), 'a revision in capitals'),
    (put('revision', 'a' * 64 + '\n'), 'a revision with a line feed after it'),
    (put('query', ''), 'an empty query'),
    (put('query', 'a\nb'), 'a query with a line feed'),
    (put('query', 'a\tb'), 'a query with a tab'),
    (put('query', 'a\x7fb'), 'a query with a delete'),
    (put('query', 'a\x85b'), 'a query with a control character past ASCII'),
    (put('query', 'q' * 2001), 'a query of 2001 characters'),
    (put('query', 7), 'a query that is a number'),
    (put('connection', 7), 'a connection that is a number'),
    (put('revision', 7), 'a revision that is a number'),
    (put('maxResults', 0), 'no result asked for'),
    (put('maxResults', -1), 'fewer than none'),
    (put('maxResults', 11), 'eleven results'),
    (put('maxResults', '5'), 'a count that is a string'),
    (put('maxResults', 2.5), 'a count with a fraction'),
]:
    refuse(arguments, request, change, why)

# A value that is no object is neither.
for validator, value in [(arguments, [request]), (arguments, 'public policy guidance'), (result, [written]), (result, None)]:
    assert not validator.is_valid(value), f'accepted: a value that is no object, {value!r:.40}'
    refused += 1

# What holds of a result of either kind.
for value in (written, grounded):
    for change, why in [
        (put('version', 2), 'a version that is not 1'),
        (put('version', '1'), 'a version that is a string'),
        (drop('version'), 'no version'),
        (drop('connection'), 'no connection'),
        (drop('revision'), 'no revision'),
        (drop('provider'), 'no provider'),
        (drop('query'), 'no query'),
        (drop('retrievedAt'), 'no instant'),
        (drop('kind'), 'no kind'),
        (drop('hits'), 'no hits member'),
        (put('provider', 'other'), 'a provider the contract does not name'),
        (put('kind', 'documents'), 'a kind the contract does not name'),
        (put('connection', 'Research'), 'a connection in capitals'),
        (put('revision', 'abc'), 'a revision that is not one'),
        (put('query', ''), 'an empty query'),
        (put('query', 'a\nb'), 'a query with a line feed'),
        (put('query', 'q' * 2001), 'a query of 2001 characters'),
        (put('query', 7), 'a query that is a number'),
        (put('connection', 7), 'a connection that is a number'),
        (put('revision', 7), 'a revision that is a number'),
        (put('retrievedAt', '2026-09-29T12:00:00+02:00'), 'an instant with a zone'),
        (put('retrievedAt', '2026-09-29T12:00:00.000Z'), 'an instant to the millisecond'),
        (put('retrievedAt', '2026-09-29T12:00:00Z\n'), 'an instant with a line feed after it'),
        (put('retrievedAt', '2026-13-01T12:00:00Z'), 'a thirteenth month'),
        (put('retrievedAt', '2026-00-10T12:00:00Z'), 'a month of nought'),
        (put('retrievedAt', '2026-09-32T12:00:00Z'), 'a thirty-second day'),
        (put('retrievedAt', '2026-09-00T12:00:00Z'), 'a day of nought'),
        (put('retrievedAt', '2026-09-29T24:00:00Z'), 'an hour of 24'),
        (put('retrievedAt', '2026-09-29T12:60:00Z'), 'a minute of 60'),
        (put('retrievedAt', '2026-09-29T12:00:60Z'), 'a second of 60'),
        (put('retrievedAt', '2026-09-29 12:00:00Z'), 'an instant with a space for its T'),
        (put('retrievedAt', 1790683200), 'an instant that is a number'),
        (put('credential', 'secret'), 'a credential'),
        (put('endpoint', 'https://api.example.org'), 'a member the result does not have'),
        (put('hits', {}), 'hits that is an object'),
        (put('hits', [copy.deepcopy(value['hits'][0]) for _ in range(11)]), 'eleven hits'),
        (put('hits', 0, 'url', 'http://example.org/plain'), 'a link that is not HTTPS'),
        (put('hits', 0, 'url', 'javascript:alert(1)'), 'a link that is a script'),
        (put('hits', 0, 'url', 'file:///etc/passwd'), 'a link that is a file'),
        (put('hits', 0, 'url', 'example.org/guidance'), 'a link with no scheme'),
        (put('hits', 0, 'url', 'https://'), 'a link that names nothing'),
        (put('hits', 0, 'url', 'https://example.org/\n'), 'a link with a line feed after it'),
        (put('hits', 0, 'url', 'https://example.org/#a\rb'), 'a link with a carriage return after the #'),
        (put('hits', 0, 'url', 'https://example.org/\x00'), 'a link with a null character'),
        (put('hits', 0, 'url', 'https://example.org/' + 'a' * 4077), 'a link of 4097 characters'),
        (put('hits', 0, 'url', 7), 'a link that is a number'),
        (put('hits', 0, 'title', 't' * 513), 'a title of 513 characters'),
        (put('hits', 0, 'title', None), 'a title that is null'),
        (put('hits', 0, 'snippet', 's' * 2001), 'an excerpt of 2001 characters'),
        (put('hits', 0, 'snippet', 7), 'an excerpt that is a number'),
        (drop('hits', 0, 'title'), 'a hit with no title member'),
        (drop('hits', 0, 'url'), 'a hit with no link'),
        (drop('hits', 0, 'snippet'), 'a hit with no excerpt member'),
        (put('hits', 0, 'score', 0.98), 'a member of a hit the result does not have'),
        (put('hits', 0, 'rawContent', 'the page'), 'the text of a page in a hit'),
        (put('hits', 0, 'https://example.org/'), 'a hit that is a string'),
    ]:
        refuse(result, value, change, why)

# One rule of the result's schema no case here can hold: the enumeration of
# kind. The condition on the provider names the one kind each provider has,
# so a kind outside the enumeration is refused by the condition first.

# What holds of search results alone: nothing generated is among them.
for change, why in [
    (put('kind', 'grounded-answer'), 'results of a search engine said to be a grounded answer'),
    (put('generatedAnswer', 'An answer.'), 'a generated answer among search results'),
    (put('attributionHtml', '<div>Search</div>'), 'attribution markup among search results'),
    (put('queries', ['public policy guidance']), 'queries among search results'),
]:
    refuse(result, written, change, why)

# What holds of a grounded answer alone: it has its links and its attribution.
for change, why in [
    (put('kind', 'search-results'), 'a grounded answer said to be search results'),
    (put('provider', 'tavily'), 'a grounded answer of a provider that generates none'),
    (put('hits', []), 'a grounded answer with no link'),
    (put('hits', 0, 'snippet', 'This is not an excerpt.'), 'a grounded answer with an excerpt'),
    (drop('attributionHtml'), 'a grounded answer without its attribution'),
    (put('attributionHtml', ''), 'attribution that is empty'),
    (put('attributionHtml', 'a' * 32001), 'attribution of 32001 characters'),
    (put('attributionHtml', None), 'attribution that is null'),
    (put('generatedAnswer', ''), 'an answer that is empty and present'),
    (put('generatedAnswer', 'a' * 12001), 'an answer of 12001 characters'),
    (put('generatedAnswer', ['An answer.']), 'an answer that is a list'),
    (put('queries', []), 'queries that is empty and present'),
    (put('queries', ['q'] * 21), 'twenty-one queries'),
    (put('queries', ['q' * 2001]), 'a query of 2001 characters among the queries'),
    (put('queries', 'public policy guidance'), 'queries that is a string'),
    (put('queries', [7]), 'a query that is a number among the queries'),
]:
    refuse(result, grounded, change, why)

# What the schemas admit at the edges of each rule.
admitted = 0
for validator, value, change, why in [
    (arguments, request, put('maxResults', 1), 'one result asked for'),
    (arguments, request, put('maxResults', 10), 'ten results asked for'),
    (arguments, request, put('connection', 'a'), 'a connection of one letter'),
    (arguments, request, put('connection', 'a' * 48), 'a connection of 48 characters'),
    (arguments, request, put('query', 'q' * 2000), 'a query of 2000 characters'),
    (arguments, request, put('query', '政策 é'), 'a query outside ASCII'),
    (result, written, put('hits', []), 'search results with no hit'),
    (result, written, put('hits', [{'title': '', 'url': 'https://example.org/%d' % n, 'snippet': ''} for n in range(10)]), 'ten hits'),
    (result, written, put('hits', 0, 'title', ''), 'an empty title'),
    (result, written, put('hits', 0, 'title', 'a\nb\x00c'), 'a title with a line feed and a null character, as a provider may write one'),
    (result, written, put('hits', 0, 'snippet', ''), 'an empty excerpt'),
    (result, written, put('retrievedAt', '2026-12-31T23:59:59Z'), 'the last second of a year'),
    (result, written, put('retrievedAt', '2026-01-01T00:00:00Z'), 'the first second of a year'),
    (result, written, put('hits', 0, 'url', 'HTTPS://EXAMPLE.ORG/A'), 'a link in capitals'),
    (result, written, put('hits', 0, 'url', 'https://example.org:443/a?b=c#d'), 'a link that names the port 443'),
    (result, written, put('hits', 0, 'url', 'https://[2001:db8::1]/'), 'a link to an address'),
    (result, written, put('hits', 0, 'url', 'https://example.org/a b'), 'a link with a space, which parses'),
    (result, written, put('hits', 0, 'url', 'https://example.org/' + 'a' * 4076), 'a link of 4096 characters'),
    (result, grounded, drop('generatedAnswer'), 'a grounded answer where the model wrote nothing'),
    (result, grounded, drop('queries'), 'a grounded answer that names no query'),
    (result, grounded, put('queries', ['']), 'a query that is empty among the queries'),
    (result, grounded, put('queries', ['q'] * 20), 'twenty queries'),
    (result, grounded, put('attributionHtml', '<script>alert(1)</script>'), 'attribution that holds a script: it is passed through as given'),
]:
    edge = copy.deepcopy(value)
    change(edge)
    assert validator.is_valid(edge), f'refused: {why}'
    admitted += 1

# Where a schema is looser than the adapter, by its own description: each of
# these is a value the adapter refuses or never writes, which its tests
# hold, and which the schema admits. They are here so that the difference is
# a stated one: a schema that came to refuse one of them would be a schema
# whose description is out of date.
looser = 0
for validator, value, change, why in [
    (arguments, request, put('query', 'é' * 1001), 'a query of 1001 characters and 2002 bytes'),
    (arguments, request, put('maxResults', 5.0), 'a count written with a fraction'),
    (result, written, put('hits', 0, 'title', 'é' * 257), 'a title of 257 characters and 514 bytes'),
    (result, written, put('hits', 0, 'url', 'https://reader@example.org/'), 'a link with user information'),
    (result, written, put('hits', 0, 'url', 'https://example.org:8443/'), 'a link that names another port'),
    (result, written, put('hits', [copy.deepcopy(written['hits'][0]), copy.deepcopy(written['hits'][0])]), 'one link twice'),
    (result, written, put('retrievedAt', '2026-02-30T12:00:00Z'), 'the thirtieth of February'),
    (result, written, put('version', 1.0), 'a version written with a fraction'),
    (result, written, put('hits', 0, 'title', 'half of a pair: \ud800'), 'a title with half of a surrogate pair'),
    (result, grounded, put('generatedAnswer', '\ud800'), 'an answer that is half of a surrogate pair'),
]:
    stated = copy.deepcopy(value)
    change(stated)
    assert validator.is_valid(stated), f'refused, against the description: {why}'
    looser += 1

print(f'PASS: the examples and the written results match the search schemas; {refused} broken variants refused, {admitted} edges admitted, {looser} stated differences admitted')
