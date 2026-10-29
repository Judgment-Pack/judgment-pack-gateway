import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const { acquireRequest, actRequest, sealRequest, deriveActionKey } = require('../dist/nodes/JudgmentPack/shared/requests.js');
const { address } = require('../dist/credentials/engine.js');

test('acquire sends what a curl of /acquire sends', () => {
	const { request, refusal } = acquireRequest({ session: 's1', source: 'tickets/live', arguments: '{"id": 1}' });
	assert.equal(refusal, undefined);
	assert.equal(request.method, 'POST');
	assert.equal(request.path, '/acquire');
	assert.deepEqual(request.body, { session: 's1', source: 'tickets/live', arguments: { id: 1 } });
	assert.match(acquireRequest({ session: 's1', source: 'x', arguments: 'not json' }).refusal, /not valid JSON/);
	assert.match(acquireRequest({ session: 's1', source: '', arguments: {} }).refusal, /the source/);
	// any value in the canonical JSON domain, and an empty one left to the engine's default
	assert.deepEqual(acquireRequest({ session: 's1', source: 'x', arguments: '[1, 2]' }).request.body.arguments, [1, 2]);
	assert.equal(acquireRequest({ session: 's1', source: 'x', arguments: '"acme"' }).request.body.arguments, 'acme');
	assert.equal(acquireRequest({ session: 's1', source: 'x', arguments: 7 }).request.body.arguments, 7);
	assert.equal('arguments' in acquireRequest({ session: 's1', source: 'x', arguments: '' }).request.body, false);
	assert.equal('arguments' in acquireRequest({ session: 's1', source: 'x', arguments: undefined }).request.body, false);
	// a null an expression resolved to is a null, and the text "null" is the value null: the engine defaults only an absent member
	assert.equal('arguments' in acquireRequest({ session: 's1', source: 'x', arguments: null }).request.body, true);
	assert.equal(acquireRequest({ session: 's1', source: 'x', arguments: null }).request.body.arguments, null);
	assert.equal(acquireRequest({ session: 's1', source: 'x', arguments: 'null' }).request.body.arguments, null);
});

test('act carries the requester’s assertions as given and refuses what the engine would refuse anyway', () => {
	const input = {
		session: 's1',
		platform: 'tickets',
		tool: 'update_ticket',
		arguments: { id: 'T-1' },
		decision: { recordDigest: 'sha256:a', packDigest: 'sha256:b' },
		cites: [{ sessionId: 's1', callIndex: 3, signature: 'ab' }],
	};
	const { request } = actRequest({ ...input, actionKeyMode: 'none' });
	assert.equal(request.path, '/act');
	assert.deepEqual(request.body, { ...input });
	assert.match(actRequest({ ...input, cites: [] }).refusal, /at least one receipt/);
	assert.match(actRequest({ ...input, cites: [{ sessionId: 's1' }] }).refusal, /sessionId, callIndex and signature/);
	assert.match(actRequest({ ...input, decision: { recordDigest: 'sha256:a' } }).refusal, /packDigest/);
	assert.match(actRequest({ ...input, arguments: '[1]' }).refusal, /JSON object/);
});

test('seal names the session and nothing else', () => {
	assert.deepEqual(sealRequest({ session: 's1' }).request.body, { session: 's1' });
	assert.match(sealRequest({ session: '' }).refusal, /session/);
	assert.match(sealRequest({ session: 5 }).refusal, /session/);
});

test('the credential resolves the path against the URL and sends the bearer only when it holds one', () => {
	const a = address({ engineUrl: 'http://127.0.0.1:8787/', token: 'tok' }, '/acquire');
	assert.equal(a.url, 'http://127.0.0.1:8787/acquire');
	assert.equal(a.headers.Authorization, 'Bearer tok');
	assert.equal(a.headers['Content-Type'], 'application/json');
	const bare = address({ engineUrl: 'http://127.0.0.1:8787', token: '' }, '/seal');
	assert.equal('Authorization' in bare.headers, false);
	assert.throws(() => address({ engineUrl: '' }, '/seal'), /names no engine URL/);
	assert.throws(() => address({ engineUrl: 'ftp://x' }, '/seal'), /http:\/\/ or https:\/\//);
	assert.equal(address({ engineUrl: 'http://e' }, 'http://elsewhere/x').url, 'http://elsewhere/x');
});

// #351 M5: an engine at configuration version 14 requires actionKey. The key
// names one intended write: every retry of it sends the same key, and another
// write another key.
test('act names its intended write with an action key, the same on every retry', () => {
	const input = {
		session: 's1',
		platform: 'tickets',
		tool: 'update_ticket',
		arguments: { id: 'T-1', fields: { b: 2, a: 1 } },
		decision: { recordDigest: 'sha256:a', packDigest: 'sha256:b' },
		cites: [{ sessionId: 's1', callIndex: 3, signature: 'ab' }],
	};
	const first = actRequest(input).request.body.actionKey;
	assert.match(first, /^[0-9a-f]{64}$/);
	// a retry opens a new session; the members' order is not the intent
	assert.equal(actRequest({ ...input, session: 'retry', arguments: { fields: { a: 1, b: 2 }, id: 'T-1' } }).request.body.actionKey, first);
	assert.equal(actRequest({ ...input, actionKeyMode: 'derive' }).request.body.actionKey, first);
	assert.equal(deriveActionKey(input), first);
	// the same derivation as the Activepieces piece's, spelled out by hand
	const { createHash } = require('node:crypto');
	const spelled = '{"arguments":{"fields":{"a":1,"b":2},"id":"T-1"},"cites":[{"callIndex":3,"sessionId":"s1","signature":"ab"}],"decision":{"packDigest":"sha256:b","recordDigest":"sha256:a"},"platform":"tickets","tool":"update_ticket"}';
	assert.equal(createHash('sha256').update('judgment-pack-plugin/action-key/1:' + spelled).digest('hex'), first);
	for (const changed of [
		{ platform: 'other' },
		{ tool: 'close_ticket' },
		{ arguments: { id: 'T-2', fields: { a: 1, b: 2 } } },
		{ decision: { recordDigest: 'sha256:c', packDigest: 'sha256:b' } },
		{ cites: [{ sessionId: 's1', callIndex: 4, signature: 'ab' }] },
	]) {
		assert.notEqual(actRequest({ ...input, ...changed }).request.body.actionKey, first, JSON.stringify(changed));
	}
	const given = 'c'.repeat(64);
	assert.equal(actRequest({ ...input, actionKeyMode: 'given', actionKey: given }).request.body.actionKey, given);
	for (const bad of ['', 'C'.repeat(64), 'c'.repeat(63), 7]) {
		assert.match(actRequest({ ...input, actionKeyMode: 'given', actionKey: bad }).refusal, /64 lowercase hexadecimal/);
	}
	assert.equal('actionKey' in actRequest({ ...input, actionKeyMode: 'none' }).request.body, false);
	assert.match(actRequest({ ...input, actionKeyMode: 'random' }).refusal, /derive, given or none/);
});

// #354 N2: the key is derived from the intent exactly as the request sends it.
// A Date is sent, and hashed, as its ISO string; an undefined member is neither
// sent nor hashed; a value JSON does not carry as it is (a Map, a Set) refuses
// derivation, since it would be sent as {} and two writes would share a key.
test('the derived action key names exactly what the request sends', () => {
	const act = (input) => actRequest(input);
	const sent = (r) => r.request.body;
	const input = {
		session: 's1',
		platform: 'tickets',
		tool: 'update_ticket',
		arguments: { id: 'T-1', due: new Date('2026-10-30T00:00:00.000Z') },
		decision: { recordDigest: 'sha256:a', packDigest: 'sha256:b' },
		cites: [{ sessionId: 's1', callIndex: 3, signature: 'ab' }],
	};
	const dated = sent(act(input));
	assert.deepEqual(dated.arguments, { id: 'T-1', due: '2026-10-30T00:00:00.000Z' });
	assert.equal(dated.actionKey, sent(act({ ...input, arguments: { id: 'T-1', due: '2026-10-30T00:00:00.000Z' } })).actionKey);
	assert.notEqual(dated.actionKey, sent(act({ ...input, arguments: { id: 'T-1', due: new Date('2026-10-31T00:00:00.000Z') } })).actionKey);
	const undefinedMember = sent(act({ ...input, arguments: { id: 'T-1', note: undefined } }));
	assert.equal('note' in undefinedMember.arguments, false);
	assert.equal(undefinedMember.actionKey, sent(act({ ...input, arguments: { id: 'T-1' } })).actionKey);
	for (const [label, bad] of [
		['a Map', { id: 'T-1', fields: new Map([['a', 1]]) }],
		['a Set', { id: 'T-1', tags: new Set(['x']) }],
		['a class instance', { id: 'T-1', value: new (class Value {})() }],
		['a function', { id: 'T-1', value: () => 1 }],
	]) {
		assert.match(act({ ...input, arguments: bad }).refusal, /cannot be derived.*explicit action key/, label);
	}
	// an explicit key is still sent with such arguments: the workflow named the write
	assert.equal(sent(act({ ...input, arguments: { fields: new Map() }, actionKeyMode: 'given', actionKey: 'e'.repeat(64) })).actionKey, 'e'.repeat(64));
});
