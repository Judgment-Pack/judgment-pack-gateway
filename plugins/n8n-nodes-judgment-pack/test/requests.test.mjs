import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const { acquireRequest, actRequest, sealRequest } = require('../dist/nodes/JudgmentPack/shared/requests.js');
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
	const { request } = actRequest(input);
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
