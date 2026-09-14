import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const { acquireRequest, actRequest, sealRequest, RequestError } = require('../dist/src/lib/common/requests.js');

const engine = { engine_url: 'http://127.0.0.1:8787/', token: 'tok' };

test('acquire sends what a curl of /acquire sends, with the bearer only when a token is given', () => {
	const r = acquireRequest(engine, { session: 's1', source: 'tickets/live', arguments: '{"id": 1}' });
	assert.equal(r.method, 'POST');
	assert.equal(r.url, 'http://127.0.0.1:8787/acquire');
	assert.deepEqual(r.body, { session: 's1', source: 'tickets/live', arguments: { id: 1 } });
	assert.equal(r.headers.Authorization, 'Bearer tok');
	const bare = acquireRequest({ engine_url: 'http://127.0.0.1:8787' }, { session: 's1', source: 'x', arguments: {} });
	assert.equal('Authorization' in bare.headers, false);
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
	const r = actRequest(engine, input);
	assert.equal(r.url, 'http://127.0.0.1:8787/act');
	assert.deepEqual(r.body, { ...input });
	assert.throws(() => actRequest(engine, { ...input, cites: [] }), RequestError);
	assert.throws(() => actRequest(engine, { ...input, cites: [{ sessionId: 's1' }] }), RequestError);
	assert.throws(() => actRequest(engine, { ...input, decision: { recordDigest: 'sha256:a' } }), RequestError);
	assert.throws(() => actRequest(engine, { ...input, arguments: '[1]' }), RequestError);
});

test('seal names the session and nothing else', () => {
	assert.deepEqual(sealRequest(engine, { session: 's1' }).body, { session: 's1' });
	assert.throws(() => sealRequest(engine, { session: '' }), RequestError);
	assert.throws(() => sealRequest(engine, { session: 5 }), RequestError);
});

test('the engine URL is required and must be http or https', () => {
	assert.throws(() => sealRequest({ engine_url: '' }, { session: 's1' }), RequestError);
	assert.throws(() => sealRequest({ engine_url: 'ftp://x' }, { session: 's1' }), RequestError);
	assert.throws(() => acquireRequest(engine, { session: 's1', source: 'x', arguments: 'not json' }), RequestError);
});
