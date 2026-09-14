import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const { acquireRequest, actRequest, sealRequest, RequestError } = require('../dist/src/lib/common/requests.js');
const { send } = require('../dist/src/lib/common/send.js');

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

test('acquire takes any JSON value as arguments and leaves an empty one to the engine’s default', () => {
	assert.deepEqual(acquireRequest(engine, { session: 's1', source: 'x', arguments: '[1, 2]' }).body.arguments, [1, 2]);
	assert.equal(acquireRequest(engine, { session: 's1', source: 'x', arguments: '"acme"' }).body.arguments, 'acme');
	assert.equal(acquireRequest(engine, { session: 's1', source: 'x', arguments: 7 }).body.arguments, 7);
	assert.equal('arguments' in acquireRequest(engine, { session: 's1', source: 'x', arguments: '' }).body, false);
	assert.equal('arguments' in acquireRequest(engine, { session: 's1', source: 'x', arguments: undefined }).body, false);
	assert.throws(() => acquireRequest(engine, { session: 's1', source: 'x', arguments: 'not json' }), RequestError);
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
});

test('sending leaves the process’s certificate verification alone, and a refusal carries the engine’s answer', async () => {
	const before = process.env.NODE_TLS_REJECT_UNAUTHORIZED;
	const server = (await import('node:http')).createServer((req, res) => {
		res.statusCode = 401;
		res.end('{"error":"no requester"}');
	});
	await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
	const port = server.address().port;
	try {
		await assert.rejects(
			send(sealRequest({ engine_url: `http://127.0.0.1:${port}` }, { session: 's1' })),
			/answered 401: \{"error":"no requester"\}/,
		);
	} finally {
		server.close();
	}
	assert.equal(process.env.NODE_TLS_REJECT_UNAUTHORIZED, before);
	assert.notEqual(process.env.NODE_TLS_REJECT_UNAUTHORIZED, '0');
});
