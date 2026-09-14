import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const { JudgmentPack } = require('../dist/nodes/JudgmentPack/JudgmentPack.node.js');
const { NodeApiError, NodeOperationError } = require('n8n-workflow');

// A stand-in for n8n's execution context: items, their parameters, the
// continue-on-fail switch, and a recording transport in the credential's place.
function context(items, { continueOnFail = false, answer = async () => ({ ok: true }) } = {}) {
	const sent = [];
	return {
		sent,
		getInputData: () => items.map(() => ({ json: {} })),
		getNodeParameter: (name, i, fallback) => (name in items[i] ? items[i][name] : fallback),
		continueOnFail: () => continueOnFail,
		getNode: () => ({ id: 'n1', name: 'Judgment Pack', type: 'judgmentPack', typeVersion: 1, position: [0, 0] }),
		helpers: {
			httpRequestWithAuthentication: async function (credential, options) {
				sent.push({ credential, options });
				return answer(options);
			},
		},
	};
}

test('with continue on fail, a refused item yields an error item and the next item still runs', async () => {
	const ctx = context(
		[
			{ operation: 'acquire', session: '', source: 'x', arguments: '' },
			{ operation: 'acquire', session: 's1', source: 'tickets/live', arguments: '{"id": 1}' },
		],
		{ continueOnFail: true },
	);
	const [out] = await new JudgmentPack().execute.call(ctx);
	assert.equal(out.length, 2);
	assert.match(out[0].json.error, /the session must be a non-empty string/);
	assert.deepEqual(out[0].pairedItem, { item: 0 });
	assert.deepEqual(out[1].json, { ok: true });
	assert.equal(ctx.sent.length, 1);
	assert.equal(ctx.sent[0].credential, 'judgmentPackEngineApi');
	assert.deepEqual(ctx.sent[0].options, {
		method: 'POST',
		url: '/acquire',
		body: { session: 's1', source: 'tickets/live', arguments: { id: 1 } },
		json: true,
	});
});

test('without continue on fail, a refusal is the node’s own error and nothing is sent', async () => {
	const ctx = context([{ operation: 'act', session: 's1', platform: 'p', tool: 't', arguments: {}, decision: {}, cites: [] }]);
	await assert.rejects(new JudgmentPack().execute.call(ctx), (e) => e instanceof NodeOperationError && /packDigest|recordDigest/.test(e.message));
	assert.equal(ctx.sent.length, 0);
});

test('the engine’s refusal is an API error, and an error item under continue on fail', async () => {
	const refuse = async () => {
		throw Object.assign(new Error('401 - no requester'), { httpCode: '401' });
	};
	const strict = context([{ operation: 'seal', session: 's1' }], { answer: refuse });
	await assert.rejects(new JudgmentPack().execute.call(strict), (e) => e instanceof NodeApiError);
	const lenient = context([{ operation: 'seal', session: 's1' }, { operation: 'seal', session: 's2' }], { continueOnFail: true, answer: refuse });
	const [out] = await new JudgmentPack().execute.call(lenient);
	assert.equal(out.length, 2);
	assert.equal(typeof out[1].json.error, 'string');
	assert.equal(lenient.sent.length, 2);
});

test('an empty acquire argument is left to the engine’s default', async () => {
	const ctx = context([{ operation: 'acquire', session: 's1', source: 'x' }]);
	await new JudgmentPack().execute.call(ctx);
	assert.deepEqual(ctx.sent[0].options.body, { session: 's1', source: 'x' });
});
