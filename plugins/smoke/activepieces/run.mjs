// Executes the Activepieces piece's actions as the framework calls them --
// the piece object from its built index, each action's run() with the
// context shape the framework hands it -- against a real engine.
import { createRequire } from 'node:module';
import assert from 'node:assert/strict';

const require = createRequire(import.meta.url);
const pieceDir = process.argv[2];
const engineUrl = process.argv[3] ?? 'http://127.0.0.1:8787';
const { judgmentPack } = require(`${pieceDir}/dist/src/index.js`);

const actions = judgmentPack.actions();
console.log('piece:', judgmentPack.displayName, 'actions:', Object.keys(actions).join(', '), 'min release:', judgmentPack.minimumSupportedRelease);
const auth = { props: { engine_url: engineUrl, token: '' } };
const ctx = (propsValue) => ({ auth, propsValue, store: {}, files: {}, run: { id: 'smoke', name: 'smoke' } });

// the connection's own validation, as the framework runs it when a connection is saved
const validation = await judgmentPack.auth.validate({ auth: auth.props });
console.log('auth validate:', JSON.stringify(validation));
assert.equal(validation.valid, true);

const session = `smoke-ap-${Date.now()}`;
const acquired = await actions['acquire'].run(ctx({ session, source: 'screening', arguments: '{"subject": "acme"}' }));
console.log('acquire receipt version:', acquired.receipt.receiptVersion, 'kind:', acquired.receipt.kind, 'callIndex:', acquired.receipt.callIndex, 'salts:', Object.keys(acquired.salts).join(','));
assert.equal(acquired.receipt.receiptVersion, '3');
assert.equal(acquired.receipt.kind, 'acquisition');
assert.equal(acquired.receipt.callIndex, 0);
assert.equal(acquired.receipt.sessionId, session);
assert.match(acquired.salts.args, /^[0-9a-f]{64}$/);
assert.match(acquired.receipt.signature, /^[0-9a-f]{128}$/);
assert.deepEqual(acquired.result, { synthetic: true, arguments: { subject: 'acme' } });

let refusal;
try {
	await actions['act'].run(ctx({ session, platform: 'tickets', tool: 'update_ticket', arguments: { id: 'T-1' }, decision: { recordDigest: 'sha256:' + 'a'.repeat(64), packDigest: 'sha256:' + 'b'.repeat(64) }, cites: [{ sessionId: session, callIndex: acquired.receipt.callIndex, signature: acquired.receipt.signature }] }));
} catch (e) {
	refusal = e.message;
}
console.log('act refusal:', refusal);
assert.match(refusal, /^the engine answered 401: /);

const sealed = await actions['seal'].run(ctx({ session }));
console.log('seal:', JSON.stringify(sealed).slice(0, 200));
assert.equal(sealed.sessionId, session);
assert.equal(sealed.finalCount, 1);
assert.match(sealed.signature, /^[0-9a-f]{128}$/);
console.log('ACTIVEPIECES SMOKE OK');
