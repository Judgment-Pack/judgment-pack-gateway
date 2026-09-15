// Executes the Activepieces piece's actions as the framework calls them --
// the piece object from its built index, each action's run() with the
// context shape the framework hands it -- against a real engine. Every check
// has a name, and the first that fails prints it -- the names the n8n
// checker gives the same checks -- and ends the run.
import { createRequire } from 'node:module';
import { isDeepStrictEqual } from 'node:util';

const require = createRequire(import.meta.url);
const pieceDir = process.argv[2];
const engineUrl = process.argv[3] ?? 'http://127.0.0.1:8787';
const { judgmentPack } = require(`${pieceDir}/dist/src/index.js`);

// the engine's 401 to an action when it has no identity, as the piece
// carries it: the status and the engine's own bytes
const ACT_REFUSAL =
	'the engine answered 401: {"error":"an action needs an authenticated requester; this engine has no identity configured","refusedAt":"requester"}';

function check(name, holds, found) {
	if (!holds) {
		console.log(`FAIL: ${name}: ${JSON.stringify(found)?.slice(0, 300)}`);
		process.exit(1);
	}
}
const hex = (value, length) => typeof value === 'string' && new RegExp(`^[0-9a-f]{${length}}$`).test(value);

const actions = judgmentPack.actions();
console.log('piece:', judgmentPack.displayName, 'actions:', Object.keys(actions).join(', '), 'min release:', judgmentPack.minimumSupportedRelease);
const auth = { props: { engine_url: engineUrl, token: '' } };
const ctx = (propsValue) => ({ auth, propsValue, store: {}, files: {}, run: { id: 'smoke', name: 'smoke' } });

// the connection's own validation, as the framework runs it when a connection is saved
const validation = await judgmentPack.auth.validate({ auth: auth.props });
console.log('auth validate:', JSON.stringify(validation));
check('connection validation', validation.valid === true, validation);

const session = `smoke-ap-${Date.now()}`;
const acquired = await actions['acquire'].run(ctx({ session, source: 'screening', arguments: '{"subject": "acme"}' }));
const receipt = acquired.receipt ?? {};
console.log('acquire receipt version:', receipt.receiptVersion, 'kind:', receipt.kind, 'callIndex:', receipt.callIndex, 'salts:', Object.keys(acquired.salts ?? {}).join(','));
check('receipt version', receipt.receiptVersion === '3', receipt.receiptVersion);
check('receipt kind', receipt.kind === 'acquisition', receipt.kind);
check('receipt index', receipt.callIndex === 0, receipt.callIndex);
check('receipt session', receipt.sessionId === session, receipt.sessionId);
check('receipt signature', hex(receipt.signature, 128), receipt.signature);
check('result', isDeepStrictEqual(acquired.result, { synthetic: true, arguments: { subject: 'acme' } }), acquired.result);
check('arguments salt', hex(acquired.salts?.args, 64), acquired.salts);

let refusal;
try {
	await actions['act'].run(ctx({ session, platform: 'tickets', tool: 'update_ticket', arguments: { id: 'T-1' }, decision: { recordDigest: 'sha256:' + 'a'.repeat(64), packDigest: 'sha256:' + 'b'.repeat(64) }, cites: [{ sessionId: session, callIndex: receipt.callIndex, signature: receipt.signature }] }));
} catch (e) {
	refusal = e.message;
}
console.log('act refusal:', refusal);
check('act refusal', refusal === ACT_REFUSAL, refusal);

const sealed = await actions['seal'].run(ctx({ session }));
console.log('seal:', JSON.stringify(sealed).slice(0, 200));
check('seal count', sealed.finalCount === 1, sealed.finalCount);
check('seal session', sealed.sessionId === session, sealed.sessionId);
check('seal signature', hex(sealed.signature, 128), sealed.signature);
console.log('ACTIVEPIECES SMOKE OK');
