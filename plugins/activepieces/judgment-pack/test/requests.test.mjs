import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const { acquireRequest, actRequest, sealRequest, RequestError } = require('../dist/src/lib/common/requests.js');
const { send, sendTo } = require('../dist/src/lib/common/send.js');

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
	// a null that was given is a null, and the text "null" is the value null: the engine defaults only an absent member
	assert.equal(acquireRequest(engine, { session: 's1', source: 'x', arguments: null }).body.arguments, null);
	assert.equal('arguments' in acquireRequest(engine, { session: 's1', source: 'x', arguments: null }).body, true);
	assert.equal(acquireRequest(engine, { session: 's1', source: 'x', arguments: 'null' }).body.arguments, null);
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

// selfSigned mints a certificate for 127.0.0.1 with openssl. Only a missing
// openssl is a reason to skip -- and not on CI, where the check must run;
// any other failure is a broken fixture and fails the test.
async function selfSigned(t) {
	const { execFileSync } = await import('node:child_process');
	const { mkdtempSync, readFileSync, rmSync } = await import('node:fs');
	const { tmpdir } = await import('node:os');
	const { join } = await import('node:path');
	const dir = mkdtempSync(join(tmpdir(), 'jp-tls-'));
	t.after(() => rmSync(dir, { recursive: true, force: true }));
	try {
		execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', join(dir, 'key.pem'), '-out', join(dir, 'cert.pem'), '-days', '1', '-subj', '/CN=127.0.0.1'], { stdio: 'ignore' });
	} catch (error) {
		if (error.code === 'ENOENT' && process.env.CI === undefined) {
			t.skip('openssl is not installed, so no certificate can be minted');
			return undefined;
		}
		throw error;
	}
	return { key: readFileSync(join(dir, 'key.pem')), cert: readFileSync(join(dir, 'cert.pem')) };
}

async function listening(server) {
	await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
	return server.address().port;
}

async function closed(server) {
	await new Promise((resolve) => server.close(resolve));
}

test('over https, a certificate the process has been told to ignore is still refused', async (t) => {
	const pair = await selfSigned(t);
	if (pair === undefined) {
		return;
	}
	const server = (await import('node:https')).createServer(pair, (req, res) => {
		res.statusCode = 200;
		res.end('{"leaked": true}');
	});
	const port = await listening(server);
	const before = process.env.NODE_TLS_REJECT_UNAUTHORIZED;
	// what the framework's client leaves behind for the whole process
	process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
	try {
		await assert.rejects(
			send(sealRequest({ engine_url: `https://127.0.0.1:${port}` }, { session: 's1' })),
			(e) => /self[- ]signed|certificate|CERT/i.test(e.message) || /CERT/.test(e.code ?? ''),
		);
	} finally {
		if (before === undefined) {
			delete process.env.NODE_TLS_REJECT_UNAUTHORIZED;
		} else {
			process.env.NODE_TLS_REJECT_UNAUTHORIZED = before;
		}
		await closed(server);
	}
});

test('an engine that accepts the connection and stops answering does not hold the flow', async () => {
	const http = await import('node:http');
	// headers never sent
	const silent = http.createServer(() => {});
	const silentPort = await listening(silent);
	try {
		await assert.rejects(
			send(sealRequest({ engine_url: `http://127.0.0.1:${silentPort}` }, { session: 's1' }), 200),
			/did not answer within 200 ms/,
		);
	} finally {
		silent.closeAllConnections();
		await closed(silent);
	}
	// headers sent, the body never finished
	const partial = http.createServer((req, res) => {
		res.statusCode = 200;
		res.write('{"result": ');
	});
	const partialPort = await listening(partial);
	try {
		await assert.rejects(
			send(sealRequest({ engine_url: `http://127.0.0.1:${partialPort}` }, { session: 's1' }), 200),
			/did not answer within 200 ms/,
		);
	} finally {
		partial.closeAllConnections();
		await closed(partial);
	}
});

test('the engine’s answer comes back as the JSON it is, and the connection is not kept', async () => {
	const http = await import('node:http');
	let received;
	const server = http.createServer((req, res) => {
		const chunks = [];
		req.on('data', (c) => chunks.push(c));
		req.on('end', () => {
			received = {
				method: req.method,
				url: req.url,
				authorization: req.headers.authorization,
				body: JSON.parse(Buffer.concat(chunks).toString()),
				length: req.headers['content-length'],
				chunked: req.headers['transfer-encoding'],
				bytes: Buffer.concat(chunks).length,
			};
			res.statusCode = 200;
			res.setHeader('Content-Type', 'application/json');
			res.end('{"result": {"id": 1}, "receipt": {"receiptVersion": 3}, "salts": {"args": "00"}}');
		});
	});
	const port = await listening(server);
	try {
		const answer = await send(acquireRequest({ engine_url: `http://127.0.0.1:${port}`, token: 'tok' }, { session: 's1', source: 'x', arguments: { id: 1 } }));
		assert.deepEqual(answer, { result: { id: 1 }, receipt: { receiptVersion: 3 }, salts: { args: '00' } });
		// the body goes whole, its length stated, never chunked
		assert.equal(received.chunked, undefined, 'the body was sent chunked');
		assert.equal(received.length, String(received.bytes));
		delete received.length;
		delete received.chunked;
		delete received.bytes;
		assert.deepEqual(received, { method: 'POST', url: '/acquire', authorization: 'Bearer tok', body: { session: 's1', source: 'x', arguments: { id: 1 } } });
		const deadline = Date.now() + 2000;
		let open = 1;
		while (open > 0 && Date.now() < deadline) {
			open = await new Promise((resolve) => server.getConnections((_, n) => resolve(n)));
			if (open > 0) {
				await new Promise((resolve) => setTimeout(resolve, 20));
			}
		}
		assert.equal(open, 0, 'the connection stayed open after the answer');
	} finally {
		server.closeAllConnections();
		await closed(server);
	}
});

test('the length stated is the body’s length in bytes, whatever its characters, and a request with no body states none', async () => {
	const http = await import('node:http');
	const received = [];
	const server = http.createServer((req, res) => {
		const chunks = [];
		req.on('data', (c) => chunks.push(c));
		req.on('end', () => {
			received.push({ method: req.method, length: req.headers['content-length'], chunked: req.headers['transfer-encoding'], bytes: Buffer.concat(chunks) });
			res.statusCode = 200;
			res.setHeader('Content-Type', 'application/json');
			res.end('{}');
		});
	});
	const port = await listening(server);
	try {
		const url = `http://127.0.0.1:${port}`;
		// accented, CJK and astral characters: two, three and four bytes
		// each in UTF-8, and one or two UTF-16 units
		const words = { subject: 'café 中文 😀', note: 'naïve' };
		const body = { session: 's1', source: 'x', arguments: words };
		const text = JSON.stringify(body);
		assert.ok(Buffer.byteLength(text) > text.length, 'the body is not multibyte: the case tests nothing');
		await send(acquireRequest({ engine_url: url }, { session: 's1', source: 'x', arguments: words }));
		assert.equal(received[0].length, String(Buffer.byteLength(text)));
		assert.equal(received[0].bytes.length, Buffer.byteLength(text));
		assert.equal(received[0].chunked, undefined, 'the body was sent chunked');
		assert.deepEqual(JSON.parse(received[0].bytes.toString('utf8')), body);
		// an empty body states a length of nothing
		await sendTo(`${url}/seal`, { method: 'POST', headers: {}, body: '' });
		assert.deepEqual([received[1].method, received[1].length, received[1].chunked, received[1].bytes.length], ['POST', '0', undefined, 0]);
		// a request with no body states no length, and is not chunked
		await sendTo(`${url}/publickey`, { method: 'GET', headers: {} });
		assert.deepEqual([received[2].method, received[2].length, received[2].chunked, received[2].bytes.length], ['GET', undefined, undefined, 0]);
	} finally {
		server.closeAllConnections();
		await closed(server);
	}
});

// rawServer answers every request with the bytes given and keeps the socket
// open until the test closes it: a peer that ignores what the client asked.
async function rawServer(answer) {
	const net = await import('node:net');
	const sockets = new Set();
	const server = net.createServer((socket) => {
		sockets.add(socket);
		socket.on('close', () => sockets.delete(socket));
		// one answer per connection, whatever fragments the request arrives in;
		// later bytes are drained and not answered again
		let answered = false;
		socket.on('data', () => {
			if (!answered) {
				answered = true;
				socket.write(answer);
			}
		});
	});
	const port = await listening(server);
	return {
		port,
		sockets,
		async close() {
			for (const socket of sockets) {
				socket.destroy();
			}
			await closed(server);
		},
	};
}

// watched fails a promise that has not settled within the given time, so a
// regression hangs no test
function watched(promise, ms) {
	let timer;
	const watchdog = new Promise((_, reject) => {
		timer = setTimeout(() => reject(new Error(`the call did not settle within ${ms} ms`)), ms);
	});
	return Promise.race([promise, watchdog]).finally(() => clearTimeout(timer));
}

test('an answer that switches protocols, which Node closes on its own, still settles the call', async () => {
	// not an http server: Node's client closes the request on a 101 without
	// reaching a response or error handler
	const server = await rawServer('HTTP/1.1 101 Switching Protocols\r\nUpgrade: nothing\r\nConnection: Upgrade\r\n\r\n');
	try {
		await assert.rejects(
			watched(send(sealRequest({ engine_url: `http://127.0.0.1:${server.port}` }, { session: 's1' }), 200), 5000),
			/closed the connection without answering|did not answer within 200 ms/,
		);
	} finally {
		await server.close();
	}
});

test('an engine that ignores the request to close the connection is closed on anyway', async () => {
	const body = '{"sealed": true}';
	const server = await rawServer(`HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: ${body.length}\r\nConnection: keep-alive\r\n\r\n${body}`);
	try {
		const answer = await watched(send(sealRequest({ engine_url: `http://127.0.0.1:${server.port}` }, { session: 's1' })), 5000);
		assert.deepEqual(answer, { sealed: true });
		// the client's side goes away, so the server's socket sees the end
		const deadline = Date.now() + 2000;
		while (server.sockets.size > 0 && Date.now() < deadline) {
			await new Promise((resolve) => setTimeout(resolve, 20));
		}
		assert.equal(server.sockets.size, 0, 'the connection stayed open after the answer');
	} finally {
		await server.close();
	}
});

test('an early answer to an upload the engine stops reading leaves nothing open', async () => {
	const http = await import('node:http');
	// answers at once and never reads the body
	const server = http.createServer((req, res) => {
		req.socket.pause();
		res.statusCode = 401;
		res.end('{"error":"no requester"}');
	});
	const port = await listening(server);
	try {
		const big = acquireRequest({ engine_url: `http://127.0.0.1:${port}` }, { session: 's1', source: 'x', arguments: { pad: 'x'.repeat(8 * 1024 * 1024) } });
		await assert.rejects(send(big, 5000), /answered 401/);
		// the request is destroyed with the answer, so the server's side of
		// the connection goes away too
		const deadline = Date.now() + 2000;
		let open = 1;
		while (open > 0 && Date.now() < deadline) {
			open = await new Promise((resolve) => server.getConnections((_, n) => resolve(n)));
			if (open > 0) {
				await new Promise((resolve) => setTimeout(resolve, 20));
			}
		}
		assert.equal(open, 0, 'the connection stayed open after the answer');
	} finally {
		server.closeAllConnections();
		await closed(server);
	}
});

test('sending leaves the process’s certificate verification alone, and a refusal carries the engine’s answer', async () => {
	const before = process.env.NODE_TLS_REJECT_UNAUTHORIZED;
	const server = (await import('node:http')).createServer((req, res) => {
		res.statusCode = 401;
		res.end('{"error":"no requester"}');
	});
	const port = await listening(server);
	try {
		await assert.rejects(
			send(sealRequest({ engine_url: `http://127.0.0.1:${port}` }, { session: 's1' })),
			/answered 401: \{"error":"no requester"\}/,
		);
	} finally {
		await closed(server);
	}
	assert.equal(process.env.NODE_TLS_REJECT_UNAUTHORIZED, before);
	assert.notEqual(process.env.NODE_TLS_REJECT_UNAUTHORIZED, '0');
});
