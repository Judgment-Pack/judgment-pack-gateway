import * as http from 'node:http';
import * as https from 'node:https';
import type { EngineRequest } from './requests';

// One request through Node's own http and https modules, the engine's answer
// as JSON. Not the framework's httpClient: the pinned
// @activepieces/pieces-common (0.12.5) sets NODE_TLS_REJECT_UNAUTHORIZED to
// "0" for the whole process before it sends, and any transport that takes
// Node's default -- fetch included -- would then let an impersonating engine
// over https collect the bearer. This one asks for certificate verification
// on every connection, whatever the process's state, and touches no state
// itself. A non-2xx answer is an error carrying the engine's status and text.
export async function send(request: EngineRequest, timeoutMs = defaultTimeoutMs): Promise<unknown> {
	return sendTo(request.url, { method: request.method, headers: request.headers, body: JSON.stringify(request.body) }, timeoutMs);
}

// The whole exchange -- connecting, the engine's headers, its body -- is
// bounded by one deadline, past which the request is destroyed and the call
// fails; an engine that accepts the connection and stops answering, at any
// point, does not hold the flow. Thirty seconds is the gateway's own bound
// on a source.
export const defaultTimeoutMs = 30_000;

export function sendTo(
	url: string,
	init: { method: string; headers: Record<string, string>; body?: string },
	timeoutMs = defaultTimeoutMs,
): Promise<unknown> {
	const target = new URL(url);
	const options: https.RequestOptions = {
		method: init.method,
		// one connection per exchange, closed with the answer, and no agent
		// pool to return it to -- an engine that ignored the header would
		// otherwise leave a socket in the default agent for a later call to
		// find; nothing outlives the answer
		agent: false,
		headers: { ...init.headers, Connection: 'close' },
		// explicit on every connection, so the process's default -- which
		// another piece's transport may have turned off -- never decides
		rejectUnauthorized: true,
	};
	return new Promise((resolve, reject) => {
		let settled = false;
		// finish settles the promise once, clears the deadline, and destroys
		// a request the exchange left open -- an upload the engine stopped
		// reading after answering early -- so nothing outlives the answer
		const finish = (outcome: () => void) => {
			if (!settled) {
				settled = true;
				clearTimeout(timer);
				outcome();
				if (!req.destroyed) {
					req.destroy();
				}
			}
		};
		const req = (target.protocol === 'https:' ? https : http).request(target, options, (res) => {
			const chunks: Buffer[] = [];
			res.on('data', (chunk: Buffer) => chunks.push(chunk));
			res.on('end', () => {
				const text = Buffer.concat(chunks).toString('utf8');
				const status = res.statusCode ?? 0;
				if (status < 200 || status >= 300) {
					finish(() => reject(new Error(`the engine answered ${status}: ${text.slice(0, 2048)}`)));
					return;
				}
				try {
					const parsed: unknown = JSON.parse(text);
					finish(() => resolve(parsed));
				} catch {
					finish(() => reject(new Error('the engine did not answer JSON')));
				}
			});
			res.on('error', (error) => finish(() => reject(error)));
		});
		// the deadline settles the promise itself, then destroys the request:
		// a request Node has already closed on its own -- after an answer
		// that switched protocols, which reaches no handler above -- would
		// swallow a destroy with an error and settle nothing
		const timer = setTimeout(() => {
			finish(() => reject(new Error(`the engine did not answer within ${timeoutMs} ms`)));
		}, timeoutMs);
		req.on('error', (error) => finish(() => reject(error)));
		req.on('close', () => finish(() => reject(new Error('the engine closed the connection without answering'))));
		if (init.body !== undefined) {
			req.write(init.body);
		}
		req.end();
	});
}
