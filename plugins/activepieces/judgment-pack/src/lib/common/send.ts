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
export async function send(request: EngineRequest): Promise<unknown> {
	return sendTo(request.url, { method: request.method, headers: request.headers, body: JSON.stringify(request.body) });
}

export function sendTo(url: string, init: { method: string; headers: Record<string, string>; body?: string }): Promise<unknown> {
	const target = new URL(url);
	const options: https.RequestOptions = {
		method: init.method,
		headers: init.headers,
		// explicit on every connection, so the process's default -- which
		// another piece's transport may have turned off -- never decides
		rejectUnauthorized: true,
	};
	return new Promise((resolve, reject) => {
		const req = (target.protocol === 'https:' ? https : http).request(target, options, (res) => {
			const chunks: Buffer[] = [];
			res.on('data', (chunk: Buffer) => chunks.push(chunk));
			res.on('end', () => {
				const text = Buffer.concat(chunks).toString('utf8');
				const status = res.statusCode ?? 0;
				if (status < 200 || status >= 300) {
					reject(new Error(`the engine answered ${status}: ${text.slice(0, 2048)}`));
					return;
				}
				try {
					resolve(JSON.parse(text));
				} catch {
					reject(new Error('the engine did not answer JSON'));
				}
			});
			res.on('error', reject);
		});
		req.on('error', reject);
		if (init.body !== undefined) {
			req.write(init.body);
		}
		req.end();
	});
}
