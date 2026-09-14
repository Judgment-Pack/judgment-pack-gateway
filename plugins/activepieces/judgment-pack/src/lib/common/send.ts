import type { EngineRequest } from './requests';

// One request through Node's own fetch, the engine's answer as JSON. Not the
// framework's httpClient: the pinned @activepieces/pieces-common (0.12.5)
// sets NODE_TLS_REJECT_UNAUTHORIZED to "0" for the process before it sends,
// which would let an impersonating engine over https collect the bearer;
// fetch verifies certificates and touches no process state. A non-2xx answer
// is an error carrying the engine's status and text.
export async function send(request: EngineRequest): Promise<unknown> {
	return sendTo(request.url, { method: request.method, headers: request.headers, body: JSON.stringify(request.body) });
}

export async function sendTo(url: string, init: { method: string; headers: Record<string, string>; body?: string }): Promise<unknown> {
	const response = await fetch(url, init);
	const text = await response.text();
	if (!response.ok) {
		throw new Error(`the engine answered ${response.status}: ${text.slice(0, 2048)}`);
	}
	try {
		return JSON.parse(text);
	} catch {
		throw new Error('the engine did not answer JSON');
	}
}
