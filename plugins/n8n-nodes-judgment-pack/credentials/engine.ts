// How a request reaches the engine: its path is resolved against the
// credential's URL, and the bearer is sent only when the credential holds
// one. Built apart from n8n so it can be tested without it.

export interface EngineCredentials {
	engineUrl?: unknown;
	token?: unknown;
}

export interface Addressed {
	url: string;
	headers: Record<string, string>;
}

export function engineBase(credentials: EngineCredentials): string {
	const url = typeof credentials.engineUrl === 'string' ? credentials.engineUrl.trim() : '';
	if (url === '') {
		throw new Error('the credential names no engine URL');
	}
	if (!/^https?:\/\//.test(url)) {
		throw new Error('the engine URL must begin with http:// or https://');
	}
	return url.replace(/\/+$/, '');
}

export function address(credentials: EngineCredentials, path: string, headers: Record<string, string> = {}): Addressed {
	const out: Record<string, string> = { ...headers, 'Content-Type': 'application/json' };
	const token = typeof credentials.token === 'string' ? credentials.token.trim() : '';
	if (token !== '') {
		out.Authorization = `Bearer ${token}`;
	}
	const url = path.startsWith('/') ? `${engineBase(credentials)}${path}` : path;
	return { url, headers: out };
}
