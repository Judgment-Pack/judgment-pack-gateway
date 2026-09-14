// The requests the piece sends, built apart from the framework so they can
// be tested without it: each is what a curl of the engine's HTTP surface
// would send (SPEC.md §6), no more.

export interface EngineCredentials {
	engine_url: string;
	token?: string;
}

export interface EngineRequest {
	method: 'POST';
	url: string;
	headers: Record<string, string>;
	body: Record<string, unknown>;
}

export class RequestError extends Error {}

export function engineBase(credentials: EngineCredentials): string {
	const url = (credentials.engine_url ?? '').trim();
	if (url === '') {
		throw new RequestError('the connection names no engine URL');
	}
	if (!/^https?:\/\//.test(url)) {
		throw new RequestError('the engine URL must begin with http:// or https://');
	}
	return url.replace(/\/+$/, '');
}

export function engineHeaders(credentials: EngineCredentials): Record<string, string> {
	const h: Record<string, string> = { 'Content-Type': 'application/json' };
	const token = (credentials.token ?? '').trim();
	if (token !== '') {
		h['Authorization'] = `Bearer ${token}`;
	}
	return h;
}

// A session is a flat token (SPEC.md §3a); the engine refuses anything else
// before a source runs, and the piece refuses an empty one before asking.
function session(value: unknown): string {
	if (typeof value !== 'string' || value.trim() === '') {
		throw new RequestError('the session must be a non-empty string');
	}
	return value;
}

function object(value: unknown, name: string): Record<string, unknown> {
	if (typeof value === 'string') {
		try {
			value = JSON.parse(value);
		} catch {
			throw new RequestError(`${name} is not valid JSON`);
		}
	}
	if (value === null || typeof value !== 'object' || Array.isArray(value)) {
		throw new RequestError(`${name} must be a JSON object`);
	}
	return value as Record<string, unknown>;
}

function array(value: unknown, name: string): unknown[] {
	if (typeof value === 'string') {
		try {
			value = JSON.parse(value);
		} catch {
			throw new RequestError(`${name} is not valid JSON`);
		}
	}
	if (!Array.isArray(value)) {
		throw new RequestError(`${name} must be a JSON array`);
	}
	return value;
}

function text(value: unknown, name: string): string {
	if (typeof value !== 'string' || value.trim() === '') {
		throw new RequestError(`${name} must be a non-empty string`);
	}
	return value;
}

export function acquireRequest(
	credentials: EngineCredentials,
	input: { session: unknown; source: unknown; arguments: unknown },
): EngineRequest {
	return {
		method: 'POST',
		url: `${engineBase(credentials)}/acquire`,
		headers: engineHeaders(credentials),
		body: {
			session: session(input.session),
			source: text(input.source, 'the source'),
			arguments: object(input.arguments, 'the arguments'),
		},
	};
}

export function actRequest(
	credentials: EngineCredentials,
	input: {
		session: unknown;
		platform: unknown;
		tool: unknown;
		arguments: unknown;
		decision: unknown;
		cites: unknown;
	},
): EngineRequest {
	const decision = object(input.decision, 'the decision');
	for (const member of ['recordDigest', 'packDigest']) {
		if (typeof decision[member] !== 'string') {
			throw new RequestError(`the decision must name ${member} as a string`);
		}
	}
	const cites = array(input.cites, 'the citations');
	if (cites.length === 0) {
		throw new RequestError('the citations must name at least one receipt; the engine refuses an empty list');
	}
	for (const cite of cites) {
		const c = object(cite, 'a citation');
		if (
			typeof c['sessionId'] !== 'string' ||
			typeof c['callIndex'] !== 'number' ||
			typeof c['signature'] !== 'string'
		) {
			throw new RequestError('a citation must carry sessionId, callIndex and signature');
		}
	}
	return {
		method: 'POST',
		url: `${engineBase(credentials)}/act`,
		headers: engineHeaders(credentials),
		body: {
			session: session(input.session),
			platform: text(input.platform, 'the platform'),
			tool: text(input.tool, 'the tool'),
			arguments: object(input.arguments, 'the arguments'),
			decision,
			cites,
		},
	};
}

export function sealRequest(credentials: EngineCredentials, input: { session: unknown }): EngineRequest {
	return {
		method: 'POST',
		url: `${engineBase(credentials)}/seal`,
		headers: engineHeaders(credentials),
		body: { session: session(input.session) },
	};
}
