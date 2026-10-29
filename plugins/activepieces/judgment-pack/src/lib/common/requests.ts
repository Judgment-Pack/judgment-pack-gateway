// The requests the piece sends, built apart from the framework so they can
// be tested without it: each is what a curl of the engine's HTTP surface
// would send (SPEC.md §6), no more.

import { createHash } from 'crypto';

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

// /acquire takes any value in the canonical JSON domain as the arguments,
// and an absent member as {}: a string is read as JSON (so the text "null"
// is the value null, sent as such), an absent or empty one leaves the member
// out for the engine's default, and a null that was given is a null.
function anyValue(value: unknown, name: string): { present: boolean; value?: unknown } {
	if (value === undefined || (typeof value === 'string' && value.trim() === '')) {
		return { present: false };
	}
	if (typeof value === 'string') {
		try {
			return { present: true, value: JSON.parse(value) };
		} catch {
			throw new RequestError(`${name} is not valid JSON`);
		}
	}
	return { present: true, value };
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
	const body: Record<string, unknown> = {
		session: session(input.session),
		source: text(input.source, 'the source'),
	};
	const args = anyValue(input.arguments, 'the arguments');
	if (args.present) {
		body['arguments'] = args.value;
	}
	return {
		method: 'POST',
		url: `${engineBase(credentials)}/acquire`,
		headers: engineHeaders(credentials),
		body,
	};
}

// The engine's action key form (SPEC.md §1.2b): 64 lowercase hexadecimal
// characters.
const actionKeyForm = /^[0-9a-f]{64}$/;

// canonicalText spells a JSON value with every object's members in code-point
// order, so one intent always spells, and hashes, the same.
function canonicalText(value: unknown): string {
	if (Array.isArray(value)) {
		return `[${value.map(canonicalText).join(',')}]`;
	}
	if (value !== null && typeof value === 'object') {
		const entries = Object.entries(value as Record<string, unknown>).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
		return `{${entries.map(([k, v]) => `${JSON.stringify(k)}:${canonicalText(v)}`).join(',')}}`;
	}
	return JSON.stringify(value);
}

// deriveActionKey names one approved intent: the same platform, tool,
// arguments, decision and citations always give the same key, so every retry
// of the step -- the flow's own retry, or the run started again -- sends the
// key its first attempt sent, and the engine answers it from its journal
// instead of writing twice. Another intent gives another key. The session is
// left out: a retry opens a new one. The n8n node derives the same key.
export function deriveActionKey(intent: {
	platform: unknown;
	tool: unknown;
	arguments: unknown;
	decision: unknown;
	cites: unknown;
}): string {
	const text = canonicalText({
		platform: intent.platform,
		tool: intent.tool,
		arguments: intent.arguments,
		decision: intent.decision,
		cites: intent.cites,
	});
	return createHash('sha256').update('judgment-pack-plugin/action-key/1:' + text, 'utf8').digest('hex');
}

// actRequest's action key: 'derive' (the default) names the intent as
// deriveActionKey does; 'given' sends the key the flow chose once for the
// intent and keeps for its retries; 'none' sends no key, which an engine at
// configuration version 14 refuses and with which a retry may write twice.
export function actRequest(
	credentials: EngineCredentials,
	input: {
		session: unknown;
		platform: unknown;
		tool: unknown;
		arguments: unknown;
		decision: unknown;
		cites: unknown;
		actionKeyMode?: unknown;
		actionKey?: unknown;
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
		body: withActionKey(
			{
				session: session(input.session),
				platform: text(input.platform, 'the platform'),
				tool: text(input.tool, 'the tool'),
				arguments: object(input.arguments, 'the arguments'),
				decision,
				cites,
			},
			input.actionKeyMode,
			input.actionKey,
		),
	};
}

function withActionKey(body: Record<string, unknown>, mode: unknown, key: unknown): Record<string, unknown> {
	switch (mode ?? 'derive') {
		case 'derive':
			return {
				...body,
				actionKey: deriveActionKey({
					platform: body['platform'],
					tool: body['tool'],
					arguments: body['arguments'],
					decision: body['decision'],
					cites: body['cites'],
				}),
			};
		case 'given':
			if (typeof key !== 'string' || !actionKeyForm.test(key)) {
				throw new RequestError('the action key must be 64 lowercase hexadecimal characters');
			}
			return { ...body, actionKey: key };
		case 'none':
			return body;
		default:
			throw new RequestError('the action key mode must be derive, given or none');
	}
}

export function sealRequest(credentials: EngineCredentials, input: { session: unknown }): EngineRequest {
	return {
		method: 'POST',
		url: `${engineBase(credentials)}/seal`,
		headers: engineHeaders(credentials),
		body: { session: session(input.session) },
	};
}
