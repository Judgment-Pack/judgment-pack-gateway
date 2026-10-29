// The requests the node sends, built apart from n8n so they can be tested
// without it: each is what a curl of the engine's HTTP surface would send
// (SPEC.md §6), no more. A builder refuses, by naming the reason, what the
// engine would refuse anyway, so the node can say so before asking; the
// engine's URL and the bearer are the credential's (authenticate in
// credentials/JudgmentPackEngineApi.credentials.ts), never read here.

import { createHash } from 'crypto';

export interface EngineRequest {
	method: 'POST';
	path: '/acquire' | '/act' | '/seal';
	body: Record<string, unknown>;
}

export type Built = { request: EngineRequest; refusal?: undefined } | { request?: undefined; refusal: string };

// check collects the first reason a request cannot be built; every reader
// answers undefined once one is recorded, and the builder answers the reason.
class check {
	refusal: string | undefined;

	refuse(reason: string): undefined {
		this.refusal ??= reason;
		return undefined;
	}

	// A session is a flat token (SPEC.md §3a); the engine refuses anything
	// else before a source runs, and the node refuses an empty one before asking.
	session(value: unknown): string | undefined {
		return this.text(value, 'the session');
	}

	text(value: unknown, name: string): string | undefined {
		if (typeof value !== 'string' || value.trim() === '') {
			return this.refuse(`${name} must be a non-empty string`);
		}
		return value;
	}

	parsed(value: unknown, name: string): unknown {
		if (typeof value !== 'string') {
			return value;
		}
		try {
			return JSON.parse(value);
		} catch {
			return this.refuse(`${name} is not valid JSON`);
		}
	}

	object(value: unknown, name: string): Record<string, unknown> | undefined {
		const v = this.parsed(value, name);
		if (this.refusal !== undefined) {
			return undefined;
		}
		if (v === null || typeof v !== 'object' || Array.isArray(v)) {
			return this.refuse(`${name} must be a JSON object`);
		}
		return v as Record<string, unknown>;
	}

	array(value: unknown, name: string): unknown[] | undefined {
		const v = this.parsed(value, name);
		if (this.refusal !== undefined) {
			return undefined;
		}
		if (!Array.isArray(v)) {
			return this.refuse(`${name} must be a JSON array`);
		}
		return v;
	}

	// /acquire takes any value in the canonical JSON domain as the
	// arguments, and an absent member as {}: a string is read as JSON (so
	// the text "null" is the value null, sent as such), an absent or empty
	// one leaves the member out for the engine's default, and a null an
	// expression resolved to is a null.
	anyValue(value: unknown, name: string): { present: boolean; value?: unknown } {
		if (value === undefined || (typeof value === 'string' && value.trim() === '')) {
			return { present: false };
		}
		const v = this.parsed(value, name);
		return { present: this.refusal === undefined, value: v };
	}

	built(request: EngineRequest): Built {
		return this.refusal === undefined ? { request } : { refusal: this.refusal };
	}
}

export function acquireRequest(input: { session: unknown; source: unknown; arguments: unknown }): Built {
	const c = new check();
	const body: Record<string, unknown> = {
		session: c.session(input.session),
		source: c.text(input.source, 'the source'),
	};
	const args = c.anyValue(input.arguments, 'the arguments');
	if (args.present) {
		body.arguments = args.value;
	}
	return c.built({ method: 'POST', path: '/acquire', body });
}

// The engine's action key form (SPEC.md §1.2b): 64 lowercase hexadecimal
// characters.
const actionKeyForm = /^[0-9a-f]{64}$/;

// canonicalText spells a JSON value with every object's members in UTF-16
// code-unit order, so one intent always spells, and hashes, the same.
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

// ActionKeyError is why no key can be derived from the intent as given.
export class ActionKeyError extends Error {}

// unfaithful names the first value JSON does not carry as it is, or is
// undefined: a function, a symbol or a bigint, and any object that is neither
// an array, a plain object nor a Date -- a Map or a Set is sent as {}, so two
// different writes would derive one key, and the second would never be sent.
function unfaithful(value: unknown, at: string): string | undefined {
	if (typeof value === 'function' || typeof value === 'symbol' || typeof value === 'bigint') {
		return at;
	}
	if (value === null || typeof value !== 'object' || value instanceof Date) {
		return undefined;
	}
	if (Array.isArray(value)) {
		for (let i = 0; i < value.length; i++) {
			const found = unfaithful(value[i], `${at}[${i}]`);
			if (found !== undefined) {
				return found;
			}
		}
		return undefined;
	}
	const prototype = Object.getPrototypeOf(value);
	if ((prototype !== Object.prototype && prototype !== null) || 'toJSON' in value) {
		return at;
	}
	for (const [name, member] of Object.entries(value as Record<string, unknown>)) {
		const found = unfaithful(member, `${at}.${name}`);
		if (found !== undefined) {
			return found;
		}
	}
	return undefined;
}

type Intent = { platform: unknown; tool: unknown; arguments: unknown; decision: unknown; cites: unknown };

// intentAsSent is the intent exactly as the request's JSON carries it: a Date
// as its ISO string, an undefined member left out. The request sends these
// values, and the key is derived from them, so the key cannot name what is not
// sent. A value JSON does not carry as it is refuses derivation.
export function intentAsSent(intent: Intent): Record<string, unknown> {
	const picked = {
		platform: intent.platform,
		tool: intent.tool,
		arguments: intent.arguments,
		decision: intent.decision,
		cites: intent.cites,
	};
	const at = unfaithful(picked, 'the write');
	if (at !== undefined) {
		throw new ActionKeyError(
			`the action key cannot be derived: ${at} is not a value JSON carries as it is (a Map, a Set or another object); give an explicit action key`,
		);
	}
	return JSON.parse(JSON.stringify(picked)) as Record<string, unknown>;
}

function keyOf(sent: Record<string, unknown>): string {
	return createHash('sha256').update('judgment-pack-plugin/action-key/1:' + canonicalText(sent), 'utf8').digest('hex');
}

// deriveActionKey names one approved intent: the same platform, tool,
// arguments, decision and citations always give the same key, so every retry
// of the item -- Retry On Fail, or the execution run again -- sends the key its
// first attempt sent, and the engine answers it from its journal instead of
// writing twice. Another intent gives another key. The session is left out: a
// retry opens a new one.
// The arguments are the ones evaluated for this attempt: an expression that
// changes per execution (the current time, a random value) gives a retry a new
// key, and the write would be sent again; give an explicit key for such a write.
export function deriveActionKey(intent: Intent): string {
	return keyOf(intentAsSent(intent));
}

// actRequest's action key: 'derive' (the default) names the intent as
// deriveActionKey does; 'given' sends the key the workflow chose once for the
// intent and keeps for its retries; 'none' sends no key, which an engine at
// configuration version 14 refuses and with which a retry may write twice.
export function actRequest(input: {
	session: unknown;
	platform: unknown;
	tool: unknown;
	arguments: unknown;
	decision: unknown;
	cites: unknown;
	actionKeyMode?: unknown;
	actionKey?: unknown;
}): Built {
	const c = new check();
	const decision = c.object(input.decision, 'the decision');
	for (const member of ['recordDigest', 'packDigest']) {
		if (decision !== undefined && typeof decision[member] !== 'string') {
			c.refuse(`the decision must name ${member} as a string`);
		}
	}
	const cites = c.array(input.cites, 'the citations');
	if (cites !== undefined && cites.length === 0) {
		c.refuse('the citations must name at least one receipt; the engine refuses an empty list');
	}
	for (const cite of cites ?? []) {
		const member = c.object(cite, 'a citation');
		if (
			member !== undefined &&
			(typeof member.sessionId !== 'string' || typeof member.callIndex !== 'number' || typeof member.signature !== 'string')
		) {
			c.refuse('a citation must carry sessionId, callIndex and signature');
		}
	}
	const body: Record<string, unknown> = {
		session: c.session(input.session),
		platform: c.text(input.platform, 'the platform'),
		tool: c.text(input.tool, 'the tool'),
		arguments: c.object(input.arguments, 'the arguments'),
		decision,
		cites,
	};
	switch (input.actionKeyMode ?? 'derive') {
		case 'derive':
			if (c.refusal === undefined) {
				try {
					const sent = intentAsSent({ platform: body.platform, tool: body.tool, arguments: body.arguments, decision, cites });
					Object.assign(body, sent);
					body.actionKey = keyOf(sent);
				} catch (error) {
					c.refuse((error as Error).message);
				}
			}
			break;
		case 'given':
			if (typeof input.actionKey !== 'string' || !actionKeyForm.test(input.actionKey)) {
				c.refuse('the action key must be 64 lowercase hexadecimal characters');
			}
			body.actionKey = input.actionKey;
			break;
		case 'none':
			break;
		default:
			c.refuse('the action key mode must be derive, given or none');
	}
	return c.built({ method: 'POST', path: '/act', body });
}

export function sealRequest(input: { session: unknown }): Built {
	const c = new check();
	const body = { session: c.session(input.session) };
	return c.built({ method: 'POST', path: '/seal', body });
}
