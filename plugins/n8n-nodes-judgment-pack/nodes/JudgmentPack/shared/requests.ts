// The requests the node sends, built apart from n8n so they can be tested
// without it: each is what a curl of the engine's HTTP surface would send
// (SPEC.md §6), no more. A builder refuses, by naming the reason, what the
// engine would refuse anyway, so the node can say so before asking; the
// engine's URL and the bearer are the credential's (authenticate in
// credentials/JudgmentPackEngineApi.credentials.ts), never read here.

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

export function actRequest(input: {
	session: unknown;
	platform: unknown;
	tool: unknown;
	arguments: unknown;
	decision: unknown;
	cites: unknown;
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
	const body = {
		session: c.session(input.session),
		platform: c.text(input.platform, 'the platform'),
		tool: c.text(input.tool, 'the tool'),
		arguments: c.object(input.arguments, 'the arguments'),
		decision,
		cites,
	};
	return c.built({ method: 'POST', path: '/act', body });
}

export function sealRequest(input: { session: unknown }): Built {
	const c = new check();
	const body = { session: c.session(input.session) };
	return c.built({ method: 'POST', path: '/seal', body });
}
