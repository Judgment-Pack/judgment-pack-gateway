import { PieceAuth, Property } from '@activepieces/pieces-framework';
import { httpClient, HttpMethod } from '@activepieces/pieces-common';
import { engineBase, engineHeaders } from './common/requests';

// The engine's URL and, when the engine is configured with an identity, a
// bearer token its issuer signed: the token names the caller on every
// acquisition receipt and the requester on every action receipt. The header
// is sent only when a token is given; an engine without an identity records
// caller: null, and an Act needs a token.
export const judgmentPackAuth = PieceAuth.CustomAuth({
	displayName: 'Judgment Pack Engine',
	description:
		'The engine’s URL and, when it is configured with an identity, a bearer token its issuer signed',
	required: true,
	props: {
		engine_url: Property.ShortText({
			displayName: 'Engine URL',
			description: 'Where the engine listens, such as http://127.0.0.1:8787',
			required: true,
			defaultValue: 'http://127.0.0.1:8787',
		}),
		token: PieceAuth.SecretText({
			displayName: 'Bearer Token',
			description: 'Leave empty for an engine with no identity configured',
			required: false,
		}),
	},
	// A public key answers at every engine: this establishes that an engine
	// listens at the URL, and nothing about the key's authenticity (SPEC §5).
	validate: async ({ auth }) => {
		try {
			await httpClient.sendRequest({
				method: HttpMethod.GET,
				url: `${engineBase(auth)}/publickey`,
				headers: engineHeaders(auth),
			});
			return { valid: true };
		} catch (e) {
			return { valid: false, error: `No engine answered at the URL: ${(e as Error).message}` };
		}
	},
});
