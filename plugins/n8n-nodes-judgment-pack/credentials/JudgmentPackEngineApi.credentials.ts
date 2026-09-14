import type {
	Icon,
	ICredentialDataDecryptedObject,
	ICredentialTestRequest,
	ICredentialType,
	IHttpRequestOptions,
	INodeProperties,
} from 'n8n-workflow';
import { address } from './engine';

// The engine's URL and, when the engine is configured with an identity, a
// bearer token its issuer signed: the token names the caller on every
// acquisition receipt and the requester on every action receipt. The node
// sends a path; the credential resolves it against the URL and adds the
// header only when a token is given (an engine without an identity records
// caller: null).
export class JudgmentPackEngineApi implements ICredentialType {
	name = 'judgmentPackEngineApi';

	displayName = 'Judgment Pack Engine API';

	icon: Icon = {
		light: 'file:../icons/judgment-pack.svg',
		dark: 'file:../icons/judgment-pack.dark.svg',
	};

	documentationUrl =
		'https://github.com/Judgment-Pack/judgment-pack-gateway/tree/main/plugins/n8n-nodes-judgment-pack#credentials';

	properties: INodeProperties[] = [
		{
			displayName: 'Engine URL',
			name: 'engineUrl',
			type: 'string',
			default: 'http://127.0.0.1:8787',
			placeholder: 'http://127.0.0.1:8787',
			description: 'Where the engine listens (its serve address); no trailing slash',
		},
		{
			displayName: 'Bearer Token',
			name: 'token',
			type: 'string',
			typeOptions: { password: true },
			default: '',
			description:
				'A token the engine’s configured identity issuer signed; leave empty for an engine with no identity configured',
		},
	];

	async authenticate(
		credentials: ICredentialDataDecryptedObject,
		requestOptions: IHttpRequestOptions,
	): Promise<IHttpRequestOptions> {
		const addressed = address(credentials, requestOptions.url, (requestOptions.headers ?? {}) as Record<string, string>);
		return { ...requestOptions, url: addressed.url, headers: addressed.headers };
	}

	// A public key answers at every engine: this establishes that an engine
	// listens at the URL, and nothing about the key's authenticity (SPEC §5).
	test: ICredentialTestRequest = {
		request: {
			baseURL: '={{$credentials.engineUrl}}',
			url: '/publickey',
			method: 'GET',
		},
	};
}
