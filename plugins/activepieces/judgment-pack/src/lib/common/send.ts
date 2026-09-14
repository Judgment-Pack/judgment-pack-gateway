import { httpClient, HttpMethod } from '@activepieces/pieces-common';
import type { EngineRequest } from './requests';

// One request, the engine's answer as JSON; a non-2xx answer is the
// framework's error, with the engine's text.
export async function send(request: EngineRequest): Promise<unknown> {
	const response = await httpClient.sendRequest<unknown>({
		method: HttpMethod.POST,
		url: request.url,
		headers: request.headers,
		body: request.body,
	});
	return response.body;
}
