import { createAction, Property } from '@activepieces/pieces-framework';
import { judgmentPackAuth } from '../auth';
import { actRequest } from '../common/requests';
import { send } from '../common/send';

export const act = createAction({
	auth: judgmentPackAuth,
	name: 'act',
	displayName: 'Act',
	description:
		'Perform a write through a platform’s write tool and get the action receipt; the engine refuses it unless it cites a verifying judgment and the requester is authenticated',
	props: {
		session: Property.ShortText({
			displayName: 'Session',
			description: 'The session the action receipt chains into',
			required: true,
		}),
		platform: Property.ShortText({
			displayName: 'Platform',
			description: 'A platform the engine is configured with, marked writable',
			required: true,
		}),
		tool: Property.ShortText({
			displayName: 'Tool',
			description: 'A tool the platform’s write binding offers',
			required: true,
		}),
		arguments: Property.Json({
			displayName: 'Arguments',
			description: 'The tool’s arguments, as a JSON object',
			required: true,
			defaultValue: {},
		}),
		decision: Property.Json({
			displayName: 'Decision',
			description: 'The decision record the write relies on: {"recordDigest": "sha256:…", "packDigest": "sha256:…"}',
			required: true,
			defaultValue: { recordDigest: '', packDigest: '' },
		}),
		cites: Property.Json({
			displayName: 'Cites',
			description: 'The receipts the decision relied on: [{"sessionId": "…", "callIndex": 0, "signature": "…"}]',
			required: true,
			defaultValue: [],
		}),
	},
	async run(context) {
		return send(
			actRequest(context.auth.props, {
				session: context.propsValue.session,
				platform: context.propsValue.platform,
				tool: context.propsValue.tool,
				arguments: context.propsValue.arguments,
				decision: context.propsValue.decision,
				cites: context.propsValue.cites,
			}),
		);
	},
});
