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
		actionKeyMode: Property.StaticDropdown({
			displayName: 'Action Key',
			description:
				'How the write is named to the engine, which answers a retry under the same key from its journal instead of writing again. Never send a refused key’s write again under a new key.',
			required: true,
			defaultValue: 'derive',
			options: {
				disabled: false,
				options: [
					{ label: 'Derive from the intent (a retry sends the same key; not for arguments that change per run)', value: 'derive' },
					{ label: 'Given (a key chosen once for this write)', value: 'given' },
					{ label: 'None (refused at configuration version 14; a retry may write twice)', value: 'none' },
				],
			},
		}),
		actionKey: Property.ShortText({
			displayName: 'Key',
			description: 'For a given key: 64 lowercase hexadecimal characters, chosen once for this write',
			required: false,
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
				actionKeyMode: context.propsValue.actionKeyMode,
				actionKey: context.propsValue.actionKey,
			}),
		);
	},
});
