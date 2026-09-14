import { createAction, Property } from '@activepieces/pieces-framework';
import { judgmentPackAuth } from '../auth';
import { acquireRequest } from '../common/requests';
import { send } from '../common/send';

export const acquire = createAction({
	auth: judgmentPackAuth,
	name: 'acquire',
	displayName: 'Acquire',
	description:
		'Run a source the engine is configured with and get its result with a signed receipt (result, receipt, salts)',
	props: {
		session: Property.ShortText({
			displayName: 'Session',
			description: 'The session the receipt chains into: a flat token the flow chooses',
			required: true,
		}),
		source: Property.ShortText({
			displayName: 'Source',
			description: 'A source the engine is configured with, such as a platform’s history or live operation',
			required: true,
		}),
		arguments: Property.Json({
			displayName: 'Arguments',
			description:
				'The canonical arguments the source receives: any JSON value; leave empty for the engine’s default, an empty object',
			required: false,
		}),
	},
	async run(context) {
		return send(
			acquireRequest(context.auth.props, {
				session: context.propsValue.session,
				source: context.propsValue.source,
				arguments: context.propsValue.arguments,
			}),
		);
	},
});
