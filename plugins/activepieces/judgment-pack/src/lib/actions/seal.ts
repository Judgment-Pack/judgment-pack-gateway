import { createAction, Property } from '@activepieces/pieces-framework';
import { judgmentPackAuth } from '../auth';
import { sealRequest } from '../common/requests';
import { send } from '../common/send';

export const seal = createAction({
	auth: judgmentPackAuth,
	name: 'seal',
	displayName: 'Seal',
	description: 'Seal a session’s final receipt count and get the seal record',
	props: {
		session: Property.ShortText({
			displayName: 'Session',
			description: 'The session to seal',
			required: true,
		}),
	},
	async run(context) {
		return send(sealRequest(context.auth.props, { session: context.propsValue.session }));
	},
});
