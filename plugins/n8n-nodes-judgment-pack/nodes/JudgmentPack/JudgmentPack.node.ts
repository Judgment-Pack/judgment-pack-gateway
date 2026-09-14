import {
	NodeApiError,
	NodeConnectionTypes,
	NodeOperationError,
	type IDataObject,
	type IExecuteFunctions,
	type INodeExecutionData,
	type INodeType,
	type INodeTypeDescription,
	type JsonObject,
} from 'n8n-workflow';
import { acquireRequest, actRequest, sealRequest, type Built } from './shared/requests';

// A client of the engine's HTTP surface (SPEC.md §6): acquire facts with a
// receipt, perform an approved write as an action with its receipt, seal a
// session. The node carries the engine's answer into the workflow as data
// and verifies nothing; a receipt is worth what `gateway verify` says about
// it later, under a key pinned out of band.
export class JudgmentPack implements INodeType {
	description: INodeTypeDescription = {
		displayName: 'Judgment Pack',
		name: 'judgmentPack',
		icon: { light: 'file:../../icons/judgment-pack.svg', dark: 'file:../../icons/judgment-pack.dark.svg' },
		group: ['input'],
		version: 1,
		subtitle: '={{$parameter["operation"]}}',
		description: 'Acquire facts with a signed receipt, perform an approved write, seal a session',
		defaults: {
			name: 'Judgment Pack',
		},
		usableAsTool: true,
		inputs: [NodeConnectionTypes.Main],
		outputs: [NodeConnectionTypes.Main],
		credentials: [
			{
				name: 'judgmentPackEngineApi',
				required: true,
			},
		],
		properties: [
			{
				displayName: 'Operation',
				name: 'operation',
				type: 'options',
				noDataExpression: true,
				options: [
					{
						name: 'Acquire',
						value: 'acquire',
						description: 'Run a configured source and get its result with a signed receipt',
						action: 'Acquire facts with a receipt',
					},
					{
						name: 'Act',
						value: 'act',
						description:
							'Perform a write through a platform’s write tool, refused unless it cites a verifying judgment',
						action: 'Perform an approved write',
					},
					{
						name: 'Seal',
						value: 'seal',
						description: 'Seal a session’s final receipt count',
						action: 'Seal a session',
					},
				],
				default: 'acquire',
			},
			{
				displayName: 'Session',
				name: 'session',
				type: 'string',
				default: '',
				required: true,
				description: 'The session the receipt chains into: a flat token the workflow chooses',
			},
			{
				displayName: 'Source',
				name: 'source',
				type: 'string',
				default: '',
				required: true,
				displayOptions: { show: { operation: ['acquire'] } },
				description: 'A source the engine is configured with, such as a platform’s history or live operation',
			},
			{
				displayName: 'Arguments',
				name: 'arguments',
				type: 'json',
				default: '',
				displayOptions: { show: { operation: ['acquire'] } },
				description:
					'The canonical arguments the source receives: any JSON value; leave empty for the engine’s default, an empty object',
			},
			{
				displayName: 'Arguments',
				name: 'arguments',
				type: 'json',
				default: '{}',
				displayOptions: { show: { operation: ['act'] } },
				description: 'The tool’s arguments, as a JSON object',
			},
			{
				displayName: 'Platform',
				name: 'platform',
				type: 'string',
				default: '',
				required: true,
				displayOptions: { show: { operation: ['act'] } },
				description: 'A platform the engine is configured with, marked writable',
			},
			{
				displayName: 'Tool',
				name: 'tool',
				type: 'string',
				default: '',
				required: true,
				displayOptions: { show: { operation: ['act'] } },
				description: 'A tool the platform’s write binding offers',
			},
			{
				displayName: 'Decision',
				name: 'decision',
				type: 'json',
				default: '{"recordDigest": "sha256:…", "packDigest": "sha256:…"}',
				displayOptions: { show: { operation: ['act'] } },
				description: 'The decision record the write relies on: its digest and the pack’s',
			},
			{
				displayName: 'Cites',
				name: 'cites',
				type: 'json',
				default: '[{"sessionId": "", "callIndex": 0, "signature": ""}]',
				displayOptions: { show: { operation: ['act'] } },
				description: 'The receipts the decision relied on, each by session, index and signature',
			},
		],
	};

	async execute(this: IExecuteFunctions): Promise<INodeExecutionData[][]> {
		const items = this.getInputData();
		const returned: INodeExecutionData[] = [];
		for (let i = 0; i < items.length; i++) {
			// everything an item can fail on -- its parameters, the request it
			// builds, the engine's answer -- is under one handler, so that with
			// continueOnFail the next item still runs
			let failure: Error | undefined;
			try {
				returned.push({ json: (await perform(this, i)) as IDataObject, pairedItem: { item: i } });
			} catch (error) {
				if (this.continueOnFail()) {
					returned.push({ json: { error: (error as Error).message }, pairedItem: { item: i } });
					continue;
				}
				failure = error as Error;
			}
			if (failure !== undefined) {
				// perform threw the node's own error or an API error; nothing is re-wrapped
				throw failure;
			}
		}
		return [returned];
	}
}

// perform builds one item's request and sends it: a refusal before asking is
// the node's own error, the engine's refusal or absence is an API error, and
// the credential resolves the path against the engine's URL and adds the
// bearer when it holds one.
async function perform(ctx: IExecuteFunctions, i: number): Promise<unknown> {
	const operation = ctx.getNodeParameter('operation', i) as string;
	let built: Built;
	switch (operation) {
		case 'acquire':
			built = acquireRequest({
				session: ctx.getNodeParameter('session', i),
				source: ctx.getNodeParameter('source', i),
				arguments: ctx.getNodeParameter('arguments', i, ''),
			});
			break;
		case 'act':
			built = actRequest({
				session: ctx.getNodeParameter('session', i),
				platform: ctx.getNodeParameter('platform', i),
				tool: ctx.getNodeParameter('tool', i),
				arguments: ctx.getNodeParameter('arguments', i),
				decision: ctx.getNodeParameter('decision', i),
				cites: ctx.getNodeParameter('cites', i),
			});
			break;
		case 'seal':
			built = sealRequest({ session: ctx.getNodeParameter('session', i) });
			break;
		default:
			throw new NodeOperationError(ctx.getNode(), `Unknown operation ${operation}`, { itemIndex: i });
	}
	if (built.request === undefined) {
		throw new NodeOperationError(ctx.getNode(), built.refusal, { itemIndex: i });
	}
	try {
		return await ctx.helpers.httpRequestWithAuthentication.call(ctx, 'judgmentPackEngineApi', {
			method: built.request.method,
			url: built.request.path,
			body: built.request.body,
			json: true,
		});
	} catch (error) {
		throw new NodeApiError(ctx.getNode(), error as JsonObject, { itemIndex: i });
	}
}
