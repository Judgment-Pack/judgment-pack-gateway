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
				default: '{}',
				displayOptions: { show: { operation: ['acquire', 'act'] } },
				description: 'The canonical arguments the source or tool receives, as a JSON object',
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
			const operation = this.getNodeParameter('operation', i) as string;
			let built: Built;
			switch (operation) {
				case 'acquire':
					built = acquireRequest({
						session: this.getNodeParameter('session', i),
						source: this.getNodeParameter('source', i),
						arguments: this.getNodeParameter('arguments', i),
					});
					break;
				case 'act':
					built = actRequest({
						session: this.getNodeParameter('session', i),
						platform: this.getNodeParameter('platform', i),
						tool: this.getNodeParameter('tool', i),
						arguments: this.getNodeParameter('arguments', i),
						decision: this.getNodeParameter('decision', i),
						cites: this.getNodeParameter('cites', i),
					});
					break;
				case 'seal':
					built = sealRequest({ session: this.getNodeParameter('session', i) });
					break;
				default:
					throw new NodeOperationError(this.getNode(), `Unknown operation ${operation}`, {
						itemIndex: i,
					});
			}
			if (built.request === undefined) {
				throw new NodeOperationError(this.getNode(), built.refusal, { itemIndex: i });
			}
			// the credential resolves the path against the engine's URL and
			// adds the bearer when it holds one
			try {
				const answer = await this.helpers.httpRequestWithAuthentication.call(this, 'judgmentPackEngineApi', {
					method: built.request.method,
					url: built.request.path,
					body: built.request.body,
					json: true,
				});
				returned.push({ json: answer as IDataObject, pairedItem: { item: i } });
			} catch (error) {
				if (this.continueOnFail()) {
					returned.push({
						json: { error: (error as Error).message },
						pairedItem: { item: i },
					});
					continue;
				}
				throw new NodeApiError(this.getNode(), error as JsonObject, { itemIndex: i });
			}
		}
		return [returned];
	}
}
