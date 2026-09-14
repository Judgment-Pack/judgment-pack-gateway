import { createPiece } from '@activepieces/pieces-framework';
import { PieceCategory } from '@activepieces/shared';
import { judgmentPackAuth } from './lib/auth';
import { acquire } from './lib/actions/acquire';
import { act } from './lib/actions/act';
import { seal } from './lib/actions/seal';

// A client of the Judgment Pack engine's HTTP surface (SPEC.md §6): the
// engine's own adapters fetch the bytes and the engine's own key signs; the
// piece carries the answer into the flow as data and verifies nothing. A
// receipt is worth what `gateway verify` says about it, under a key pinned
// out of band, and the consumer checks that before relying on the bytes.
// The framework's custom-call action is not offered: it sends through the
// framework's httpClient, which in the pinned version disables certificate
// verification for the process (src/lib/common/send.ts).
export const judgmentPack = createPiece({
	displayName: 'Judgment Pack',
	description: 'Acquire facts with a signed receipt, perform an approved write, seal a session',
	auth: judgmentPackAuth,
	minimumSupportedRelease: '0.82.0',
	logoUrl: 'https://raw.githubusercontent.com/Judgment-Pack/judgment-pack-gateway/main/plugins/n8n-nodes-judgment-pack/icons/judgment-pack.svg',
	categories: [PieceCategory.DEVELOPER_TOOLS],
	authors: ['Judgment-Pack'],
	actions: [acquire, act, seal],
	triggers: [],
});
