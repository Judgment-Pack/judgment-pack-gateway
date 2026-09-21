# Connected note sources: Notion and Obsidian

Status: implementation proposed; requires material-decision review before merge.

This extends the personal connections companion and document attachment contract.
It does not change `SPEC.md`, the frozen receipt corpus, or the signing module.

## Ownership and limits

`gateway-connections --provider notion|obsidian` owns connection state in separate
provider namespaces below the operator's private state directory. The parent fixes
the principal. All requests use the existing bounded private JSON-lines pipe.
Tokens and absolute vault paths never become chat context, request arguments to the
signer, or attachment records. The custody model remains the same local OS-account
model as Google connections: private 0700 directories and 0600 atomic state files,
not an encrypted credential vault or multi-user organization service.

The shared operations are `status`, `search`, `select`, and `disconnect`. Search
returns `{selectionContext, items:[{id,title,url,description?}], more}`. Select takes
`{selectionContext, resourceIds}` and returns up to four `{resourceId,grant}` values.
A grant expires after five minutes, is consumed once, and is tied to the connection.
A disconnect or configuration change invalidates pending retrieval results.
Search is a user action in the picker. It does not grant the model unrestricted
account search. A future agent search capability needs its own explicit grant and
resource/tool policy; connecting or attaching a note must not silently enable it.

`adapter-sources --provider notion|obsidian --principal ...` consumes a selection
on stdin. The credential root is operator configuration, never a request member.
Retrieval has a 55-second deadline, 4 MiB text bound, and 16 MiB output bound.
The ordinary attachment preview, retained original, consumer verification, and
citation mechanisms apply to the resulting snapshot.

## Notion

The reviewed endpoint is `https://mcp.notion.com/mcp`. OAuth discovery is accepted
only on `https://mcp.notion.com` and only for the exact documented authorization,
token, and registration endpoints. No discovery response may nominate another
origin. HTTP redirects are refused; authorization opens in the user's browser.

The companion dynamically registers a public PKCE client. It persists its client
identity and loopback redirect together and reuses them across restarts. If the
registered loopback port is occupied, sign-in fails with a recoverable message;
it does not silently replace the registration and orphan an existing grant.
The callback is IPv4 loopback only, validates Host, state and expiry, and is single
use. The code verifier is held in memory. Token exchange uses the discovered
resource audience. No user-managed Google registration is involved.

Rotating refresh tokens are serialized with a separate OS file lock shared by
broker and adapter processes. The state lock stays free during network I/O so
local disconnect takes effect immediately. A refreshed token commits only against
the same connection generation. `invalid_grant` clears the connection; it is never
retried. Other provider failures do not erase an otherwise recoverable connection.
Disconnect deletes local credentials and grants become unusable. This slice does
not claim provider-side revocation: the UI directs the user to remove the Notion
connection in Notion settings as well.

The new `mcphttp` package implements bounded Streamable HTTP, accepts JSON and SSE
responses, negotiates protocol versions, echoes session IDs, and serves no model
sampling, roots, or elicitation. It does not fall back to the legacy two-endpoint
SSE transport. A lost/incomplete stream fails the operation. Transport support is
reusable; adding arbitrary URLs or another OAuth issuer requires another reviewed
provider profile. The existing stdio MCP adapter is unchanged.

Tool permission is a fixed allowlist: `notion-get-tool-access`, `notion-search`,
`notion-ai-search`, `notion-fetch`. Tool descriptions and read-only annotations do
not grant permission. Search routes according to the exposed tool/access map.
Notion may search sources connected inside its workspace; the connection UI states
this. Only results with a matching Notion page ID and an approved Notion URL are
selectable. Fetch accepts a Notion ID, not an arbitrary URL. No write tool can be
called through this companion. Plan restrictions remain Notion's, not bypassed.

The attachment is a snapshot of text returned by the fetch tool, including any
provider-reported incompleteness. It is not a recursive crawl, complete database
export, or a guarantee that every linked page was included. Notion retrieval uses
the existing `mcp` receipt shape and adapter envelope.

## Obsidian

Obsidian vaults are local folders of Markdown notes. This connection uses no
Obsidian plugin, local REST server, OAuth flow, or remote sync credentials.
Configure takes `{path}` for an existing absolute vault folder containing an
`.obsidian` directory. The path is held only in the companion's private state.
Use the path on the machine running Desk. A vault synced from another device must
have a local copy on that machine.

Only `.md` notes are read. Hidden names (including `.obsidian` and `.trash`), known
symlinks, nonregular files, traversal paths, and Windows alternate-stream syntax
are refused or skipped. Files are opened under `os.Root`; a racing symlink cannot
escape the chosen vault. Reads never write to the vault. The final file open uses
no-follow and nonblocking flags on supported platforms. Size and modification time
are checked around a read; a detected concurrent edit refuses the snapshot.

Search visits at most 10,000 entries and 24 directory levels, returns at most 20
matches, and reads at most 32 MiB of note content per search. Results may be partial;
`more` asks the user to narrow the search. A selected note has a 4 MiB bound.
Absolute paths are omitted from results and records. Source links use only
`obsidian://open` with an encoded vault name and relative note name. Vault names
are not globally unique; the saved snapshot remains the source used in chat even
if the desktop app later opens a similarly named vault.

Obsidian produces the attachment record directly under the existing `command`
receipt shape. It does not pretend to be an HTTP or MCP upstream.

## Attachment extension

Attachment version 1 adds a recognized source variant:

```
{kind:"connected-source", provider:"notion"|"obsidian", resourceId, url,
 version:"sha256:...", format:"text-snapshot-v1"}
```

Every listed field is required and no other source field is emitted. The document
version and source version equal the retained text's SHA-256 document ID. The
original is base64 inline, and the processor is `adapter-document/text/1`. Existing
Google and inline variants are unchanged. Old consumers reject this unknown source
kind rather than misidentifying it as an inline file. Updated consumers validate
provider-specific resource IDs and URLs and bind the selection to the signed
argument commitment. A receipt verifies byte lineage, not the accuracy, authority,
or completeness of the provider's content.

## Verification

Tests cover OAuth registration/callback, audience and PKCE, foreign discovery
refusal, token rotation serialization, terminal invalid_grant, disconnect during
refresh, the search/select/snapshot lifecycle, grant replay, vault traversal and
symlinks, hidden configuration exclusion, and retained snapshots after note edits.
Transport tests cover JSON/SSE, session headers, tool allowlists, redirects, wrong
IDs, duplicate members, result/error ambiguity, credential echoes (including JSON
escapes), incomplete streams, notification floods and response bounds.
No live Notion account or real Obsidian vault is used by these tests.

## References

- https://developers.notion.com/guides/mcp/build-mcp-client
- https://developers.notion.com/guides/mcp/mcp-supported-tools
- https://modelcontextprotocol.io/specification/2025-11-25/basic/transports
- https://help.obsidian.md/data-storage
- https://help.obsidian.md/Extending+Obsidian/Obsidian+URI
