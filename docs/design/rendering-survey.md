# Design note: published servers that render documents, as read on 2026-09-28

**Status: a dated record, not normative.** It is the evidence
[ADR-0006](../adr/0006-documents-are-rendered-by-an-adapter.md) cites for not fronting a
published server. It records what was read, where, and at which release. It is not kept
current: what a project publishes later does not change what this note says was read.

## What the feature needs

Beyond what the catalog asks of an MCP binding — the `mcp` shape, an image pinned by digest and
a declared licence ([catalog/README.md](../../catalog/README.md),
[engine-config.md](engine-config.md)) — rendering needs three things of a server.

1. **The file in the result.** A receipt covers what a tool answers. Where the answer names a
   path and does not hold the file, the receipt does not cover the document.
2. **Text of any language.** The desk ships twelve locales: `de`, `en`, `es`, `fr`, `it`,
   `ja`, `ko`, `pt-BR`, `pt-PT`, `yue-Hant`, `zh-Hans` and `zh-Hant`. They are the files under
   `web/src/i18n/locales/` of the desk repository at commit
   `c742cbcf03e61a98e5aea7c285e67835c0efb3e8`. Five of them, `ja`, `ko`, `yue-Hant`, `zh-Hans`
   and `zh-Hant`, are written in scripts outside Latin-1.
3. **No access beyond what this repository holds.** For Google Drive that is the `drive.file`
   scope (`adapters/connections/provider.go`).

## What was read

Each fact below was read from the project's own files at the commit its release tag names.

| Server | Release | Commit | Licence | Image, as its registry served the tag |
|---|---|---|---|---|
| `cyanheads/docgen-mcp-server` | `v0.2.3` | `1121bb9d7f05aa474199596f316fa9572191a550` | Apache-2.0 | `ghcr.io/cyanheads/docgen-mcp-server:0.2.3`, index `sha256:cb00f7493b954b406490e0f00475ae866d476ac80c100a1a492dce28c05b0a2f` |
| `valdo404/docx-system` | `v1.6.0` | `6aadcce74ac0f14f7815b898e9a9af73e21ba980` | MIT | `docker.io/valdo404/docx-mcp:1.6.0`, index `sha256:ff6fcb094d77e483ebfdbce162a62fb7173a47fb66fa999536b25178c1193c68` |
| `taylorwilsdon/google_workspace_mcp` | `v1.29.0` | `ed70fb9068231ee13484bc2d53bdde2451e34d31` | MIT | `ghcr.io/taylorwilsdon/google_workspace_mcp:1.29.0`, index `sha256:22fb14c9c2620fda40e3587122fb97c9dee51a57f992a0987d6b4c842e325440` |

**`docgen-mcp-server`, for PDF.**

- `README.md`: "The lightweight engine renders structured layout (headings, paragraphs, lists,
  tables) but not arbitrary CSS, images, or scripts".
- `README.md`: a document at or under `DOCGEN_INLINE_MAX_BYTES`, 5,242,880 by default, is
  returned inline as base64.
- `src/services/document/render-service.ts`: the renderer embeds the standard fonts Helvetica
  and Helvetica Bold, and a comment on its text filter reads "Keep printable Latin-1
  (U+0020..U+00FF); drop everything else".

It meets need 1 and not need 2.

**`docx-mcp`, for Word.**

- `README.md`: the server "exposes 21 tools over MCP stdio transport".
- `README.md`: `document_save` is described as "Save document to disk (original path or new
  path)."
- `src/DocxMcp/Tools/DocumentTools.cs`: `document_save` returns a string, and the string is
  `"Document saved to '{target}'."` with the path in it.
- No file under `src/DocxMcp/Tools/` encodes a file's bytes into an answer. The one use of
  base64 in the source is in `src/DocxMcp/Persistence/WalEntry.cs`, for the server's own log.

No tool of the release meets need 1.

**`google_workspace_mcp`, for Google Docs.**

- `auth/scopes.py`: `DOCS_SCOPES` lists `documents.readonly`, `documents`, `drive.readonly`
  and `drive.file`.

As configured for documents it does not meet need 3.

## What this does not establish

- **No image was run.** Every statement comes from a README, a source file or a registry
  answer.
- **It is about the tools and the configuration as published.** It does not show that no
  wrapper could return a saved file in a result, or that no configuration of the Google server
  could be held to `drive.file`.
- **It is three servers.** They were the strongest of a wider reading of the MCP registry,
  Docker's catalog and GitHub on the same day. That reading is not recorded here, and this
  note does not claim that no other server exists.
- **Licences are as GitHub detected them** at the release, with the `LICENSE` file present in
  each of the three repositories.

## Sample text for the language condition

ADR-0006 names a condition for looking again at a published server: that it renders this text.
The sample is each locale's own name for its language, which is fixed and short. For Japanese
the name is followed by its reading in hiragana, so that the sample holds hiragana as well as
kanji. Together they put accented Latin letters, hiragana and kanji, hangul, and simplified and
traditional Chinese characters on one page. No sample holds katakana.

| Locale | Sample |
|---|---|
| `de` | Deutsch |
| `en` | English |
| `es` | español |
| `fr` | français |
| `it` | italiano |
| `ja` | 日本語 (にほんご) |
| `ko` | 한국어 |
| `pt-BR` | português (Brasil) |
| `pt-PT` | português (Portugal) |
| `yue-Hant` | 粵語 |
| `zh-Hans` | 简体中文 |
| `zh-Hant` | 繁體中文 |

**The criterion.** A PDF made from a document holding the twelve samples meets it when both of
these hold for every sample: the text extracted from the PDF is the sample, character for
character; and the page draws it with glyphs of a font, none of them the glyph a font shows
for a character it lacks. The sample is a floor. It exercises no right-to-left layout and no
complex shaping, and a PDF that meets the criterion has shown neither. A locale added to the
desk later adds its own name to the table.
