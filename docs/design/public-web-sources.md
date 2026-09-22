# Selected public web sources

Status: candidate, dependent on the connection catalog work. Different-vendor
material-decision review is required before merge.

`adapter-web` consumes exactly `{"url":"https://example.com/policy"}` on stdin
and returns an HTTP acquisition envelope containing an attachment-v1 record. It
reads one explicitly selected public URL. It is not a search engine, an account
connection, a browser, or a general outbound HTTP tool. It accepts no headers,
credentials, executable settings, or network-policy overrides from the caller.
The signing engine remains in its existing process; receipt v3, canonicalization,
and the frozen conformance corpus are unchanged.

## Admission and bounds

URLs are UTF-8, at most 4,096 bytes; JSON input is at most 8,192 bytes. Only HTTPS,
port 443 (explicit or implicit), without userinfo or a fragment is admitted.
ASCII DNS names or public IP literals are accepted. Single-label names, private
suffixes, private/loopback/link-local/multicast/unspecified addresses, IPv4 special
ranges and non-global or special IPv6 ranges are rejected conservatively. Every
A/AAAA answer must pass; at most 16 answers and four numeric connection attempts
are accepted. The transport dials a checked numeric address while keeping the
original HTTP Host and TLS hostname. It does not resolve that address again.
Redirects undergo the same checks; at most five redirects follow the initial
request. Proxy environment variables, cookies, and authorization are not used.
TLS verification is mandatory. There is no production insecure-test override.

The total operation deadline is 45 seconds. Fetches also have a 30-second client
deadline, 8-second dial/TLS and 10-second response-header limits. Headers are
bounded at 32 KiB. Only successful `200` responses with HTML, plain text, or PDF
media types are retained, up to 4 MiB. Text charsets must be UTF-8 or US-ASCII;
compressed HTTP responses are refused. Output is at most 16 MiB. PDF processing
uses the existing local document extractor, its inflate/page limits, and a
25-second processing context within the outer deadline; OCR is disabled.
Scanned/unreadable pages keep the existing partial/failed extraction contract.

Address checks follow the [OWASP SSRF guidance](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)
on validating DNS answers and redirects. These are application-level controls;
operators still control routing, DNS infrastructure, trust roots, and network
egress. A valid public address is not an assertion of publisher trust.

## Snapshot identity

HTML is tokenized to static UTF-8 text. Scripts, styles, templates, noscript and
SVG contents are excluded; no assets or JavaScript are fetched/executed. Whitespace
is simplified and block boundaries retained. This is not browser-rendered text
and not a claim that all information in the page was extracted. Plain text and
PDF retain the fetched original bytes. No raw HTML is rendered in Desk.

The new `provenance.source` variant has exactly:

- `kind: "web"`, `requestedUrl`, and final `url`;
- `mediaType`, the fetched response MIME type;
- `responseDigest`, SHA-256 of the fetched response bytes;
- `version`, SHA-256 of retained bytes, equal to `document.id` and
  `document.version`;
- `format: "static-text-v1"` for HTML converted to `text/plain`, or
  `"original-v1"` for unchanged plain text/PDF.

The original is inline base64. For original-v1, responseDigest also equals the
retained digest. HTML's responseDigest identifies fetched bytes that are not
retained; a consumer can verify the retained text and signed report, not reproduce
HTML conversion from that digest alone. The attachment checker validates the
variant, bytes, sizes, processing shape and identity relationships.

The acquisition reports the final endpoint without its query, a statement
containing GET/requested/final URLs, a raw-response digest snapshot, and the
verified TLS peer certificate's SHA-256 fingerprint. The gateway commits the
statement under its existing receipt contract. Source URLs remain visible in
the retained result, including any query parameters. Users should attach public
links, not secret-bearing URLs. A receipt verifies the signed adapter report and
byte lineage; it does not establish publisher authority, accuracy, or completeness.

## Discovery

`gateway-connections --catalog` advances to **version 2** and adds `sources`.
The existing `providers` descriptors are unchanged. Public web is advertised as
`{id:"web", input:"url", mediaTypes:["text/html","text/plain","application/pdf"],
maxBytes:4194304}`. This metadata is not a grant or an account status. Older strict
v1 consumers refuse v2; Desk updates with an exact bundle pin. There is no `web`
provider in the connection broker and no invented connect/disconnect operation.

## Validation

Local TLS fixtures exercise redirect identities, headers/cookies, public/private
DNS mixtures, numeric dialing, redirect re-resolution, private IP/special IPv6
refusals, cancellation, size/MIME/charset/compression limits, static HTML content,
plain originals, and text/scanned PDF extraction. Attachment tests reject invalid
web identities; CI validates actual producer output against the published schema.
