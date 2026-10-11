# Selected public web sources

Status: shipped in v0.3.0 (#148), building on the connection catalog.

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
request. Every redirect is also held to the requested origin: a hop to another
scheme, host or port is refused as `web-redirect-origin` before it is requested
(#224), unless an operator's [redirect policy](#operator-redirect-policies)
covers that one hop. Proxy environment variables, cookies, and authorization are not used.
TLS verification is mandatory. There is no production insecure-test override.

The total operation deadline is 45 seconds, or 140 seconds when the adapter is
launched with `--document-processing` and a processor is configured. Fetches also have a 30-second client
deadline, 8-second dial/TLS and 10-second response-header limits. Headers are
bounded at 32 KiB. Only successful `200` responses with HTML, plain text, or PDF
media types are retained, up to 4 MiB. Text charsets must be UTF-8 or US-ASCII;
compressed HTTP responses are refused. Output is at most 16 MiB. PDF processing
uses the existing local document extractor, its inflate/page limits, and a
25-second processing context within the outer deadline. OCR runs for a PDF only
when the adapter is launched with `--document-processing` and the operator's
settings enable a processor, and the processing deadline is then that setting's,
10 to 120 seconds
([attachments](attachments.md#document-processing-ocr-under-the-managed-local-plan)).
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
  `"original-v1"` for unchanged plain text/PDF;
- and, only when a read followed a cross-origin hop under an operator's
  redirect policy, `redirectPolicy` naming it (`"google-grounding"`); see the
  [consumer contract](#consumer-contract).

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

## Operator redirect policies

A redirect policy is a named, fixed exception to the origin rule that the
operator enables for the web source. This distribution supports one,
`google-grounding`: a Google grounding search result is a link to
`https://vertexaisearch.cloud.google.com/grounding-api-redirect/<token>`, which
answers with a redirect to the publisher, and without the policy every such
link is refused as `web-redirect-origin`.

### Configuration

The policies are the adapter's command line, the operator's declaration of the
source: `adapter-web --redirect-policies=LIST`, where LIST is policy names
separated by single commas, given once, in one word. A gateway operator writes
it into the source (`--source "web=adapter-web --redirect-policies=google-grounding"`).
Under the managed local plan, `gateway-connections --local-plan` adds
`--redirect-policies=LIST` to the `web` source's arguments while
`JPACK_WEB_REDIRECT_POLICIES`, in the environment the companion is asked with,
names a policy; unset or empty, the plan is byte for byte the plan without it.
`web-discovery` is never given the flag, and `adapter-web --discover` refuses it.

An empty LIST is no policy. A name this distribution does not support, a name
given twice, whitespace or an empty item refuses the list whole, never read as
a smaller one: the adapter refuses to start (exit 2) with the one line
`web-redirect-policy-unknown: …` on standard error, before it reads the request,
and the companion refuses `--local-plan` and `--source-capabilities` the same
way, so a desk does not start a local gateway on a list it cannot follow.

Nothing a request, a model's output or a URL carries can enable a policy. The
request stays exactly `{url}` or `{url, site}`; a request with any other member
is refused as `web-invalid-request` before any network request.

**Activation.** The adapter is started for each acquisition, reads its command
line then and keeps nothing between reads. A gateway fixes a source's command
line when it starts, and a desk reads the plan when it starts its local
gateway, so enabling or removing a policy takes effect at that gateway's next
start, from its first read.

### `google-grounding`

One change of origin is followed, and only when all of these hold:

- the read is a plain read: discovery and a site-scoped read (`site`) follow no
  policy hop, held to one origin as before;
- the requested URL is exactly the grounding endpoint: `https`, the host
  `vertexaisearch.cloud.google.com` spelled in lowercase, port 443 implicit or
  explicit, a path of `/grounding-api-redirect/` and one non-empty segment with
  no `/`, nothing percent-encoded and not `.` or `..`, and no query (an empty
  `?` included);
- the hop is the redirect of the first response, before any other redirect;
- its destination is admitted as any requested URL is (https, port 443, no
  userinfo, a name or literal that passes the address rules, every DNS answer
  public at the dial), and is another origin.

The destination's origin is then the origin every later hop is held to:
same-origin redirects at the publisher are followed within the six requests,
and a second change of origin, a return to the provider or any other
cross-origin hop is refused as `web-redirect-origin`. An invalid or private
destination is refused under its own token before the policy is consulted.
Every hop keeps the transport above: TLS verification, the timeouts, the header
and body bounds, the media checks. The adapter keeps no cookie jar and sends
no cookie, authorization or referrer header on any hop.

**What it establishes, and what it does not.** Enabling the policy is the
operator's acceptance that a grounding result may lead the reader on to the
publisher it names. It is not evidence about the publisher: the provider
choosing the destination does not make that page authoritative, accurate or
complete, and the record says which policy was followed, not that following it
was right. A read under the policy discloses the token in the requested URL to
the provider, and the reader's address to the provider and the publisher, as
any read discloses it to the server it reads.

## Consumer contract

What a consumer such as Desk reads about redirect policies, in three places.

**The configuration report.** `gateway-connections --source-capabilities`
writes one JSON object on stdout:

```json
{"version":1,"sources":[{"id":"web","redirectPolicies":{"supported":["google-grounding"],"enabled":[]}}]}
```

`supported` is what an operator of this distribution can enable; `enabled` is
what `JPACK_WEB_REDIRECT_POLICIES` in the companion's environment enables, read
exactly as `--local-plan` reads it, so a report and a plan asked with the same
environment agree. It is read from the verified installed companion, like the
catalog and the plan, and creates, locks and writes nothing; with another
discovery flag, or a list it cannot follow, it exits 2. It is a document of its
own because readers of the catalog and the plan hold their members closed.

**The refusal.** `adapter-web` writes one line on standard error. For a redirect
refused by the origin rule, the token is followed by one space and a JSON
object:

```text
web-redirect-origin {"redirect":{"from":"https://vertexaisearch.cloud.google.com","permitted":false,"policy":"google-grounding","to":"https://example.com"}}
```

The reference gateway answers `/acquire` with `400` and
`{"error": "source failed: " + the first 200 bytes of the source's standard error}`
(`go/serve.go`), and the adapter writes the member only when the whole line is
at most 200 bytes, so a member arrives whole or not at all; past that the line
is the token alone. Members, in code-point order:

- `from`, `to`: the origin of the response that redirected and of its
  `Location`, `https://` and the host as the URL spelled it, in lowercase, an
  IPv6 literal in brackets. Never a path, a token, a query or credentials;
- `policy`: the supported policy whose eligibility this hop meets in this read
  and which the operator's configuration does not enable, or `null` when no
  supported policy covers the hop;
- `permitted`: `false`, since the configuration in force did not permit the
  hop.

So `policy` non-null, supported and not enabled says a configuration review can
change the outcome; `null` says no policy this distribution has would follow
the hop, and a consumer offers no review. A hard refusal, such as
`web-invalid-url` or `web-public-only`, never carries the member: it is not a
configuration choice. The token stays the line's first word, so a consumer that
reads the first `web-…` word reads the refusal as before. Discovery's per-page
`reason` stays the bare token.

**Provenance.** A record read under a policy carries
`provenance.source.redirectPolicy` naming it; a record read without one is
unchanged byte for byte, without the member. The member is an optional
addition within attachment version `"1"`
([attachments](attachments.md#versioning)), signed as the rest of the record is
(the receipt commits the result); no receipt or signature format changes. The
acquisition statement keeps its three members, `method`, `requestedUrl` and
`url`. `requestedUrl` is the grounding link as requested, `url` the publisher's
page that answered.

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
plain originals, and text/scanned PDF extraction. A fixture serving several
virtual hosts behind synthetic DNS holds the redirect policy: the default
refusal with one request, the one permitted hop with no cookie, credential or
referrer on any hop, and each hop it does not cover refused under its token. Attachment tests reject invalid
web identities; CI validates actual producer output against the published schema.
