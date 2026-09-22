# S3 file source

Status: implementation for review. Scope: read-only files in one explicitly
configured general-purpose S3 bucket/prefix, in commercial AWS regions. This is
not pack/chat storage, cloud deployment, account inventory or account-wide search.

## Authentication and dependency decision

The gateway takes region, bucket, optional prefix, access key ID, secret access
key, optional session token and token expiration (RFC 3339) through the existing
catalog-v3 form. Temporary credentials require their expiration. Credentials are
stored only in the gateway's private 0700/0600, per-principal aws-s3 custody,
using the existing no-follow, atomic-write and interprocess-lock implementation.
They are not put in the catalog, account status, source URL, receipt, CLI or logs.
No default AWS credential chain, profile lookup, external process, environment
credentials, IMDS or SSO cache is used. Browser-based IAM Identity Center sign-in
is future work; this slice does not represent a credential form as OAuth.

Use the official AWS SDK for Go v2 SigV4 signer (pinned in adapters/go.mod) with
explicit credentials and S3 path escaping. HTTP listing/HEAD/GET are small,
bounded operations implemented here to keep response admission and retry policy
explicit. No handwritten signature algorithm; no full S3 SDK/default-config
chain. Third-party dependencies remain outside the signer module. AWS SDK and
Smithy licenses are included in the distribution notices.

Configure checks ListObjectsV2 in the exact bucket/prefix before committing a
new generation. Concurrent disconnect or policy disable wins over that check.
Expired/invalid credentials require user replacement. Disconnect deletes local
credentials and invalidates outstanding browse contexts and grants; it reports
revoked:false because an IAM key remains valid at AWS until removed there.

## Listing, selection and acquisition

- Production origins are fixed HTTPS s3.<commercial-region>.amazonaws.com. No
  custom endpoint, redirect, proxy, region redirect, requester-pays header,
  customer decryption key, restore action, write, or automatic retry is used.
- Prefix queries append to the configured prefix; listing is flat. ListObjectsV2
  requests URL encoding and at most 24 objects, bounded to 256 KiB upstream and
  the existing 48 KiB public page. Vendor cursors are retained privately; public
  opaque cursors bind to the connection, query, generation and five-minute browse
  session. Oversized public pages resume via StartAfter at the last emitted key;
  unshown keys are not skipped. Up to eight pages remain selectable; older selections expire.
- Listed metadata must have bounded keys, sizes and ETags and stay within scope.
  Archived, oversized, empty and unsupported objects remain disabled. Access or
  download restrictions not evident from listing are checked at selection/read.
- Select admits at most four unique IDs from retained pages. Conditional HEAD
  must match each listed ETag and size. A five-minute single-use grant binds the
  object metadata and available VersionId to the current connection.
- GET uses If-Match and the selected VersionId where supplied, caps the body at
  4 MiB, checks returned ETag/version/length, and rechecks local generation after
  fetching and processing. Only the explicitly selected PDF/text bytes enter the
  existing resource-v1 producer. PDF OCR remains off.
- S3 metadata and request authentication never become document provenance. The
  signed resource identity is provider + bucket/key; retained bytes determine
  document identity. Long display filenames are shortened without changing the
  resource key. This attests byte lineage, not semantic truth or IAM policy.

## Desk compatibility and delivery evidence

Only catalog v3 advertises aws-s3. The v2 catalog is unchanged. The existing
adapter-sources executable and local launch plan admit it, so no new binary name,
Desk provider switch, UI, or receipt verifier variant is needed. All twelve
locales include setup labels and instructions. The neutral icon is intentional.

Acceptance must cover credentials/cursor/grant isolation, malformed and bounded
responses, exact escaped keys and signed requests, object changes, unavailable
objects, expiry, disconnect races, and secret exclusion. A real Desk browser
smoke must use the new gateway with the unchanged Desk binary, including a signed
attachment. Fake upstream tests are recorded separately from real AWS testing.
Live AWS acceptance remains pending a user-supplied test bucket/account; no
credentials, paid resources or live-provider claims are inferred from fixtures.

References checked 2026-09-22:
- https://docs.aws.amazon.com/sdk-for-go/v2/developer-guide/configure-gosdk.html
- https://docs.aws.amazon.com/AmazonS3/latest/API/API_ListObjectsV2.html
- https://docs.aws.amazon.com/AmazonS3/latest/API/API_HeadObject.html
- https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetObject.html
