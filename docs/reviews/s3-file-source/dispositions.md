# S3 review dispositions

The user authorized Codex clean-room review for this integration work. This is
same-vendor independent review under that exception, not cross-vendor compliance.
The drafting model is OpenAI Codex; the independent reviewer is a separately
started OpenAI Codex agent without the drafting conversation.

- **S3-IR-1 accepted:** use AWS Smithy's S3 path encoder before signing. Regression
  expectations spell out AWS percent-encoded paths, including reserved characters,
  Unicode, literal escapes, repeated slashes and dot segments.
- **S3-IR-2 accepted:** admit rows against the actual serialized page budget. Split
  oversized provider pages using bounded private StartAfter state, preserving all
  unseen keys. Test 24 maximum-length, HTML-escaped keys across pages and reads.
- **S3-IR-3 accepted:** forward every nonempty VersionId, including `null`; test an
  old null version that remains available after a new current version appears.

All three external reviewer probes pass after these changes. Reviewer code was
not copied into production; the author independently implemented dispositions.
The author also bound S3 grants to the policy epoch so a grant cannot revive after
disable/re-enable, and shortened only document display names for 255-byte producer
compatibility. Resource IDs retain exact keys.
