# S3 through unchanged Desk

Use a built Desk bundle, its checkout (with web dependencies installed), a runtime
binary and a synthetic pack project. No real AWS or AI credentials are used.

Set `DESK_BUNDLE`, `DESK_CHECKOUT`, `JPACK_BINARY`, `JPACK_FIXTURE_PROJECT`,
`CHROMIUM_PATH`, `S3_SMOKE_WORK` (new temporary directory), and
`JPACK_S3_SMOKE_READY` (temporary JSON path). From `adapters/`, start:

```
go test ./connections -run '^TestS3DeskFixture$' -count=1 -timeout=21m
```

Once the ready JSON exists, from the repository root:

```
python3 testdata/s3-desk/build-overlay.py
node testdata/s3-desk/smoke.mjs
```

Create `${JPACK_S3_SMOKE_READY}.stop` to stop the fixture. The test automatically
expires after 20 minutes. The Desk smoke uses localhost port 18923 and isolated
config/chat/project directories. It never sends a chat to a model.

The overlay changes only S3 transport routing and trust to the fixture's local
TLS listener/certificate; configuration, catalog, custody, SigV4 signing,
listing, selection, conditional GET, extraction, gateway receipts and Desk
verification remain real. The fixture independently verifies signatures using
standard-library HMAC. Neither the overlay nor its endpoint is in a production
build. Desk's executable SHA256 must remain identical. Screenshots and assertions
are written under `$S3_SMOKE_WORK/evidence`.
