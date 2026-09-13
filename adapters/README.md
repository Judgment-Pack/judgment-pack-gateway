# adapters

The gateway's second module: the programs that reach outside catalogs and hand the
signer bytes over the source contract of [SPEC.md §6](../SPEC.md), in the envelope
[ADR-0002](../docs/adr/0002-adapters-report-in-the-envelope.md) settled. An adapter is
spawned by `gateway serve` as its own process, holds one platform's credentials, and
is never linked into the signer: `boundary_test.go` fails `go test ./...` on the first
import of the core module.

```
cd adapters && gofmt -l . && go vet ./... && go test ./...
go build -o adapter-airbyte ./cmd/adapter-airbyte
```

## adapter-airbyte

Runs a connector image that speaks the Airbyte protocol — the catalog of several
hundred sources — through the operator's container runtime, and reads **one page of
one stream** per acquisition: the records as the result, and the acquisition as the
adapter recorded it.

```
gateway serve ./store gateway.seed gateway:acme ./registry.jsonl \
  --source history='adapter-airbyte --image airbyte/source-postgres:3.6.1@sha256:… --credentials /run/secrets/warehouse --endpoint warehouse.internal:5432' \
  --source-shape history=airbyte \
  --source-env history=HOME
```

- `--image` must be pinned by digest: what runs is what the receipt names.
- `--credentials` is the connector's configuration JSON, a file the adapter's identity
  can read and the signer's cannot ([SECURITY.md](../SECURITY.md)). It is mounted
  read-only into the connector's container and never passed through an environment.
- `--runtime` is `docker` by default; `podman` works the same. The runtime inherits
  the adapter's environment, which is what the operator declared with `--source-env`:
  a runtime needs its `HOME`, and `PATH` is copied by default.
- `--endpoint` is the host the connector reaches, as the operator names it; the
  connector's own configuration is not read for it.

The request, as canonical arguments on stdin:

```json
{"stream": "decisions", "limit": 1000, "state": "<the previous receipt's snapshot>"}
```

`limit` is the page's floor, not a cut: once it is reached, records are kept until the
connector emits a checkpoint that covers them, so the next page never repeats a record;
past `--max-records` without one, the read is given up on. `state` is the previous
page's `snapshot`, exactly as its receipt recorded it, and is handed back to the
connector in the form it reads.

What the envelope carries, and so what the receipt records:

| Member | From |
|---|---|
| `adapter` | the pinned image: name, tag, digest |
| `endpoint` | `--endpoint`, or `null` |
| `statement` | the read request — stream, sync mode, cursor, the state resumed from — which the gateway commits to under a salt |
| `snapshot` | the connector's last checkpoint for the stream, compacted and otherwise as emitted, or `null` when it offered none |
| `peerIdentity` | `null`: a connector inside a container does not tell the adapter who it connected to |
| `schema` | the digest of the stream's discovered schema, canonicalized per §1.1 with any non-integer number carried as its decimal text |
| `upstreamToken` | `null`: the connector protocol carries none |
| `observedAt` | when the last record of the page was read |
| `result`, `page: true` | the records, each carried into the canon domain: member names sorted, and a number with a fraction or an exponent, or past ±(2^53−1), carried as a string holding its literal exactly |

Two honest bounds. The record data are the connector's: a record with a duplicate
member name or invalid UTF-8 fails the acquisition rather than being repaired. And the
page is bounded twice — by `--max-output` here and by the gateway's
`--source-max-output` there; keep the first at or below the second, so a page that is
too large is reported rather than killed mid-write.

Tests run the adapter against a stand-in for the container runtime
(`internal/fakeruntime`), so no runtime is needed to test it and none is used in CI;
the adapter's canonicalizer answers to the same frozen vectors as the core's
(`corpus/canon.json`), read from disk and never linked.
