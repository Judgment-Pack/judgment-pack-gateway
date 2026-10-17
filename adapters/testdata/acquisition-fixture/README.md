# Acquisition fixture harness

This is a separate, explicitly tagged test program for Gateway #289. It supplies
deterministic HTTPS dependencies to the existing page and managed-search
acquisition bodies so consumers can exercise real acquisition envelopes and
Gateway-signed receipts without live providers. It is not a release program or a
private-network option for an installed adapter.

Every added Go file requires `gateway_acquisition_fixture`. Ordinary builds,
tests, command inventory and releases do not include the harness or its bridges.
The bridges delegate to `websource.readOptions` and `connections.searchAcquire`:
request validation, revision/daily allowance checks, HTTP/TLS, normalization,
redirect policy, static page extraction, attachment validation and acquisition
envelope construction remain the production bodies. The shipping CLI parsers and
the public `ReadWith`/`ReadSearch` factory selection are not exercised by this
injection. Tests using this harness must state that limit, and must not claim
official adapter binary coverage, source truth or qualification decisions.

The adapters CI job explicitly runs the tagged contract tests, vet and Python
builder/smoke refusal tests; these are separate from its ordinary build checks.

The fixed corpus uses invented company, professional and procurement records.
`https://api.tavily.com/search` returns three links under
`https://example.com/fixtures/`: `company`, `person` and `notice`. Configure only
a disposable Tavily connection with the fake credential `tvly-fixture-only`.
The harness keeps the canonical provider endpoint; it does not override the
acquisition endpoint to match a local listener. Page paths include:

| Path | Fixture behavior |
| --- | --- |
| `/fixtures/company`, `/fixtures/person`, `/fixtures/notice` | Fixed HTML with synthetic source statements |
| `/fixtures/start` | Same-origin redirect to `/fixtures/company?view=full`; offers a cookie that must not follow |
| `/fixtures/leave-scope` | Same-origin redirect to `/outside/company?view=full`; consumer final-endpoint checks must refuse a profile scoped to `/fixtures/` |
| `/fixtures/private-redirect` | Redirect to loopback; the production public-address rule refuses it |
| `/robots.txt` | Allows `/fixtures/` and disallows `/outside/` |

Each acquisition invocation owns one short-lived loopback TLS server. A generated
certificate names only the two fixed virtual hosts; its root is explicitly
trusted, and hostname verification remains enabled. Page DNS supplies one
synthetic public address through the existing dependency seam, then the production
public-address/dial check runs before the injected dial maps that exact target to
loopback. Search accepts only the exact canonical POST endpoint. Unknown names,
addresses, ports, URLs and methods fail without external DNS or dialing. There is
no proxy, environment endpoint/CA override, arbitrary fixture file or network
fallback. The inherited `JPACK_CONNECTIONS_DIR` selects only the disposable private
connection store, as the ordinary local source plan requires.

The source protocol is deliberately closed. The binary is placed in the fixture
bundle's `adapter-web` and `adapter-sources` role slots. Page accepts only a plain
read or `--describe-research` alone. Search accepts only `--provider web-search`,
`--principal desk-local`, optional `--state-dir`, and either read-only
`--describe-research` or optional `--long-search`. Other providers, discovery,
document processing, redirect-policy flags, duplicate/unknown flags and endpoint
arguments refuse. Requests keep the ordinary bounded JSON source contracts.
Descriptors reuse the production descriptor functions without starting fixture
network services. A descriptor grants no profile, scope, permission or receipt.

Build from this checkout into a **new disposable directory**. Inputs must be the
explicit, independently verified native Gateway release archive, its published
checksums and the consumer's verified `component-artifacts.json` containing the
Gateway artifact provenance. The builder verifies the local signed Git tag, exact
commit, archive checksum and every copied program/license hash. It preserves this
base provenance and signed-tag/checksum evidence. It does not itself verify GitHub
artifact attestations; the supplied artifact provenance must already have been
verified by the operator. No downloads occur, including Go dependency downloads.

```sh
python3 adapters/testdata/acquisition-fixture/build.py \
  --base-archive /path/to/judgment-pack-gateway_0.18.0_linux_amd64.tar.gz \
  --base-checksums /path/to/checksums.txt \
  --base-provenance /path/to/component-artifacts.json \
  --base-tag v0.18.0 \
  --base-commit 552141b5e0b06cc2523387e575799fea1ab2eca6 \
  --output /path/to/new-gateway-fixture-bundle
```

The signer and other companions remain exact base-archive bytes. Only the two
adapter slots contain the fixture executable. `document.OwnIdentity` reports that
executable's actual digest and a stamped `fixture.<source-revision>` version; the
fixture manifest is explicitly separate from the official release. Both role
slots contain the same executable, with the invoked filename selecting the role.
`fixture-provenance.json` records the source revision, every regular file in the
adapters module (including embedded assets, tests, scripts and the builder), and
replacement program hashes. Directory and file symlinks refuse before any name
filter; the complete module inventory is checked before and after compilation.
The builder hash comes from that same frozen inventory. A review build additionally requires
`--allow-dirty-fixture-source` and records `.dirty` in the version and provenance;
it never presents uncommitted fixture code as the signed base release. Consumers
approve only this exact fixture manifest for the individual test, using their
existing replacement-bundle test seam. Do not install it or change global trust.

Run focused tagged checks from `adapters/`:

```sh
go test -race -tags gateway_acquisition_fixture \
  ./internal/acquisitionfixture ./websource ./connections ./testdata/acquisition-fixture \
  -run 'Test(Fixture|AcquisitionFixture)' -count=1
go vet -tags gateway_acquisition_fixture \
  ./internal/acquisitionfixture ./websource ./connections ./testdata/acquisition-fixture
PYTHONDONTWRITEBYTECODE=1 python3 testdata/acquisition-fixture/build_test.py
PYTHONDONTWRITEBYTECODE=1 python3 testdata/acquisition-fixture/smoke_test.py
```

After building, the opt-in signer smoke admits the complete known program set and
matches every signer/control companion and replacement to its provenance before
executing any subprocess. It uses only disposable private state and
performs exactly one search and one page acquisition. It seals their session and
asks the unmodified base Gateway to verify the retained receipt signatures and
chain. It checks that each receipt names the true fixture executable/version and
that the page's submitted URL bytes survive the redirect. There are zero model
calls and zero decisions:

```sh
python3 testdata/acquisition-fixture/smoke.py --bundle /path/to/new-gateway-fixture-bundle
```

These checks cover network closure, TLS roots/hostname verification, real page
extraction/provenance, identity agreement, strict request refusal, durable search
charging and the closed process protocol. Signing remains in the unmodified
Gateway process; the harness never imports the core, reads its seed or fabricates
a receipt. Consumer end-to-end tests must separately verify the genuine returned
receipts, pinned profiles, found-value citations, scope refusals and offline replay.
