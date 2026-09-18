// Package adapters is the root of the gateway's second module: the programs
// that reach outside catalogs — connector images speaking the Airbyte protocol,
// MCP servers, plain HTTP — and hand the bytes they fetched to the signer over
// the source contract in SPEC.md §6 (canonical arguments on stdin, one JSON
// result on stdout).
//
// What it holds, and the one rule it lives under, is recorded in
// docs/adr/0001-one-engine-four-processes.md: an adapter is shipped in the same
// release as the gateway and runs as its own process, spawned by the gateway
// exactly as any `--source NAME=CMD` is, declared an adapter of its shape with
// `--source-shape` and answering with the envelope of SPEC.md §6
// (docs/adr/0002-adapters-report-in-the-envelope.md) -- or, for the document
// adapter, left a bare source under the command shape
// (docs/adr/0004-documents-are-an-adapter-under-the-command-shape.md). It holds a platform's
// credentials; it never holds the signing seed; and it never imports the core
// module, so nothing in it can be linked into the process that signs.
// boundary_test.go makes `go test ./...` fail on the first import that crosses
// that line.
//
//	airbyte/               the Airbyte-shaped adapter: a pinned connector image
//	                       run through the operator's container runtime, one
//	                       page of one stream per acquisition
//	mcp/                   the MCP-shaped adapter: a client of an MCP server
//	                       over stdio, one tool call per acquisition
//	httpsource/            the HTTP-shaped adapter: one request over TLS to an
//	                       endpoint the operator fixed, one request per acquisition
//	attachment/            the document attachment record, version 1
//	                       (docs/design/attachments.md): its types, its text
//	                       normalisation and Check, the reference check of its rules
//	document/              the document adapter, a bare source: one attached
//	                       document read for its text into a versioned record
//	document/pdf/          its PDF reader, standard library only
//	cmd/adapter-airbyte/   their commands
//	cmd/adapter-mcp/
//	cmd/adapter-http/
//	cmd/adapter-document/
//	internal/canon/        §1.1 canonical form, answering to corpus/canon.json
//	internal/pdfgen/       a PDF writer for fixtures and tests
//	internal/containers/   a container run and ended with its absence established
//	internal/redact/       a connector's configuration kept out of diagnostics
//	internal/fakeruntime/  stand-ins for the container runtime and for an MCP
//	internal/fakemcp/      server, for tests
//
// README.md says how an adapter is wired to `gateway serve`.
package adapters
