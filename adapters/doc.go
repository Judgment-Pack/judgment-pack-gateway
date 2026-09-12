// Package adapters is the root of the gateway's second module: the programs
// that reach outside catalogs — connector images speaking the Airbyte protocol,
// MCP servers, plain HTTP — and hand the bytes they fetched to the signer over
// the source contract in SPEC.md §6 (canonical arguments on stdin, one JSON
// result on stdout).
//
// The module is empty on purpose at this point. What it will hold, and the one
// rule it lives under, is recorded in docs/adr/0001-one-engine-four-processes.md:
// an adapter is shipped in the same release as the gateway and runs as its own
// process, spawned by the gateway exactly as any `--source NAME=CMD` is today.
// It holds a platform's credentials; it never holds the signing seed; and it
// never imports the core module, so nothing in it can be linked into the
// process that signs. boundary_test.go makes `go test ./...` fail on the first
// import that crosses that line.
package adapters
