//go:build !unix

package main

// The existing store's best-effort directory sync is not sufficient to promise
// durable dispatch reservation. Keep keyed effects unavailable on these hosts
// until an equivalent native journal implementation has been verified.
const actionJournalSupported = false
