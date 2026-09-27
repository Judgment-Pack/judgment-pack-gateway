# Long source reads and caller custody

Gateway keeps its existing synchronous `/acquire` API. A caller can wait for a
long read without a browser request owning that wait. Operators can configure
`--source-timeout` up to seven days; the default remains 30 seconds. The adapter's
own deadline remains effective and should leave Gateway time for cleanup.

Durability belongs to a separate **caller** process: Runner's
`jpack-source-worker`. That process has no signing key. It makes one ordinary
acquisition, stores its request and returned proof in its own private state, and
lets Runner reconnect to the same operation. This is the same custody boundary
as an application retaining the `/acquire` response it received.

Gateway's receipt store never gains an operations directory, retained arguments,
or commitment salts. SPEC.md §1.2a and §6, the receipt format, and the frozen corpus
are unchanged. Copying or verifying the signer store does not copy the caller's
proof secrets. The caller store must be backed up separately and kept private.

If the caller worker restarts after completing and retaining a response, it can
return that exact response. If it stops after sending the acquisition but before
retaining the response, it records uncertainty and does not repeat the source.
The same applies when Gateway disappears mid-acquisition. Provider-native job
handles and callbacks require a later adapter contract.

Cancellation is local to the caller: the worker cancels its HTTP wait, but a
Gateway source or remote provider may still finish. Runner fences late results
and makes no decision from cancelled or expired preparation. This implementation
does not promise remote cancellation or retry an uncertain provider invocation.

## Review disposition

The initial candidate implemented `/operations` inside the signer and persisted
`{result, receipt, salts}`. Independent Codex clean-room review identified that
this contradicted the normative non-retention guarantee. The operations API and
persistence were removed from Gateway, rather than changing that guarantee.
Only the operator-configurable timeout ceiling remains in core. The matching
Runner change owns durable acquisition as the Gateway's caller.
