# Synthetic streams for the microsoft-graph binding

Answers shaped like the directory service's v1.0 JSON (a `value` array,
`@odata.nextLink`, `@odata.deltaLink`), for the streams of
`catalog/microsoft-graph.json`. Every name, id, host, address and UPN
in them is invented: hosts are example.com, example.org
and example.net, addresses are in the documentation ranges 192.0.2.0/24 and
198.51.100.0/24, GUIDs are `00000000-0000-4000-8000-...`. The links name
`https://graph.example.com`; the test replaces that host with the loopback
endpoint it serves.

`go/graph_streams_test.go` serves these files and reads them through the
shipped binding and the real `adapter-http`.

## Streams: two pages each

`<stream>.1.json` carries `@odata.nextLink`, an absolute URL under the
endpoint; `<stream>.2.json` is the last page. The last page of each delta
stream carries `@odata.deltaLink` (`$deltatoken=<stream>-round-1`).

| Stream | Path |
|---|---|
| `users-delta` (delta) | `/v1.0/users/delta` |
| `groups-delta` (delta) | `/v1.0/groups/delta` |
| `group-members` | `/v1.0/groups/{id}/members` |
| `role-assignments` | `/v1.0/roleManagement/directory/roleAssignments` |
| `role-definitions` | `/v1.0/roleManagement/directory/roleDefinitions` |
| `oauth2-permission-grants` | `/v1.0/oauth2PermissionGrants` |
| `service-principals` | `/v1.0/servicePrincipals` |
| `sign-ins` | `/v1.0/auditLogs/signIns` |
| `directory-audits` | `/v1.0/auditLogs/directoryAudits` |
| `risk-detections` | `/v1.0/identityProtection/riskDetections` |
| `risky-users` | `/v1.0/identityProtection/riskyUsers` |
| `user-registration-details` | `/v1.0/reports/authenticationMethods/userRegistrationDetails` |
| `devices` | `/v1.0/devices` |
| `organization` | `/v1.0/organization` |

## Cases: a status file and a body file

A `<case>.status` file holds the HTTP status on its first line and any
header lines (`Name: value`) after it; `<case>.json` is the body.

| Case | Status | Stream and case covered |
|---|---|---|
| `delta-expired` | 410 | `users/delta` read with a delta token no longer held; the body is the `syncStateNotFound` error |
| `throttled` | 429, `Retry-After: 7` | a later page of `auditLogs/signIns` read too fast |
| `unlicensed` | 403 | `identityProtection/riskDetections` of a directory without the licence the feature needs; generic wording |
| `delta-resync` | 400 | `groups/delta` read with a delta token no longer held, answered `400` with the `resyncRequired` error, a pair the binding declares an expired reference |
| `denied` | 403 | `identity/conditionalAccess/policies` read by a credential not granted the permission; the body is the `Authorization_RequestDenied` error, on the binding's access list |
| `oauth2-permission-grants.empty.json` | 200 (no status file) | `oauth2PermissionGrants` present but empty: `{"value":[]}` |
