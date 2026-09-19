# Optional publisher Google registration mechanism

Distribution policy updated 2026-09-19: **public source and GitHub releases ship
without publisher Google registration**. Installation owners configure their own
Desktop app through the host's Admin setup UI. In Desk this is **Admin → Connections**;
account consent and selection remain in chat. No personal or organization-owned
publisher registration belongs in public artifacts or an automatic bootstrap.

The earlier proposal to ship a registered public Desktop bundle is superseded.
The existing optional embedding mechanism described below is retained for explicit
downstream use; its existence does not authorize a registered public release.
Hosted deployments must choose their own appropriate OAuth application type,
redirects and credential-custody model. This local Desktop mechanism does not
implement a hosted multi-user OAuth service.

In a downstream distribution that explicitly supplies its own app registration,
users can grant access through Google consent without registering another app.
Drive then opens Google's file picker; Gmail returns to the host's email selection
interface. Account consent is still required for every user.

The publisher enables Drive API, Google Picker API and Gmail API in a controlled
Google Cloud project, sets Google Auth Platform branding/audience/data access,
and creates a **Desktop app** OAuth client. Separate testing and production
registrations are recommended by Google. External testing uses designated test
users; a production distribution must satisfy Google's applicable verification
requirements, including the restricted `gmail.readonly` scope. If selected email
content is sent to an external AI provider, its data use must also be reviewed
against Google's user-data requirements; local token custody does not settle that.

For that optional downstream mechanism, build tooling writes the Desktop registration JSON into the archived build
tree's `adapters/cmd/gateway-connections/publisher-google.json` before compiling.
The file in source control remains `{}`. Its `installed.client_id` and optional
`installed.client_secret` are the only operational fields. Web/service-account
registrations, duplicate keys, invalid values and inputs over 16 KiB are refused.
The host should normalize the input to those fields and never print it. Native
application registration is distributed application identity; it is not a user
credential and cannot be treated as a confidential web-server secret.

Only the connection companion embeds the registration. The signer and content
adapters do not embed it. The distribution's companion checksum covers it. There
is no project-provided path, browser-supplied default or environment-selected
OAuth server. The existing configure RPC remains an explicit operator override.

At startup the companion installs the publisher client into an unconfigured
gateway-owned private store, under its existing state lock. Existing clients and
accounts always win, even if a later build carries a different registration. No
silent client rotation or account migration is performed. Malformed existing
state fails closed. Disabled connections cannot start authorization. Provider
stores remain separate; Google revocation can still affect other connections in
the same Cloud project.

No client registration is created by this code, and no synthetic client is used
in production. Public builds retain `setup-required` until the installation owner
explicitly configures the provider. Their build checks must preserve the empty
registration sentinel rather than requiring a publisher registration. Existing
local registrations and accounts remain valid across public application updates.

References checked 2026-09-19:
- https://developers.google.com/identity/protocols/oauth2/native-app
- https://developers.google.com/workspace/drive/picker/guides/desktop-mobile-picker
- https://developers.google.com/workspace/gmail/api/auth/scopes
- https://developers.google.com/identity/protocols/oauth2/production-readiness/restricted-scope-verification
