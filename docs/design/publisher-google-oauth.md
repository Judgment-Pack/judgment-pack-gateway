# Publisher Google sign-in for local distributions

The app publisher registers its application once; ordinary users do not create
Google Cloud projects, supply API credentials, or visit an enterprise admin page.
Users choose Google Drive or Gmail, continue to Google, choose an account and
grant access. Drive then opens Google's file picker; Gmail returns to the host's
email selection interface. Account consent is still required for every user.

The publisher enables Drive API, Google Picker API and Gmail API in a controlled
Google Cloud project, sets Google Auth Platform branding/audience/data access,
and creates a **Desktop app** OAuth client. Separate testing and production
registrations are recommended by Google. External testing uses designated test
users; a production distribution must satisfy Google's applicable verification
requirements, including the restricted `gmail.readonly` scope. If selected email
content is sent to an external AI provider, its data use must also be reviewed
against Google's user-data requirements; local token custody does not settle that.

Release tooling writes the Desktop registration JSON into the archived build
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
in production. Source-only builds retain `setup-required` until explicitly
configured. Release tooling should fail a Google-enabled release if the publisher
registration was not supplied. Missing registration is a publisher packaging
problem, not onboarding work for a nontechnical user.

References checked 2026-09-19:
- https://developers.google.com/identity/protocols/oauth2/native-app
- https://developers.google.com/workspace/drive/picker/guides/desktop-mobile-picker
- https://developers.google.com/workspace/gmail/api/auth/scopes
- https://developers.google.com/identity/protocols/oauth2/production-readiness/restricted-scope-verification
