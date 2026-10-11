# Local Google-account use

This fork defaults to local use with an imported Google login session. It does not implement Google SSO or OAuth: sign in to Gemini in your browser, then manually import that account's Cookie through your local admin panel. Never commit cookies, admin tokens, API keys, config files containing secrets, or the runtime database.

## Start from this fork

```sh
go build -o gemini-web2api-go .
ADMIN_TOKEN='<your private admin token>' ./gemini-web2api-go
```

Open `http://127.0.0.1:8083/admin/`, sign in with your admin token, and add the intended Google account in the Cookie pool. The API key shown in Settings authenticates clients to this local service; it is not a Google API key. Use a Google account that your company has approved for Gemini and import only that account.

For Docker, build this fork instead of pulling an upstream image:

```sh
ADMIN_TOKEN='<your private admin token>' docker compose up -d --build
```

The container listens on `0.0.0.0` internally; Compose publishes only `127.0.0.1:8083` on the host. Native runs default to `127.0.0.1`. Admin access always requires a token when the panel is enabled. URL query tokens are not accepted.

## Data and credential destinations

- Conversation prompts, tool results and attachments are sent to Google Gemini. Anything a client includes in those inputs, including pasted passwords or keys, is part of that conversation; this fork does not attempt to guess or redact arbitrary secrets inside user input.
- Google session Cookie and derived Google authorization are sent only to explicit Google HTTPS endpoints. Media hosts: `lh3.googleusercontent.com`, `work.fife.usercontent.google.com`, `contribution.usercontent.google.com`. Upload/RPC hosts: `gemini.google.com`, `push.clients6.google.com`, `content-push.googleapis.com`. Session refresh host: `accounts.google.com`. Each media redirect is checked before sending another request. Userinfo, HTTP and non-default ports are rejected.
- Unknown media/upload hosts fail with an error. If Google changes its download or upload domains, verify the new Google endpoint before changing the allowlist; do not allow arbitrary suffixes or substring matches.
- Input images and videos must use inline `data:` URLs. The service does not fetch client-supplied external, localhost or internal URLs.
- `require_login` defaults to `true` and is a startup setting. An empty/disabled Cookie pool, an anonymous cached conversation, or an unusable login session fails before sending the conversation anonymously. Runtime `anon_first` and `fallback_anon` cannot override it. Setting `require_login: false` in config deliberately restores upstream anonymous behavior; do not do this for company inputs.
- Login is required, but Workspace tenant/email and enterprise data-protection policy are not independently verified by the proxy. Those depend on the account you import and your Google Workspace setup.
- Google Cookie and this service's API/session keys remain in the local SQLite database as usable values. New storage directories use `0700`; the database and existing WAL/SHM files use `0600`. Protect your Cookie export and any backups in the same way. This is file access protection, not database encryption, and it does not protect against programs running as your own OS user. `SQL_DSN` is rejected at startup to avoid sending credentials to a remote database.
- Optional explicitly configured network proxies remain supported. Google connections retain TLS certificate verification; only use proxies and trust roots you control or trust.
- Token counting is local. The tokenizer may initially download a public encoding file from OpenAI's Azure blob storage; it does not upload the prompt for token counting.

## Verification

Run `go test ./...` and `go test -race ./...`. Security tests use fake credentials and in-memory HTTP transports. They verify that attacker URLs and unsafe redirects never reach the transport, accepted Google media redirects still work, remote input URLs are rejected, anonymous routes are blocked when login is required, admin authentication fails closed, and SQLite permissions are restricted.

These tests do not log in to a company account or verify live Google media/SSO compatibility. The existing live upload probe is opt-in via `GW2A_UPLOAD_PROBE`; leave it unset for offline tests.

## Remaining notes

- Error records can include truncated upstream error text. Do not treat them as guaranteed free of all input content. Restrict access to logs and backups.
- Request bodies and downloaded media still lack a complete process-wide memory budget. Normal single-user traffic has not been identified as a problem; exposing the service to untrusted/shared clients would need additional limits.
- The patches address the reviewed credential-routing and local-use risks. They do not certify every transitive dependency or future upstream update.
