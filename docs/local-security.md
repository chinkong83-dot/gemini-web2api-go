# Local Google-account use

This fork defaults to a dedicated Chrome session for both Google login and Gemini requests. Google Cookie values are not imported into the Go Cookie pool or SQL database. The local API remains `/v1/chat/completions` and `/v1/responses`.

## Desktop startup and visibility

Install Google Chrome, then build and start this fork:

```sh
go build -o gemini-web2api-go .
ADMIN_TOKEN='<private admin token>' ./gemini-web2api-go

# Keep Chrome visible after login.
GEMINI_SHOW_BROWSER=1 ADMIN_TOKEN='<private admin token>' ./gemini-web2api-go

# Hide Chrome after login (also the default when unset).
GEMINI_SHOW_BROWSER=0 ADMIN_TOKEN='<private admin token>' ./gemini-web2api-go
```

If the dedicated profile is not signed in, Chrome opens visibly for you to complete Google/company SSO. Login checks require the account control, editable Gemini input and signed-in page token. With the default setting, Chrome then restarts headless using the same profile. Change the visibility environment variable by restarting the service.

First use normally needs one SSO login because this is a new profile. Subsequent starts reuse it until Google/company policy requires authentication again. Regular Chrome and Python proxy profiles are not copied or reused.

The profile is in your OS user-config directory under `gemini-web2api-go/chrome-profile`. `--browser-profile` can specify another dedicated empty directory; unrelated nonempty profiles are rejected. `--chrome-path` specifies the installed Chrome executable if needed. The profile directory uses `0700` and contains sensitive browser state; do not commit/upload it or unprotected backups.

Open `http://127.0.0.1:8083/admin/` with the admin token. **Google login** shows readiness and visibility, and has a check/reopen login button. Requests fail while login is unavailable. The local API key in Settings authenticates API clients; it is not a Google API key.

## OpenCode

OpenCode supports this service through its OpenAI-compatible Chat Completions provider. See [OpenCode's custom-provider documentation](https://opencode.ai/docs/providers/#custom-provider).

Set `GEMINI_PROXY_API_KEY` to the local API key from Settings, then run from this repository:

```sh
export GEMINI_PROXY_API_KEY='<local proxy API key>'
OPENCODE_CONFIG=./examples/opencode.json opencode
```

[examples/opencode.json](../examples/opencode.json) uses provider ID `gemini-go-browser`, package `@ai-sdk/openai-compatible`, and base URL `http://127.0.0.1:8083/v1`. It includes Pro/Flash entries and a conservative context limit; actual model availability depends on the Google account. Change the port if needed. You may instead merge that provider into your own config or store its key via OpenCode `/connect`.

The example does not modify your existing OpenCode setup automatically. Function calling remains the upstream proxy's prompt/fence-based implementation, not Google's official structured tool API. Long agent sessions are still subject to the web protocol's prompt-byte limits.

## Credential and data boundaries

- Prompts, tool results and attachments go to Google Gemini. Input secrets are not automatically redacted: passwords/keys included in client inputs are part of that conversation.
- Chrome handles native Cookie scope and session renewal. Google authorization derived from SAPISID is calculated inside the Gemini page. Client API keys and manually supplied Cookie/Authorization/Origin/Referer headers are removed before building the browser request script.
- Business destinations require explicit Google HTTPS hosts. Gemini requests stay on `gemini.google.com`; upload/RPC hosts are `gemini.google.com`, `push.clients6.google.com`, `content-push.googleapis.com`; media hosts are `lh3.googleusercontent.com`, `work.fife.usercontent.google.com`, `contribution.usercontent.google.com`. Request interception checks each redirect before sending it, including POST redirects. HTTP, userinfo, non-default ports, out-of-scope hosts and more than six hops fail closed. Human SSO navigation works normally in Chrome, including your company's identity provider.
- No unrelated browser profile is inspected. Login checks inspect account/editor controls and the page token, not password fields. Browser protocol debug logging is disabled, and Set-Cookie headers are not returned by the adapter.
- Input images/videos require inline `data:` URLs; external, localhost and internal image URLs are not fetched.
- Browser mode requires login, never falls back to the legacy HTTP/Cookie pool, and disables legacy Cookie refresh. Cookie-file and legacy proxy settings are rejected. The old Cookie/proxy UI is inactive; Chrome uses its own network settings.
- Workspace tenant/email and enterprise data-protection policy are not independently verified. Use the account your company has approved for Gemini.
- Local SQLite contains proxy API keys, admin sessions and request metadata. New directories use `0700`; DB/WAL/SHM use `0600`. `SQL_DSN` is rejected. Existing legacy Cookie rows are preserved, not migrated into Chrome or deleted automatically. Permissions do not protect against other programs running as your OS user.
- Browser requests are serialized so stream/redirect events cannot mix between callers; queue time shares the request timeout. Browser responses are capped at 128 MiB. Large client request bodies still lack a complete process-wide memory budget.
- Token counting is local. The tokenizer may download a public encoding file from OpenAI's Azure blob storage; it does not upload prompts for counting.

## Legacy HTTP and Docker

`--browser=false` explicitly selects the previous Cookie-based HTTP mode, retaining the Google-host restrictions and login requirement. It requires manual Cookie import and is not the desktop SSO flow.

The minimal Docker image has no desktop Chrome, so its CMD explicitly uses `--browser=false`. Build it from this fork, set a private `ADMIN_TOKEN`, and import a Cookie in its local panel. Native desktop mode is the supported path for SSO and the visibility toggle; interactive Chrome in Docker is not included.

## Verification and remaining limits

```sh
go test ./...
go test -race ./...
# Installed Chrome, fresh temporary profile, fake HTTPS endpoints only:
GW2A_BROWSER_TESTS=1 go test -run 'TestChrome|TestBrowser' ./internal/app
# Installed OpenCode, isolated config/data, fake local API only:
GW2A_OPENCODE_TESTS=1 go test -run TestOpenCodeCLIUsesBrowserProxyAPI ./internal/app
```

Tests cover native Cookie scoping, in-page authorization, incremental streaming, binary media/cross-origin uploads, blocked POST redirects, profile persistence, default login-then-hide/always-visible modes, API compatibility, and no fallback to legacy credentials.

They do not perform real company SSO or verify live Gemini model/media availability. Google UI/protocol changes can cause login detection or generation failures; inspect the changed UI/endpoint instead of widening host rules. Error records may contain truncated upstream text. These tests do not comprehensively certify all transitive dependencies or future upstream updates.
