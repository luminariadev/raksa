# Defensive Threat Model (`raksa` Layer 7)

## Trust Boundaries

1. **Tool Discovery & Execution (`internal/runner`)**: Invokes known Raksa binary names directly via `exec.CommandContext` without invoking a system shell (`/bin/sh -c` or `cmd.exe /c`). Timeouts and concurrency limits prevent runaway child processes.
2. **Binary Supply Chain (`raksa install`, `scripts/install.*`)**: Never executes unverified remote scripts via piped shell downloads. Every archive download is first hashed with SHA-256 and matched against the corresponding release `SHA256SUMS.txt` or `checksums-sha256.txt` before extraction.
3. **Report Parsing & HTML Output (`internal/aggregator`, `internal/report`)**: Untrusted upstream strings are parsed with strict JSON decoding (`4 MiB` per-line scanner limits) and rendered in HTML via Go `html/template` contextual auto-escaping (`<script>` payloads cannot execute). Table outputs strip ANSI control characters.
4. **Embedded Web Workbench (`internal/server`, `internal/webui`)**:
   - Serves zero third-party CDNs, zero inline `<script>`, and zero inline `style=""` attributes under strict `Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'; object-src 'none'; frame-ancestors 'none'`.
   - Enforces `HttpOnly; SameSite=Strict` session cookies exchanged via constant-time token validation (`crypto/subtle`) and blocks cross-origin `POST` requests using `Origin` and `Sec-Fetch-Site` anti-CSRF checks.
   - Uses `textContent` / SVG DOM APIs across `app.js` so untrusted finding strings cannot inject DOM HTML.
5. **AI Defense Assistant (`internal/assistant`)**:
   - Strictly read-only: grounds responses using read-only checks and never writes config patches or executes remediation automatically.
   - Validates `http://` / `https://` scheme on Ollama/BYOK endpoints, caps HTTP response reads to `2 MiB`, and reads bearer credentials exclusively from `RAKSA_AI_API_KEY` (never persisted on disk or returned in responses).
6. **Desktop Sidecar (`desktop/src-tauri`)**:
   - Enforces `#![forbid(unsafe_code)]`, binds strictly to loopback (`127.0.0.1` ephemeral port), passes a fresh per-process session token via `RAKSA_DESKTOP_TOKEN` environment variable rather than CLI flags, and cleans up the child server on exit.
7. **SIEM Bridge (`internal/bridge`)**: Validates explicit `http://` or `https://` URLs, bounds response reads to `4 MiB`, enforces request timeouts, and reads bearer tokens solely from environment variables (`token_env`) rather than plaintext config keys.
8. **History Ledger (`internal/store`)**: Every run entry records `prev_hash` and `entry_hash` (`SHA-256`) so unauthorized edits to historical posture metrics fail `raksa posture --verify`.
9. **Non-Destructive Defaults (`internal/remediate`, `internal/mcphub`, `POST /api/v1/waivers`)**: Remediation previews produce unified diffs only; fail-closed waivers enforce explicit `reason` and `YYYY-MM-DD expires_on` before persisting `.raksa.yml`.
