# Changelog

All notable changes to `raksa` (Layer 7 Hybrid Orchestrator & Workbench) will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.1] - 2026-11-27

### Added
- **Apple Liquid Glass Rounded Theme (`internal/webui/assets/{index.html,styles.css,app.js}`)**:
  - Floating translucent frosted-glass panels (`backdrop-filter: blur(28px) saturate(185%)`), ambient aurora radial backdrop, specular hairline highlights, squircle rounded cards, macOS traffic dots, Apple Segmented Controls, toast notifications, and instant **Dark Glass / Light Glass** toggle (`localStorage` persisted) with zero external CDNs or inline script/style attributes.
- **Progressive Disclosure (`Simple` Mode Default + 1-Click `Pro` Mode + Built-In User Guide)**:
  - **Simple Mode**: Calm 2-panel layout featuring Health Score, 1-click Quick Checks (*Check Code & Secrets*, *Check Website Security*, *Check Computer / Server*), prioritized *Issues & Fixes* cards with plain urgency labels (*Urgent*, *Important*, *Moderate*, *Low*), green recommended fix callouts, collapsible technical details, and a clean *Ask Raksa* chat pane.
  - **Pro Mode**: Instant 1-click toggle back to the full 3-panel L1-L7 workbench (Hybrid layer checkboxes, YAML Playbooks, Attack-vs-Defense Matrix, Diff Workbench, SIEM Ledger, and 61 MCP tools).
  - **User Guide (`view-guide`)**: Step-by-step Quick Start, Simple vs Pro comparison, Urgency glossary, and 6-layer plain-English overview reachable from both modes.
- **Simplified Rounded Unicode + TrueColor TUI (`internal/tui`, `cmd/raksa`)**:
  - Defaults to a beginner-friendly 6-item **Simple Quick Menu** (`Scan Project Now`, `Issues & Fixes`, `Ask Assistant`, `Quick Guide`, `Pro Mode`, `Quit`) with rounded Unicode cards (`╭─╮` / `╰─╯`), posture progress bar, glass-friendly foreground-only TrueColor ANSI palette, wrapped `/verify` box framing, and `--no-color` / `--color` CLI flags.

## [0.3.0] - 2026-11-27

### Added
- **Read-Only BYOK AI Defense Assistant (`internal/assistant`, `/api/v1/assistant/*`, Right Panel tab)**:
  - Zero-key **Offline Deterministic** mode grounding prioritized findings, Attack-vs-Defense gaps, SHA-256 history ledger checks, and read-only `fix-preview` plans.
  - **Local Ollama** (`http://localhost:11434` / `RAKSA_OLLAMA_URL`) and external standard **BYOK** chat endpoint adapter (`RAKSA_AI_ENDPOINT` + `RAKSA_AI_API_KEY` read solely from environment variables and never exposed in API payloads).
  - Embedded Web UI renders transparent **Tool Call Cards**, citation badges, 4 quick-prompt chips, and a `Ctrl+K` Command Palette action cleanly under strict `Content-Security-Policy`.
- **Interactive Terminal Workbench (`raksa tui`, `internal/tui`)**: Zero-dependency Blue Team menu and slash-command shell (`/scan`, `/layers`, `/playbook`, `/doctor`, `/matrix`, `/fix`, `/verify`, `/ask`, `/ui`, `/quit`) designed for SSH and headless servers.
- **Pure-Rust Tauri v2 Desktop App (`desktop/`)**: `#![forbid(unsafe_code)]` sidecar lifecycle manager (`desktop/src-tauri/src/sidecar.rs` + `main.rs`) allocating an ephemeral loopback port, generating a per-session token (`RAKSA_DESKTOP_TOKEN`), and wrapping `raksa ui` in a native OS window.
- **Visual Verification & Hero Showcase (`docs/images/raksa-workbench.png`)**: Added live-captured 1440x900 3-panel Web Workbench + AI Assistant hero image to `README.md` alongside full `v0.3.0` ecosystem parity across Layers 1-7.

## [0.2.0] - 2026-11-27

### Added
- **Embedded 3-Panel Hybrid Web Workbench (`internal/webui`, `raksa ui` / `serve`)**: Zero-external-dependency vanilla HTML/CSS/JS SPA compiled directly into the static Go binary via `go:embed`, featuring:
  - Top Command Bar with target/profile controls, global posture gauge pill, and `Ctrl+K` Command Palette.
  - Left Hybrid Explorer with L1-L6 status tree, selective multi-layer checkboxes, single-layer scan actions, and 1-click YAML Playbook execution.
  - Center multi-tab workspace covering Posture Overview (SVG gauge + `runs.ndjson` sparkline), Findings Explorer (search/filters, raw evidence drawer, fail-closed `.raksa.yml` waiver modal, SARIF/HTML/JSON/Markdown exports), Attack-vs-Defense Matrix, Read-Only Fix Workbench, and SIEM Bridge & SHA-256 Ledger Verifier.
  - Collapsible Right Panel with live Server-Sent Events (`/api/v1/events`) telemetry stream and searchable 61-tool MCP Hub directory.
- **Hardened Workbench HTTP/SSE Server (`internal/server`)**: Enforces strict `Content-Security-Policy` (`default-src 'self'; script-src 'self'`), HSTS, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy`, `Permissions-Policy`, COOP/CORP headers, `HttpOnly; SameSite=Strict` token-to-cookie session bootstrap, and same-origin anti-CSRF protection on mutating endpoints.
- **Release & CI Workflow Hardening**: Added `workflow_dispatch` tag input + validation to `.github/workflows/release.yml`, Node 24 JS action runtime enforcement (`FORCE_JAVASCRIPT_ACTIONS_TO_NODE24: true`), updated GitHub Actions pins, added live `raksa ui` CSP + API smoke tests to `ci.yml`, and exposed port `8787` in `Dockerfile` and `deploy/docker-compose.yml`.

## [0.1.0] - 2026-11-27

### Added
- **Hybrid Multi-Layer Runner (`internal/runner`)**: Concurrent execution across Layers 1-6 with bounded workers, per-layer timeouts, profile presets (`full`, `repo`, `host`, `web`, `incident`), explicit `--layers` selection, automatic L1-L5 -> L6 `raksa-siem correlate` chaining, graceful `not_installed` degradation, `doctor` SHA-256 verification, and `install` (`--dry-run` + checksum validation).
- **Schema v1 Aggregator & Governance (`internal/aggregator`, `internal/policy`)**: Cross-layer finding normalization and canonical deduplication, `0-100 (A+..F)` posture scoring, `.raksa.yml` auto-discovery, fail-closed waivers (`reason` + `expires_on`), and deterministic SHA-256 baselines.
- **Tamper-Evident Run Ledger (`internal/store`)**: Pure-Go SHA-256 hash-chained `runs.ndjson` history tracking with `raksa posture --verify`.
- **Declarative Playbooks & Attack-vs-Defense Matrix (`internal/playbook`, `playbooks/`)**: 5 curated YAML playbooks (`pre-release-gate`, `host-hardening-audit`, `web-edge-defense`, `incident-triage`, `ddos-readiness`) and a 16-row defensive coverage matrix mapped to MITRE ATT&CK and D3FEND.
- **Read-Only Fix Workbench & SIEM Bridge (`internal/remediate`, `internal/bridge`)**: Aggregates unified diffs from `hostguard`, `pipeguard`, and `webshield`, and integrates with `raksa-siem` REST APIs (`/healthz`, `/api/v1/ingest`, `/api/v1/posture`, `/api/v1/ledger/verify`).
- **Federated 61-Tool MCP Hub (`internal/mcphub`)**: Single stdio JSON-RPC 2.0 server exposing 8 Layer 7 meta-tools and proxying all 53 upstream Layer 1-6 MCP tools.
- **Reporters & Open-Core ABI (`internal/report`, `internal/ext`)**: Table, Schema v1 JSON, merged SARIF 2.1.0, Markdown PR summaries, standalone offline HTML/SVG executive reports, and clean Open-Core interfaces under Apache-2.0.
- **CI/CD, Deployment & Distribution**: Multi-stage non-root distroless `Dockerfile` with `HEALTHCHECK`, hardened `deploy/docker-compose.yml`, SHA-256 verified install scripts (`scripts/install.sh`, `scripts/install.ps1`), reusable GitHub Action (`action/action.yml`), Agent Skill (`skills/raksa-defense-workbench/SKILL.md`), and GitHub Actions CI + 6-platform Release workflows.
