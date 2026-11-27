# `raksa` Layer 7 Technical Architecture

## Design Goals

1. **Clusterless Orchestration**: Coordinate all 6 shipped defensive tools (`raksa-netguard`, `raksa-hostguard`, `raksa-webshield`, `raksa-pipeguard`, `raksa-iocscan`, `raksa-siem`) from one static Go binary without requiring background databases or external brokers.
2. **Hybrid Mode Execution**:
   - *Unified*: `raksa scan --profile full` aggregates Layer 1-5 findings, correlates them through Layer 6 `raksa-siem correlate`, computes global `0-100 (A+..F)` posture, and updates the SHA-256 hash-chained `runs.ndjson` ledger.
   - *Modular*: `--profile repo|host|web|incident` or `--layers ...` isolates individual layers without wasting runtime.
   - *Graceful*: Uninstalled binaries produce structured `not_installed` layer status records with exact install guidance.
3. **Unified Surface Parity (`v0.3.0`)**: The same orchestration primitives drive the CLI (`cmd/raksa`), interactive terminal workbench (`raksa tui`), embedded 3-panel Web Workbench (`raksa ui`), Tauri v2 Desktop App (`desktop/`), read-only AI Defense Assistant (`internal/assistant`), GitHub Action (`action/action.yml`), and 61-tool stdio MCP Hub (`internal/mcphub`).

## Package & Component Responsibilities

| Component | Responsibility |
| :--- | :--- |
| `internal/schema` | Raksa Finding Schema v1 models, Layer 1-6 catalog metadata (`152` rules, `53` MCP tools), posture calculator (`0-100`), and Attack-vs-Defense matrix. |
| `internal/ext` | Open-Core interface boundaries (`AuthProvider`, `ComplianceMapper`, `EditionMetadata`) enabling build-tag enterprise extensions. |
| `internal/policy` | `.raksa.yml` config parsing, strict validation, fail-closed waivers (`reason` + `expires_on`), and deterministic SHA-256 baselines. |
| `internal/store` | Pure-Go append-only SHA-256 hash-chained scan ledger (`runs.ndjson`) with `VerifyChain` tamper detection. |
| `internal/aggregator` | Schema v1 JSON / NDJSON report parser, canonical cross-layer deduplication, and `SuiteReport` merger. |
| `internal/runner` | Binary discovery, `doctor` SHA-256 probing, bounded concurrent L1-L5 runner, L6 `correlate` chaining, and SHA-256 verified archive installer. |
| `internal/playbook` | Declarative YAML playbook validator/loader backed by embedded `playbooks/*.yml`. |
| `internal/remediate` | Read-only unified diff collector wrapping `hostguard fix-preview`, `pipeguard fix-preview`, and `webshield generate-policy`. |
| `internal/bridge` | HTTP client connecting `raksa` to `raksa-siem` REST APIs (`/healthz`, `/api/v1/ingest`, `/api/v1/posture`, `/api/v1/ledger/verify`). |
| `internal/mcphub` | Newline-delimited JSON-RPC 2.0 server hosting 8 local tools and proxying 53 upstream L1-L6 tools. |
| `internal/assistant` | Read-only BYOK AI Defense Assistant supporting Offline Deterministic, Local Ollama, and external API adapters with grounded Tool Call Cards. |
| `internal/tui` | Zero-dependency interactive terminal workbench (`raksa tui`) for headless/SSH workflows. |
| `internal/report` | Table, JSON, merged SARIF 2.1.0, Markdown PR summary, and offline HTML/SVG executive reporters. |
| `internal/webui` | Embedded zero-dependency HTML/CSS/vanilla-JS assets powering the 3-panel Hybrid Web Workbench (`go:embed`). |
| `internal/server` | Hardened HTTP + SSE telemetry server enforcing strict CSP, `HttpOnly; SameSite=Strict` cookies, token auth, and anti-CSRF checks. |
| `desktop/src-tauri` | Pure-Rust (`#![forbid(unsafe_code)]`) Tauri v2 desktop wrapper spawning `raksa ui` on an isolated loopback port with a per-session token. |

## Next Milestone Preview (`v0.4.0` -> `v1.0.0`)

- **`v0.4.0` Defensive Gap Closure (L1-L7 Sync)**: Synchronized upgrades adding DDoS/flood readiness playbooks, read-only DNS/email (`SPF`/`DKIM`/`DMARC`/`DNSSEC`) posture checks, and cross-framework compliance crosswalks alongside Layer 1-4 `v0.4.0` releases.
- **`v1.0.0` Enterprise Contract Freeze**: API/Schema/MCP/Extension ABI freeze, Cosign/SLSA signatures, CycloneDX/SPDX SBOMs, and 24h endurance soak benchmarks.
