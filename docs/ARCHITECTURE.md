# `raksa` Layer 7 Technical Architecture

## Design Goals

1. **Clusterless Orchestration**: Coordinate all 6 shipped defensive tools (`raksa-netguard`, `raksa-hostguard`, `raksa-webshield`, `raksa-pipeguard`, `raksa-iocscan`, `raksa-siem`) from one static Go binary without requiring background databases or external brokers.
2. **Hybrid Mode Execution**:
   - *Unified*: `raksa scan --profile full` aggregates Layer 1-5 findings, correlates them through Layer 6 `raksa-siem correlate`, computes global `0-100 (A+..F)` posture, and updates the SHA-256 hash-chained `runs.ndjson` ledger.
   - *Modular*: `--profile repo|host|web|incident` or `--layers ...` isolates individual layers without wasting runtime.
   - *Graceful*: Uninstalled binaries produce structured `not_installed` layer status records with exact install guidance.
3. **Single Federated Control Plane for Humans & Agents**: The same orchestration primitives drive the CLI (`cmd/raksa`), GitHub Action (`action/action.yml`), and the 61-tool stdio MCP Hub (`internal/mcphub`).

## Package Responsibilities

| Package | Responsibility |
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
| `internal/report` | Table, JSON, merged SARIF 2.1.0, Markdown PR summary, and offline HTML/SVG executive reporters. |

## Roadmap Preview (`v0.2.0` -> `v0.3.0`)

- **`v0.2.0` Web Workbench (`raksa ui`)**: Serves an embedded React + TypeScript 3-panel Hybrid workbench over `http://127.0.0.1` (`//go:embed`) backed by local SQLite WAL history and live SSE streaming.
- **`v0.3.0` Desktop App (`Tauri v2`) & BYOK AI Assistant**: Wraps the same frontend + `raksa` Go sidecar into native `.msi`/`.dmg`/`.AppImage` installers alongside a read-only BYOK AI Defense Assistant wired to the 61 MCP tools.
