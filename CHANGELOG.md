# Changelog

All notable changes to `raksa` (Layer 7 Hybrid Orchestrator) will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-11-27

### Added
- **Hybrid Multi-Layer Runner (`internal/runner`)**: Concurrent execution across Layers 1-6 with bounded workers, per-layer timeouts, profile presets (`full`, `repo`, `host`, `web`, `incident`), explicit `--layers` selection, automatic L1-L5 -> L6 `raksa-siem correlate` chaining, graceful `not_installed` degradation, `doctor` SHA-256 verification, and `install` (`--dry-run` + checksum validation).
- **Schema v1 Aggregator & Governance (`internal/aggregator`, `internal/policy`)**: Cross-layer finding normalization and canonical deduplication, `0-100 (A+..F)` posture scoring, `.raksa.yml` auto-discovery, fail-closed waivers (`reason` + `expires_on`), and deterministic SHA-256 baselines.
- **Tamper-Evident Run Ledger (`internal/store`)**: Pure-Go SHA-256 hash-chained `runs.ndjson` history tracking with `raksa posture --verify`.
- **Declarative Playbooks & Attack-vs-Defense Matrix (`internal/playbook`, `playbooks/`)**: 5 curated YAML playbooks (`pre-release-gate`, `host-hardening-audit`, `web-edge-defense`, `incident-triage`, `ddos-readiness`) and a 16-row defensive coverage matrix mapped to MITRE ATT&CK and D3FEND.
- **Read-Only Fix Workbench & SIEM Bridge (`internal/remediate`, `internal/bridge`)**: Aggregates unified diffs from `hostguard`, `pipeguard`, and `webshield`, and integrates with `raksa-siem` REST APIs (`/healthz`, `/api/v1/ingest`, `/api/v1/posture`, `/api/v1/ledger/verify`).
- **Federated 61-Tool MCP Hub (`internal/mcphub`)**: Single stdio JSON-RPC 2.0 server exposing 8 Layer 7 meta-tools and proxying all 53 upstream Layer 1-6 MCP tools.
- **Reporters & Open-Core ABI (`internal/report`, `internal/ext`)**: Table, Schema v1 JSON, merged SARIF 2.1.0, Markdown PR summaries, standalone offline dark-mode HTML executive reports, and clean Open-Core interfaces under Apache-2.0.
- **CI/CD, Deployment & Distribution**: Multi-stage non-root distroless `Dockerfile` with `HEALTHCHECK`, hardened `deploy/docker-compose.yml`, SHA-256 verified install scripts (`scripts/install.sh`, `scripts/install.ps1`), reusable GitHub Action (`action/action.yml`), Agent Skill (`skills/raksa-defense-workbench/SKILL.md`), and GitHub Actions CI + 6-platform Release workflows.
