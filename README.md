<div align="center">

# raksa

### Hybrid Defense-in-Depth Workbench & Blue Team Orchestrator (Layer 7)

Unifying network, host, web, DevSecOps, IoC/malware, and SIEM defenses (**152 built-in rules | 61 MCP tools | Embedded Web UI | Tauri v2 Desktop | BYOK AI Assistant**) into one deterministic control plane.

[![CI](https://github.com/luminariadev/raksa/actions/workflows/ci.yml/badge.svg)](https://github.com/luminariadev/raksa/actions/workflows/ci.yml)
[![Release](https://github.com/luminariadev/raksa/actions/workflows/release.yml/badge.svg)](https://github.com/luminariadev/raksa/actions/workflows/release.yml)
[![Release Tag](https://img.shields.io/github/v/release/luminariadev/raksa)](https://github.com/luminariadev/raksa/releases)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Go Version](https://img.shields.io/badge/go-1.24%2B-00ADD8.svg)](go.mod)
[![MCP Tools](https://img.shields.io/badge/MCP-61%20tools-6f42c1.svg)](docs/ARCHITECTURE.md)
[![Web UI](https://img.shields.io/badge/Web%20UI-embedded%203--panel-0ea5e9.svg)](docs/ARCHITECTURE.md)
[![Desktop](https://img.shields.io/badge/Desktop-Tauri%20v2-1f6feb.svg)](desktop/README.md)
[![SARIF](https://img.shields.io/badge/SARIF-2.1.0-orange.svg)](docs/ARCHITECTURE.md)

</div>

<p align="center">
  <img src="docs/images/raksa-workbench.png" alt="Raksa 3-Panel Hybrid Defense Workbench" width="960">
</p>

---

**`raksa`** (from Sundanese/Sanskrit *raksa*, meaning to guard or protect) is the Layer 7 flagship umbrella orchestrator and workbench of the Raksa Security Suite. In **`v0.3.0`**, it reaches full ecosystem version parity with Layers 1-6, uniting a **clusterless Go CLI & TUI** with a **3-panel Hybrid Web Workbench (`raksa ui`)**, a **read-only BYOK AI Defense Assistant**, and a **pure-Rust `Tauri v2` Desktop App (`desktop/`)**.

## Why `raksa` Stands Out

- **Hybrid 3-Panel Workbench (`raksa ui` & `Tauri v2` Desktop)**: Run a single `Full Audit (L1-L6)` or drill down via per-layer sidebar checkboxes, individual layer scans, YAML playbooks, `Ctrl+K` Command Palette, Attack-vs-Defense Matrix, Read-Only Diff Viewer, and live SSE telemetry.
- **Read-Only BYOK AI Defense Assistant (`internal/assistant`)**: Ships with an **Offline Deterministic** mode (zero API keys required), **Local Ollama** (`http://localhost:11434`), and standard external **BYOK** endpoint adapters (`RAKSA_AI_ENDPOINT` + `RAKSA_AI_API_KEY`). Every reply cites verified Tool Call Cards and never auto-mutates files.
- **Interactive Terminal Workbench (`raksa tui`)**: Zero-dependency keyboard/slash-command Blue Team shell for headless Linux hosts and SSH sessions.
- **Zero-Cluster Core & Hash-Chained Ledger**: No mandatory OpenSearch, PostgreSQL, or Docker daemon to scan and correlate. Run history is stored locally in tamper-evident `runs.ndjson`.
- **Hardened Web & Desktop Security (`100/100 A+`)**: Enforces strict CSP (`default-src 'self'; script-src 'self'`), HSTS, `X-Frame-Options: DENY`, `HttpOnly; SameSite=Strict` token-to-cookie sessions, anti-CSRF checks, and a `#![forbid(unsafe_code)]` Rust desktop sidecar.
- **Federated 61-Tool MCP Hub**: One `raksa mcp` server exposes **8 orchestrator meta-tools** plus **53 specialized Layer 1-6 tools**.

---

## Hybrid Architecture

```mermaid
flowchart TB
    Desktop["Tauri v2 Native Desktop Shell (desktop/)"] --> Server["Hardened REST + SSE Server (internal/server)"]
    WebUI["Embedded 3-Panel Web Workbench (raksa ui)"] --> Server
    TUI["Interactive Terminal Workbench (raksa tui)"] --> Core["raksa Control Plane (Static Go Binary)"]
    CLI["raksa CLI / GHA / Agent Skills"] --> Core
    Assistant["Read-Only AI Assistant (Local / Ollama / BYOK)"] --> Core
    MCP["Coding Agents / Local MCP Clients"] --> MCPHub["Unified MCP Hub (61 Tools)"]
    Server --> Assistant
    Server --> Core
    MCPHub --> Core
    Core --> Runner["Hybrid Parallel Runner & SHA-256 Installer"]
    Core --> Agg["Schema v1 Merger, Dedup & 0-100 Posture"]
    Core --> Store["Hash-Chained runs.ndjson"]
    Core --> SIEMBridge["SIEM HTTP & Correlate Bridge"]
    Runner --> L1["L1 NetGuard (10 rules)"]
    Runner --> L2["L2 HostGuard (29 rules)"]
    Runner --> L3["L3 WebShield (30 rules)"]
    Runner --> L4["L4 PipeGuard (33 rules)"]
    Runner --> L5["L5 IOCScan (27 rules)"]
    SIEMBridge --> L6["L6 SIEM (23 rules)"]
```

## Covered Defensive Ecosystem (Uniform `v0.3.0`)

| Layer | Repository | Language | Version | Rules | MCP Tools | Defensive Domain |
| :--- | :--- | :--- | :---: | ---: | ---: | :--- |
| **L1** | [raksa-netguard](https://github.com/luminariadev/raksa-netguard) | Go | `v0.3.0` | `10` | `5` | Open-port baseline auditing, vertical/horizontal/distributed scan detection |
| **L2** | [raksa-hostguard](https://github.com/luminariadev/raksa-hostguard) | Rust | `v0.3.0` | `29` | `9` | HMAC-signed event-driven FIM, Linux/SSH/systemd/Docker CIS & `fix-preview` |
| **L3** | [raksa-webshield](https://github.com/luminariadev/raksa-webshield) | Go + TS | `v0.3.0` | `30` | `8` | HTTP headers, CSP/CORS/TLS audit, Nginx/Caddy/Ingress lint, semantic WAF sidecar |
| **L4** | [raksa-pipeguard](https://github.com/luminariadev/raksa-pipeguard) | Go | `v0.3.0` | `33` | `9` | Secrets, CycloneDX/SPDX SBOM, OSV/KEV/EPSS CVEs, OCI image scan, IaC & CI |
| **L5** | [raksa-iocscan](https://github.com/luminariadev/raksa-iocscan) | Python | `v0.3.0` | `27` | `10` | Pure-Python YARA engine, Imphash/FastCDC, PE/ELF/Mach-O, document & archive triage |
| **L6** | [raksa-siem](https://github.com/luminariadev/raksa-siem) | Go + Py | `v0.3.0` | `23` | `12` | 13-format log normalizer, Sigma/EQL correlator, attack graph, hash-chained ledger |
| **L7** | **`raksa`** (This Repo) | Go + Rust | **`v0.3.0`** | - | `+8` | Hybrid orchestrator, Web Workbench, AI Defense Assistant, TUI, Desktop App |

---

## 30-Second Quickstart

### Build or Launch Workbench (Web, TUI, Desktop)

```bash
# Build raksa from source (Go 1.24+)
go build -trimpath -o raksa ./cmd/raksa

# Launch embedded 3-panel Web Workbench + AI Defense Assistant
./raksa ui --path .

# Or preview offline with included multi-layer fixtures
./raksa ui --from-reports ./testdata

# Launch interactive terminal workbench for SSH / headless Linux hosts
./raksa tui --path .
```

For native Windows/macOS/Linux desktop builds, see [desktop/README.md](desktop/README.md).

### Hybrid CLI Scans & Executive Reporting

```bash
# Inspect installed tools, versions, and SHA-256 digests
raksa doctor

# Preview download URLs & SHA-256 checksums for Layer 1-6 tools
raksa install --dry-run

# Run Hybrid repository/DevSecOps profile across installed layers
raksa scan --path . --profile repo --format table --fail-on high

# Selective modular run on specific layers (graceful if others are absent)
raksa scan --path . --layers pipeguard,hostguard,siem --format sarif --output suite.sarif

# Aggregate upstream Schema v1 reports offline and generate standalone HTML report
raksa scan --from-reports ./testdata --format html --fail-on none --output suite.html

# Inspect tamper-evident run ledger & verify SHA-256 continuity
raksa posture --verify

# Preview read-only hardening diffs aggregated from L2/L3/L4
raksa fix-preview --path . --format diff

# Inspect built-in YAML playbooks and Attack-vs-Defense matrix
raksa playbooks list
raksa attack-matrix
```

---

## Federated 61-Tool MCP Server

Configure any stdio MCP client with:

```json
{
  "mcpServers": {
    "raksa": {
      "command": "raksa",
      "args": ["mcp"]
    }
  }
}
```

Orchestrator tools (`raksa_doctor`, `raksa_full_audit`, `raksa_posture_summary`, `raksa_correlate_all`, `raksa_defense_coverage`, `raksa_plan_remediation`, `raksa_list_playbooks`, `raksa_verify_history`) run directly in Go, while all 53 upstream `netguard_*`, `hostguard_*`, `webshield_*`, `pipeguard_*`, `iocscan_*`, and `siem_*` tools proxy cleanly to their respective `<tool> mcp` binary.

---

## GitHub Actions Usage

```yaml
- name: Run Raksa Hybrid Defense Gate
  uses: luminariadev/raksa/action@v0.3.0
  with:
    path: .
    profile: repo
    format: sarif
    fail-on: high
    output: raksa.sarif
```

## Documentation & Roadmap

- [Architecture & Hybrid Control Plane](docs/ARCHITECTURE.md)
- [Attack-vs-Defense Coverage Matrix](docs/ATTACK_VS_DEFENSE_MATRIX.md)
- [Open-Core & Enterprise Extension Model](docs/OPEN_CORE_MODEL.md)
- [Defensive Threat Model](docs/THREAT_MODEL.md)
- [Benchmarks & Verification Targets](docs/BENCHMARKS.md)
- [Desktop App Shell Guide](desktop/README.md)
- [Changelog](CHANGELOG.md) | [Security Policy](SECURITY.md) | [Contributing](CONTRIBUTING.md)
