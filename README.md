<div align="center">

# raksa

### Hybrid Defense-in-Depth Workbench & Blue Team Orchestrator (Layer 7)

Unifying network, host, web, DevSecOps, IoC/malware, and SIEM defenses (**152 built-in rules | 61 MCP tools**) into one deterministic static binary.

[![CI](https://github.com/luminariadev/raksa/actions/workflows/ci.yml/badge.svg)](https://github.com/luminariadev/raksa/actions/workflows/ci.yml)
[![Release](https://github.com/luminariadev/raksa/actions/workflows/release.yml/badge.svg)](https://github.com/luminariadev/raksa/actions/workflows/release.yml)
[![Release Tag](https://img.shields.io/github/v/release/luminariadev/raksa)](https://github.com/luminariadev/raksa/releases)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Go Version](https://img.shields.io/badge/go-1.24%2B-00ADD8.svg)](go.mod)
[![MCP Tools](https://img.shields.io/badge/MCP-61%20tools-6f42c1.svg)](docs/ARCHITECTURE.md)
[![SARIF](https://img.shields.io/badge/SARIF-2.1.0-orange.svg)](docs/ARCHITECTURE.md)

</div>

---

**`raksa`** (from Sundanese/Sanskrit *raksa*, meaning to guard or protect) is the Layer 7 flagship umbrella orchestrator of the Raksa Security Suite. It pairs a **clusterless, deterministic Go control plane** with **Hybrid orchestration** across all six independent defensive layers (`v0.3.0`), unifying findings into **Schema v1**, **SARIF 2.1.0**, **Markdown PR summaries**, **offline HTML executive reports**, and a federated **61-tool MCP Hub**.

## Why `raksa` Stands Out

- **Hybrid Orchestration (Unified + Modular)**: Run a single one-command `Full Audit` across Layers 1-6 or isolate a targeted profile (`repo`, `host`, `web`, `incident`) and specific `--layers`. Missing tools degrade cleanly to `not_installed` with exact install commands instead of breaking workflows.
- **Zero-Cluster & Offline-First Core**: No mandatory OpenSearch, PostgreSQL, Docker daemon, or LLM token burn to scan and correlate. History is persisted locally in a SHA-256 hash-chained ledger (`runs.ndjson`).
- **Federated 61-Tool MCP Hub**: One `raksa mcp` connection gives AI coding agents (Antigravity, Cursor, standard stdio MCP clients) access to **8 orchestrator meta-tools** plus **53 specialized Layer 1-6 tools**.
- **Read-Only Patch Workbench**: Aggregates deterministic unified diffs across host (`raksa-hostguard`), IaC/CI (`raksa-pipeguard`), and edge headers/proxies (`raksa-webshield`) without auto-mutating files.
- **Apache-2.0 Open-Core Architecture**: Individual and team orchestration stays 100% open source; clean `internal/ext` interfaces enable private compliance packs and fleet extensions via Go build tags.

---

## Hybrid Architecture

```mermaid
flowchart TB
    CLI["raksa CLI / GHA / Agent Skills"] --> Core["raksa Control Plane (Static Go Binary)"]
    MCP["Coding Agents / Local Assistants"] --> MCPHub["Unified MCP Hub (61 Tools)"]
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

## Covered Defensive Ecosystem (Layers 1-6)

| Layer | Repository | Language | Rules | MCP Tools | Defensive Domain |
| :--- | :--- | :--- | ---: | ---: | :--- |
| **L1** | [raksa-netguard](https://github.com/luminariadev/raksa-netguard) | Go | `10` | `5` | Open-port baseline auditing, vertical/horizontal/distributed scan detection |
| **L2** | [raksa-hostguard](https://github.com/luminariadev/raksa-hostguard) | Rust | `29` | `9` | HMAC-signed event-driven FIM, Linux/SSH/systemd/Docker CIS & `fix-preview` |
| **L3** | [raksa-webshield](https://github.com/luminariadev/raksa-webshield) | Go + TS | `30` | `8` | HTTP headers, CSP/CORS/TLS audit, Nginx/Caddy/Ingress lint, semantic WAF sidecar |
| **L4** | [raksa-pipeguard](https://github.com/luminariadev/raksa-pipeguard) | Go | `33` | `9` | Secrets, CycloneDX/SPDX SBOM, OSV/KEV/EPSS CVEs, OCI image scan, IaC & CI |
| **L5** | [raksa-iocscan](https://github.com/luminariadev/raksa-iocscan) | Python | `27` | `10` | Pure-Python YARA engine, Imphash/FastCDC, PE/ELF/Mach-O, document & archive triage |
| **L6** | [raksa-siem](https://github.com/luminariadev/raksa-siem) | Go + Py | `23` | `12` | 13-format log normalizer, Sigma/EQL correlator, attack graph, hash-chained ledger |
| **L7** | **`raksa`** (This Repo) | Go | - | `+8` | Hybrid orchestrator, posture grading, YAML playbooks, HTML/SARIF, **61-tool MCP Hub** |

---

## 30-Second Quickstart

### Build or Install Verified Binaries

```bash
# Build raksa from source (Go 1.24+)
go build -trimpath -o raksa ./cmd/raksa

# Preview download URLs & SHA-256 checksums for Layer 1-6 tools
./raksa install --dry-run

# Inspect installed tools, versions, and SHA-256 digests
./raksa doctor
```

### Hybrid Scans & Executive Reporting

```bash
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
  uses: luminariadev/raksa/action@v0.1.0
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
- [Changelog](CHANGELOG.md) | [Security Policy](SECURITY.md) | [Contributing](CONTRIBUTING.md)
