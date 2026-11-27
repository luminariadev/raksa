---
name: raksa-defense-workbench
description: Orchestrate Raksa Layer 1-7 defensive security audits, cross-layer correlation, attack-vs-defense checks, and read-only hardening patch previews via CLI or the 61-tool raksa MCP hub.
---

# Raksa Defense Workbench Skill

Use this skill when performing defensive security audits, CI/CD release gates, host hardening reviews, malware triage, or SIEM correlation across a repository, container stack, or host workspace.

## Core Defensive Principles
1. **100% Defensive Scope**: Raksa inspects local workspaces, configurations, artifacts, headers, and telemetry logs. Never run unauthorized scans against third-party hosts.
2. **Read-Only by Default**: Generate remediation patches via `raksa fix-preview` / `raksa_plan_remediation` and require explicit operator confirmation before writing configuration changes.
3. **Hybrid Execution**: Run full L1-L6 coverage (`--profile full`) or scoped modular profiles (`repo`, `host`, `web`, `incident`) depending on task scope.

## Standard CLI Workflow

```bash
# 1. Inspect installed Layer 1-6 tools and digests
raksa doctor

# 2. Run Hybrid repository/DevSecOps audit with SARIF output
raksa scan --path . --profile repo --format sarif --fail-on high --output raksa.sarif

# 3. Inspect Attack-vs-Defense coverage gaps
raksa attack-matrix

# 4. Generate read-only remediation patches for review
raksa fix-preview --path . --format diff

# 5. Verify local tamper-evident SHA-256 scan ledger
raksa posture --verify
```

## Federated 61-Tool MCP Hub
Start the unified stdio JSON-RPC 2.0 MCP hub with:

```bash
raksa mcp
```

- Start with `raksa_doctor` to verify which L1-L6 binaries are installed.
- Use `raksa_full_audit` or `raksa_posture_summary` for cross-layer triage.
- Drill down selectively into `netguard_*`, `hostguard_*`, `webshield_*`, `pipeguard_*`, `iocscan_*`, or `siem_*` tools for specialized checks.
- Always finish remediation suggestions with `raksa_plan_remediation` rather than directly editing files without review.
