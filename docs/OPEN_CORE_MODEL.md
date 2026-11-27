# Open-Core Architecture & Enterprise Extension Model

`luminariadev/raksa` is licensed under **Apache License 2.0** and provides the complete single-node and CI/CD Hybrid Workbench open source:

- Multi-layer CLI orchestrator (`doctor`, `install`, `scan`, `posture`, `fix-preview`, `playbooks`, `attack-matrix`)
- Federated 61-tool stdio MCP Hub (`raksa mcp`)
- Hash-chained local run history (`runs.ndjson`)
- SARIF 2.1.0, Markdown PR reports, and standalone offline HTML executive reports
- Upcoming `v0.2.0` embedded Web Workbench and `v0.3.0` Tauri v2 Desktop App

## Extension Interfaces (`internal/ext`)

To support commercial enterprise tiers without maintaining a separate fork of `raksa`, `internal/ext` defines pluggable interfaces:

1. **`AuthProvider`**: Default OSS implementation (`LocalAuthProvider`) handles single-operator token verification. Private enterprise modules implement SAML 2.0, OIDC SSO, SCIM provisioning, and multi-team RBAC.
2. **`ComplianceMapper`**: Default OSS implementation (`OSSComplianceMapper`) tags findings with MITRE D3FEND, CIS Benchmarks, OWASP ASVS, SLSA, and NIST mappings. Private compliance packs generate automated auditor evidence bundles for **ISO 27001, SOC 2 Type II, PCI-DSS 4.0, and UU PDP (Indonesia) / GDPR**.
3. **`EditionMetadata`**: Exposes build-time edition capabilities cleanly in `raksa version --format json` and downstream UIs.

Private enterprise repositories (`luminariadev/raksa-enterprise` and `luminariadev/raksa-cloud`) import `github.com/luminariadev/raksa` as a Go module dependency and wire enterprise providers via Go build tags (`-tags enterprise`).
