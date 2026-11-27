# Security Policy

## Scope & Defensive Posture

`raksa` is built exclusively for defensive security posture assessment, configuration auditing, malware triage orchestration, and Blue Team telemetry correlation. It does not ship exploit payloads or unauthorized offensive scanners.

## Supply-Chain & Binary Verification

- Release archives on GitHub include `SHA256SUMS.txt` generated during tag builds.
- `raksa install` verifies the downloaded archive digest against `SHA256SUMS.txt` before extracting binaries.
- `raksa doctor` computes live SHA-256 digests of installed Layer 1-6 executables.
- Container images run as non-root `65532:65532` on `gcr.io/distroless/static-debian12:nonroot`.

## Reporting Vulnerabilities

If you discover a security vulnerability in `raksa` (such as command-argument injection, unsafe path traversal during archive extraction, template injection, or MCP input handling bugs):

1. Open a private GitHub Security Advisory on `luminariadev/raksa` rather than filing a public issue with exploit details.
2. Include the component (`runner`, `aggregator`, `mcphub`, `report`, `store`), minimal reproduction steps, and expected vs actual behavior.
3. Initial triage is targeted within 72 hours.
