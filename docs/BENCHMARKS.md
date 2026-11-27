# Benchmarks & Runtime Characteristics

Measured locally on Go `1.26` (`CGO_ENABLED=0`) and Rust `1.100` against `v0.3.0` core packages, embedded Web Workbench, AI Defense Assistant, and `testdata/` fixtures:

- **External Runtime Dependencies**: `1` (`gopkg.in/yaml.v3 v3.0.1`); zero mandatory databases, Node runtimes, message brokers, or container runtime daemons required for CLI, `raksa tui`, `raksa ui`, `raksa mcp`, or offline AI Assistant mode.
- **Embedded Web Workbench Assets (`internal/webui`)**: Compact zero-framework HTML/CSS/vanilla-JS bundle compiled straight into the Go binary via `go:embed` (~35 KB uncompressed across `index.html`, `styles.css`, `app.js`).
- **Web Header Posture (`raksa-webshield audit-headers`)**: Hardened local HTTP responses pass `WEB-001` through `WEB-104` at **`100/100 (A+)`** with zero JS console or CSP errors verified at `1440x900`.
- **Desktop Sidecar (`desktop/src-tauri/src/sidecar.rs`)**: Pure-`std` `#![forbid(unsafe_code)]` Rust sidecar module passing unit tests in `< 0.01s`.
- **Aggregator + Deduplication + Policy/Baseline Pipeline**: Processes multi-layer Schema v1 JSON/NDJSON reports in single-digit milliseconds in memory.
- **Container Footprint**: Multi-stage `gcr.io/distroless/static-debian12:nonroot` image (`USER 65532:65532`, `HEALTHCHECK` enabled).

Detailed cross-tool microbenchmarks (`go test -bench=. -benchmem ./...`) and 24-hour endurance soak suites will be expanded through `v1.0.0` contract freeze milestones.
