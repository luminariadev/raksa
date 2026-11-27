# Benchmarks & Runtime Characteristics

Measured locally on Go `1.26` (`CGO_ENABLED=0`) against `v0.1.0` core packages and `testdata/` fixtures:

- **External Runtime Dependencies**: `1` (`gopkg.in/yaml.v3 v3.0.1`); zero mandatory databases, message brokers, or container runtime daemons required for core CLI or MCP Hub usage.
- **Aggregator + Deduplication + Policy/Baseline Pipeline**: Processes multi-layer Schema v1 JSON/NDJSON reports in single-digit milliseconds in memory.
- **Federated MCP Hub (`raksa mcp`)**: Cold start + JSON-RPC `initialize` + `tools/list` (`61` tools) + local tool invocation completes within one fast stdio process cycle.
- **Container Footprint**: Multi-stage `gcr.io/distroless/static-debian12:nonroot` image (`USER 65532:65532`, `HEALTHCHECK` enabled).

Detailed cross-tool microbenchmarks (`go test -bench=. -benchmem ./...`) and 24-hour endurance soak suites will be tracked alongside `v0.2.0` Web Workbench and `v1.0.0` contract freeze milestones.
