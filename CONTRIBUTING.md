# Contributing to `raksa`

Contributions that strengthen defensive coverage, determinism, ergonomics, and cross-layer compatibility across Raksa Layers 1-7 are welcome.

## Development Prerequisites

- Go `1.24+` (tested on `1.26`)
- Optional local Layer 1-6 tools (`raksa doctor`) for end-to-end orchestration checks

## Local Checks

```bash
gofmt -l cmd internal playbooks
go vet ./...
go test -race -count=1 ./...
```

## Coding Standards

1. **Minimal External Dependencies**: Keep runtime dependencies constrained cleanly (`gopkg.in/yaml.v3` in core `v0.1.0`; zero external DB assumptions in core OSS).
2. **Defensive-Only Contract**: Never add offensive attack/exploitation modules or auto-mutating commands without explicit operator review gates.
3. **Conventional Commits**: Prefix commits with `feat:`, `fix:`, `test:`, `docs:`, `ci:`, or `chore:`.
4. **Apache-2.0 Licensing**: All contributions to this public repository are licensed under [Apache License 2.0](LICENSE).
