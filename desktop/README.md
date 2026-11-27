# Raksa Desktop App (`Tauri v2`)

`desktop/` wraps the embedded **Raksa 3-Panel Hybrid Web Workbench** in a lightweight native OS window via `Tauri v2` (`#![forbid(unsafe_code)]`), automatically launching `raksa ui` as an isolated loopback sidecar (`localhost:<ephemeral-port>`) protected with a per-session random `HttpOnly; SameSite=Strict` token.

## Prerequisites

1. `raksa` Go binary on `PATH` (or set `RAKSA_BIN=/path/to/raksa`).
2. Rust toolchain (`rustup` / `cargo`, edition `2021`) and OS WebView dependencies per Tauri v2 (`WebView2` on Windows, `webkit2gtk-4.1` on Linux, Xcode WebKit on macOS).
3. Tauri CLI:

```bash
cargo install tauri-cli --version "^2" --locked
```

## Build & Run

```bash
# Run in desktop mode against current workspace
cd desktop/src-tauri
RAKSA_WORKSPACE="../.." cargo tauri dev

# Or build native installer (.msi / .AppImage / .dmg)
cargo tauri build
```

## Sidecar Environment Overrides

| Variable | Purpose |
| :--- | :--- |
| `RAKSA_BIN` | Override path to `raksa` CLI binary |
| `RAKSA_WORKSPACE` | Initial workspace target directory |
| `RAKSA_FROM_REPORTS` | Optional pre-loaded Schema v1 fixtures directory/file |
| `RAKSA_SIEM_URL` | Optional Layer 6 `raksa-siem` HTTP endpoint |
