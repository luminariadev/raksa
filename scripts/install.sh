#!/usr/bin/env bash
set -euo pipefail

VERSION="${RAKSA_VERSION:-v0.2.0}"
INSTALL_DIR="${RAKSA_BIN_DIR:-$HOME/.raksa/bin}"

OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"
case "$ARCH" in
  x86_64|amd64) ARCH="amd64" ;;
  arm64|aarch64) ARCH="arm64" ;;
  *)
    echo "Unsupported CPU architecture: $ARCH" >&2
    exit 1
    ;;
esac

case "$OS" in
  linux|darwin) ;;
  *)
    echo "Unsupported OS for install.sh: $OS (use install.ps1 on Windows)" >&2
    exit 1
    ;;
esac

PKG="raksa-${VERSION}-${OS}-${ARCH}"
BASE_URL="https://github.com/luminariadev/raksa/releases/download/${VERSION}"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

echo "Downloading ${PKG}.tar.gz and SHA256SUMS.txt ..."
curl -fsSL "${BASE_URL}/SHA256SUMS.txt" -o "${TMP_DIR}/SHA256SUMS.txt"
curl -fsSL "${BASE_URL}/${PKG}.tar.gz" -o "${TMP_DIR}/${PKG}.tar.gz"

echo "Verifying SHA-256 checksum ..."
if command -v sha256sum >/dev/null 2>&1; then
  (cd "$TMP_DIR" && grep " ${PKG}.tar.gz\$" SHA256SUMS.txt | sha256sum -c -)
elif command -v shasum >/dev/null 2>&1; then
  (cd "$TMP_DIR" && grep " ${PKG}.tar.gz\$" SHA256SUMS.txt | shasum -a 256 -c -)
else
  echo "Neither sha256sum nor shasum found; aborting unverified install." >&2
  exit 1
fi

tar -xzf "${TMP_DIR}/${PKG}.tar.gz" -C "$TMP_DIR"
mkdir -p "$INSTALL_DIR"
install -m 0755 "${TMP_DIR}/${PKG}/raksa" "${INSTALL_DIR}/raksa"

echo "Installed raksa ${VERSION} to ${INSTALL_DIR}/raksa"
echo "Add '${INSTALL_DIR}' to your PATH, then run: raksa doctor"
