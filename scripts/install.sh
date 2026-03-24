#!/usr/bin/env bash
set -euo pipefail

# XTunnel installer script
REPO="https://github.com/yourname/xtunnel"
VERSION="${XTUNNEL_VERSION:-latest}"
INSTALL_DIR="/usr/local/bin"
OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"

case $ARCH in
  x86_64) ARCH="amd64" ;;
  arm64|aarch64) ARCH="arm64" ;;
  *) echo "Unsupported architecture: $ARCH"; exit 1 ;;
esac

echo "⚡ Installing XTunnel v${VERSION} (${OS}/${ARCH})..."

BINARY="xtunnel-${OS}-${ARCH}"
URL="${REPO}/releases/download/${VERSION}/${BINARY}"

if command -v curl &>/dev/null; then
  curl -fsSL "$URL" -o /tmp/xtunnel
elif command -v wget &>/dev/null; then
  wget -q "$URL" -O /tmp/xtunnel
else
  echo "Error: curl or wget required"
  exit 1
fi

chmod +x /tmp/xtunnel
sudo mv /tmp/xtunnel "$INSTALL_DIR/xtunnel"

echo "✓ XTunnel installed to $INSTALL_DIR/xtunnel"
echo ""
echo "  Quick start:"
echo "  export XTUNNEL_SERVER=xtunnel.io:7000"
echo "  xtunnel http 3000"
