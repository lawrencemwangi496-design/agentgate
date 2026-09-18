#!/usr/bin/env bash
set -e

REPO="lawrencemwangi496-design/agentgate"
TAR_NAME="agentgate-linux-x86_64.tar.gz"
DOWNLOAD_URL="https://github.com/${REPO}/releases/latest/download/${TAR_NAME}"

echo ""
echo "=========================================================="
echo "             🚪 AgentGate Quick Installer"
echo "=========================================================="

# Check OS and Architecture
OS="$(uname -s)"
ARCH="$(uname -m)"

if [ "$OS" != "Linux" ] || [ "$ARCH" != "x86_64" ]; then
    echo "⚠️ Warning: Automated prebuilt binary is currently built for Linux x86_64 (detected $OS $ARCH)."
    echo "Attempting to install via cargo if available..."
    if command -v cargo >/dev/null 2>&1; then
        cargo install --git "https://github.com/${REPO}.git"
        echo "✅ Installed via Cargo!"
        exit 0
    else
        echo "❌ Cargo not found. Please install Rust from https://rustup.rs"
        exit 1
    fi
fi

# Determine install location
if [ "$(id -u)" -eq 0 ]; then
    INSTALL_DIR="/usr/local/bin"
else
    INSTALL_DIR="${HOME}/.local/bin"
    mkdir -p "$INSTALL_DIR"
fi

TMP_DIR="$(mktemp -d)"
echo "⬇️ Downloading latest AgentGate release..."

if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$DOWNLOAD_URL" -o "${TMP_DIR}/${TAR_NAME}"
elif command -v wget >/dev/null 2>&1; then
    wget -qO "${TMP_DIR}/${TAR_NAME}" "$DOWNLOAD_URL"
else
    echo "❌ Error: Neither curl nor wget is installed."
    exit 1
fi

echo "📦 Installing binary to ${INSTALL_DIR}/agentgate..."
tar -xzf "${TMP_DIR}/${TAR_NAME}" -C "$TMP_DIR"

if [ -w "$INSTALL_DIR" ]; then
    mv "${TMP_DIR}/agentgate" "${INSTALL_DIR}/agentgate"
    chmod +x "${INSTALL_DIR}/agentgate"
else
    sudo mv "${TMP_DIR}/agentgate" "${INSTALL_DIR}/agentgate"
    sudo chmod +x "${INSTALL_DIR}/agentgate"
fi

rm -rf "$TMP_DIR"

# Check if INSTALL_DIR is in PATH
case ":$PATH:" in
    *":$INSTALL_DIR:"*) ;;
    *)
        echo "⚠️  Note: ${INSTALL_DIR} is not in your current PATH."
        echo "   Add it with: export PATH=\"${INSTALL_DIR}:\$PATH\""
        echo ""
        ;;
esac

echo "✅ AgentGate installed successfully!"
echo ""

# If terminal is interactive or tty is available, open the manager immediately!
if [ -c /dev/tty ]; then
    exec "${INSTALL_DIR}/agentgate" < /dev/tty
elif [ -t 0 ]; then
    exec "${INSTALL_DIR}/agentgate"
else
    echo "👉 Run 'agentgate' to launch the interactive manager!"
fi
