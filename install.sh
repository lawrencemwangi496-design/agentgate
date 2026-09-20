#!/usr/bin/env bash
set -e

REPO="lawrencemwangi496-design/agentgate"
TAR_NAME="agentgate-linux-x86_64.tar.gz"
DOWNLOAD_URL="https://github.com/${REPO}/releases/latest/download/${TAR_NAME}"
CHECKSUMS_URL="https://github.com/${REPO}/releases/latest/download/SHA256SUMS"

# Parse command line flags
IS_UPDATE=false
NO_LAUNCH=false
for arg in "$@"; do
    case "$arg" in
        --update) IS_UPDATE=true ;;
        --no-launch) NO_LAUNCH=true ;;
    esac
done

echo ""
echo "=========================================================="
if [ "$IS_UPDATE" = true ]; then
    echo "             🚪 AgentGate Release Updater"
else
    echo "             🚪 AgentGate Quick Installer"
fi
echo "=========================================================="

# Check OS and Architecture
OS="$(uname -s)"
ARCH="$(uname -m)"

if [ "$OS" != "Linux" ] || [ "$ARCH" != "x86_64" ]; then
    echo "⚠️  Note: Prebuilt binary is currently packaged for Linux x86_64 (detected $OS $ARCH)."
    echo "Falling back to compiling from source via Cargo..."
    if command -v cargo >/dev/null 2>&1; then
        cargo install --git "https://github.com/${REPO}.git"
        echo "✅ Installed via Cargo!"
        exit 0
    else
        echo "❌ Cargo not found. Please install Rust from https://rustup.rs or use a supported Linux x86_64 system."
        exit 1
    fi
fi

# Verify SHA-256 verification tool is available before proceeding (fail-closed)
if command -v sha256sum >/dev/null 2>&1; then
    SHA_TOOL="sha256sum"
elif command -v shasum >/dev/null 2>&1; then
    SHA_TOOL="shasum"
else
    echo "❌ Error: Neither 'sha256sum' nor 'shasum' is installed on this system." >&2
    echo "   AgentGate requires cryptographic checksum verification to prevent supply chain tampering." >&2
    echo "   Please install coreutils or perl-Digest-SHA, or install via 'cargo install --git https://github.com/${REPO}.git'" >&2
    exit 1
fi

# Determine install location intelligently
# 1. If an existing agentgate binary is already on PATH, overwrite it in-place
# 2. If system config /etc/agentgate exists or user is root, use /usr/local/bin
# 3. Otherwise default to ~/.local/bin
EXISTING_BIN="$(command -v agentgate 2>/dev/null || true)"
if [ -n "$EXISTING_BIN" ] && [ -x "$EXISTING_BIN" ]; then
    INSTALL_DIR="$(dirname "$EXISTING_BIN")"
elif [ -d "/etc/agentgate" ] || [ "$(id -u)" -eq 0 ] || [ -w "/usr/local/bin" ]; then
    INSTALL_DIR="/usr/local/bin"
else
    INSTALL_DIR="${HOME}/.local/bin"
    mkdir -p "$INSTALL_DIR"
fi

TMP_DIR="$(mktemp -d)"
echo "⬇️  Downloading latest AgentGate release archive..."

CHECKSUM_PRESENT=false
if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$DOWNLOAD_URL" -o "${TMP_DIR}/${TAR_NAME}"
    if curl -fsSL "$CHECKSUMS_URL" -o "${TMP_DIR}/SHA256SUMS" 2>/dev/null; then
        CHECKSUM_PRESENT=true
    fi
elif command -v wget >/dev/null 2>&1; then
    wget -qO "${TMP_DIR}/${TAR_NAME}" "$DOWNLOAD_URL"
    if wget -qO "${TMP_DIR}/SHA256SUMS" "$CHECKSUMS_URL" 2>/dev/null; then
        CHECKSUM_PRESENT=true
    fi
else
    echo "❌ Error: Neither curl nor wget is installed." >&2
    exit 1
fi

# Cryptographic integrity verification (fail-closed when published)
if [ "$CHECKSUM_PRESENT" = true ] && [ -s "${TMP_DIR}/SHA256SUMS" ]; then
    echo "🔒 Verifying release binary checksum against published SHA256SUMS..."
    (
        cd "$TMP_DIR"
        if [ "$SHA_TOOL" = "sha256sum" ]; then
            grep "$TAR_NAME" SHA256SUMS | sha256sum -c --status
        else
            grep "$TAR_NAME" SHA256SUMS | shasum -a 256 -c --status
        fi
    )
    if [ $? -ne 0 ]; then
        echo "❌ FATAL: Checksum verification failed! The downloaded archive does not match the official SHA-256 hash." >&2
        echo "   This could indicate a network error, mirror tampering, or compromised artifact." >&2
        rm -rf "$TMP_DIR"
        exit 1
    fi
    echo "✓ Checksum verification passed."
else
    echo "⚠️  Notice: Official SHA256SUMS file not published for this release tag. Skipping hash verification."
fi

echo "📦 Installing binaries to ${INSTALL_DIR}..."
tar -xzf "${TMP_DIR}/${TAR_NAME}" -C "$TMP_DIR"

if [ -w "$INSTALL_DIR" ]; then
    mv "${TMP_DIR}/agentgate" "${INSTALL_DIR}/agentgate"
    chmod +x "${INSTALL_DIR}/agentgate"
    if [ -f "${TMP_DIR}/agentgated" ]; then
        mv "${TMP_DIR}/agentgated" "${INSTALL_DIR}/agentgated"
        chmod +x "${INSTALL_DIR}/agentgated"
    fi
else
    echo "🔒 System install location detected (${INSTALL_DIR}). Elevating with sudo..."
    sudo mv "${TMP_DIR}/agentgate" "${INSTALL_DIR}/agentgate"
    sudo chmod +x "${INSTALL_DIR}/agentgate"
    if [ -f "${TMP_DIR}/agentgated" ]; then
        sudo mv "${TMP_DIR}/agentgated" "${INSTALL_DIR}/agentgated"
        sudo chmod +x "${INSTALL_DIR}/agentgated"
    fi
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

# Deeper service reload & restart on update
if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet agentgate 2>/dev/null; then
    echo "🔄 Restarting active AgentGate systemd service..."
    if [ "$(id -u)" -eq 0 ]; then
        systemctl daemon-reload && systemctl restart agentgate
    else
        sudo systemctl daemon-reload && sudo systemctl restart agentgate
    fi
    echo "✓ AgentGate systemd service restarted with new release."
elif "${INSTALL_DIR}/agentgate" status 2>/dev/null | grep -q "RUNNING"; then
    echo "🔄 Restarting active AgentGate daemon..."
    "${INSTALL_DIR}/agentgate" restart 2>/dev/null || true
    echo "✓ AgentGate daemon restarted with new release."
fi

if [ "$IS_UPDATE" = true ] || [ "$NO_LAUNCH" = true ]; then
    echo "✅ AgentGate updated to latest release successfully!"
    exit 0
fi

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
