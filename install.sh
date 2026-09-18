#!/usr/bin/env bash
set -e

echo "=========================================================="
echo "             🚪 AgentGate Server Installer"
echo "=========================================================="

INSTALL_DIR="/usr/local/bin"

if ! command -v cargo >/dev/null 2>&1; then
    echo "❌ Rust/Cargo is not installed on this system."
    echo "💡 You can install Rust quickly with:"
    echo "   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"
    echo "   or copy the precompiled binary from your PC using scp:"
    echo "   scp ~/.local/bin/agentgate user@server:/usr/local/bin/"
    exit 1
fi

echo "📦 Compiling and installing AgentGate from GitHub..."
TMP_DIR=$(mktemp -d)
git clone --depth 1 https://github.com/lawrencemwangi496-design/agentgate.git "$TMP_DIR"
cd "$TMP_DIR"
cargo build --release

if [ -w "$INSTALL_DIR" ]; then
    cp target/release/agentgate "$INSTALL_DIR/agentgate"
else
    sudo cp target/release/agentgate "$INSTALL_DIR/agentgate"
fi

rm -rf "$TMP_DIR"

echo "⚙️ Initializing AgentGate..."
agentgate init

echo ""
echo "=========================================================="
echo "🎉 AgentGate installed successfully at $INSTALL_DIR/agentgate"
echo "=========================================================="
echo "👉 Start server on all interfaces:  agentgate start --remote"
echo "👉 Or launch the interactive menu:  agentgate"
echo "=========================================================="
