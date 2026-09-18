#!/usr/bin/env bash
set -euo pipefail

echo "============================================="
echo "        Installing AgentGate"
echo "============================================="

INSTALL_DIR="${HOME}/.local/bin"
mkdir -p "${INSTALL_DIR}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

if [ -f "${REPO_DIR}/target/release/agentgate" ]; then
    cp "${REPO_DIR}/target/release/agentgate" "${INSTALL_DIR}/agentgate"
    chmod +x "${INSTALL_DIR}/agentgate"
    echo "✓ Installed agentgate binary to ${INSTALL_DIR}/agentgate"
else
    echo "Release binary not found. Building with cargo..."
    cd "${REPO_DIR}"
    cargo build --release
    cp "${REPO_DIR}/target/release/agentgate" "${INSTALL_DIR}/agentgate"
    chmod +x "${INSTALL_DIR}/agentgate"
    echo "✓ Built and installed agentgate binary to ${INSTALL_DIR}/agentgate"
fi

# Run initialization
"${INSTALL_DIR}/agentgate" init

echo ""
echo "🎉 AgentGate installed successfully!"
echo "Run 'agentgate --help' to get started."
