#!/usr/bin/env bash
# ==============================================================================
# AgentGate - Flawless Automated Installer & Setup Script
# Works for both root (system-wide) and non-root (user-level) installations
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

echo "=========================================================="
echo "         🚪 AgentGate - Privilege Bridge Setup"
echo "=========================================================="

# Determine install location based on user privilege
if [ "$(id -u)" -eq 0 ]; then
    INSTALL_DIR="/usr/local/bin"
    IS_ROOT=true
    echo "→ Installing system-wide as root..."
else
    INSTALL_DIR="${HOME}/.local/bin"
    IS_ROOT=false
    echo "→ Installing in user environment (${INSTALL_DIR})..."
fi

mkdir -p "${INSTALL_DIR}"

# 1. Locate or build binary
if [ -f "${REPO_DIR}/target/release/agentgate" ]; then
    cp "${REPO_DIR}/target/release/agentgate" "${INSTALL_DIR}/agentgate"
    chmod +x "${INSTALL_DIR}/agentgate"
    echo "✓ Installed binary to ${INSTALL_DIR}/agentgate"
else
    echo "→ Release binary not found. Compiling with cargo..."
    if ! command -v cargo &>/dev/null; then
        echo "❌ Error: 'cargo' is required to compile AgentGate from source." >&2
        exit 1
    fi
    (cd "${REPO_DIR}" && cargo build --release)
    cp "${REPO_DIR}/target/release/agentgate" "${INSTALL_DIR}/agentgate"
    chmod +x "${INSTALL_DIR}/agentgate"
    echo "✓ Built and installed binary to ${INSTALL_DIR}/agentgate"
fi

# 2. Check PATH
if [[ ":$PATH:" != *":${INSTALL_DIR}:"* ]]; then
    echo "⚠️  Note: ${INSTALL_DIR} is not in your PATH."
    echo "   Add this line to your ~/.bashrc or ~/.zshrc:"
    echo "   export PATH=\"${INSTALL_DIR}:\$PATH\""
fi

# 3. Initialize AgentGate configuration and certificates
echo ""
echo "→ Initializing AgentGate environment..."
"${INSTALL_DIR}/agentgate" init

# 4. Optional Systemd service setup
if [ "$IS_ROOT" = true ] && [ -d /etc/systemd/system ]; then
    echo ""
    echo "→ Setting up systemd system service..."
    cp "${REPO_DIR}/agentgate.service" /etc/systemd/system/agentgate.service
    systemctl daemon-reload
    echo "✓ Installed /etc/systemd/system/agentgate.service"
    echo "  To enable and start on boot: systemctl enable --now agentgate"
elif [ -d "${HOME}/.config" ]; then
    USER_SYSTEMD_DIR="${HOME}/.config/systemd/user"
    mkdir -p "${USER_SYSTEMD_DIR}"
    cat <<EOF > "${USER_SYSTEMD_DIR}/agentgate.service"
[Unit]
Description=AgentGate - Secure AI Agent Privilege Bridge
After=network.target

[Service]
Type=simple
ExecStart=${INSTALL_DIR}/agentgate serve
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=default.target
EOF
    if command -v systemctl &>/dev/null; then
        systemctl --user daemon-reload || true
        echo "✓ Installed user systemd service to ${USER_SYSTEMD_DIR}/agentgate.service"
        echo "  To run as background service:"
        echo "    systemctl --user enable --now agentgate"
    fi
fi

echo ""
echo "=========================================================="
echo "🎉 AgentGate setup is complete and ready!"
echo ""
echo "Quick Commands:"
echo "  1. Start server:      agentgate serve"
echo "  2. Create agent key:  agentgate token create --name my-agent --policy read-only"
echo "  3. List policies:     agentgate policy list"
echo "  4. Check status:      agentgate status"
echo "  5. Audit logs:        agentgate logs"
echo "=========================================================="
