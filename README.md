# AgentGate

AgentGate is a policy-enforcement daemon and scoped execution proxy for autonomous AI agents and automation systems on Linux.

When automated tools (such as coding agents, CI/CD runners, or remote LLMs) need to run commands on a host, granting raw SSH access or unrestricted `sudo` (`NOPASSWD: ALL`) creates an uncontained failure domain. An errant model hallucination, an unescaped path, or a prompt injection attack can compromise or destroy host state.

AgentGate addresses this by acting as a gateway between automation callers and the operating system. It validates requests against declarative allow/deny policies, blocks destructive commands through universal guardrails, drops privileges to dedicated system accounts, and executes binaries directly without an intermediate shell parser.

AgentGate is **not** an SSH replacement, a hypervisor, or a container runtime. It is an execution proxy designed to limit the blast radius of automated callers.

---

## Threat Model and Boundaries

Understanding what AgentGate enforces—and what it does not—is critical for deploying it safely.

| Capability | Scope |
| :--- | :--- |
| **Accidental Destruction Guardrail** | Intercepts destructive patterns (`rm -rf /`, raw disk writes via `dd`, filesystem formatting via `mkfs`, partition wipes, host reboots) before process launch, even under broad policies. |
| **Direct POSIX Invocation** | Passes arguments directly as array pointers (`execvp`). Shell metacharacters (`;`, `&&`, `\|`, `` ` ``, `$()`, `>`, `<`) are rejected by the parser, preventing shell command-chaining injection. |
| **Least-Privilege OS Users** | Drops UID, GID, and supplementary groups to dedicated unprivileged system users (e.g., `ag-<name>`) via `setresuid` prior to execution. |
| **Granular Sudoers Generation** | Generates minimal `/etc/sudoers.d/` grants for specific commands, rejecting binaries with known shell escapes (GTFOBins) and prohibiting wildcards. |
| **Audit Logging** | Writes append-only `JSONL` records capturing socket-verified peer IPs, token names, command arguments, duration, and exit codes. |
| **Decoupled Control Plane** | Provides a web dashboard authenticated via RFC 6238 TOTP (Google Authenticator, 1Password, Bitwarden) for policy management and real-time telemetry. |

### What AgentGate Does Not Do

- **It does not sandbox arbitrary code inside interpreters:** If a policy permits `/usr/bin/python3` or `/usr/bin/bash` without OS user privilege dropping, the agent inherits the full capabilities of that interpreter. For untrusted or autonomous agents, dedicated unprivileged OS accounts (`--user-mode`) are required.
- **It does not replace virtualization or containers:** AgentGate regulates access to host binaries. It does not provide filesystem virtualization, kernel isolation, or cgroup memory/CPU limits.
- **It does not replace SSH:** SSH is a secure transport and interactive shell protocol. AgentGate is a non-interactive execution API and policy filter.

---

## System Architecture

AgentGate consists of two binaries and an optional standalone control console:

```
┌────────────────────────────────────────────────────────┐
│                      Callers                           │
│   AI Agents (MCP)  •  CLI / Scripts  •  HTTP Clients   │
└───────────────────────────┬────────────────────────────┘
                            │ Bearer Token (ag_...)
                            ▼
┌────────────────────────────────────────────────────────┐
│                   agentgated (Daemon)                  │
│                                                        │
│  ┌──────────────────┐  ┌────────────────────────────┐  │
│  │ Policy Engine    │  │ Privilege Dropping         │  │
│  │ - Allow / Deny   │  │ - POSIX setresuid / gid    │  │
│  │ - Guardrails     │  │ - Dedicated system users   │  │
│  └──────────────────┘  └────────────────────────────┘  │
│  ┌──────────────────┐  ┌────────────────────────────┐  │
│  │ Direct Exec      │  │ Audit & Auth               │  │
│  │ - No sh -c       │  │ - RFC 6238 TOTP (Admin)    │  │
│  │ - execvp array   │  │ - JSONL structured audit   │  │
│  └──────────────────┘  └────────────────────────────┘  │
└───────────────────────────┬────────────────────────────┘
                            ▼
               Target Operating System
```

1. **`agentgated`** (Host Daemon)
   - Background service running as root or a dedicated service account.
   - Binds to Unix domain socket or local/remote network interfaces (`127.0.0.1:7991` or `0.0.0.0:7991`).
   - Enforces policies, drops privileges, executes processes, and streams audit events via SSE.
   - Manages token records, system user accounts, and RFC 6238 TOTP secrets.

2. **`agentgate`** (Operator CLI & MCP Server)
   - Interactive terminal manager (TUI) for local server configuration, token management, and status checks.
   - CLI execution client (`agentgate exec <command>`) for scripts and CI/CD pipelines.
   - Model Context Protocol (MCP) server for integrating with Claude Desktop, Cursor, or custom agent runners.

3. **Web Control Console** (`console.html`)
   - Standalone single-page interface for remote monitoring and administration.
   - Authenticates via RFC 6238 TOTP (compatible with standard mobile/desktop authenticator apps).
   - Features client-side policy editing, real-time schema validation, local PC import/export, and daemon restart signaling.

---

## Installation

### Binary Releases (Linux x86_64)

Install via the automated installer script:

```bash
curl -fsSL https://raw.githubusercontent.com/lawrencemwangi496-design/agentgate/main/install.sh | sudo bash
```

The script verifies downloaded archives against published SHA-256 checksums and aborts if verification fails.

### Building From Source

Prerequisites: Rust 1.80+ and a standard C compiler toolchain.

```bash
git clone https://github.com/lawrencemwangi496-design/agentgate.git
cd agentgate
cargo build --release --bins
```

The compiled binaries will be placed in:
- `target/release/agentgate` (Client CLI)
- `target/release/agentgated` (Host Daemon)

---

## Getting Started

### 1. Initialize and Start the Daemon

Using the interactive manager:

```bash
sudo agentgate
```

Select `1) Set up AgentGate (Server)` to initialize configuration directories, generate TLS certificates, configure the service, and create the initial administrator token.

Alternatively, run the daemon manually:

```bash
# Start the daemon in the foreground
sudo agentgated --listen 127.0.0.1:7991
```

### 2. Configure TOTP for Dashboard Access

To access the web console, generate a two-factor authentication secret:

```bash
sudo agentgated totp setup
```

This outputs a Base32 secret key and an `otpauth://` URI. Add this key to your authenticator app (Google Authenticator, 1Password, Bitwarden, or Aegis).

To check status or regenerate keys:

```bash
# Check configuration status
agentgated totp status

# Regenerate secret (invalidates previous keys)
sudo agentgated totp setup --reset
```

### 3. Issue Scoped Agent Tokens

Generate tokens bound to specific policies and privilege levels:

```bash
# Diagnostic token: read-only policy, runs as dedicated unprivileged user ag-monitor
sudo agentgate token create --name monitor --policy read-only --user-mode

# Operational token: scoped sudoers entries for specific maintenance commands
sudo agentgate token create --name webops --tier ops

# Administrative token: short-lived (max 24h)
sudo agentgate token create --name emergency-admin --tier admin --expires 4h
```

Tokens are displayed once upon creation and stored as SHA-256 hashes on disk.

---

## Execution Policies

Policies are declarative YAML files stored in `/etc/agentgate/policies/` (or `~/.config/agentgate/policies/`).

### Standard Policy (`agent.yaml`)
Designed for trusted development agents that require general execution freedom with guardrails against catastrophic accidents:

```yaml
name: agent
description: "General execution with safety guardrails against catastrophic destruction"
guardrails: true
allow:
  - command: "*"
    args: ["*"]
deny:
  - command: rm
    args: ["-rf", "/*"]
  - command: rm
    args: ["-rf", "/"]
  - command: rm
    args: ["-rf", "~"]
  - command: mkfs*
    args: ["*"]
  - command: dd
    args: ["*"]
  - command: shutdown
    args: ["*"]
  - command: reboot
    args: ["*"]
  - command: passwd
    args: ["*"]
  - command: cat
    args: ["/etc/shadow"]
```

### Action Templates (`pipeline.yaml`)
For CI/CD pipelines and fixed automation, arbitrary binary execution can be disabled entirely in favor of named multi-step actions:

```yaml
name: pipeline
description: "Automation pipeline policy restricted to predefined actions"
guardrails: true
allow: []
actions:
  deploy:
    description: "Pull updates and reload application services"
    steps:
      - "/usr/bin/git -C /srv/app pull --ff-only"
      - "/usr/bin/systemctl reload app.service"
    stop_on_failure: true
```

Tokens restricted to actions can only invoke predefined steps:

```bash
curl -X POST https://127.0.0.1:7991/v1/action/deploy \
  -H "Authorization: Bearer ag_..." \
  -H "Content-Type: application/json" \
  -d '{"params": {}}'
```

---

## AI Agent Integration

### Model Context Protocol (MCP)

AgentGate includes a native Model Context Protocol server, allowing direct integration with MCP-compliant AI tools.

Start the MCP server:

```bash
agentgate mcp
```

Add the server to your agent configuration (e.g., `claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "agentgate": {
      "command": "agentgate",
      "args": ["mcp"]
    }
  }
}
```

The agent will be able to discover allowed commands and execute them within the bounds of its configured token.

### CLI Client Execution

Automation scripts and operators can dispatch commands directly:

```bash
# Standard output
agentgate exec uptime

# Machine-readable JSON output (includes stdout, stderr, exit code, duration)
agentgate exec --json systemctl status nginx
```

---

## Command Reference

### `agentgate` (Client & Management CLI)

| Subcommand | Description |
| :--- | :--- |
| `agentgate` | Launch interactive terminal management interface |
| `agentgate exec <cmd>` | Execute a command through the daemon API |
| `agentgate action <name>` | Execute a predefined named action template |
| `agentgate start` | Start the daemon as a managed background process |
| `agentgate stop` | Terminate the background daemon process |
| `agentgate status` | Inspect daemon health, network bindings, and active policies |
| `agentgate token create` | Issue a scoped token (`--tier`, `--user-mode`, `--actions`, `--expires`) |
| `agentgate token list` | Display active tokens, associated policies, and expiration dates |
| `agentgate token revoke` | Revoke a token and clean up any associated sudoers entries |
| `agentgate policy list` | List available policy files |
| `agentgate logs` | Inspect recent command audit records |
| `agentgate mcp` | Run the Model Context Protocol stdio server |

### `agentgated` (Host Daemon)

| Subcommand / Option | Description |
| :--- | :--- |
| `agentgated` | Run the daemon process in foreground |
| `--listen <addr>` | Specify interface and port binding (default: `127.0.0.1:7991`) |
| `--config <path>` | Path to custom configuration file |
| `agentgated totp setup` | Generate or display the RFC 6238 TOTP 2FA secret |
| `agentgated totp setup --reset` | Overwrite and generate a new TOTP 2FA secret |
| `agentgated totp status` | Check if TOTP authentication is active |

---

## Security Reporting

To report security vulnerabilities, please refer to the reporting guidelines in [SECURITY.md](file:///var/home/scorpion/agentgate/SECURITY.md).

---

## License

MIT License. See [LICENSE](file:///var/home/scorpion/agentgate/LICENSE) for details.
