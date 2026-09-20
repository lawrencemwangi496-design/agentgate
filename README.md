# AgentGate 🚪⚡

> **The structured privilege bridge and safety seatbelt for autonomous AI agents and automation.**  
> Execute commands safely on your Linux machines without sharing SSH keys, exposing passwords, or granting unrestricted `sudo`.

---

## 🧭 Threat Model: Seatbelt vs. Prison

AgentGate is designed with an explicit, honest threat model:

| What AgentGate IS | What AgentGate IS NOT |
| :--- | :--- |
| 🛡️ **An accident guardrail ("seatbelt")** against LLM hallucinations, catastrophic accidental commands (`rm -rf /`, `/boot` wipes, disk formatting), and naive prompt injection. | 🚫 **NOT a virtualized sandbox** against an adversarial agent holding an unrestricted root token without OS user boundaries. |
| 🔑 **A structured credential bridge** providing revokable, scoped bearer tokens with optional per-token unprivileged OS users (`ag-<name>`). | 🚫 **NOT a magic barrier against Turing-complete interpreters:** If a policy allows `python3` or `perl` in root mode, the agent has the full power of that interpreter. |
| 📜 **An immutable, tamper-evident audit logger** that records real socket-level peer IPs, execution duration, and exit codes. | 🚫 **NOT a replacement for containers/VMs** when executing untrusted or adversarial third-party code. |
| ⚡ **A native agent interface** offering a clean HTTP/REST API, native CLI wrapper (`agentgate exec`), and Model Context Protocol (MCP) server. | 🖥️ **A decoupled web control plane** with RFC 6238 TOTP 2FA, live policy linting, and PC file import/export. |

> [!NOTE]
> If you are giving an agent broad permissions, **enable per-token OS user isolation (`--user-mode`) or security tiers (`--tier ops`)**. Denylists protect against accidental destruction, but OS user separation is what creates a true security boundary.

---

## Why AgentGate is Better than SSH for AI Agents

| Feature | SSH / sudo | AgentGate 🚪 |
| :--- | :--- | :--- |
| **Credentials** | Raw SSH private keys or root passwords shared directly with the LLM | Scoped, revokable SHA-256 tokens (`ag_...`) or RFC 6238 TOTP admin sessions |
| **Safety Guardrails** | All-or-nothing root access (`sudo NOPASSWD: ALL`) | **Universal Guardrails:** Destructive commands (`rm -rf /`, `mkfs`, `dd`, `shutdown`, `/etc/shadow`) are permanently blocked at the gateway level |
| **Execution Layer** | Raw interactive PTY allows shell piping, background jobs, and escape tricks | **No Shell Parser:** Commands execute directly via POSIX `execvp`. Shell metacharacters (`;`, `&&`, `\|`, `` ` ``, `$()`, `>`, `<`) are rejected by the parser |
| **Privilege Dropping** | Requires complex custom PAM and sudo rules per key | **Per-Token OS Users:** Daemon drops UID, GID, and supplementary groups to dedicated system users (`ag-<name>`) |
| **Audit Trail** | Fragmented bash history (easily altered or cleared) | Structured `JSONL` audit log with socket-verified peer IPs, duration, and exit codes |
| **Revocation** | Rotating SSH keys or changing passwords disrupts multiple services | Instant single-token revocation with atomic file locking (`flock`) |
| **Ergonomics** | Fragile SSH timeouts, complex TTY prompts, password hangs | Native CLI (`agentgate exec`), JSON REST API, built-in MCP server, and live web control console |

---

## 🏗️ Architecture: Daemon vs. Client

AgentGate is built as two purpose-built binaries:

1. **`agentgated`** — **The Engine (Daemon)**
   - Runs as a headless system service on the host machine.
   - Listens on Unix domain sockets or HTTP/HTTPS (`0.0.0.0:7991`).
   - Handles POSIX command execution, policy enforcement, audit streaming (SSE), and RFC 6238 TOTP authentication.
   - Manages token stores, system users, and sudoers configurations.

2. **`agentgate`** — **The Operator Interface (Client CLI)**
   - Terminal interactive manager (TUI) for configuring servers, creating tokens, and viewing logs.
   - CLI execution client (`agentgate exec <command>`) for operators and scripts.
   - Built-in Model Context Protocol (`agentgate mcp`) server for AI agents.

---

## ⚡ 1-Minute Quick Start

### 1. Install

Install directly on your Linux x86_64 server:

```bash
curl -fsSL https://raw.githubusercontent.com/lawrencemwangi496-design/agentgate/main/install.sh | sudo bash
```

*The installer verifies the release archive against official `SHA256SUMS` and fails closed if verification fails.*

Or build from source:

```bash
cargo build --release --bins
# Binaries located in target/release/agentgate and target/release/agentgated
```

### 2. Launch the Interactive Manager

Run `agentgate` to launch the interactive terminal manager:

```bash
agentgate
```

```text
==========================================================
                 🚪 AgentGate Manager
==========================================================
  AgentGate:     🟢 RUNNING (127.0.0.1:7991, PID: 4210)
  Client Config: 🟢 Connected (https://127.0.0.1:7991)

  1) Set up AgentGate (Server)
     → Configure network, TLS certificates & start service
  2) Connect to AgentGate (Client)
     → Configure laptop to connect to a remote server
  3) Secure Shell (Interactive console)
  4) Manage Tokens (Create, List, Revoke)
  5) View Audit Logs
  6) Stop AgentGate
  7) Update AgentGate
  0) Exit

Select an option [0-7]: 
```

- **Option 1 (Set up Server):** Starts the server, generates TLS certificates, creates an agent token, and automatically configures your local client.
- **Option 3 (Secure Shell):** Drops directly into the interactive agent console to run permitted commands live.

---

## 🖥️ Decoupled Web Control Console & Remote Management

AgentGate includes an industrial charcoal/slate web dashboard (`src/web/console.html`) designed for browser-based remote control of the daemon.

```
┌─────────────────────────┐               HTTP/HTTPS API (JSON/SSE)
│   Any Browser Window    │ ────────────────────────────────────────► ┌───────────────────────────┐
│ (PC / Laptop / Phone)   │ ◄──────────────────────────────────────── │ agentgated (Remote Daemon)│
│ console.html            │   Token / TOTP Bearer Session             │ Listening on 0.0.0.0:7991 │
└─────────────────────────┘                                           └───────────────────────────┘
```

### Key Capabilities:
- **RFC 6238 TOTP 2FA (Zero External Dependencies)**: Log in securely using **Google Authenticator**, **1Password**, **Bitwarden**, or **Aegis**. No SMTP server, no email deliveries, and no external third-party services required.
- **Decoupled Remote Connection**: Open `console.html` from any PC or static host, type in your daemon's IP, port, and authentication code to connect.
- **Local PC Policy Import (`📥 Import`) & Export (`📤 Export`)**: Load existing policy YAML files directly from your computer into the browser editor, or download server policies to your PC with one click.
- **Live Policy Linter & Schema Validator**: Validates YAML formatting in real time, warns if tabs are used for indentation, counts allow/deny rules, and flags dangerous unguardrailed commands (`rm -rf`, `mkfs`, `dd`, `chmod 777`).
- **Remote Host Daemon Restart**: Initiate a clean restart of the remote `agentgated` process directly from the top toolbar with confirmation.

### Managing TOTP via CLI:
```bash
# View or initialize the 2FA secret (prints Base32 key and otpauth:// URI):
agentgated totp setup

# Regenerate a new 2FA secret:
agentgated totp setup --reset

# Check whether 2FA is active:
agentgated totp status
```

---

## 🛡️ Default Starter Policies

AgentGate ships with starter policies tailored to distinct agent roles:

### 1. `agent.yaml` — Autonomous Agent Seatbelt
Designed for trusted autonomous agents (Claude, Gemini, Cursor) that need freedom to run build commands, diagnostics, and git, while protected against catastrophic accidents:

```yaml
name: agent
description: "Seatbelt policy for autonomous AI agents — broad command execution with strict destructive guardrails"
guardrails: true
allow:
  - command: "*"
    args: ["*"]
deny:
  # Filesystem destruction
  - command: rm
    args: ["-rf", "/*"]
  - command: rm
    args: ["-rf", "/"]
  - command: rm
    args: ["-rf", "~"]
  # Formatting & raw disk writes
  - command: mkfs*
    args: ["*"]
  - command: dd
    args: ["*"]
  # Shutdown & lockout
  - command: shutdown
    args: ["*"]
  - command: reboot
    args: ["*"]
  # Password tampering
  - command: passwd
    args: ["*"]
  - command: cat
    args: ["/etc/shadow"]
```

### 2. `pipeline.yaml` — CI/CD Action Templates
Eliminates arbitrary command execution entirely for automated pipelines. Tokens with this policy can only execute predefined, parameterized action workflows:

```yaml
name: pipeline
description: "CI/CD and automation pipeline policy — named action templates only"
guardrails: true
allow: []
actions:
  deploy:
    description: "Pull latest git changes and restart service"
    steps:
      - "/usr/bin/git -C /var/www/site pull --ff-only"
      - "/usr/bin/systemctl reload nginx"
    stop_on_failure: true
  test:
    description: "Run automated health test"
    steps:
      - "/usr/bin/curl -f http://127.0.0.1:7991/health"
    stop_on_failure: true
```

### 3. `read-only.yaml` — Diagnostics Only
Permits non-modifying diagnostic inspection (`uptime`, `df`, `free`, `ps`, `systemctl status`, `journalctl`, `ss`).

---

## 🔒 Security Architecture & Hardening

### 1. Security Tiers & OS User Isolation
To eliminate single-string root risk, tokens can be bound to isolated system users and security tiers:

```bash
# Create an agent token with dedicated system user 'ag-coder' and 'read' tier:
agentgate token create --name coder --tier read

# Create an ops token with narrow sudoers grants:
agentgate token create --name webops --tier ops

# Create an admin token with mandatory short-lived expiry (max 24h):
agentgate token create --name deployer --tier admin --expires 8h
```

- **`read` tier:** Defaults to `read-only` policy, dedicated OS user `ag-<name>`, zero sudo privileges.
- **`ops` tier:** Dedicated OS user with minimal `/etc/sudoers.d/agentgate-<name>` entry generated specifically for needed commands. Validated with `visudo -cf` before installation.
- **`admin` tier:** Short-lived tokens only (strictly limited to $\le$ 24 hours).

### 2. Narrow Sudoers Generator & GTFOBins Protection
When generating sudoers entries, AgentGate enforces hard security constraints:
- **No GTFOBins:** Binaries with known shell escapes (`vim`, `nano`, `less`, `python3`, `bash`, `find`, `env`, `git`) are strictly rejected.
- **No Wildcards:** Grants must specify fully-qualified absolute paths and exact arguments (e.g. `/usr/bin/systemctl restart nginx`, NOT `/usr/bin/systemctl *`).
- **Syntax Verification:** All generated files are verified with `visudo -cf` in a temporary directory prior to atomic installation to `/etc/sudoers.d/`.

### 3. Direct POSIX Execution (No Shell Parser)
Commands are parsed by `ParsedCommand` and passed as argument arrays directly to `std::process::Command` / `tokio::process::Command`.
- Disallowed metacharacters: `;`, `&`, `|`, `` ` ``, `$`, `(`, `)`, `>`, `<`, `\n`, `\r`.
- Shell injection is stopped at the door because no shell parser ever interprets the command string.

---

## 💻 Client & AI Agent Usage

### CLI Execution
Once logged in via `agentgate login --token <TOKEN>`, commands can be run directly:

```bash
# Diagnostic inspection
agentgate exec uptime
agentgate exec df -h
agentgate exec free -m

# JSON mode (structured machine output for LLM parsing)
agentgate exec --json systemctl status nginx
```

### Model Context Protocol (MCP) Server
Connect Claude Desktop, Cursor, or any MCP-compatible agent directly to AgentGate:

```bash
agentgate mcp
```

Add to your `claude_desktop_config.json`:
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

---

## 📜 Command Reference

### Client CLI (`agentgate`)
| Command | Description |
| :--- | :--- |
| `agentgate` | Launch interactive TUI manager |
| `agentgate start` | Start server in background (like `tailscale up`) |
| `agentgate stop` | Stop background server (like `tailscale down`) |
| `agentgate status` | View server status, network addresses, and active policies |
| `agentgate exec <cmd>` | Execute a command through the gateway |
| `agentgate action <name>` | Execute a named multi-step action template |
| `agentgate token create` | Create a token (`--tier`, `--user-mode`, `--actions`, `--expires`) |
| `agentgate token list` | List all tokens, tiers, OS users, and expiration dates |
| `agentgate token revoke` | Instantly revoke a token and clean up OS users/sudoers |
| `agentgate policy list` | Inspect loaded execution policies |
| `agentgate logs` | View recent command audit logs |
| `agentgate update` | Update AgentGate to the latest release |
| `agentgate mcp` | Start Model Context Protocol server |

### Host Daemon (`agentgated`)
| Command | Description |
| :--- | :--- |
| `agentgated` | Start the foreground HTTP/socket execution server |
| `agentgated totp setup` | Display or generate RFC 6238 TOTP 2FA secret |
| `agentgated totp setup --reset` | Reset and reconfigure TOTP 2FA secret |
| `agentgated totp status` | Check if TOTP 2FA is currently active |

---

## Security Policy

For vulnerability reports and coordinated disclosure procedures, please see [SECURITY.md](file:///var/home/scorpion/agentgate/SECURITY.md).

---

## License

MIT © [Lawrence Mwangi](https://github.com/lawrencemwangi496-design)
