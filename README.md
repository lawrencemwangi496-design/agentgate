# AgentGate 🚪⚡

> **The zero-trust privilege gateway for AI agents and LLMs.**  
> Execute commands safely on your Linux machines without sharing SSH keys, exposing passwords, or granting unrestricted `sudo`.

---

## Why AgentGate is Better than SSH for AI Agents

| Feature | SSH / sudo | AgentGate 🚪 |
| :--- | :--- | :--- |
| **Credentials** | Raw SSH private keys or root passwords shared with the LLM | Scoped, revokable SHA-256 tokens (`ag_...`) |
| **Access Control** | All-or-nothing root access (`sudo NOPASSWD: ALL`) | **Universal Guardrails:** AI has freedom to diagnose and build, but destructive commands (`rm -rf /`, `mkfs`, `shutdown`, `passwd`) are permanently blocked at the gateway level |
| **Shell Injection** | Raw PTY allows arbitrary shell piping, background jobs, and escape tricks | **Zero Shell:** Commands execute strictly via POSIX exec (`execvp`). Shell metacharacters (`;`, `&&`, `|`, `` ` ``, `$()`) are blocked at the parser |
| **Audit Trail** | Fragmented bash history (easily wiped or altered) | Immutable, structured audit log (`JSONL`) recording every command, token, duration, and exit code |
| **Revocation** | Rotating SSH keys or changing root passwords disrupts all users | 1-click instant token revocation without stopping the service |
| **Agent Ergonomics** | Fragile SSH timeouts, complex TTY prompts, password hangs | Clean HTTP/REST API, native CLI wrapper (`agentgate exec`), and built-in Model Context Protocol (MCP) server |

---

## ⚡ 1-Minute Quick Start

### 1. Install (Docker-Style Single Binary)

Install directly on your server with root capabilities:

```bash
curl -fsSL https://raw.githubusercontent.com/lawrencemwangi496-design/agentgate/main/install.sh | sudo bash
```

### 2. Launch the Manager

Run `agentgate` to launch the interactive terminal manager:

```bash
agentgate
```

```text
==========================================================
                 🚪 AgentGate Manager
==========================================================
  AgentGate:     🟢 RUNNING (0.0.0.0:7991, PID: 4210)
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

## 🛡️ The Universal Guardrail Policy Engine

AgentGate solves the fundamental tension between **agent autonomy** and **server safety**. Instead of locking the AI in a brittle, narrow allowlist where basic diagnostic flags are blocked, AgentGate uses a **deny-first guardrail policy** (`standard.yaml`):

```yaml
name: standard
description: "General execution with safety guardrails (destructive commands permanently blocked)"
allow:
  - command: "*"
    args: ["*"]
deny:
  # Destructive filesystem wipes
  - command: rm
    args: ["-rf", "/*"]
  - command: rm
    args: ["-rf", "/"]
  - command: rm
    args: ["-rf", "~"]

  # Disk formatting & partition destruction
  - command: mkfs*
    args: ["*"]
  - command: dd
    args: ["*"]
  - command: fdisk
    args: ["*"]
  - command: parted
    args: ["*"]
  - command: wipefs
    args: ["*"]

  # System shutdown & reboot lockout
  - command: shutdown
    args: ["*"]
  - command: reboot
    args: ["*"]
  - command: poweroff
    args: ["*"]
  - command: init
    args: ["0"]

  # User credential hijacking
  - command: passwd
    args: ["*"]
  - command: chpasswd
    args: ["*"]
  - command: cat
    args: ["/etc/shadow"]
  - command: cat
    args: ["*shadow*"]

  # Permission sabotage
  - command: chmod
    args: ["-R", "777", "/"]
  - command: chmod
    args: ["-R", "000", "/"]
```

### What This Means in Practice:
- **AI Freedom:** The agent can run `uptime -p`, `df -h`, `cat /etc/nginx/nginx.conf`, `docker ps`, `systemctl status postgresql`, and compile code without being blocked by missing flags.
- **Strict Protection:** The gateway **rejects any destructive command** in the deny list with exit code `126`, protecting your server from hallucinations, rogue scripts, or prompt injections.
- **Custom Policies:** Any custom policy created with `agentgate policy create <name>` automatically inherits these security guardrails.

---

## 💻 Client & AI Usage

### Seamless CLI Execution

Once connected, your AI agent can execute commands directly without typing passwords or writing brittle `curl` scripts:

```bash
# Diagnostic inspection
agentgate exec uptime
agentgate exec df -h
agentgate exec free -m

# Service management
agentgate exec systemctl status nginx
agentgate exec "docker ps -a"

# JSON output mode (ideal for agent parsing)
agentgate exec --json systemctl status nginx
```

### Model Context Protocol (MCP) Server

AgentGate features native support for the Model Context Protocol:

```bash
agentgate mcp
```
Connect your LLM (Claude Desktop, Cursor, Gemini) directly to AgentGate as an MCP tool provider for zero-overhead, native tool-calling capabilities.

---

## 🔄 Automatic & Seamless Updates

Keep AgentGate updated just like `tailscale update`:

```bash
agentgate update
```

The background server also includes an automatic updater that checks GitHub releases every 30 minutes to ensure you always have the latest security patches.

---

## 🔒 Security Architecture

1. **POSIX Argument Execution:** Commands are parsed and executed directly using `std::process::Command` without invoking `/bin/sh` or `/bin/bash`.
2. **Strict Injection Filtering:** Shell chaining characters (`;`, `&&`, `||`, `` ` ``, `$()`, `>`, `<`, `\n`) are rejected at the parser level before process creation.
3. **Constant-Time Verification:** Bearer tokens are hashed with SHA-256 and compared using constant-time algorithms (`subtle::ConstantTimeEq`) to prevent timing attacks.
4. **Denial-of-Service Defense:** Request body limits (64KB) and concurrency rate limiting (128 max concurrent requests) protect server resources.
5. **Detailed Audit Trail:** Every event is logged to `~/.config/agentgate/logs/audit-YYYY-MM-DD.jsonl`.

---

## 📜 CLI Reference

| Command | Description |
| :--- | :--- |
| `agentgate` | Launch interactive TUI manager |
| `agentgate start` | Start server in the background (like `tailscale up`) |
| `agentgate stop` | Stop background server (like `tailscale down`) |
| `agentgate status` | View server PID, network addresses, and active policies |
| `agentgate exec <cmd>` | Execute a command through the gateway |
| `agentgate token create` | Generate a new scoped agent token |
| `agentgate token list` | List all registered tokens and expiration dates |
| `agentgate token revoke` | Instantly revoke an agent token |
| `agentgate policy list` | Inspect loaded execution policies |
| `agentgate logs` | View recent command audit logs |
| `agentgate update` | Update AgentGate to the latest release |
| `agentgate mcp` | Start Model Context Protocol server |

---

## License

MIT © [Lawrence Mwangi](https://github.com/lawrencemwangi496-design)
