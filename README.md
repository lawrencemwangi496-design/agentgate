# AgentGate 🚪🔒

> **The secure privilege bridge for AI agents.**  
> Give AI coding agents, DevOps bots, and LLMs the ability to execute necessary server commands without ever sharing your sudo password, SSH keys, or root access.

---

## The Problem

When you pair with AI agents (Claude, Gemini, Cursor, ChatGPT, Antigravity) for infrastructure, debugging, and DevOps:
- **No sudo access:** Agents cannot type passwords in interactive terminal prompts.
- **Security nightmare:** Giving an AI agent unrestricted `sudo` or `NOPASSWD: ALL` is dangerous—a single prompt injection or hallucinated `rm` command could destroy your host.
- **Read-only deadlock:** The agent can diagnose issues, but cannot restart a service, check a secured config, or manage containers.

---

## The AgentGate Solution

**AgentGate** is a lightweight, single-binary daemon written in Rust that acts as a secure reverse-proxy gatekeeper for command execution:

1. **Deny-by-default Policy Allowlist:** Agents can *only* run commands explicitly defined in YAML policies.
2. **Zero Shell Execution:** Commands are executed strictly via POSIX `exec` arguments—**never passed to `sh -c` or `bash -c`**. Shell chaining (`;`, `&&`, `|`, `` ` ``, `$()`, redirects) is blocked at the parser level.
3. **Scoped Bearer Tokens:** Create isolated tokens with expiration and specific policy bindings.
4. **Instant Revocation:** Revoke tokens in real-time from the CLI without restarting the daemon.
5. **Full Audit Logging:** Every allowed, denied, and injection-blocked command is recorded with timestamps, durations, and exit codes.
6. **Built-in TLS:** Auto-generates local self-signed certificates on first run.

---

## Quick Start

### 1. Initialize
```bash
agentgate init
```
This generates default directories (`~/.config/agentgate/` or `/etc/agentgate/`), starter policies (`read-only`, `docker-ops`, `webserver-ops`), and local TLS certificates.

### 2. Create a Scoped Token
```bash
agentgate token create --name my-claude-agent --policy read-only
```
Output:
```text
✅ Token created successfully!
----------------------------------------------------------------------
NAME:       my-claude-agent
POLICY:     read-only
EXPIRES:    Never
TOKEN:      ag_9a8b7c6d5e4f...
----------------------------------------------------------------------
⚠️  Save this token now! It will NOT be shown again.
```

### 3. Start the Daemon
```bash
agentgate serve
```
Listens securely on `https://127.0.0.1:7991`.

### 4. Send Commands from AI Agent
```bash
curl -k -X POST https://127.0.0.1:7991/v1/exec \
  -H "Authorization: Bearer ag_9a8b7c6d5e4f..." \
  -H "Content-Type: application/json" \
  -d '{"command": "uptime"}'
```
Response:
```json
{
  "exit_code": 0,
  "stdout": " 14:00:00 up 1 hour, 1 user, load average: 1.20, 1.45, 1.10\n",
  "stderr": "",
  "duration_ms": 4
}
```

---

## Security in Action

### 1. Blocked Unauthorized Command
If the agent attempts to inspect `/etc/shadow`:
```bash
curl -k -X POST https://127.0.0.1:7991/v1/exec \
  -H "Authorization: Bearer ag_..." \
  -H "Content-Type: application/json" \
  -d '{"command": "cat /etc/shadow"}'
```
Response:
```json
{
  "error": "command_denied",
  "message": "command 'cat /etc/shadow' is not allowed by policy 'read-only'",
  "exit_code": -1
}
```

### 2. Blocked Shell Injection Attempt
If an attacker or prompt injection tricks the agent into command chaining:
```bash
curl -k -X POST https://127.0.0.1:7991/v1/exec \
  -H "Authorization: Bearer ag_..." \
  -H "Content-Type: application/json" \
  -d '{"command": "uptime; rm -rf /"}'
```
Response:
```json
{
  "error": "injection_blocked",
  "message": "command contains disallowed shell metacharacter: ';'",
  "exit_code": -1
}
```

### 3. Instant Revocation
```bash
agentgate token revoke my-claude-agent
```
Any subsequent request is immediately returned `401 Unauthorized`.

---

## Audit Logs

Inspect all activity across tokens:
```bash
agentgate logs
```
Output:
```text
╭────────────────┬─────────────────┬─────────────────────────┬───────────┬──────────────────┬──────┬─────────╮
│ TIME           │ TOKEN           │ COMMAND                 │ POLICY    │ RESULT           │ EXIT │ DUR(ms) │
├────────────────┼─────────────────┼─────────────────────────┼───────────┼──────────────────┼──────┼─────────┤
│ 09-18 13:56:44 │ my-claude-agent │ uptime && whoami        │ read-only │ InjectionBlocked │ -1   │ 0       │
│ 09-18 13:56:39 │ my-claude-agent │ uptime; cat /etc/shadow │ read-only │ InjectionBlocked │ -1   │ 0       │
│ 09-18 13:56:33 │ my-claude-agent │ cat /etc/os-release     │ read-only │ Allowed          │ 0    │ 2       │
│ 09-18 13:56:28 │ my-claude-agent │ cat /etc/shadow         │ read-only │ Denied           │ -1   │ 0       │
│ 09-18 13:56:21 │ my-claude-agent │ uptime                  │ read-only │ Allowed          │ 0    │ 8       │
╰────────────────┴─────────────────┴─────────────────────────┴───────────┴──────────────────┴──────┴─────────╯
```

Filter for security events only:
```bash
agentgate logs --denied
```

---

## Policy Definition Syntax

Policies are stored as YAML in `~/.config/agentgate/policies/`:

```yaml
name: webserver-ops
description: "Manage nginx and view system status"
rules:
  - command: systemctl
    args: ["status", "*"]          # Wildcard: check status of any service
  - command: systemctl
    args: ["restart", "nginx"]     # Exact match: can only restart nginx
  - command: journalctl
    args: ["-u", "nginx", "*"]     # Wildcard trailing: read nginx logs
  - command: cat
    args: ["/etc/nginx/nginx.conf"]
  - command: nginx
    args: ["-t"]
```

---

## License
MIT
