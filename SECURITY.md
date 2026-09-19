# Security Policy

## Supported Versions

Only the latest minor release branch of AgentGate receives active security patches.

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |
| < 0.1.0 | :x:                |

---

## Reporting a Vulnerability

We take the security of AgentGate seriously. If you discover a security vulnerability, please do **NOT** open a public issue or discuss it in public discussion forums.

Please report security issues via email to:
**`security@agentgate.dev`** (or directly contact repository maintainers via GitHub private security advisories).

### What to include in your report:
1. **Description:** A detailed explanation of the vulnerability.
2. **Reproduction:** Exact step-by-step reproduction instructions or proof-of-concept (CLI commands, policy files, payload shapes).
3. **Impact:** The practical security impact (e.g., policy bypass, unauthenticated privilege escalation, denial of service).
4. **Environment:** OS, kernel version, AgentGate version, and whether OS user isolation (`--user-mode`) or tiers were in use.

### Response Timeline
- **Initial Acknowledgement:** Within 48 hours of receipt.
- **Triage & Reproduction:** Within 5 business days.
- **Remediation & Fix:** We work to release patches as quickly as possible.
- **Coordinated Disclosure:** We adhere to a standard **90-day coordinated disclosure policy** to give operators adequate time to upgrade before public disclosure.

---

## Threat Model & Security Architecture

To evaluate AgentGate accurately, operators must understand its design boundaries and threat model.

### 1. Guardrail / "Seatbelt" Model (Default Mode)
In default mode, AgentGate acts as an **ergonomic safety guardrail ("seatbelt")** for **trusted AI agents, CI/CD pipelines, and remote automation**.
- It blocks prompt injection bypasses and accidental catastrophic commands (`rm -rf /`, `/boot` wipes, disk formatting, partition destruction, account lockout).
- It prevents shell metacharacter injection (`;`, `&`, `|`, `` ` ``, `$()`, `>`, `<`) by executing commands directly without an intermediate shell parser.
- It provides cryptographically enforced audit logging with real peer socket IP resolution.

### 2. Multi-Tier Isolation & Narrow Sudo (Hardened Mode)
A bearer token running commands as `root` is fundamentally an open permission. If a trusted agent might hallucinate or if you run third-party autonomous agents, **you should not rely solely on exec denylists**. General-purpose interpreters (`python3`, `node`, `perl`, `bash`), compilers, and binaries documented in GTFOBins can be instructed to perform arbitrary I/O.

To establish **true least-privilege security boundaries**, operators must configure OS user separation:
- **Per-Token OS Users (`--user-mode` / `--os-user`):** The AgentGate daemon executes commands under dedicated, unprivileged system users (e.g., `ag-<name>`), dropping all root privileges, UIDs, GIDs, and supplementary groups via `pre_exec` before process launch.
- **Security Tiers (`--tier read|ops|admin`):**
  - `read`: Diagnostic and monitoring commands only. Zero sudo access granted.
  - `ops`: Limited operational actions. Narrow `/etc/sudoers.d/` grants with fully-qualified paths, exact arguments, no wildcards, and strict prohibition of GTFOBins binaries. Verified with `visudo -cf` prior to installation.
  - `admin`: Elevated maintenance with mandatory short-lived token lifetimes (maximum 24 hours).
- **Named Action Templates (`POST /v1/action/<name>`):** Automated CI/CD pipelines can be granted action-only tokens (`actions: ["deploy"]`) that completely disable arbitrary command execution (`POST /v1/exec`).

---

## What AgentGate Protects Against

- **Catastrophic System Destruction:** Hardened guardrails enforce semantic checks on all command variations (e.g. `rm -r -f /`, `rm --recursive /`, `find / -delete`, `mkfs`, `dd`, `reboot`, permission zeroing) even when policies use `allow: ["*"]`.
- **Shell Parser Injection:** The `ParsedCommand` parser rejects shell metacharacters and executes directly via `std::process::Command` array passing, bypassing shell interpretation.
- **IP Spoofing:** Audit logging relies on socket-level peer IP addresses and strictly rejects forged `X-Forwarded-For` headers unless the request originates from an explicitly trusted proxy.
- **Credential Brute-Forcing & DoS:** Per-IP failure throttling and exponential lockouts mitigate brute-force attempts and audit log bloat.
- **Advisory Token File Corruption:** Concurrent token creation, validation, and revocation are synchronized using in-process mutexes and advisory file locks (`flock`) with atomic temporary file replacement.
- **Supply Chain Tampering:** The installer verifies SHA-256 release checksums and fails closed if integrity verification fails.
