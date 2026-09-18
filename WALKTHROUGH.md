# ShipAI Video Submission Walkthrough & Script 🎬

> **Target length:** 5 to 7 minutes  
> **Tools:** OBS Studio (screen capture), Gemini (voiceover), Kdenlive (trimming & audio sync)

---

## Video Outline & Timeline

| Time | Scene / Screen Action | Voiceover Script (Feed into Gemini TTS) |
|---|---|---|
| **0:00 - 1:00** | **The Sudo Problem:** Open terminal. Run `sudo systemctl restart sshd`. Show `sudo: a password is required`. Try `cat /etc/shadow` -> `Permission denied`. | "AI agents are transforming software engineering, but the moment an agent tries to touch a Linux server or DevOps pipeline, it hits an iron wall: privilege boundaries. You cannot give an AI agent your sudo password. And giving it NOPASSWD in sudoers is an unmitigated disaster if the model hallucinates or gets prompt-injected. That leaves agents as powerless, read-only spectators." |
| **1:00 - 2:00** | **Introducing AgentGate:** Switch to terminal or slide showing AgentGate architecture. | "To solve this, I built AgentGate. AgentGate is a lightweight Rust daemon that acts as a secure, scoped privilege proxy for AI agents. Instead of passwords or raw SSH keys, the agent interacts with an API using scoped bearer tokens, bound to strict deny-by-default allowlist policies. Most importantly: AgentGate never invokes a shell, making command injection impossible." |
| **2:00 - 3:15** | **Initialization & Policies:** Run `agentgate init`. Run `agentgate policy list`. Run `agentgate policy show webserver-ops`. | "Setup takes one command: `agentgate init`. This creates our directories, generates self-signed TLS certificates, and installs starter policies like read-only diagnostics, Docker operations, and web server management. Looking at the webserver-ops policy, notice how granular it is: the agent is permitted to check systemctl status for any service, but it can only restart nginx, and test nginx configs. Nothing else." |
| **3:15 - 4:15** | **Token Generation & Daemon Start:** Run `agentgate token create --name devops-agent --policy read-only`. Show the token output. Start `agentgate serve` in split terminal. Run `agentgate status`. | "Now we issue a scoped token for our AI agent with `agentgate token create`. The 256-bit token is displayed once and hashed on disk with SHA-256. We start the daemon with `agentgate serve`, listening locally over TLS on port 7991. Running `agentgate status` confirms the bridge is active and ready." |
| **4:15 - 5:30** | **Live Execution & Security Proof:** <br>1. Run curl with `uptime` -> Success.<br>2. Run curl with `cat /etc/shadow` -> Rejected `command_denied`.<br>3. Run curl with `uptime; rm -rf /` -> Rejected `injection_blocked`. | "Now let's watch it work. First, the agent sends an approved command: uptime. The daemon verifies the token, checks the policy, executes the binary, and returns the exit code and output in under 5 milliseconds. Next, what happens if the agent attempts an unauthorized action like reading `/etc/shadow`? AgentGate immediately blocks it with a 403 Forbidden: command denied by policy. And if an attacker attempts prompt injection, trying to chain commands with semicolons or ampersands, the parser detects shell metacharacters and blocks it before any process is spawned." |
| **5:30 - 6:30** | **Audit Trail & Instant Revocation:** Run `agentgate logs`. Show the table. Run `agentgate token revoke devops-agent`. Re-run curl -> 401 Unauthorized. | "Every single action—allowed, denied, or injection-blocked—is recorded in a structured audit log. Running `agentgate logs` gives operators immediate forensic visibility. And if an agent goes rogue or completes its job, revoking access is instantaneous with `agentgate token revoke`. Subsequent requests are rejected immediately without needing to restart the daemon." |
| **6:30 - 7:00** | **Closing Thoughts:** Terminal showing clean status. | "Video shows what benchmark claims don't: the real boundary of AI in infrastructure. With AgentGate, we don't have to choose between total agent paralysis and total system compromise. We give agents exactly the agency they need, and not an ounce more." |

---

## Step-by-Step Recording Guide with OBS & Kdenlive

### 1. Record Screen with OBS
- Set resolution to 1080p (1920x1080) at 30 or 60 fps.
- Use a clean terminal font (e.g. Fira Code, JetBrains Mono, size 16-18) so viewers on laptop screens can read easily.
- Run through the commands in order using a split-terminal or tmux layout.

### 2. Generate Voiceover with Gemini
- Paste the text snippets from the table above into Gemini or Google Text-to-Speech / ElevenLabs.
- Export the generated audio as `.wav` or `.mp3`.

### 3. Edit in Kdenlive
- Import your OBS screen recording `.mp4` into Track 1.
- Import your Gemini voiceover audio into Audio Track 1.
- Use Kdenlive's razor tool (`X`) to align cuts and trim pauses so the screen action matches the voice.
- Add simple text lower-thirds (e.g. "Command Allowlisting", "Zero Shell Execution", "Instant Revocation").
- Export as MP4 (H.264 / AAC).
- Submit link to [Towards Data Science ShipAI](https://towardsdatascience.com/shipai)!
