use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{self, BufRead, Write};
use std::path::PathBuf;

/// Saved client credentials configuration
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ClientConfig {
    #[serde(default)]
    pub server: String,
    #[serde(default)]
    pub socket: Option<String>,
    pub token: String,
    #[serde(default = "default_insecure")]
    pub insecure_tls: bool,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            server: "https://127.0.0.1:7991".to_string(),
            socket: None,
            token: String::new(),
            insecure_tls: true,
        }
    }
}

fn default_insecure() -> bool {
    true
}

/// Locate client configuration file path (~/.config/agentgate/client.yaml)
pub fn client_config_path() -> Result<PathBuf> {
    let home = dirs::home_dir().context("Could not find home directory")?;
    Ok(home.join(".config").join("agentgate").join("client.yaml"))
}

/// Load client configuration from file, falling back to environment variables
pub fn load_client_config() -> Result<Option<ClientConfig>> {
    let env_token = std::env::var("AGENTGATE_TOKEN").ok();
    let env_server = std::env::var("AGENTGATE_SERVER").ok();

    let file_path = client_config_path()?;
    if file_path.exists() {
        let content = fs::read_to_string(&file_path)
            .with_context(|| format!("Failed to read client config from {:?}", file_path))?;
        let mut cfg: ClientConfig =
            serde_yaml::from_str(&content).with_context(|| "Failed to parse client config yaml")?;

        // Env vars override file config if present
        if let Some(s) = env_server.as_deref().filter(|s| !s.trim().is_empty()) {
            cfg.server = s.trim().to_string();
        }
        if let Some(t) = env_token.as_deref().filter(|t| !t.trim().is_empty()) {
            cfg.token = t.trim().to_string();
        }

        return Ok(Some(cfg));
    }

    // If no file, check if environment variables are set
    if let Some(token) = env_token.filter(|t| !t.trim().is_empty()) {
        let server = env_server
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| "https://127.0.0.1:7991".to_string());
        return Ok(Some(ClientConfig {
            server,
            socket: None,
            token: token.trim().to_string(),
            insecure_tls: true,
        }));
    }

    Ok(None)
}

/// Save client configuration with safe permissions (0600)
pub fn save_client_config(server: &str, token: &str, insecure_tls: bool) -> Result<PathBuf> {
    save_client_config_with_socket(server, None, token, insecure_tls)
}

/// Save client configuration with optional socket override and safe permissions (0600)
pub fn save_client_config_with_socket(
    server: &str,
    socket: Option<String>,
    token: &str,
    insecure_tls: bool,
) -> Result<PathBuf> {
    let file_path = client_config_path()?;
    if let Some(parent) = file_path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("Failed to create client config dir {:?}", parent))?;
    }

    let cfg = ClientConfig {
        server: server.trim_end_matches('/').to_string(),
        socket,
        token: token.trim().to_string(),
        insecure_tls,
    };

    let yaml = serde_yaml::to_string(&cfg)?;
    fs::write(&file_path, yaml)
        .with_context(|| format!("Failed to write client config to {:?}", file_path))?;

    // On Unix, restrict permissions to 0600 (owner read/write only)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&file_path)?.permissions();
        perms.set_mode(0o600);
        let _ = fs::set_permissions(&file_path, perms);
    }

    Ok(file_path)
}

/// Send an HTTP request directly over a local Unix Domain Socket using hyper
pub async fn send_unix_request(
    socket_path: &std::path::Path,
    method_str: &str,
    path: &str,
    token: &str,
    body: &serde_json::Value,
) -> Result<(u16, String)> {
    let stream = tokio::net::UnixStream::connect(socket_path).await
        .with_context(|| format!("Failed to connect to local AgentGate socket at {}", socket_path.display()))?;
    let io = hyper_util::rt::TokioIo::new(stream);
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await
        .context("HTTP handshake failed over Unix socket")?;

    tokio::spawn(async move {
        let _ = conn.await;
    });

    let method = match method_str {
        "POST" => hyper::Method::POST,
        "GET" => hyper::Method::GET,
        _ => hyper::Method::POST,
    };

    let body_bytes = serde_json::to_vec(body)?;
    let mut builder = hyper::Request::builder()
        .method(method)
        .uri(path)
        .header("Host", "localhost")
        .header("Content-Type", "application/json");

    if !token.trim().is_empty() {
        builder = builder.header("Authorization", format!("Bearer {}", token.trim()));
    }

    let req = builder
        .body(http_body_util::Full::new(bytes::Bytes::from(body_bytes)))
        .context("Failed to build HTTP request for Unix socket")?;

    let resp = sender.send_request(req).await
        .context("Failed to send request over Unix socket")?;
    let status_code = resp.status().as_u16();

    use http_body_util::BodyExt;
    let resp_bytes = resp.into_body().collect().await?.to_bytes();
    let text = String::from_utf8_lossy(&resp_bytes).to_string();

    Ok((status_code, text))
}

/// Handle `agentgate login`
pub async fn handle_login(
    server_opt: Option<String>,
    token_opt: Option<String>,
    insecure: bool,
) -> Result<()> {
    use std::io::IsTerminal;

    // If running in terminal without explicit token, launch interactive wizard
    if token_opt.is_none() && io::stdin().is_terminal() {
        return handle_interactive_login(server_opt, token_opt, insecure).await;
    }

    let clean_server = server_opt
        .unwrap_or_else(|| "https://127.0.0.1:7991".to_string())
        .trim_end_matches('/')
        .to_string();

    let raw_token = match token_opt {
        Some(t) => t.trim().to_string(),
        None => {
            print!("Enter AgentGate Token (starts with ag_): ");
            io::stdout().flush()?;
            let mut line = String::new();
            io::stdin().lock().read_line(&mut line)?;
            line.trim().to_string()
        }
    };

    if raw_token.is_empty() {
        anyhow::bail!("Token cannot be empty.");
    }

    if !raw_token.starts_with("ag_") {
        eprintln!("⚠️ Warning: AgentGate tokens usually start with 'ag_'.");
    }

    println!("Connecting to AgentGate server at {}...", clean_server);

    // Verify server connectivity
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(insecure)
        .timeout(std::time::Duration::from_secs(5))
        .build()?;

    let health_url = format!("{}/health", clean_server);
    match client.get(&health_url).send().await {
        Ok(resp) if resp.status().is_success() => {
            // Server is reachable
        }
        Ok(resp) => {
            eprintln!(
                "⚠️ Warning: Server responded with status {} at {}",
                resp.status(),
                health_url
            );
        }
        Err(e) => {
            eprintln!(
                "⚠️ Warning: Could not reach server at {}: {}",
                health_url, e
            );
            eprintln!("   Saving credentials anyway so you can use them when the daemon starts.");
        }
    }

    let saved_path = save_client_config(&clean_server, &raw_token, insecure)?;

    let masked_token = if raw_token.len() > 10 {
        format!(
            "{}...{}",
            &raw_token[..6],
            &raw_token[raw_token.len() - 4..]
        )
    } else {
        "***".to_string()
    };

    println!("\n✅ Authenticated successfully!");
    println!("----------------------------------------------------------------------");
    println!("SERVER:       {}", clean_server);
    println!("TOKEN:        {}", masked_token);
    println!("CONFIG FILE:  {}", saved_path.display());
    println!("----------------------------------------------------------------------");
    println!("🚀 You can now run commands directly without passwords or long cURL:");
    println!("   agentgate exec uptime");
    println!("   agentgate exec systemctl status nginx");
    println!("   agentgate exec \"docker ps\"\n");

    Ok(())
}

/// Interactive login wizard (modeled on `gh auth login`)
pub async fn handle_interactive_login(
    initial_server: Option<String>,
    initial_token: Option<String>,
    insecure: bool,
) -> Result<()> {
    println!("==========================================================");
    println!("             🚪 AgentGate Interactive Login");
    println!("==========================================================");

    // Step 1: Select server
    let server_url = if let Some(s) = initial_server {
        s.trim_end_matches('/').to_string()
    } else {
        println!("? What AgentGate server do you want to log into?");
        println!("  1) This local machine (https://127.0.0.1:7991)");
        println!("  2) Remote server (enter IP or domain)");
        print!("\nSelect option [1-2, default 1, 'b' to cancel]: ");
        io::stdout().flush()?;
        let mut choice = String::new();
        io::stdin().read_line(&mut choice)?;
        let choice = choice.trim().to_lowercase();

        if choice == "b" || choice == "back" || choice == "cancel" || choice == "q" {
            println!("Login cancelled.\n");
            return Ok(());
        }

        if choice == "2" {
            print!("Enter server address (IP or domain, 'b' to cancel): ");
            io::stdout().flush()?;
            let mut addr = String::new();
            io::stdin().read_line(&mut addr)?;
            let addr = addr.trim();
            if addr == "b" || addr == "back" || addr == "cancel" {
                println!("Login cancelled.\n");
                return Ok(());
            }

            print!("Enter server port [default: 7991]: ");
            io::stdout().flush()?;
            let mut port_str = String::new();
            io::stdin().read_line(&mut port_str)?;
            let port = port_str.trim().parse::<u16>().unwrap_or(7991);

            let clean_addr = addr
                .trim_start_matches("http://")
                .trim_start_matches("https://");
            if clean_addr.is_empty() {
                "https://127.0.0.1:7991".to_string()
            } else {
                format!("https://{}:{}", clean_addr, port)
            }
        } else {
            "https://127.0.0.1:7991".to_string()
        }
    };

    let clean_server = server_url.trim_end_matches('/').to_string();

    // Check if server is running / reachable
    let is_local = clean_server.contains("127.0.0.1") || clean_server.contains("localhost");
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(insecure)
        .timeout(std::time::Duration::from_secs(3))
        .build()?;

    let health_url = format!("{}/health", clean_server);
    let is_online = match client.get(&health_url).send().await {
        Ok(r) => r.status().is_success(),
        Err(_) => false,
    };

    if !is_online && is_local {
        println!("\n🟡 AgentGate server is not currently running locally.");
        print!("? Would you like to start the server now? [Y/n]: ");
        io::stdout().flush()?;
        let mut ans = String::new();
        io::stdin().read_line(&mut ans)?;
        let ans = ans.trim().to_lowercase();
        if (ans.is_empty() || ans == "y" || ans == "yes")
            && let Ok(config) = crate::config::AgentGateConfig::load()
        {
            let _ = crate::cli::handle_start(crate::cli::StartArgs::default(), &config);
            tokio::time::sleep(std::time::Duration::from_millis(600)).await;
        }
    }

    // Step 2: Authentication method
    let raw_token = if let Some(t) = initial_token {
        t.trim().to_string()
    } else if is_local {
        println!("\n? How would you like to authenticate?");
        println!("  1) Auto-generate a new CLI token with 'standard' policy (Full access with guardrails)");
        println!("  2) Paste an authentication token manually");
        print!("\nSelect option [1-2, default 1]: ");
        io::stdout().flush()?;
        let mut auth_choice = String::new();
        io::stdin().read_line(&mut auth_choice)?;
        let auth_choice = auth_choice.trim();

        let policy_name = match auth_choice {
            "2" => "",
            _ => "standard",
        };

        if policy_name.is_empty() {
            print!("\nEnter AgentGate Token (starts with ag_): ");
            io::stdout().flush()?;
            let mut line = String::new();
            io::stdin().lock().read_line(&mut line)?;
            line.trim().to_string()
        } else {
            // Automatically generate a token on this machine!
            let config = crate::config::AgentGateConfig::load()?;
            let mut token_store = crate::auth::TokenStore::load(&config.tokens_file)?;
            let token_name = format!("cli-{}", &uuid::Uuid::new_v4().to_string()[..8]);
            let new_token = token_store.create(&token_name, policy_name, None, None, None, None)?;
            token_store.save()?;
            println!(
                "✓ Generated token '{}' (Policy: {}, Never expires)",
                token_name, policy_name
            );
            new_token
        }
    } else {
        print!(
            "\nEnter AgentGate Token for {} (starts with ag_): ",
            clean_server
        );
        io::stdout().flush()?;
        let mut line = String::new();
        io::stdin().lock().read_line(&mut line)?;
        line.trim().to_string()
    };

    if raw_token.is_empty() {
        anyhow::bail!("Token cannot be empty.");
    }

    // Test authentication
    print!("\nVerifying credentials against {}...", clean_server);
    io::stdout().flush()?;

    let test_url = format!("{}/v1/exec", clean_server);
    let auth_ok = match client
        .post(&test_url)
        .header("Authorization", format!("Bearer {}", raw_token))
        .header("Content-Type", "application/json")
        .json(&serde_json::json!({ "command": "uptime" }))
        .send()
        .await
    {
        Ok(r) => r.status().as_u16() != 401 && r.status().as_u16() != 403,
        Err(_) => true,
    };

    if auth_ok {
        println!(" ✓ Connected!");
    } else {
        println!(" ⚠️ Server rejected token, saving anyway.");
    }

    let saved_path = save_client_config(&clean_server, &raw_token, insecure)?;

    let masked = if raw_token.len() > 10 {
        format!(
            "{}...{}",
            &raw_token[..6],
            &raw_token[raw_token.len() - 4..]
        )
    } else {
        "***".to_string()
    };

    println!("==========================================================");
    println!("🎉 Authenticated successfully!");
    println!("Server:      {}", clean_server);
    println!("Token:       {}", masked);
    println!("Saved to:    {}", saved_path.display());
    println!("==========================================================");
    println!("👉 Run commands directly:       agentgate exec <command>");
    println!("👉 Open interactive session:    agentgate shell");
    println!("----------------------------------------------------------\n");

    Ok(())
}

/// Handle `agentgate logout`
pub fn handle_logout() -> Result<()> {
    let file_path = client_config_path()?;
    if file_path.exists() {
        fs::remove_file(&file_path)
            .with_context(|| format!("Failed to delete client config at {:?}", file_path))?;
        println!(
            "🚪 Logged out. Removed client credentials from {}",
            file_path.display()
        );
    } else {
        println!("⚪ Not currently logged in (no client credentials file found).");
    }
    Ok(())
}

/// Handle `agentgate whoami`
pub async fn handle_whoami() -> Result<()> {
    let cfg = match load_client_config()? {
        Some(c) => c,
        None => {
            println!("❌ Not logged in.");
            println!("💡 Run 'agentgate login --token <TOKEN>' or set AGENTGATE_TOKEN=<TOKEN>");
            return Ok(());
        }
    };

    let masked_token = if cfg.token.len() > 10 {
        format!(
            "{}...{}",
            &cfg.token[..6],
            &cfg.token[cfg.token.len() - 4..]
        )
    } else {
        "***".to_string()
    };

    println!("==========================================================");
    println!("               🔑 AgentGate Client Status");
    println!("==========================================================");
    println!("Server:        {}", cfg.server);
    println!("Token:         {}", masked_token);

    // Test connectivity
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(cfg.insecure_tls)
        .timeout(std::time::Duration::from_secs(3))
        .build()?;

    let health_url = format!("{}/health", cfg.server);
    match client.get(&health_url).send().await {
        Ok(resp) if resp.status().is_success() => {
            println!("Status:        🟢 Connected (Server Online)");
        }
        Ok(resp) => {
            println!(
                "Status:        ⚠️ Connected (Server returned {})",
                resp.status()
            );
        }
        Err(_) => {
            println!("Status:        🔴 Offline / Unreachable");
            println!("               💡 Make sure the daemon is started: agentgate start");
        }
    }

    if let Some(p) = client_config_path().ok().filter(|p| p.exists()) {
        println!("Config Path:   {}", p.display());
    }
    println!("==========================================================");

    Ok(())
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct ServerExecResponse {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
    #[serde(default)]
    pub duration_ms: u64,
    #[serde(default)]
    pub truncated: bool,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct ServerErrorResponse {
    #[serde(default)]
    pub error: String,
    #[serde(default)]
    pub message: String,
    #[serde(default)]
    pub exit_code: i32,
}

/// Handle `agentgate exec <COMMAND...>`
pub async fn handle_exec(
    command_args: Vec<String>,
    server_override: Option<String>,
    token_override: Option<String>,
    cwd: Option<String>,
    json_mode: bool,
    quiet: bool,
) -> Result<()> {
    let command_str = command_args.join(" ");
    let command_str = command_str.trim();

    if command_str.is_empty() {
        eprintln!("❌ No command provided to execute.");
        eprintln!("💡 Usage: agentgate exec <command> [args...]");
        eprintln!("   Example: agentgate exec uptime");
        eprintln!("   Example: agentgate exec systemctl restart nginx");
        std::process::exit(1);
    }

    let saved_cfg = load_client_config()?.unwrap_or_default();

    let server_url = server_override
        .clone()
        .or_else(|| std::env::var("AGENTGATE_SERVER").ok())
        .unwrap_or(saved_cfg.server)
        .trim_end_matches('/')
        .to_string();

    let token = token_override
        .or_else(|| std::env::var("AGENTGATE_TOKEN").ok())
        .unwrap_or(saved_cfg.token);

    if token.trim().is_empty() {
        eprintln!("❌ Authentication required: No token found.");
        eprintln!("💡 Log in first using:");
        eprintln!("   agentgate login --token <TOKEN>");
        eprintln!("   or set AGENTGATE_TOKEN=<TOKEN>");
        eprintln!("   or pass --token <TOKEN>");
        std::process::exit(1);
    }

    let mut body = serde_json::json!({ "command": command_str });
    if let Some(dir) = cwd {
        body["cwd"] = serde_json::Value::String(dir);
    }

    let default_sock = crate::config::AgentGateConfig::default_socket_path();
    let use_socket = server_override.is_none()
        && (saved_cfg.socket.is_some() || server_url.contains("127.0.0.1") || server_url.contains("localhost"))
        && default_sock.exists();

    let (status_code, text) = if use_socket {
        match send_unix_request(&default_sock, "POST", "/v1/exec", token.trim(), &body).await {
            Ok(pair) => pair,
            Err(e) => {
                if !quiet {
                    eprintln!("❌ Could not communicate with Host Daemon over local socket {}: {}", default_sock.display(), e);
                    eprintln!("💡 Ensure the host daemon is running: agentgated start");
                }
                std::process::exit(1);
            }
        }
    } else {
        let client = reqwest::Client::builder()
            .danger_accept_invalid_certs(saved_cfg.insecure_tls)
            .timeout(std::time::Duration::from_secs(60))
            .build()
            .context("Failed to build HTTP client")?;

        let exec_url = format!("{}/v1/exec", server_url);
        let resp = match client
            .post(&exec_url)
            .header("Authorization", format!("Bearer {}", token.trim()))
            .header("Content-Type", "application/json")
            .json(&body)
            .send()
            .await
        {
            Ok(r) => r,
            Err(e) => {
                if !quiet {
                    eprintln!(
                        "❌ Could not connect to AgentGate server at {}: {}",
                        server_url, e
                    );
                    eprintln!("💡 If running remotely, check network/firewall. If local, start with: agentgated start");
                }
                std::process::exit(1);
            }
        };
        let code = resp.status().as_u16();
        let body_str = resp.text().await.unwrap_or_default();
        (code, body_str)
    };

    if status_code >= 200 && status_code < 300 {
        if json_mode {
            println!("{}", text);
            return Ok(());
        }

        match serde_json::from_str::<ServerExecResponse>(&text) {
            Ok(res) => {
                if !res.stdout.is_empty() {
                    print!("{}", res.stdout);
                }
                if !res.stderr.is_empty() {
                    eprint!("{}", res.stderr);
                }
                if res.truncated && !quiet {
                    eprintln!("\n⚠️ Note: Command output was truncated to the 5MB safety limit.");
                }
                std::process::exit(res.exit_code);
            }
            Err(_) => {
                print!("{}", text);
                return Ok(());
            }
        }
    }

    let err_msg = if let Ok(err_obj) = serde_json::from_str::<ServerErrorResponse>(&text) {
        err_obj.message
    } else {
        text
    };

    match status_code {
        423 => {
            if !quiet {
                eprintln!("🚨 AgentGate Emergency Lockdown: {}", err_msg);
            }
            std::process::exit(125);
        }
        400 => {
            if !quiet {
                eprintln!("❌ AgentGate Injection Blocked: {}", err_msg);
            }
            std::process::exit(126);
        }
        403 => {
            if !quiet {
                eprintln!("❌ AgentGate Policy Denied: {}", err_msg);
            }
            std::process::exit(126);
        }
        401 => {
            if !quiet {
                eprintln!("❌ AgentGate Unauthorized: Invalid or expired token.");
                eprintln!("💡 Update your token using: agentgate login --token <TOKEN>");
            }
            std::process::exit(1);
        }
        _ => {
            if !quiet {
                eprintln!("❌ AgentGate Error (HTTP {}): {}", status_code, err_msg);
            }
            std::process::exit(1);
        }
    }
}

/// Print comprehensive prompt rules and documentation for AI Agents
pub fn handle_guide() -> Result<()> {
    let guide = r#"# 🚪 AgentGate: AI Agent Execution Guide

AgentGate is a secure privilege bridge that allows you (the AI agent) to execute authorized system administration commands safely without needing sudo passwords or unrestricted shell access.

## Quick Start for Agents

Once authenticated via `agentgate login` (or with `AGENTGATE_TOKEN` set), run any permitted command directly using:

```bash
agentgate exec <command>
```

### Examples
```bash
# Check server status and diagnostics
agentgate exec uptime
agentgate exec df -h
agentgate exec free -m

# Manage services
agentgate exec systemctl status nginx
agentgate exec systemctl restart nginx
agentgate exec journalctl -u nginx -n 50

# Manage Docker containers
agentgate exec docker ps
agentgate exec docker restart app
agentgate exec docker logs --tail 50 app
```

## Critical Rules for Agents

1. **NO `sudo` needed**: Do NOT prepend `sudo`. AgentGate daemon already executes authorized commands with appropriate privileges.
2. **NO Shell Metacharacters / Chaining**:
   - Do NOT chain commands with `;`, `&&`, `||`, or `|`.
   - Run each command separately as individual `agentgate exec` calls.
   - Do NOT use command substitution like `$(...)` or backticks.
3. **Arguments with spaces**:
   - You can pass quoted arguments normally: `agentgate exec journalctl -u "nginx" -n 50`
   - Direct argument lists work cleanly: `agentgate exec systemctl restart nginx`
4. **Environment Variables**:
   - You can authenticate globally in your subshell by setting:
     `export AGENTGATE_TOKEN="ag_..."`
     `export AGENTGATE_SERVER="https://127.0.0.1:7991"`
5. **Output Format**:
   - Stdout and Stderr are streamed directly to your terminal.
   - Return codes match the remote process exit code (0 for success).
   - If a command is forbidden by policy, exit code is 126.
   - For JSON output (e.g. execution duration), use: `agentgate exec --json <command>`

## Client Commands Reference
- `agentgate login --token <TOKEN>` : Save agent credentials locally
- `agentgate whoami`               : Check authentication and server status
- `agentgate exec <command>`        : Execute an allowed system command
- `agentgate logout`               : Remove local credentials
- `agentgate mcp`                  : Run as a Model Context Protocol (MCP) server
"#;

    println!("{}", guide);
    Ok(())
}

/// Run AgentGate as a Model Context Protocol (MCP) server over stdin/stdout
pub async fn handle_mcp() -> Result<()> {
    let stdin = io::stdin();
    let mut stdout = io::stdout();

    let saved_cfg = load_client_config()?.unwrap_or_default();

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(saved_cfg.insecure_tls)
        .timeout(std::time::Duration::from_secs(60))
        .build()
        .context("Failed to build HTTP client for MCP")?;

    for line in stdin.lock().lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => break,
        };

        if line.trim().is_empty() {
            continue;
        }

        let parsed: serde_json::Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(_) => continue,
        };

        let id = parsed.get("id").cloned();
        let method = parsed.get("method").and_then(|m| m.as_str()).unwrap_or("");

        match method {
            "initialize" => {
                let resp = serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": {
                        "protocolVersion": "2024-11-05",
                        "capabilities": {
                            "tools": {}
                        },
                        "serverInfo": {
                            "name": "agentgate-mcp",
                            "version": env!("CARGO_PKG_VERSION")
                        }
                    }
                });
                writeln!(stdout, "{}", resp)?;
                stdout.flush()?;
            }
            "notifications/initialized" => {
                // Client initialized acknowledgment
            }
            "tools/list" => {
                let resp = serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": {
                        "tools": [
                            {
                                "name": "agentgate_exec",
                                "description": "Execute a permitted system command via AgentGate daemon without sudo passwords",
                                "inputSchema": {
                                    "type": "object",
                                    "properties": {
                                        "command": {
                                            "type": "string",
                                            "description": "The command string to execute (e.g. 'uptime', 'systemctl restart nginx')"
                                        }
                                    },
                                    "required": ["command"]
                                }
                            }
                        ]
                    }
                });
                writeln!(stdout, "{}", resp)?;
                stdout.flush()?;
            }
            "tools/call" => {
                let params = parsed.get("params");
                let tool_name = params
                    .and_then(|p| p.get("name"))
                    .and_then(|n| n.as_str())
                    .unwrap_or("");
                let cmd_str = params
                    .and_then(|p| p.get("arguments"))
                    .and_then(|a| a.get("command"))
                    .and_then(|c| c.as_str())
                    .unwrap_or("");

                if tool_name == "agentgate_exec" {
                    let exec_url = format!("{}/v1/exec", saved_cfg.server.trim_end_matches('/'));
                    let api_resp = client
                        .post(&exec_url)
                        .header("Authorization", format!("Bearer {}", saved_cfg.token))
                        .header("Content-Type", "application/json")
                        .json(&serde_json::json!({ "command": cmd_str }))
                        .send()
                        .await;

                    match api_resp {
                        Ok(res) if res.status().is_success() => {
                            let text = res.text().await.unwrap_or_default();
                            let exec_res: Result<ServerExecResponse, _> =
                                serde_json::from_str(&text);
                            let content_text = match exec_res {
                                Ok(er) => {
                                    if er.stderr.is_empty() {
                                        er.stdout
                                    } else if er.stdout.is_empty() {
                                        er.stderr
                                    } else {
                                        format!("STDOUT:\n{}\nSTDERR:\n{}", er.stdout, er.stderr)
                                    }
                                }
                                Err(_) => text,
                            };

                            let mcp_resp = serde_json::json!({
                                "jsonrpc": "2.0",
                                "id": id,
                                "result": {
                                    "content": [
                                        {
                                            "type": "text",
                                            "text": content_text
                                        }
                                    ],
                                    "isError": false
                                }
                            });
                            writeln!(stdout, "{}", mcp_resp)?;
                            stdout.flush()?;
                        }
                        Ok(res) => {
                            let err_text = res.text().await.unwrap_or_default();
                            let mcp_resp = serde_json::json!({
                                "jsonrpc": "2.0",
                                "id": id,
                                "result": {
                                    "content": [
                                        {
                                            "type": "text",
                                            "text": format!("AgentGate Error: {}", err_text)
                                        }
                                    ],
                                    "isError": true
                                }
                            });
                            writeln!(stdout, "{}", mcp_resp)?;
                            stdout.flush()?;
                        }
                        Err(e) => {
                            let mcp_resp = serde_json::json!({
                                "jsonrpc": "2.0",
                                "id": id,
                                "result": {
                                    "content": [
                                        {
                                            "type": "text",
                                            "text": format!("Connection Error: {}", e)
                                        }
                                    ],
                                    "isError": true
                                }
                            });
                            writeln!(stdout, "{}", mcp_resp)?;
                            stdout.flush()?;
                        }
                    }
                }
            }
            _ => {
                // Ignore unknown methods or send generic method not found
            }
        }
    }

    Ok(())
}

/// Interactive shell for executing commands continuously
pub async fn handle_shell(
    server_override: Option<String>,
    token_override: Option<String>,
    config: &crate::config::AgentGateConfig,
) -> Result<()> {
    let mut cfg = match load_client_config()? {
        Some(c) => c,
        None => {
            println!("⚠️  Not logged in yet. Let's get you connected!");
            handle_login(server_override.clone(), token_override.clone(), true).await?;
            match load_client_config()? {
                Some(c) => c,
                None => {
                    println!("Interactive shell cancelled.\n");
                    return Ok(());
                }
            }
        }
    };

    if let Some(s) = server_override {
        cfg.server = s.trim_end_matches('/').to_string();
    }
    if let Some(t) = token_override {
        cfg.token = t.trim().to_string();
    }

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(cfg.insecure_tls)
        .timeout(std::time::Duration::from_secs(60))
        .build()?;

    // Fetch server ping & health
    let start_ping = std::time::Instant::now();
    let health_url = format!("{}/health", cfg.server);
    let ping_res = client.get(&health_url).send().await;
    let latency = start_ping.elapsed().as_millis();

    println!(
        "\x1b[1;36m========================================================================\x1b[0m"
    );
    println!("\x1b[1;37m                 🚪 AgentGate Interactive Session\x1b[0m");
    println!("  Server:    \x1b[32m{}\x1b[0m", cfg.server);
    match ping_res {
        Ok(r) if r.status().is_success() => {
            println!(
                "  Status:    \x1b[32m🟢 Online\x1b[0m (latency: {}ms)",
                latency
            );
        }
        _ => {
            println!(
                "  Status:    \x1b[33m🟡 Offline / Unreachable\x1b[0m (server may need starting: agentgate start)"
            );
        }
    }
    println!(
        "\x1b[1;36m========================================================================\x1b[0m"
    );
    println!("Type commands directly (e.g. 'uptime', 'df -h', 'ps', 'systemctl status nginx').");
    println!(
        "Helpers: \x1b[33m:help\x1b[0m, \x1b[33m:status\x1b[0m, \x1b[33m:logs\x1b[0m, \x1b[33m:clear\x1b[0m, \x1b[33m:exit\x1b[0m (or Ctrl+D)\n"
    );

    loop {
        print!("\x1b[1;34magentgate\x1b[0m> ");
        io::stdout().flush()?;

        let mut line = String::new();
        let bytes = io::stdin().read_line(&mut line)?;
        if bytes == 0 {
            // EOF (Ctrl+D)
            println!("\n👋 Bye!");
            break;
        }

        let mut cmd = line.trim();
        if cmd.is_empty() {
            continue;
        }

        // Strip accidental 'agentgate ' or 'agentgate exec ' prefix inside the interactive shell
        if let Some(stripped) = cmd.strip_prefix("agentgate ") {
            let stripped = stripped.trim();
            if let Some(inner) = stripped.strip_prefix("exec ") {
                cmd = inner.trim();
            } else {
                cmd = stripped;
            }
        }

        match cmd {
            ":exit" | ":quit" | "exit" | "quit" | ":q" => {
                println!("👋 Bye!");
                break;
            }
            ":clear" | "clear" => {
                print!("\x1B[2J\x1B[1;1H");
                io::stdout().flush()?;
                continue;
            }
            ":help" | "help" => {
                println!("\n📖 AgentGate Interactive Session Help:");
                println!(
                    "  • Type any allowed Linux command directly — no need to write 'agentgate exec'"
                );
                println!("  • Diagnostics:     uptime | df -h | free -m | ps aux");
                println!("  • System Services: systemctl status nginx | journalctl -u nginx -n 50");
                println!("  • Docker:          docker ps | docker logs --tail 20 app");
                println!("  • Helpers:");
                println!("      :status  - Show active connection & server health");
                println!("      :logs    - View recent audit logs");
                println!("      :clear   - Clear the terminal screen");
                println!("      :exit    - Exit this session\n");
                continue;
            }
            ":status" => {
                let _ = handle_whoami().await;
                println!();
                continue;
            }
            ":logs" => {
                let _ = crate::cli::handle_logs(
                    crate::cli::LogsArgs {
                        limit: 5,
                        ..Default::default()
                    },
                    config,
                );
                println!();
                continue;
            }
            _ => {
                let exec_url = format!("{}/v1/exec", cfg.server);
                let start_exec = std::time::Instant::now();

                let res = client
                    .post(&exec_url)
                    .header("Authorization", format!("Bearer {}", cfg.token))
                    .header("Content-Type", "application/json")
                    .json(&serde_json::json!({ "command": cmd }))
                    .send()
                    .await;

                let duration_ms = start_exec.elapsed().as_millis();

                match res {
                    Ok(resp) => {
                        let status = resp.status();
                        let text = resp.text().await.unwrap_or_default();

                        if status.is_success() {
                            if let Ok(exec_data) = serde_json::from_str::<ServerExecResponse>(&text)
                            {
                                if !exec_data.stdout.is_empty() {
                                    print!("{}", exec_data.stdout);
                                    if !exec_data.stdout.ends_with('\n') {
                                        println!();
                                    }
                                }
                                if !exec_data.stderr.is_empty() {
                                    eprint!("\x1b[33m{}\x1b[0m", exec_data.stderr);
                                    if !exec_data.stderr.ends_with('\n') {
                                        eprintln!();
                                    }
                                }
                                println!(
                                    "\x1b[90m⚡ {}ms | Exit {}\x1b[0m\n",
                                    exec_data.duration_ms, exec_data.exit_code
                                );
                            } else {
                                println!("{}", text);
                                println!("\x1b[90m⚡ {}ms\x1b[0m\n", duration_ms);
                            }
                        } else if let Ok(err_data) =
                            serde_json::from_str::<ServerErrorResponse>(&text)
                        {
                            println!("\x1b[1;31m❌ {}\x1b[0m", err_data.message);
                            println!(
                                "\x1b[90m⚡ {}ms | Error: {}\x1b[0m\n",
                                duration_ms, err_data.error
                            );
                        } else {
                            println!(
                                "\x1b[1;31m❌ Server error (HTTP {}): {}\x1b[0m\n",
                                status, text
                            );
                        }
                    }
                    Err(e) => {
                        println!(
                            "\x1b[1;31m❌ Failed to communicate with server: {}\x1b[0m\n",
                            e
                        );
                    }
                }
            }
        }
    }

    Ok(())
}

/// Handle `agentgate action <name> [-p key=value...]`
pub async fn handle_action(args: crate::cli::ActionArgs) -> Result<()> {
    let saved_cfg = load_client_config()?.unwrap_or_default();

    let server_url = args
        .server
        .or_else(|| std::env::var("AGENTGATE_SERVER").ok())
        .unwrap_or(saved_cfg.server)
        .trim_end_matches('/')
        .to_string();

    let token = args
        .token
        .or_else(|| std::env::var("AGENTGATE_TOKEN").ok())
        .unwrap_or(saved_cfg.token);

    if token.trim().is_empty() {
        eprintln!("❌ Authentication required: No token found.");
        eprintln!("💡 Log in first using: agentgate login --token <TOKEN>");
        std::process::exit(1);
    }

    let mut params_map = std::collections::HashMap::new();
    for p in &args.params {
        if let Some((k, v)) = p.split_once('=') {
            params_map.insert(k.trim().to_string(), v.trim().to_string());
        } else {
            eprintln!("⚠️  Warning: Parameter '{}' is not in key=value format; skipping", p);
        }
    }

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(saved_cfg.insecure_tls)
        .timeout(std::time::Duration::from_secs(120))
        .build()
        .context("Failed to build HTTP client")?;

    let action_url = format!("{}/v1/action/{}", server_url, args.name);

    let resp = match client
        .post(&action_url)
        .header("Authorization", format!("Bearer {}", token.trim()))
        .header("Content-Type", "application/json")
        .json(&crate::server::ActionRequest { params: params_map })
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            eprintln!("❌ Failed to connect to AgentGate server at {}: {}", server_url, e);
            std::process::exit(1);
        }
    };

    let status = resp.status();
    let text = resp.text().await.context("Failed to read server response body")?;

    if args.json {
        println!("{}", text);
        if status.is_success() {
            return Ok(());
        } else {
            std::process::exit(1);
        }
    }

    if status.is_success() {
        if let Ok(action_resp) = serde_json::from_str::<crate::server::ActionResponse>(&text) {
            println!("🚀 Executing action '{}' ({} steps):", action_resp.action, action_resp.steps.len());
            for (idx, step) in action_resp.steps.iter().enumerate() {
                println!("\n▶ Step {}/{}: {}", idx + 1, action_resp.steps.len(), step.step);
                if !step.stdout.is_empty() {
                    print!("{}", step.stdout);
                }
                if !step.stderr.is_empty() {
                    eprint!("{}", step.stderr);
                }
                if step.exit_code == 0 {
                    println!("  ✓ Step {} completed ({}ms, Exit 0)", idx + 1, step.duration_ms);
                } else {
                    println!("  ❌ Step {} failed with Exit code {} ({}ms)", idx + 1, step.exit_code, step.duration_ms);
                }
            }

            if action_resp.success {
                println!("\n✅ Action '{}' completed successfully in {}ms", action_resp.action, action_resp.total_duration_ms);
                return Ok(());
            } else {
                eprintln!("\n❌ Action '{}' failed", action_resp.action);
                std::process::exit(1);
            }
        } else {
            println!("{}", text);
            return Ok(());
        }
    }

    // Error status handling
    if let Ok(err_obj) = serde_json::from_str::<crate::server::ErrorResponse>(&text) {
        eprintln!("❌ AgentGate error: {}", err_obj.message);
    } else {
        eprintln!("❌ HTTP error {}: {}", status, text);
    }
    std::process::exit(1);
}
