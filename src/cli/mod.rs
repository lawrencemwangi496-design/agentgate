use crate::audit::AuditLogger;
use crate::auth::TokenStore;
use crate::config::AgentGateConfig;
use crate::policy::{Policy, PolicyRule, PolicyStore};
use crate::server::cert;
use anyhow::{Context, Result, bail};
use clap::{Args, Parser, Subcommand};
use std::fs;
use std::os::unix::process::CommandExt;
use std::path::Path;
use tabled::settings::Style;
use tabled::{Table, Tabled};

#[derive(Parser)]
#[command(
    name = "agentgate",
    about = "Secure bridge letting AI agents execute commands on your machine without your password",
    version = env!("CARGO_PKG_VERSION")
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Initialize configuration, default policies, and TLS certificates
    Init(InitArgs),

    /// Start the AgentGate daemon in the background (like tailscale up)
    Start(StartArgs),

    /// Stop the running AgentGate daemon (like tailscale down)
    Stop,

    /// Restart the running AgentGate daemon
    Restart(StartArgs),

    /// Run the AgentGate server in the foreground (for debugging or systemd)
    Serve(ServeArgs),

    /// Check daemon status, health, and loaded policies
    Status(StatusArgs),

    /// Execute an authorized system command through AgentGate (client tool, like gh)
    #[command(name = "exec", alias = "run")]
    Exec(ExecArgs),

    /// Interactive TUI shell to execute commands directly (like gh / local console)
    #[command(name = "shell", aliases = ["console", "connect", "sh"])]
    Shell(ShellArgs),

    /// Open interactive manager menu (press 1, 2, 3 to configure and manage)
    #[command(name = "menu", aliases = ["ui", "manager"])]
    Menu,

    /// Log in AI agent client with an access token (like gh auth login)
    Login(LoginArgs),

    /// Log out client and remove saved credentials
    Logout,

    /// Show current client authentication status (like gh auth status)
    Whoami,

    /// Print AI agent instruction guide and system prompt rules
    Guide,

    /// Start Model Context Protocol (MCP) server for native AI tool calling
    Mcp,

    /// Manage authentication tokens for AI agents
    #[command(alias = "tokens")]
    Token(TokenCommand),

    /// Manage command execution policies
    #[command(alias = "policies")]
    Policy(PolicyCommand),

    /// View audit logs of executed and blocked commands
    Logs(LogsArgs),

    /// Update AgentGate to the latest release
    #[command(alias = "upgrade")]
    Update,
}

#[derive(Args, Clone, Default)]
pub struct InitArgs {
    /// Default port to configure (default: 7991)
    #[arg(long)]
    pub port: Option<u16>,

    /// Default address to listen on (default: 127.0.0.1)
    #[arg(long)]
    pub listen: Option<String>,

    /// Bind to 0.0.0.0 for network, external agents, browsers, and remote access
    #[arg(long, aliases = ["public", "network"])]
    pub remote: bool,

    /// Bind to 127.0.0.1 for local machine CLI access only
    #[arg(long)]
    pub local: bool,

    /// Run interactive configuration wizard
    #[arg(long, short)]
    pub interactive: bool,
}

#[derive(Args, Clone, Default)]
pub struct StartArgs {
    /// Address to listen on (default: 127.0.0.1, or configured)
    #[arg(long)]
    pub listen: Option<String>,

    /// Port to listen on (default: 7991, or configured)
    #[arg(long)]
    pub port: Option<u16>,

    /// Bind to 0.0.0.0 for network, external agents, browsers, and remote access
    #[arg(long, aliases = ["public", "network"])]
    pub remote: bool,

    /// Bind to 127.0.0.1 for local machine CLI access only
    #[arg(long)]
    pub local: bool,

    /// Run as plain HTTP without TLS (useful for private network testing)
    #[arg(long, default_value_t = false)]
    pub no_tls: bool,
}

#[derive(Args, Clone, Default)]
pub struct ServeArgs {
    /// Address to listen on (default: 127.0.0.1, or configured)
    #[arg(long)]
    pub listen: Option<String>,

    /// Port to listen on (default: 7991, or configured)
    #[arg(long)]
    pub port: Option<u16>,

    /// Bind to 0.0.0.0 for network, external agents, browsers, and remote access
    #[arg(long, aliases = ["public", "network"])]
    pub remote: bool,

    /// Bind to 127.0.0.1 for local machine CLI access only
    #[arg(long)]
    pub local: bool,

    /// Optional path to custom TLS certificate (e.g. Let's Encrypt fullchain.pem)
    #[arg(long)]
    pub tls_cert: Option<std::path::PathBuf>,

    /// Optional path to custom TLS private key (e.g. Let's Encrypt privkey.pem)
    #[arg(long)]
    pub tls_key: Option<std::path::PathBuf>,

    /// Run as plain HTTP without TLS (useful for private network testing)
    #[arg(long, default_value_t = false)]
    pub no_tls: bool,
}

#[derive(Args, Clone, Default)]
pub struct StatusArgs {
    /// Address of running daemon (default: 127.0.0.1, or configured)
    #[arg(long)]
    pub host: Option<String>,

    /// Port of running daemon (default: 7991, or configured)
    #[arg(long)]
    pub port: Option<u16>,

    /// Use HTTPS
    #[arg(long, default_value_t = true)]
    pub tls: bool,
}

#[derive(Args, Clone, Debug)]
pub struct ExecArgs {
    /// Command and arguments to execute (e.g. 'uptime', 'systemctl restart nginx')
    #[arg(trailing_var_arg = true, required = true)]
    pub command: Vec<String>,

    /// Override server URL (e.g. https://127.0.0.1:7991)
    #[arg(long)]
    pub server: Option<String>,

    /// Override auth token
    #[arg(long)]
    pub token: Option<String>,

    /// Output full JSON response from server
    #[arg(long, default_value_t = false)]
    pub json: bool,

    /// Suppress error banners
    #[arg(long, short, default_value_t = false)]
    pub quiet: bool,
}

#[derive(Args, Clone, Debug, Default)]
pub struct LoginArgs {
    /// AgentGate authentication token (starts with ag_)
    #[arg(long, short)]
    pub token: Option<String>,

    /// Server URL to connect to (default: interactive prompt or https://127.0.0.1:7991)
    #[arg(long, short)]
    pub server: Option<String>,

    /// Allow self-signed TLS certificates (default: true for localhost)
    #[arg(long, default_value_t = true)]
    pub insecure: bool,
}

#[derive(Args, Clone, Debug, Default)]
pub struct ShellArgs {
    /// Server URL to connect to (default: configured server)
    #[arg(long, short)]
    pub server: Option<String>,

    /// AgentGate authentication token (default: configured token)
    #[arg(long, short)]
    pub token: Option<String>,
}

#[derive(Args, Clone, Default)]
pub struct TokenCommand {
    #[command(subcommand)]
    pub command: Option<TokenSubcommand>,
}

#[derive(Subcommand, Clone)]
pub enum TokenSubcommand {
    /// Create a new scoped token for an AI agent
    Create {
        /// Unique name for the token (e.g. 'claude-infra', 'gemini-debug')
        #[arg(long)]
        name: String,

        /// Policy name to attach to this token
        #[arg(long)]
        policy: String,

        /// Token expiration duration (e.g. '24h', '7d', '30m'). Defaults to never.
        #[arg(long)]
        expires: Option<String>,
    },

    /// List all generated tokens
    List,

    /// Revoke a token by name
    Revoke {
        /// Name of the token to revoke
        name: String,
    },
}

#[derive(Args, Clone, Default)]
pub struct PolicyCommand {
    #[command(subcommand)]
    pub command: Option<PolicySubcommand>,
}

#[derive(Subcommand, Clone)]
pub enum PolicySubcommand {
    /// List all available policies
    List,

    /// Show the rules of a policy
    Show {
        /// Policy name
        name: String,
    },

    /// Create a new policy file with starter template
    Create {
        /// Policy name
        name: String,
        /// Description of the policy
        #[arg(long, default_value = "Custom execution policy")]
        description: String,
    },

    /// Delete a policy
    Delete {
        /// Policy name
        name: String,
    },
}

#[derive(Args, Clone, Default)]
pub struct LogsArgs {
    /// Maximum number of recent entries to show
    #[arg(long, default_value_t = 50)]
    pub limit: usize,

    /// Filter logs by token name
    #[arg(long)]
    pub token: Option<String>,

    /// Show only denied and injection-blocked attempts
    #[arg(long, default_value_t = false)]
    pub denied: bool,
}

#[derive(Tabled)]
struct TokenRow {
    #[tabled(rename = "NAME")]
    name: String,
    #[tabled(rename = "POLICY")]
    policy: String,
    #[tabled(rename = "CREATED AT")]
    created_at: String,
    #[tabled(rename = "EXPIRES")]
    expires: String,
    #[tabled(rename = "LAST USED")]
    last_used_at: String,
}

#[derive(Tabled)]
struct PolicyRow {
    #[tabled(rename = "NAME")]
    name: String,
    #[tabled(rename = "DESCRIPTION")]
    description: String,
    #[tabled(rename = "RULES COUNT")]
    rules_count: usize,
}

#[derive(Tabled)]
struct AuditRow {
    #[tabled(rename = "TIME")]
    time: String,
    #[tabled(rename = "TOKEN")]
    token: String,
    #[tabled(rename = "COMMAND")]
    command: String,
    #[tabled(rename = "POLICY")]
    policy: String,
    #[tabled(rename = "RESULT")]
    result: String,
    #[tabled(rename = "EXIT")]
    exit_code: String,
    #[tabled(rename = "DUR(ms)")]
    duration: String,
}

// Embedded default starter policies
const STARTER_READ_ONLY: &str = include_str!("../../policies/read-only.yaml");
const STARTER_DOCKER: &str = include_str!("../../policies/docker-ops.yaml");

pub fn detect_network_addresses(port: u16, protocol: &str) -> Vec<(&'static str, String)> {
    let mut addrs = Vec::new();
    addrs.push(("Local", format!("{}://127.0.0.1:{}", protocol, port)));

    if let Some(output) = std::process::Command::new("ip")
        .args(["-brief", "-4", "addr"])
        .output()
        .ok()
        .filter(|o| o.status.success())
    {
        let text = String::from_utf8_lossy(&output.stdout);
        for line in text.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 3 {
                let iface = parts[0];
                let ip_cidr = parts[2];
                let ip = ip_cidr.split('/').next().unwrap_or(ip_cidr);
                if iface == "lo" || ip == "127.0.0.1" {
                    continue;
                }
                addrs.push(("Network IP", format!("{}://{}:{}", protocol, ip, port)));
            }
        }
    }
    addrs
}

fn prompt_interactive_init(_default_listen: &str, default_port: u16) -> Result<(String, u16)> {
    use std::io::Write;

    println!("==========================================================");
    println!("             🚪 AgentGate Configuration Setup");
    println!("==========================================================");
    println!("Choose where AgentGate should accept connections from:");
    println!("  1) Local only (127.0.0.1) [Recommended for local CLI agents on this PC]");
    println!("  2) All interfaces (0.0.0.0) [For remote servers, web browsers & external access]");
    print!("\nSelect option [1-2, default 1]: ");
    std::io::stdout().flush()?;
    let mut choice = String::new();
    std::io::stdin().read_line(&mut choice)?;
    let choice = choice.trim();

    let listen = match choice {
        "2" => "0.0.0.0".to_string(),
        _ => "127.0.0.1".to_string(),
    };

    print!("Port to listen on [default: {}]: ", default_port);
    std::io::stdout().flush()?;
    let mut port_str = String::new();
    std::io::stdin().read_line(&mut port_str)?;
    let port = port_str.trim().parse::<u16>().unwrap_or(default_port);

    Ok((listen, port))
}

pub fn handle_init(args: InitArgs, config: &AgentGateConfig) -> Result<()> {
    use std::io::IsTerminal;

    let (chosen_listen, chosen_port) = if args.remote {
        ("0.0.0.0".to_string(), args.port.unwrap_or(7991))
    } else if args.local {
        ("127.0.0.1".to_string(), args.port.unwrap_or(7991))
    } else if let Some(l) = args.listen {
        (l, args.port.unwrap_or(7991))
    } else if let Some(p) = args.port {
        (config.listen_addr.clone(), p)
    } else if args.interactive
        || (std::io::stdin().is_terminal() && args.port.is_none() && args.listen.is_none())
    {
        prompt_interactive_init(&config.listen_addr, config.listen_port)?
    } else {
        (config.listen_addr.clone(), config.listen_port)
    };

    AgentGateConfig::init(Some(chosen_port), Some(chosen_listen))?;

    // Populate starter policies if they don't already exist
    let starters = [
        ("read-only.yaml", STARTER_READ_ONLY),
        ("docker-ops.yaml", STARTER_DOCKER),
    ];

    for (fname, content) in starters {
        let dest = config.policies_dir.join(fname);
        if !dest.exists() {
            fs::write(&dest, content)
                .with_context(|| format!("Failed to write default starter policy {:?}", dest))?;
            println!("  ✓ Installed starter policy: {}", dest.display());
        }
    }

    // Ensure self-signed TLS certificates
    cert::ensure_self_signed_cert(&config.tls_cert_path(), &config.tls_key_path())?;
    println!(
        "  ✓ Generated TLS certificate at: {}",
        config.tls_cert_path().display()
    );
    println!(
        "  ✓ Generated TLS private key at: {}",
        config.tls_key_path().display()
    );

    println!("\n✨ Setup complete! To start the daemon:");
    println!("  agentgate start\n");
    println!("To create your first token for an AI agent:");
    println!("  agentgate token create --name my-agent --policy read-only\n");

    Ok(())
}

pub fn read_pid(pid_file: &Path) -> Option<i32> {
    if !pid_file.exists() {
        return None;
    }
    let content = fs::read_to_string(pid_file).ok()?;
    let pid: i32 = content.trim().parse().ok()?;
    if unsafe { libc::kill(pid, 0) == 0 } {
        Some(pid)
    } else {
        let _ = fs::remove_file(pid_file);
        None
    }
}

pub fn get_process_port(pid: i32) -> Option<u16> {
    let cmdline_path = format!("/proc/{}/cmdline", pid);
    let content = fs::read(cmdline_path).ok()?;
    let args: Vec<String> = content
        .split(|&b| b == 0)
        .filter_map(|s| String::from_utf8(s.to_vec()).ok())
        .collect();

    args.windows(2)
        .find(|w| w[0] == "--port")
        .and_then(|w| w[1].parse::<u16>().ok())
}

pub fn get_process_listen(pid: i32) -> Option<String> {
    let cmdline_path = format!("/proc/{}/cmdline", pid);
    let content = fs::read(cmdline_path).ok()?;
    let args: Vec<String> = content
        .split(|&b| b == 0)
        .filter_map(|s| String::from_utf8(s.to_vec()).ok())
        .collect();

    args.windows(2)
        .find(|w| w[0] == "--listen")
        .map(|w| w[1].clone())
}

pub fn handle_start(args: StartArgs, config: &AgentGateConfig) -> Result<()> {
    let target_listen = if args.remote {
        "0.0.0.0".to_string()
    } else if args.local {
        "127.0.0.1".to_string()
    } else if let Some(l) = args.listen {
        l
    } else {
        config.listen_addr.clone()
    };

    let target_port = args.port.unwrap_or(config.listen_port);

    if let Some(pid) = read_pid(&config.pid_file) {
        let active_port = get_process_port(pid).unwrap_or(config.listen_port);
        println!("🟢 AgentGate is already running (PID: {})", pid);
        println!("   Address: https://{}:{}", config.listen_addr, active_port);
        println!("   Stop with: agentgate stop");
        return Ok(());
    }

    // Check if the target port is already in use before attempting to spawn
    let bind_addr: std::net::SocketAddr = format!("{}:{}", target_listen, target_port)
        .parse()
        .with_context(|| format!("Invalid address {}:{}", target_listen, target_port))?;

    if let Err(e) = std::net::TcpListener::bind(bind_addr) {
        if e.kind() == std::io::ErrorKind::AddrInUse {
            eprintln!(
                "❌ Port {} is already in use by another process on {}.",
                target_port, target_listen
            );
            eprintln!("💡 You can choose a different port using:");
            eprintln!("   agentgate start --port <PORT>");
            eprintln!("   or set: export AGENTGATE_PORT=<PORT>");
            bail!("Port conflict: {} is already in use", target_port);
        } else {
            eprintln!("❌ Cannot bind to {}:{}: {}", target_listen, target_port, e);
            bail!("Cannot bind: {}", e);
        }
    }

    let exe = std::env::current_exe().context("Failed to get current executable path")?;
    let log_file = config.logs_dir.join("daemon.log");
    let out_file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_file)
        .with_context(|| format!("Failed to open log at {:?}", log_file))?;
    let err_file = out_file.try_clone()?;

    let mut cmd = std::process::Command::new(exe);
    cmd.arg("serve");
    cmd.arg("--listen").arg(&target_listen);
    cmd.arg("--port").arg(target_port.to_string());
    if args.no_tls {
        cmd.arg("--no-tls");
    }
    cmd.stdin(std::process::Stdio::null());
    cmd.stdout(out_file);
    cmd.stderr(err_file);

    unsafe {
        cmd.pre_exec(|| {
            libc::setsid();
            Ok(())
        });
    }

    let mut child = cmd.spawn().context("Failed to spawn background process")?;
    let pid = child.id() as i32;

    fs::write(&config.pid_file, pid.to_string())
        .with_context(|| format!("Failed to write PID file {:?}", config.pid_file))?;

    std::thread::sleep(std::time::Duration::from_millis(600));

    // Verify child process didn't immediately crash or exit
    if let Ok(Some(status)) = child.try_wait() {
        let _ = fs::remove_file(&config.pid_file);
        let log_tail = fs::read_to_string(&log_file).unwrap_or_default();
        let last_lines: Vec<&str> = log_tail.lines().rev().take(6).collect();
        eprintln!(
            "❌ AgentGate failed to start (exit status: {}).",
            status
        );
        if !last_lines.is_empty() {
            eprintln!("   Error details from log ({}):", log_file.display());
            for line in last_lines.iter().rev() {
                eprintln!("     {}", line);
            }
        }
        bail!("Process exited immediately after startup");
    }

    let protocol = if args.no_tls { "http" } else { "https" };
    println!("🟢 AgentGate started in background (PID: {})", pid);
    println!(
        "   Listening on: {}://{}:{}",
        protocol, target_listen, target_port
    );

    let addrs = if target_listen == "0.0.0.0" {
        detect_network_addresses(target_port, protocol)
    } else {
        Vec::new()
    };

    if !addrs.is_empty() {
        println!("\n🌐 Network Access URLs:");
        for (label, url) in &addrs {
            println!("   • {:14} {}", label, url);
        }
    }

    println!("\n🖥️  Web Browser Console:");
    println!(
        "   Local:             {}://127.0.0.1:{}/",
        protocol, target_port
    );
    for (label, url) in &addrs {
        if label != &"Localhost" {
            println!("   Remote/Network:    {}/", url);
        }
    }
    println!("\n   Logs:         {}", log_file.display());
    println!("   Execute with: agentgate exec <command>");
    println!("   Stop anytime: agentgate stop");

    Ok(())
}

pub fn handle_stop(config: &AgentGateConfig) -> Result<()> {
    let Some(pid) = read_pid(&config.pid_file) else {
        println!("⚪ AgentGate is not running.");
        return Ok(());
    };

    println!("Stopping AgentGate (PID: {})...", pid);
    unsafe {
        libc::kill(pid, libc::SIGTERM);
    }

    let start = std::time::Instant::now();
    while std::time::Instant::now().duration_since(start).as_secs() < 5 {
        if unsafe { libc::kill(pid, 0) != 0 } {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }

    if unsafe { libc::kill(pid, 0) == 0 } {
        unsafe {
            libc::kill(pid, libc::SIGKILL);
        }
    }

    let _ = fs::remove_file(&config.pid_file);
    println!("🛑 AgentGate stopped.");

    Ok(())
}

pub fn handle_restart(args: StartArgs, config: &AgentGateConfig) -> Result<()> {
    handle_stop(config)?;
    std::thread::sleep(std::time::Duration::from_millis(300));
    handle_start(args, config)?;
    Ok(())
}

pub fn handle_status(args: StatusArgs, config: &AgentGateConfig) -> Result<()> {
    let pid_opt = read_pid(&config.pid_file);
    let target_host = args
        .host
        .or_else(|| pid_opt.and_then(get_process_listen))
        .unwrap_or_else(|| config.listen_addr.clone());
    let target_port = args
        .port
        .or_else(|| pid_opt.and_then(get_process_port))
        .unwrap_or(config.listen_port);

    println!("==========================================================");
    println!("             🚪 AgentGate Daemon Status");
    println!("==========================================================");

    if let Some(pid) = pid_opt {
        println!("Daemon:        🟢 RUNNING (PID: {})", pid);
    } else {
        let addr = format!("{}:{}", target_host, target_port);
        let port_open = std::net::TcpStream::connect_timeout(
            &addr
                .parse()
                .unwrap_or_else(|_| "127.0.0.1:7991".parse().unwrap()),
            std::time::Duration::from_millis(500),
        )
        .is_ok();

        if port_open {
            println!("Daemon:        🟢 RUNNING (Foreground or systemd)");
        } else {
            println!("Daemon:        🔴 STOPPED");
            println!("Start daemon:  agentgate start");
            println!("==========================================================");
            return Ok(());
        }
    }

    let protocol = if args.tls { "https" } else { "http" };
    println!(
        "Listening:     {}://{}:{}",
        protocol, target_host, target_port
    );
    println!("Web Console:   {}://127.0.0.1:{}/", protocol, target_port);
    if target_host == "0.0.0.0" {
        let addrs = detect_network_addresses(target_port, protocol);
        for (label, url) in &addrs {
            if label != &"Local" {
                println!("  • {:12} {}", label, url);
            }
        }
    }
    println!("Config Dir:    {}", config.config_dir.display());
    println!("PID File:      {}", config.pid_file.display());
    println!(
        "Daemon Log:    {}",
        config.logs_dir.join("daemon.log").display()
    );

    let policy_store = PolicyStore::load(&config.policies_dir).ok();
    let policies_count = policy_store.map(|ps| ps.list().len()).unwrap_or(0);
    let token_store = TokenStore::load(&config.tokens_file).ok();
    let tokens_count = token_store.map(|ts| ts.list().len()).unwrap_or(0);

    println!("Policies:      {} loaded", policies_count);
    println!("Tokens:        {} configured", tokens_count);

    if let Ok(Some(client_cfg)) = crate::client::load_client_config() {
        let masked = if client_cfg.token.len() > 10 {
            format!(
                "{}...{}",
                &client_cfg.token[..6],
                &client_cfg.token[client_cfg.token.len() - 4..]
            )
        } else {
            "***".to_string()
        };
        println!(
            "Client CLI:    🟢 Configured ({}, {})",
            client_cfg.server, masked
        );
    } else {
        println!("Client CLI:    ⚪ Not logged in (run 'agentgate login')");
    }

    println!("==========================================================");

    Ok(())
}

pub fn handle_update() -> Result<()> {
    println!("🔄 Checking for updates and installing latest AgentGate release...");
    let status = std::process::Command::new("sh")
        .arg("-c")
        .arg("curl -fsSL https://raw.githubusercontent.com/lawrencemwangi496-design/agentgate/main/install.sh | bash")
        .status()
        .context("Failed to execute update script")?;

    if status.success() {
        println!("✅ AgentGate updated successfully! Run 'agentgate --version' to verify.");
    } else {
        println!("⚠️  Update command returned non-zero status. You can update manually with:");
        println!("   curl -fsSL https://raw.githubusercontent.com/lawrencemwangi496-design/agentgate/main/install.sh | bash");
    }
    Ok(())
}

pub fn handle_token(cmd: Option<TokenSubcommand>, config: &AgentGateConfig) -> Result<()> {
    let mut store = TokenStore::load(&config.tokens_file)?;

    match cmd.unwrap_or(TokenSubcommand::List) {
        TokenSubcommand::Create {
            name,
            policy,
            expires,
        } => {
            // Verify policy exists
            let policy_store = PolicyStore::load(&config.policies_dir)?;
            if policy_store.get(&policy).is_none() {
                bail!(
                    "Policy '{}' does not exist. Available policies: {:?}",
                    policy,
                    policy_store
                        .list()
                        .iter()
                        .map(|p| &p.name)
                        .collect::<Vec<_>>()
                );
            }

            let duration = if let Some(exp_str) = expires {
                parse_duration(&exp_str)?
            } else {
                None
            };

            let raw_token = store.create(&name, &policy, duration)?;

            let expires_display = match duration {
                Some(d) => {
                    let expiry_time = chrono::Utc::now() + d;
                    format!(
                        "{} (at {} UTC)",
                        format_duration_human(d),
                        expiry_time.format("%Y-%m-%d %H:%M")
                    )
                }
                None => "Never (Permanent long-lasting token)".to_string(),
            };

            println!("\n✅ Token created successfully!");
            println!("----------------------------------------------------------------------");
            println!("NAME:       {}", name);
            println!("POLICY:     {}", policy);
            println!("EXPIRES:    {}", expires_display);
            println!("TOKEN:      {}", raw_token);
            println!("----------------------------------------------------------------------");
            println!("⚠️  Save this token now! It will NOT be shown again.");
            println!("\n🚀 Quick Agent Login (like gh auth login):");
            println!("  agentgate login --token {}", raw_token);
            println!("\nThen execute commands effortlessly without passwords or token wastage:");
            println!("  agentgate exec uptime");
            println!("  agentgate exec systemctl restart nginx");
            println!("\nOr use with cURL if preferred:");
            println!(
                "curl -k -X POST https://{}:{}/v1/exec \\\n  \
                -H \"Authorization: Bearer {}\" \\\n  \
                -H \"Content-Type: application/json\" \\\n  \
                -d '{{\"command\": \"uptime\"}}'\n",
                config.listen_addr, config.listen_port, raw_token
            );
        }
        TokenSubcommand::List => {
            let tokens = store.list();
            if tokens.is_empty() {
                println!(
                    "No tokens found. Create one with: agentgate token create --name <name> --policy <policy>"
                );
                return Ok(());
            }

            let rows: Vec<TokenRow> = tokens
                .iter()
                .map(|t| TokenRow {
                    name: t.name.clone(),
                    policy: t.policy.clone(),
                    created_at: t.created_at.format("%Y-%m-%d %H:%M").to_string(),
                    expires: format_expiry(t.expires_at),
                    last_used_at: t
                        .last_used_at
                        .map(|dt| dt.format("%Y-%m-%d %H:%M").to_string())
                        .unwrap_or_else(|| "Never".to_string()),
                })
                .collect();

            let mut table = Table::new(rows);
            table.with(Style::rounded());
            println!("{}", table);
        }
        TokenSubcommand::Revoke { name } => {
            if store.revoke(&name)? {
                println!(
                    "✓ Token '{}' has been revoked and can no longer be used.",
                    name
                );
            } else {
                println!("Token '{}' not found.", name);
            }
        }
    }

    Ok(())
}

pub fn handle_policy(cmd: Option<PolicySubcommand>, config: &AgentGateConfig) -> Result<()> {
    let mut store = PolicyStore::load(&config.policies_dir)?;

    match cmd.unwrap_or(PolicySubcommand::List) {
        PolicySubcommand::List => {
            let policies = store.list();
            if policies.is_empty() {
                println!("No policies found in {}", config.policies_dir.display());
                return Ok(());
            }

            let rows: Vec<PolicyRow> = policies
                .iter()
                .map(|p| PolicyRow {
                    name: p.name.clone(),
                    description: p.description.clone(),
                    rules_count: p.rules.len(),
                })
                .collect();

            let mut table = Table::new(rows);
            table.with(Style::rounded());
            println!("{}", table);
        }
        PolicySubcommand::Show { name } => {
            let file_path = config.policies_dir.join(format!("{}.yaml", name));
            if file_path.exists() {
                let content = fs::read_to_string(&file_path)?;
                println!("{}", content);
            } else {
                println!("Policy '{}' not found at {:?}", name, file_path);
            }
        }
        PolicySubcommand::Create { name, description } => {
            let new_policy = Policy {
                name: name.clone(),
                description,
                rules: vec![PolicyRule {
                    command: "echo".to_string(),
                    args: vec!["*".to_string()],
                }],
            };
            store.save_policy(&new_policy)?;
            let file_path = config.policies_dir.join(format!("{}.yaml", name));
            println!("✓ Policy created at: {}", file_path.display());
            println!("Edit this file to add allowed commands.");
        }
        PolicySubcommand::Delete { name } => {
            if store.delete_policy(&name)? {
                println!("✓ Policy '{}' deleted.", name);
            } else {
                println!("Policy '{}' not found.", name);
            }
        }
    }

    Ok(())
}

pub fn handle_logs(args: LogsArgs, config: &AgentGateConfig) -> Result<()> {
    let logger = AuditLogger::new(config.logs_dir.clone());
    let entries = logger.read_recent(args.limit, args.token.as_deref(), args.denied)?;

    if entries.is_empty() {
        println!("No audit logs found.");
        return Ok(());
    }

    let rows: Vec<AuditRow> = entries
        .iter()
        .map(|e| AuditRow {
            time: e.timestamp.format("%m-%d %H:%M:%S").to_string(),
            token: e.token_name.clone(),
            command: e.command.clone(),
            policy: e.policy.clone(),
            result: format!("{:?}", e.result),
            exit_code: e
                .exit_code
                .map(|c| c.to_string())
                .unwrap_or_else(|| "-".to_string()),
            duration: e
                .duration_ms
                .map(|d| d.to_string())
                .unwrap_or_else(|| "-".to_string()),
        })
        .collect();

    let mut table = Table::new(rows);
    table.with(Style::rounded());
    println!("{}", table);

    Ok(())
}

pub fn parse_duration(s: &str) -> Result<Option<chrono::Duration>> {
    let clean = s.trim().to_lowercase();
    if clean.is_empty()
        || clean == "never"
        || clean == "forever"
        || clean == "none"
        || clean == "0"
        || clean == "infinite"
    {
        return Ok(None);
    }

    let parts: Vec<&str> = clean.split_whitespace().collect();
    let (num_str, unit_str) = if parts.len() == 2 {
        (parts[0], parts[1])
    } else {
        let split_idx = clean.find(|c: char| !c.is_ascii_digit()).ok_or_else(|| {
            anyhow::anyhow!(
                "Missing time unit. Use e.g. '2h', '12 hours', '7d', '30 days', '1 year', or 'never'"
            )
        })?;
        (&clean[..split_idx], &clean[split_idx..])
    };

    let count: i64 = num_str.parse().context("Invalid number in duration")?;
    if count <= 0 {
        bail!("Duration must be a positive number");
    }

    match unit_str {
        "s" | "sec" | "secs" | "second" | "seconds" => Ok(Some(chrono::Duration::seconds(count))),
        "m" | "min" | "mins" | "minute" | "minutes" => Ok(Some(chrono::Duration::minutes(count))),
        "h" | "hr" | "hrs" | "hour" | "hours" => Ok(Some(chrono::Duration::hours(count))),
        "d" | "day" | "days" => Ok(Some(chrono::Duration::days(count))),
        "w" | "wk" | "wks" | "week" | "weeks" => Ok(Some(chrono::Duration::weeks(count))),
        "mo" | "mon" | "month" | "months" => Ok(Some(chrono::Duration::days(count * 30))),
        "y" | "yr" | "yrs" | "year" | "years" => Ok(Some(chrono::Duration::days(count * 365))),
        _ => bail!(
            "Unknown duration unit '{}'. Use e.g. '2h', '12 hours', '7d', '30 days', '1 year', or 'never'",
            unit_str
        ),
    }
}

pub fn format_duration_human(d: chrono::Duration) -> String {
    let days = d.num_days();
    let hours = d.num_hours();
    let minutes = d.num_minutes();
    let seconds = d.num_seconds();

    if days >= 365 {
        let years = days / 365;
        format!("in {} year{}", years, if years > 1 { "s" } else { "" })
    } else if days >= 30 {
        let months = days / 30;
        format!("in {} month{}", months, if months > 1 { "s" } else { "" })
    } else if days > 0 {
        format!("in {} day{}", days, if days > 1 { "s" } else { "" })
    } else if hours > 0 {
        format!("in {} hour{}", hours, if hours > 1 { "s" } else { "" })
    } else if minutes > 0 {
        format!(
            "in {} minute{}",
            minutes,
            if minutes > 1 { "s" } else { "" }
        )
    } else {
        format!(
            "in {} second{}",
            seconds,
            if seconds > 1 { "s" } else { "" }
        )
    }
}

pub fn format_expiry(expires_at: Option<chrono::DateTime<chrono::Utc>>) -> String {
    let Some(exp) = expires_at else {
        return "Never (Permanent)".to_string();
    };

    let now = chrono::Utc::now();
    if now > exp {
        format!("⚠️ EXPIRED ({})", exp.format("%Y-%m-%d %H:%M"))
    } else {
        let remaining = exp - now;
        let human = format_duration_human(remaining);
        format!("{} ({})", human, exp.format("%Y-%m-%d %H:%M"))
    }
}

/// Interactive Main Menu (TUI Manager for AgentGate)
pub async fn handle_main_menu(config: &AgentGateConfig) -> Result<()> {
    use std::io::Write;

    loop {
        let pid_opt = read_pid(&config.pid_file);
        let client_cfg = crate::client::load_client_config().ok().flatten();

        println!("\x1b[1;36m==========================================================\x1b[0m");
        println!("\x1b[1;37m                 🚪 AgentGate Manager\x1b[0m");
        println!("\x1b[1;36m==========================================================\x1b[0m");

        if let Some(pid) = pid_opt {
            let port = get_process_port(pid).unwrap_or(config.listen_port);
            let host = get_process_listen(pid).unwrap_or_else(|| config.listen_addr.clone());
            println!(
                "  AgentGate:     \x1b[32m🟢 RUNNING\x1b[0m ({}:{}, PID: {})",
                host, port, pid
            );
        } else {
            println!("  AgentGate:     \x1b[31m🔴 STOPPED\x1b[0m");
        }

        if let Some(ref c) = client_cfg {
            println!(
                "  Client Config: \x1b[32m🟢 Connected\x1b[0m ({})",
                c.server
            );
        } else {
            println!("  Client Config: \x1b[33m⚪ Not configured\x1b[0m");
        }

        println!("\n  \x1b[1;32m1)\x1b[0m \x1b[1mSet up AgentGate (Server)\x1b[0m");
        println!("     → Configure network, TLS certificates & start service");
        println!("  \x1b[1;34m2)\x1b[0m \x1b[1mConnect to AgentGate (Client)\x1b[0m");
        println!("     → Configure laptop to connect to a remote server");
        println!("  \x1b[1m3)\x1b[0m Secure Shell (Interactive console)");
        println!("  \x1b[1m4)\x1b[0m Manage Tokens (Create, List, Revoke)");
        println!("  \x1b[1m5)\x1b[0m View Audit Logs");
        if pid_opt.is_some() {
            println!("  \x1b[1m6)\x1b[0m Stop AgentGate");
        } else {
            println!("  \x1b[1m6)\x1b[0m Start AgentGate");
        }
        println!("  \x1b[1m7)\x1b[0m Update AgentGate");
        println!("  \x1b[1m0)\x1b[0m Exit");

        print!("\nSelect an option [0-7]: ");
        std::io::stdout().flush()?;

        let mut input = String::new();
        let bytes = std::io::stdin().read_line(&mut input)?;
        if bytes == 0 {
            println!("\n👋 Goodbye!");
            break;
        }

        let choice = input.trim().to_lowercase();
        println!();

        match choice.as_str() {
            "1" => {
                let _ = handle_server_setup_wizard(config).await;
                println!();
            }
            "2" => {
                let _ = handle_client_setup_wizard(config).await;
                println!();
            }
            "3" => {
                let _ = crate::client::handle_shell(None, None, config).await;
                println!();
            }
            "4" => {
                let _ = handle_token_menu(config);
                println!();
            }
            "5" => {
                println!("--- Recent Audit Logs ---");
                let _ = handle_logs(
                    LogsArgs {
                        limit: 10,
                        ..Default::default()
                    },
                    config,
                );
                println!();
            }
            "6" => {
                if pid_opt.is_some() {
                    let _ = handle_stop(config);
                } else {
                    let _ = handle_start(StartArgs::default(), config);
                }
                println!();
            }
            "7" => {
                let _ = handle_update();
                println!();
            }
            "0" | "exit" | "quit" | "q" => {
                println!("👋 Goodbye!");
                break;
            }
            _ => {
                println!("Invalid option. Please choose 0-7.\n");
            }
        }
    }

    Ok(())
}

fn handle_token_menu(config: &AgentGateConfig) -> Result<()> {
    use std::io::Write;

    println!("--- Token Management ---");
    println!("  1) Create a new token");
    println!("  2) List active tokens");
    println!("  3) Revoke a token");
    println!("  0) Back");
    print!("\nSelect [0-3, default 0]: ");
    std::io::stdout().flush()?;

    let mut choice = String::new();
    std::io::stdin().read_line(&mut choice)?;
    match choice.trim() {
        "1" => {
            print!("Enter token name [default: agent-token, 'b' to cancel]: ");
            std::io::stdout().flush()?;
            let mut name = String::new();
            std::io::stdin().read_line(&mut name)?;
            let name_trim = name.trim();
            if name_trim == "b" || name_trim == "back" || name_trim == "cancel" {
                println!("Cancelled.");
                return Ok(());
            }
            let name = if name_trim.is_empty() {
                "agent-token".to_string()
            } else {
                name_trim.to_string()
            };

            println!("\nSelect policy:");
            println!("  1) read-only     (System diagnostics: uptime, df, free, ps, uname, logs)");
            println!("  2) docker-ops    (Docker container management)");
            print!("Select [1-2, default 1, 'b' to cancel]: ");
            std::io::stdout().flush()?;
            let mut pol = String::new();
            std::io::stdin().read_line(&mut pol)?;
            let pol_trim = pol.trim();
            if pol_trim == "b" || pol_trim == "back" || pol_trim == "cancel" {
                println!("Cancelled.");
                return Ok(());
            }
            let policy = match pol_trim {
                "2" => "docker-ops",
                _ => "read-only",
            };

            println!("\nSelect expiration:");
            println!("  1) 24 hours");
            println!("  2) 7 days");
            println!("  3) 30 days");
            println!("  4) Never (Permanent)");
            print!("Select [1-4, default 1, 'b' to cancel]: ");
            std::io::stdout().flush()?;
            let mut exp = String::new();
            std::io::stdin().read_line(&mut exp)?;
            let exp_trim = exp.trim();
            if exp_trim == "b" || exp_trim == "back" || exp_trim == "cancel" {
                println!("Cancelled.");
                return Ok(());
            }
            let expires = match exp_trim {
                "2" => Some("7d".to_string()),
                "3" => Some("30d".to_string()),
                "4" => Some("never".to_string()),
                _ => Some("24h".to_string()),
            };

            let token_sub = TokenSubcommand::Create {
                name,
                policy: policy.to_string(),
                expires,
            };
            handle_token(Some(token_sub), config)?;
        }
        "2" => {
            handle_token(Some(TokenSubcommand::List), config)?;
        }
        "3" => {
            print!("Enter token name to revoke ('b' to cancel): ");
            std::io::stdout().flush()?;
            let mut name = String::new();
            std::io::stdin().read_line(&mut name)?;
            let name_trim = name.trim();
            if name_trim == "b" || name_trim == "back" || name_trim == "cancel" {
                println!("Cancelled.");
                return Ok(());
            }
            if !name_trim.is_empty() {
                handle_token(
                    Some(TokenSubcommand::Revoke {
                        name: name_trim.to_string(),
                    }),
                    config,
                )?;
            }
        }
        _ => {}
    }
    Ok(())
}

async fn handle_server_setup_wizard(config: &AgentGateConfig) -> Result<()> {
    use std::io::Write;

    println!("\x1b[1;36m==========================================================\x1b[0m");
    println!("\x1b[1;37m             🚪 AgentGate Server Setup\x1b[0m");
    println!("\x1b[1;36m==========================================================\x1b[0m");

    // 1. Initialize config, policies, and certs
    println!("⚙️ Initializing policies and TLS certificates...");
    handle_init(
        InitArgs {
            remote: true,
            ..Default::default()
        },
        config,
    )?;

    // 2. Choose network binding
    println!("\nWhere should the server accept connections from?");
    println!("  1) All network interfaces (0.0.0.0) [Recommended for remote access]");
    println!("  2) Local machine only (127.0.0.1)");
    print!("Select [1-2, default 1, 'b' to cancel]: ");
    std::io::stdout().flush()?;
    let mut net_choice = String::new();
    std::io::stdin().read_line(&mut net_choice)?;
    let net_trimmed = net_choice.trim().to_lowercase();
    if net_trimmed == "b" || net_trimmed == "back" || net_trimmed == "cancel" {
        println!("Setup cancelled.\n");
        return Ok(());
    }
    let remote = net_trimmed != "2";

    print!("Port to listen on [default: 7991, 'b' to cancel]: ");
    std::io::stdout().flush()?;
    let mut port_str = String::new();
    std::io::stdin().read_line(&mut port_str)?;
    let port_trimmed = port_str.trim().to_lowercase();
    if port_trimmed == "b" || port_trimmed == "back" || port_trimmed == "cancel" {
        println!("Setup cancelled.\n");
        return Ok(());
    }
    let port = port_trimmed.parse::<u16>().unwrap_or(7991);

    // 3. Start AgentGate
    println!("\n🚀 Starting AgentGate...");
    let start_args = StartArgs {
        listen: None,
        port: Some(port),
        remote,
        local: !remote,
        no_tls: false,
    };
    handle_start(start_args, config)?;

    // Discover network addresses to show user
    let addrs = detect_network_addresses(port, "https");

    println!("\n\x1b[1;32m==========================================================\x1b[0m");
    println!("\x1b[1;32m🎉 AGENTGATE SERVER READY!\x1b[0m");
    println!("\x1b[1;32m==========================================================\x1b[0m");
    println!("Port:  {}", port);
    println!("\nReachable Addresses for this server:");
    for (label, url) in &addrs {
        println!("  • {:12} {}", label, url);
    }

    // Optional token generation
    print!("\nWould you like to generate an access token now? [y/N]: ");
    std::io::stdout().flush()?;
    let mut tok_ans = String::new();
    std::io::stdin().read_line(&mut tok_ans)?;
    let tok_ans = tok_ans.trim().to_lowercase();

    if tok_ans == "y" || tok_ans == "yes" {
        println!("\nSelect policy for this token:");
        println!("  1) read-only     (Safe diagnostics: uptime, df, free, ps, logs)");
        println!("  2) docker-ops    (Manage Docker containers)");
        print!("Select [1-2, default 1]: ");
        std::io::stdout().flush()?;
        let mut pol_choice = String::new();
        std::io::stdin().read_line(&mut pol_choice)?;
        let policy = match pol_choice.trim() {
            "2" => "docker-ops",
            _ => "read-only",
        };

        println!("\nSelect token duration:");
        println!("  1) 24 hours");
        println!("  2) 7 days");
        println!("  3) 30 days");
        println!("  4) Never (Permanent)");
        print!("Select [1-4, default 1]: ");
        std::io::stdout().flush()?;
        let mut exp_choice = String::new();
        std::io::stdin().read_line(&mut exp_choice)?;
        let expires = match exp_choice.trim() {
            "2" => Some("7d".to_string()),
            "3" => Some("30d".to_string()),
            "4" => Some("never".to_string()),
            _ => Some("24h".to_string()),
        };

        let mut store = TokenStore::load(&config.tokens_file)?;
        let duration = expires
            .as_deref()
            .and_then(|e| parse_duration(e).ok().flatten());
        let token_name = format!("agent-{}", &uuid::Uuid::new_v4().to_string()[..6]);
        let raw_token = store.create(&token_name, policy, duration)?;
        store.save()?;

        println!("\n🔑 Access Token Created:");
        println!("  \x1b[1;33m{}\x1b[0m", raw_token);
        println!("  Policy: {}", policy);
    } else {
        println!("\n👉 To create an access token anytime, run:");
        println!("   agentgate token create --name my-agent --policy read-only");
    }

    println!("\n\x1b[1;36m👉 ON YOUR LAPTOP / CLIENT PC:\x1b[0m");
    println!("   Connect with: agentgate client connect --server <SERVER_IP>:{} --token <TOKEN>", port);
    println!("\x1b[1;32m==========================================================\x1b[0m\n");

    Ok(())
}

async fn handle_client_setup_wizard(config: &AgentGateConfig) -> Result<()> {
    use std::io::Write;

    println!("\x1b[1;36m==========================================================\x1b[0m");
    println!("\x1b[1;37m             🚪 AgentGate Client Setup\x1b[0m");
    println!("\x1b[1;36m==========================================================\x1b[0m");

    print!("Enter server IP or hostname [default: 127.0.0.1, 'b' to cancel]: ");
    std::io::stdout().flush()?;
    let mut server_ip = String::new();
    std::io::stdin().read_line(&mut server_ip)?;
    let server_ip = server_ip.trim();
    if server_ip == "b" || server_ip == "back" || server_ip == "cancel" {
        println!("Cancelled.\n");
        return Ok(());
    }
    let host = if server_ip.is_empty() {
        "127.0.0.1"
    } else {
        server_ip
    };

    print!("Enter server port [default: 7991, 'b' to cancel]: ");
    std::io::stdout().flush()?;
    let mut port_str = String::new();
    std::io::stdin().read_line(&mut port_str)?;
    let port_str = port_str.trim();
    if port_str == "b" || port_str == "back" || port_str == "cancel" {
        println!("Cancelled.\n");
        return Ok(());
    }
    let port = port_str.parse::<u16>().unwrap_or(7991);

    let clean_host = host
        .trim_start_matches("http://")
        .trim_start_matches("https://");
    let server_url = format!("https://{}:{}", clean_host, port);

    print!("Paste AgentGate Token (starts with ag_, 'b' to cancel): ");
    std::io::stdout().flush()?;
    let mut token = String::new();
    std::io::stdin().read_line(&mut token)?;
    let token = token.trim().to_string();
    if token == "b" || token == "back" || token == "cancel" {
        println!("Cancelled.\n");
        return Ok(());
    }

    if token.is_empty() {
        println!("❌ Token cannot be empty.\n");
        return Ok(());
    }

    print!("\nTesting connection to {}...", server_url);
    std::io::stdout().flush()?;

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(std::time::Duration::from_secs(5))
        .build()?;

    let test_res = client.get(format!("{}/health", server_url)).send().await;
    match test_res {
        Ok(r) if r.status().is_success() => {
            println!(" \x1b[32m✓ Connected successfully!\x1b[0m");
        }
        _ => {
            println!(
                " \x1b[33m⚠️ Server unreachable or offline, saving credentials anyway.\x1b[0m"
            );
        }
    }

    crate::client::save_client_config(&server_url, &token, true)?;

    println!("\n\x1b[1;32m==========================================================\x1b[0m");
    println!("\x1b[1;32m🎉 CLIENT CONFIGURED & READY!\x1b[0m");
    println!("Server:  {}", server_url);
    println!(
        "Token:   {}...{}",
        &token[..6.min(token.len())],
        &token[token.len().saturating_sub(4)..]
    );
    println!("\x1b[1;32m==========================================================\x1b[0m");
    println!("👉 Run commands directly:     agentgate exec uptime");
    println!("👉 Open interactive shell:    agentgate shell\n");

    print!("Would you like to open the interactive shell now? [Y/n]: ");
    std::io::stdout().flush()?;
    let mut ans = String::new();
    std::io::stdin().read_line(&mut ans)?;
    let ans = ans.trim().to_lowercase();
    if ans.is_empty() || ans == "y" || ans == "yes" {
        crate::client::handle_shell(Some(server_url), Some(token), config).await?;
    }

    Ok(())
}
