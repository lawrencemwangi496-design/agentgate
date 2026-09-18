use crate::audit::AuditLogger;
use crate::auth::TokenStore;
use crate::config::AgentGateConfig;
use crate::policy::{Policy, PolicyRule, PolicyStore};
use crate::server::cert;
use anyhow::{bail, Context, Result};
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
    pub command: Commands,
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
    Token(TokenCommand),

    /// Manage command execution policies
    Policy(PolicyCommand),

    /// View audit logs of executed and blocked commands
    Logs(LogsArgs),
}

#[derive(Args, Clone, Default)]
pub struct InitArgs {
    /// Default port to configure (default: 7991)
    #[arg(long)]
    pub port: Option<u16>,

    /// Default address to listen on (default: 127.0.0.1)
    #[arg(long)]
    pub listen: Option<String>,
}

#[derive(Args, Clone, Default)]
pub struct StartArgs {
    /// Address to listen on (default: 127.0.0.1, or configured)
    #[arg(long)]
    pub listen: Option<String>,

    /// Port to listen on (default: 7991, or configured)
    #[arg(long)]
    pub port: Option<u16>,

    /// Run as plain HTTP without TLS
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

    /// Optional path to custom TLS certificate (e.g. Let's Encrypt fullchain.pem)
    #[arg(long)]
    pub tls_cert: Option<std::path::PathBuf>,

    /// Optional path to custom TLS private key (e.g. Let's Encrypt privkey.pem)
    #[arg(long)]
    pub tls_key: Option<std::path::PathBuf>,

    /// Run as plain HTTP without TLS
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

#[derive(Args, Clone, Debug)]
pub struct LoginArgs {
    /// AgentGate authentication token (starts with ag_)
    #[arg(long, short)]
    pub token: Option<String>,

    /// Server URL to connect to
    #[arg(long, short, default_value = "https://127.0.0.1:7991")]
    pub server: String,

    /// Allow self-signed TLS certificates (default: true for localhost)
    #[arg(long, default_value_t = true)]
    pub insecure: bool,
}

#[derive(Args)]
pub struct TokenCommand {
    #[command(subcommand)]
    pub command: TokenSubcommand,
}

#[derive(Subcommand)]
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

#[derive(Args)]
pub struct PolicyCommand {
    #[command(subcommand)]
    pub command: PolicySubcommand,
}

#[derive(Subcommand)]
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

#[derive(Args)]
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
const STARTER_WEBSERVER: &str = include_str!("../../policies/webserver-ops.yaml");

pub fn handle_init(args: InitArgs, config: &AgentGateConfig) -> Result<()> {
    AgentGateConfig::init(args.port, args.listen)?;

    // Populate starter policies if they don't already exist
    let starters = [
        ("read-only.yaml", STARTER_READ_ONLY),
        ("docker-ops.yaml", STARTER_DOCKER),
        ("webserver-ops.yaml", STARTER_WEBSERVER),
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
    println!("  ✓ Generated TLS certificate at: {}", config.tls_cert_path().display());
    println!("  ✓ Generated TLS private key at: {}", config.tls_key_path().display());

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

pub fn handle_start(args: StartArgs, config: &AgentGateConfig) -> Result<()> {
    let target_listen = args.listen.unwrap_or_else(|| config.listen_addr.clone());
    let target_port = args.port.unwrap_or(config.listen_port);

    if let Some(pid) = read_pid(&config.pid_file) {
        let active_port = get_process_port(pid).unwrap_or(config.listen_port);
        println!("🟢 AgentGate daemon is already running (PID: {})", pid);
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
            eprintln!("❌ Port {} is already in use by another process on {}.", target_port, target_listen);
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
        .with_context(|| format!("Failed to open daemon log at {:?}", log_file))?;
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

    let mut child = cmd.spawn().context("Failed to spawn background daemon")?;
    let pid = child.id() as i32;

    fs::write(&config.pid_file, pid.to_string())
        .with_context(|| format!("Failed to write PID file {:?}", config.pid_file))?;

    std::thread::sleep(std::time::Duration::from_millis(600));

    // Verify child process didn't immediately crash or exit
    if let Ok(Some(status)) = child.try_wait() {
        let _ = fs::remove_file(&config.pid_file);
        let log_tail = fs::read_to_string(&log_file).unwrap_or_default();
        let last_lines: Vec<&str> = log_tail.lines().rev().take(6).collect();
        eprintln!("❌ AgentGate daemon failed to start (exit status: {}).", status);
        if !last_lines.is_empty() {
            eprintln!("   Error details from log ({}):", log_file.display());
            for line in last_lines.iter().rev() {
                eprintln!("     {}", line);
            }
        }
        bail!("Daemon exited immediately after startup");
    }

    let protocol = if args.no_tls { "http" } else { "https" };
    println!("🟢 AgentGate daemon started in background (PID: {})", pid);
    println!("   Listening on: {}://{}:{}", protocol, target_listen, target_port);
    println!("   Daemon logs:  {}", log_file.display());
    println!("   Execute with: agentgate exec <command>");
    println!("   Stop anytime: agentgate stop");

    Ok(())
}

pub fn handle_stop(config: &AgentGateConfig) -> Result<()> {
    let Some(pid) = read_pid(&config.pid_file) else {
        println!("⚪ AgentGate daemon is not running.");
        return Ok(());
    };

    println!("Stopping AgentGate daemon (PID: {})...", pid);
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
    println!("🛑 AgentGate daemon stopped.");

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
    let target_host = args.host.unwrap_or_else(|| config.listen_addr.clone());
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
            &addr.parse().unwrap_or_else(|_| "127.0.0.1:7991".parse().unwrap()),
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

    println!("Listening:     https://{}:{}", target_host, target_port);
    println!("Config Dir:    {}", config.config_dir.display());
    println!("PID File:      {}", config.pid_file.display());
    println!("Daemon Log:    {}", config.logs_dir.join("daemon.log").display());

    let policy_store = PolicyStore::load(&config.policies_dir).ok();
    let policies_count = policy_store.map(|ps| ps.list().len()).unwrap_or(0);
    let token_store = TokenStore::load(&config.tokens_file).ok();
    let tokens_count = token_store.map(|ts| ts.list().len()).unwrap_or(0);

    println!("Policies:      {} loaded", policies_count);
    println!("Tokens:        {} configured", tokens_count);

    if let Ok(Some(client_cfg)) = crate::client::load_client_config() {
        let masked = if client_cfg.token.len() > 10 {
            format!("{}...{}", &client_cfg.token[..6], &client_cfg.token[client_cfg.token.len() - 4..])
        } else {
            "***".to_string()
        };
        println!("Client CLI:    🟢 Configured ({}, {})", client_cfg.server, masked);
    } else {
        println!("Client CLI:    ⚪ Not logged in (run 'agentgate login')");
    }

    println!("==========================================================");

    Ok(())
}

pub fn handle_token(cmd: TokenSubcommand, config: &AgentGateConfig) -> Result<()> {
    let mut store = TokenStore::load(&config.tokens_file)?;

    match cmd {
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
                    format!("{} (at {} UTC)", format_duration_human(d), expiry_time.format("%Y-%m-%d %H:%M"))
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
                println!("No tokens found. Create one with: agentgate token create --name <name> --policy <policy>");
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
                println!("✓ Token '{}' has been revoked and can no longer be used.", name);
            } else {
                println!("Token '{}' not found.", name);
            }
        }
    }

    Ok(())
}

pub fn handle_policy(cmd: PolicySubcommand, config: &AgentGateConfig) -> Result<()> {
    let mut store = PolicyStore::load(&config.policies_dir)?;

    match cmd {
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
        format!("in {} minute{}", minutes, if minutes > 1 { "s" } else { "" })
    } else {
        format!("in {} second{}", seconds, if seconds > 1 { "s" } else { "" })
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
