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

    /// Start the AgentGate daemon in the background
    Start(StartArgs),

    /// Stop the running AgentGate daemon
    Stop,

    /// Restart the running AgentGate daemon
    Restart(StartArgs),

    /// Run the AgentGate server in the foreground
    Serve(ServeArgs),

    /// Check daemon status, health, and loaded policies
    Status(StatusArgs),

    /// Execute an authorized system command through AgentGate
    #[command(name = "exec", alias = "run")]
    Exec(ExecArgs),

    /// Execute a named multi-step action defined in a policy
    #[command(name = "action", alias = "act")]
    Action(ActionArgs),

    /// Interactive shell to execute commands directly
    #[command(name = "shell", aliases = ["console", "connect", "sh"])]
    Shell(ShellArgs),

    /// Open interactive manager menu
    #[command(name = "menu", aliases = ["ui", "manager"])]
    Menu,

    /// Log in client with an access token
    Login(LoginArgs),

    /// Log out client and remove saved credentials
    Logout,

    /// Show current client authentication status
    Whoami,

    /// Print AI agent instruction guide and system prompt rules
    Guide,

    /// Start Model Context Protocol server for native AI tool calling
    Mcp,

    /// Manage authentication tokens for AI agents
    #[command(alias = "tokens")]
    Token(TokenCommand),

    /// Manage command execution policies
    #[command(alias = "policies")]
    Policy(PolicyCommand),

    /// View audit logs of executed and blocked commands
    Logs(LogsArgs),

    /// Manage TOTP 2FA for dashboard authentication
    Totp(TotpCommand),

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

    /// Working directory in which to execute the command
    #[arg(long)]
    pub cwd: Option<String>,

    /// Output full JSON response from server
    #[arg(long, default_value_t = false)]
    pub json: bool,

    /// Suppress error banners
    #[arg(long, short, default_value_t = false)]
    pub quiet: bool,
}

#[derive(Args, Clone, Debug)]
pub struct ActionArgs {
    /// Name of the action defined in the policy (e.g. 'deploy')
    pub name: String,

    /// Optional action parameters formatted as key=value (e.g. -p branch=main)
    #[arg(long = "param", short = 'p')]
    pub params: Vec<String>,

    /// Override server URL (e.g. https://127.0.0.1:7991)
    #[arg(long)]
    pub server: Option<String>,

    /// Override auth token
    #[arg(long)]
    pub token: Option<String>,

    /// Output full JSON response from server
    #[arg(long, default_value_t = false)]
    pub json: bool,
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

        /// Policy name to attach to this token (defaults to 'standard')
        #[arg(long, default_value = "standard")]
        policy: String,

        /// Token expiration duration (e.g. '24h', '7d', '30m'). Defaults to never.
        #[arg(long)]
        expires: Option<String>,

        /// Run commands under an isolated, dedicated OS system user (ag-<name>)
        #[arg(long)]
        user_mode: bool,

        /// Explicit OS system user name to bind to
        #[arg(long)]
        os_user: Option<String>,

        /// Security tier ('read', 'ops', 'admin') with pre-configured OS user and narrow sudoers
        #[arg(long)]
        tier: Option<String>,

        /// Comma-separated list of allowed named actions for pipeline tokens (e.g. 'deploy,test'). Disables arbitrary exec.
        #[arg(long)]
        actions: Option<String>,
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
pub struct TotpCommand {
    #[command(subcommand)]
    pub command: Option<TotpSubcommand>,
}

#[derive(Subcommand, Clone)]
pub enum TotpSubcommand {
    /// Setup or display TOTP 2FA secret for dashboard authentication
    Setup {
        /// Force re-generation of secret even if one already exists
        #[arg(long, default_value_t = false)]
        reset: bool,
    },
    /// Show whether TOTP authentication is currently configured
    Status,
}

#[derive(Args, Clone, Debug, Default)]
pub struct DashboardTokenArgs {
    /// Token lifetime (e.g. 24h, 7d, 30d, default: 24h)
    #[arg(long, default_value = "24h")]
    pub expires: String,

    /// Custom token name identifier
    #[arg(long, default_value = "dashboard-admin")]
    pub name: String,
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
    #[tabled(rename = "TIER")]
    tier: String,
    #[tabled(rename = "OS USER")]
    os_user: String,
    #[tabled(rename = "CREATED AT")]
    created_at: String,
    #[tabled(rename = "EXPIRES")]
    expires: String,
    #[tabled(rename = "ACTIONS")]
    actions: String,
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
const STARTER_AGENT: &str = include_str!("../../policies/agent.yaml");
const STARTER_PIPELINE: &str = include_str!("../../policies/pipeline.yaml");
const STARTER_READ_ONLY: &str = include_str!("../../policies/read-only.yaml");
const STARTER_STANDARD: &str = include_str!("../../policies/standard.yaml");

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
        ("agent.yaml", STARTER_AGENT),
        ("pipeline.yaml", STARTER_PIPELINE),
        ("read-only.yaml", STARTER_READ_ONLY),
        ("standard.yaml", STARTER_STANDARD),
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

    println!("\n✨ Setup complete! To start AgentGate:");
    println!("  agentgate start\n");
    println!("To create your first token for an AI agent:");
    println!("  agentgate token create --name my-agent --policy standard\n");

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

/// Find any actively running AgentGate server process across:
/// 1. The active config's pid file
/// 2. The system-wide /etc/agentgate/agentgate.pid file
/// 3. The invoking user's ~/.config/agentgate/agentgate.pid (if running via sudo)
/// 4. Active Linux processes running `agentgate serve`
pub fn find_running_daemon(config: &AgentGateConfig) -> Option<i32> {
    // 1. Check active config's pid file
    if let Some(pid) = read_pid(&config.pid_file) {
        return Some(pid);
    }

    // 2. Check system-wide /etc/agentgate/agentgate.pid
    let system_pid = Path::new("/etc/agentgate/agentgate.pid");
    if system_pid != config.pid_file.as_path()
        && let Some(pid) = read_pid(system_pid)
    {
        return Some(pid);
    }

    // 3. If running as root via sudo, check original user's config pid file
    if let Ok(sudo_user) = std::env::var("SUDO_USER") {
        let user_pid = std::path::PathBuf::from(format!(
            "/home/{}/.config/agentgate/agentgate.pid",
            sudo_user
        ));
        if user_pid != config.pid_file
            && let Some(pid) = read_pid(&user_pid)
        {
            return Some(pid);
        }
    }

    // 4. Scan /proc for running `agentgate serve` process
    if let Ok(entries) = fs::read_dir("/proc") {
        let current_pid = std::process::id() as i32;
        for entry in entries.flatten() {
            let file_name = entry.file_name();
            let name_str = file_name.to_string_lossy();
            if let Ok(pid) = name_str.parse::<i32>() {
                if pid == current_pid {
                    continue;
                }
                let cmdline_path = entry.path().join("cmdline");
                if let Ok(content) = fs::read(&cmdline_path) {
                    let args: Vec<String> = content
                        .split(|&b| b == 0)
                        .filter_map(|s| String::from_utf8(s.to_vec()).ok())
                        .collect();
                    let is_agentgate = args
                        .first()
                        .map(|b| b.ends_with("agentgate"))
                        .unwrap_or(false);
                    let is_serve = args.iter().any(|a| a == "serve");
                    if is_agentgate && is_serve && unsafe { libc::kill(pid, 0) == 0 } {
                        return Some(pid);
                    }
                }
            }
        }
    }

    None
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

    if let Some(pid) = find_running_daemon(config) {
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
            // Check if AgentGate is already running under systemd or another process
            let is_systemd = std::process::Command::new("systemctl")
                .args(["is-active", "--quiet", "agentgate"])
                .status()
                .map(|s| s.success())
                .unwrap_or(false);

            let check_addr: std::net::SocketAddr = format!("127.0.0.1:{}", target_port)
                .parse()
                .unwrap_or(bind_addr);

            let port_open = std::net::TcpStream::connect_timeout(
                &check_addr,
                std::time::Duration::from_millis(400),
            )
            .is_ok();

            if is_systemd {
                println!("🟢 AgentGate is already running as a system service (systemd)!");
                println!("   Listening: https://{}:{}", config.listen_addr, target_port);
                println!("   Status:    sudo systemctl status agentgate");
                println!("   Restart:   sudo systemctl restart agentgate");
                println!("   Stop:      sudo systemctl stop agentgate");
                return Ok(());
            } else if port_open {
                println!("🟢 AgentGate is already running on port {}!", target_port);
                println!("   Address:   https://{}:{}", config.listen_addr, target_port);
                println!("   Status:    agentgate status");
                println!("   Stop:      agentgate stop");
                return Ok(());
            }

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
    // 1. Check if systemd service is active first
    let is_systemd = std::process::Command::new("systemctl")
        .args(["is-active", "--quiet", "agentgate"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);

    if is_systemd {
        println!("Stopping AgentGate systemd service...");
        let status = std::process::Command::new("systemctl")
            .args(["stop", "agentgate"])
            .status();

        if let Ok(s) = status && s.success() {
            println!("🛑 AgentGate systemd service stopped.");
            return Ok(());
        } else {
            eprintln!("❌ Failed to stop systemd service: root privileges required.");
            eprintln!("💡 Run with sudo: sudo systemctl stop agentgate (or sudo agentgate stop)");
            bail!("Requires sudo to stop AgentGate systemd service");
        }
    }

    let Some(pid) = find_running_daemon(config) else {
        // Port-listening fallback check
        let addr = format!("{}:{}", config.listen_addr, config.listen_port);
        let port_open = std::net::TcpStream::connect_timeout(
            &addr
                .parse()
                .unwrap_or_else(|_| "127.0.0.1:7991".parse().unwrap()),
            std::time::Duration::from_millis(300),
        )
        .is_ok();

        if port_open {
            eprintln!(
                "⚠️  No AgentGate PID file found, but port {} is actively listening.",
                config.listen_port
            );
            eprintln!("💡 If AgentGate is running under another user, terminate it with:");
            eprintln!("   sudo fuser -k {}/tcp", config.listen_port);
            bail!("AgentGate port is in use by another process or user");
        } else {
            println!("⚪ AgentGate is not running.");
        }
        return Ok(());
    };

    println!("Stopping AgentGate (PID: {})...", pid);
    let kill_res = unsafe { libc::kill(pid, libc::SIGTERM) };
    if kill_res != 0 {
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::EPERM) {
            eprintln!(
                "❌ Permission denied: AgentGate (PID: {}) is running under another user (such as root).",
                pid
            );
            eprintln!("💡 Please run with sudo: sudo agentgate stop");
            bail!("Permission denied stopping AgentGate (PID: {})", pid);
        } else {
            eprintln!("⚠️ Failed to send signal to PID {}: {}", pid, err);
        }
    }

    let start = std::time::Instant::now();
    while std::time::Instant::now().duration_since(start).as_secs() < 5 {
        if unsafe { libc::kill(pid, 0) != 0 } {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }

    if unsafe { libc::kill(pid, 0) == 0 } {
        let _ = unsafe { libc::kill(pid, libc::SIGKILL) };
    }

    let _ = fs::remove_file(&config.pid_file);
    let _ = fs::remove_file("/etc/agentgate/agentgate.pid");
    if let Ok(sudo_user) = std::env::var("SUDO_USER") {
        let user_pid = std::path::PathBuf::from(format!(
            "/home/{}/.config/agentgate/agentgate.pid",
            sudo_user
        ));
        let _ = fs::remove_file(user_pid);
    }
    println!("🛑 AgentGate stopped.");

    Ok(())
}

pub fn handle_restart(args: StartArgs, config: &AgentGateConfig) -> Result<()> {
    let is_systemd = std::process::Command::new("systemctl")
        .args(["is-active", "--quiet", "agentgate"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);

    if is_systemd {
        println!("Restarting AgentGate systemd service...");
        let status = std::process::Command::new("systemctl")
            .args(["restart", "agentgate"])
            .status();

        if let Ok(s) = status && s.success() {
            println!("🟢 AgentGate systemd service restarted.");
            return Ok(());
        } else {
            eprintln!("❌ Failed to restart systemd service: root privileges required.");
            eprintln!("💡 Run with sudo: sudo systemctl restart agentgate (or sudo agentgate restart)");
            bail!("Requires sudo to restart AgentGate systemd service");
        }
    }

    handle_stop(config)?;
    std::thread::sleep(std::time::Duration::from_millis(300));
    handle_start(args, config)?;
    Ok(())
}

pub fn handle_status(args: StatusArgs, config: &AgentGateConfig) -> Result<()> {
    let pid_opt = find_running_daemon(config);
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

    let current_exe = std::env::current_exe().unwrap_or_default();
    let is_system_install = current_exe.starts_with("/usr/local/bin")
        || current_exe.starts_with("/usr/bin")
        || Path::new("/etc/agentgate").exists();

    let is_root = unsafe { libc::geteuid() == 0 };

    let mut cmd = if is_system_install && !is_root {
        println!("🔒 Detected system installation (requires root privileges to update).");
        println!("   Elevating with sudo...");
        let mut c = std::process::Command::new("sudo");
        c.args([
            "sh",
            "-c",
            "curl -fsSL https://raw.githubusercontent.com/lawrencemwangi496-design/agentgate/main/install.sh | bash -s -- --update",
        ]);
        c
    } else {
        let mut c = std::process::Command::new("sh");
        c.args([
            "-c",
            "curl -fsSL https://raw.githubusercontent.com/lawrencemwangi496-design/agentgate/main/install.sh | bash -s -- --update",
        ]);
        c
    };

    let status = cmd.status().context("Failed to execute update script")?;

    if status.success() {
        println!("\n✅ AgentGate updated successfully! Run 'agentgate --version' to verify.");
    } else {
        println!("\n⚠️  Update command returned non-zero status.");
        if is_system_install && !is_root {
            println!("💡 Try running with sudo: sudo agentgate update");
        } else {
            println!("💡 You can update manually with: curl -fsSL https://raw.githubusercontent.com/lawrencemwangi496-design/agentgate/main/install.sh | bash");
        }
    }
    Ok(())
}

/// Helper to create a system user for token isolation
pub fn create_system_user(username: &str) -> Result<()> {
    if crate::executor::resolve_os_user(username).is_ok() {
        return Ok(());
    }
    let status = std::process::Command::new("useradd")
        .args(["--system", "--shell", "/usr/sbin/nologin", "--no-create-home", username])
        .status()
        .with_context(|| format!("Failed to execute 'useradd' for user '{}'", username))?;
    if !status.success() {
        bail!("Failed to create system user '{}' with useradd (exit code {:?})", username, status.code());
    }
    Ok(())
}

/// Helper to remove a system user upon token revocation
pub fn remove_system_user(username: &str) -> Result<()> {
    if crate::executor::resolve_os_user(username).is_err() {
        return Ok(());
    }
    let _ = std::process::Command::new("userdel")
        .arg(username)
        .status();
    Ok(())
}

pub fn handle_token(cmd: Option<TokenSubcommand>, config: &AgentGateConfig) -> Result<()> {
    let mut store = TokenStore::load(&config.tokens_file)?;

    match cmd.unwrap_or(TokenSubcommand::List) {
        TokenSubcommand::Create {
            name,
            policy,
            expires,
            user_mode,
            os_user,
            tier,
            actions,
        } => {
            let normalized_tier = tier.as_deref().map(|t| t.to_lowercase());

            // Validate tier if specified
            if let Some(ref t) = normalized_tier {
                match t.as_str() {
                    "read" | "ops" | "admin" => {}
                    _ => bail!("Invalid tier '{}'. Valid tiers are: 'read', 'ops', 'admin'", t),
                }
            }

            let initial_duration = if let Some(exp_str) = expires {
                parse_duration(&exp_str)?
            } else {
                None
            };

            // Configure tier defaults: policy, OS user, duration constraints, sudoers
            let (final_policy, bound_os_user, final_duration) = match normalized_tier.as_deref() {
                Some("read") => {
                    let pol = if policy == "standard" { "read-only".to_string() } else { policy };
                    let u = os_user.unwrap_or_else(|| format!("ag-{}", name));
                    if let Err(e) = create_system_user(&u) {
                        eprintln!("⚠️  Notice: system user '{}' could not be auto-created: {}. Please ensure user exists.", u, e);
                    }
                    (pol, Some(u), initial_duration)
                }
                Some("ops") => {
                    let pol = if policy == "standard" { "docker-ops".to_string() } else { policy };
                    let u = os_user.unwrap_or_else(|| format!("ag-{}", name));
                    if let Err(e) = create_system_user(&u) {
                        eprintln!("⚠️  Notice: system user '{}' could not be auto-created: {}. Please ensure user exists.", u, e);
                    }
                    // Exact commands only for narrow sudo
                    let ops_commands = vec![
                        "/usr/bin/systemctl restart nginx".to_string(),
                        "/usr/bin/systemctl reload nginx".to_string(),
                    ];
                    let content = crate::sudoers::generate_sudoers_content(&u, &ops_commands)?;
                    match crate::sudoers::install_sudoers_fragment(&name, &content) {
                        Ok(p) => println!("✓ Sudoers fragment installed safely: {:?}", p),
                        Err(e) => eprintln!("⚠️  Notice: sudoers fragment could not be installed (run with root/sudo): {}", e),
                    }
                    (pol, Some(u), initial_duration)
                }
                Some("admin") => {
                    // Admin tier requires a short mandatory expiry (maximum 24 hours)
                    let dur = match initial_duration {
                        Some(d) if d <= chrono::Duration::hours(24) => Some(d),
                        Some(_) => {
                            bail!("Admin tier requires a short mandatory expiry (maximum 24 hours).");
                        }
                        None => {
                            println!("ℹ️  Admin tier defaults to short mandatory 24-hour expiry.");
                            Some(chrono::Duration::hours(24))
                        }
                    };
                    let pol = policy;
                    let u = os_user.unwrap_or_else(|| format!("ag-{}", name));
                    if let Err(e) = create_system_user(&u) {
                        eprintln!("⚠️  Notice: system user '{}' could not be auto-created: {}. Please ensure user exists.", u, e);
                    }
                    // Exact commands only for admin operations
                    let admin_commands = vec![
                        "/usr/bin/systemctl restart nginx".to_string(),
                        "/usr/bin/systemctl reload nginx".to_string(),
                    ];
                    let content = crate::sudoers::generate_sudoers_content(&u, &admin_commands)?;
                    match crate::sudoers::install_sudoers_fragment(&name, &content) {
                        Ok(p) => println!("✓ Sudoers fragment installed safely: {:?}", p),
                        Err(e) => eprintln!("⚠️  Notice: sudoers fragment could not be installed (run with root/sudo): {}", e),
                    }
                    (pol, Some(u), dur)
                }
                None => {
                    let bound_u = if user_mode || os_user.is_some() {
                        let u = os_user.unwrap_or_else(|| format!("ag-{}", name));
                        if let Err(e) = create_system_user(&u) {
                            eprintln!("⚠️  Notice: system user '{}' could not be auto-created: {}. Please ensure user exists.", u, e);
                        }
                        Some(u)
                    } else {
                        None
                    };
                    (policy, bound_u, initial_duration)
                }
                _ => unreachable!(),
            };

            // Verify policy exists
            let policy_store = PolicyStore::load(&config.policies_dir)?;
            if policy_store.get(&final_policy).is_none() {
                bail!(
                    "Policy '{}' does not exist. Available policies: {:?}",
                    final_policy,
                    policy_store
                        .list()
                        .iter()
                        .map(|p| &p.name)
                        .collect::<Vec<_>>()
                );
            }

            let parsed_actions = actions.map(|acts| {
                acts.split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect::<Vec<String>>()
            });

            let raw_token = store.create(
                &name,
                &final_policy,
                final_duration,
                bound_os_user.clone(),
                normalized_tier.clone(),
                parsed_actions.clone(),
            )?;

            let expires_display = match final_duration {
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

            let actions_display = match &parsed_actions {
                Some(acts) => acts.join(", "),
                None => "* (Arbitrary execution permitted)".to_string(),
            };

            println!("\n✅ Token created successfully!");
            println!("----------------------------------------------------------------------");
            println!("NAME:       {}", name);
            println!("TIER:       {}", normalized_tier.as_deref().unwrap_or("custom"));
            println!("POLICY:     {}", final_policy);
            println!("ACTIONS:    {}", actions_display);
            println!("OS USER:    {}", bound_os_user.as_deref().unwrap_or("daemon default (no user isolation)"));
            println!("EXPIRES:    {}", expires_display);
            println!("TOKEN:      {}", raw_token);
            println!("----------------------------------------------------------------------");
            println!("⚠️  Save this token now! It will NOT be shown again.");
            println!("\n🚀 Quick Agent Login:");
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
                    tier: t.tier.clone().unwrap_or_else(|| "custom".to_string()),
                    os_user: t.os_user.clone().unwrap_or_else(|| "default".to_string()),
                    created_at: t.created_at.format("%Y-%m-%d %H:%M").to_string(),
                    expires: format_expiry(t.expires_at),
                    actions: t
                        .actions
                        .as_ref()
                        .map(|a| a.join(", "))
                        .unwrap_or_else(|| "*".to_string()),
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
            let token_entry = store.list().iter().find(|t| t.name == name).cloned();
            if store.revoke(&name)? {
                if let Some(token) = token_entry
                    && let Some(ref os_user) = token.os_user
                {
                    let _ = remove_system_user(os_user);
                }
                // Also clean up any sudoers fragment
                let _ = crate::sudoers::remove_sudoers_fragment(&name);
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
                guardrails: true,
                allow: vec![PolicyRule {
                    command: "*".to_string(),
                    args: vec!["*".to_string()],
                }],
                deny: crate::policy::default_guardrails(),
                rules: Vec::new(),
                actions: std::collections::HashMap::new(),
            };
            store.save_policy(&new_policy)?;
            let file_path = config.policies_dir.join(format!("{}.yaml", name));
            println!("✓ Policy created at: {}", file_path.display());
            println!("Guardrails: Destructive system commands (rm -rf /, mkfs, shutdown, etc.) automatically blocked.");
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

pub fn handle_totp(cmd: Option<TotpSubcommand>, config: &AgentGateConfig) -> Result<()> {
    match cmd.unwrap_or(TotpSubcommand::Status) {
        TotpSubcommand::Status => {
            let existing = crate::dashboard::load_totp_secret(&config.totp_file)?;
            if existing.is_some() {
                println!("🟢 TOTP 2FA is CONFIGURED for dashboard authentication.");
                println!("   Config file: {}", config.totp_file.display());
                println!("   To reset: agentgated totp setup --reset");
            } else {
                println!("⚪ TOTP 2FA is NOT CONFIGURED.");
                println!("   To configure: agentgated totp setup");
            }
        }
        TotpSubcommand::Setup { reset } => {
            let existing = crate::dashboard::load_totp_secret(&config.totp_file)?;
            if existing.is_some() && !reset {
                println!("⚠️  TOTP is already configured on this host.");
                println!("   To replace it with a new secret, run: agentgated totp setup --reset");
                return Ok(());
            }

            let secret = crate::dashboard::generate_secret();
            crate::dashboard::save_totp_secret(&config.totp_file, &secret)?;

            let uri = crate::dashboard::generate_otpauth_uri(&secret, "AgentGate", "admin");

            println!("\n==========================================================");
            println!("       🔐 AgentGate Dashboard TOTP Authenticator Setup");
            println!("==========================================================");
            println!("Secret Key:  {}", secret);
            println!("URI:         {}", uri);
            println!("Saved to:    {}", config.totp_file.display());
            println!("----------------------------------------------------------");
            println!("How to use:");
            println!("  1. Open Google Authenticator, 1Password, Aegis, or Bitwarden");
            println!("  2. Add new account and enter the Secret Key above");
            println!("  3. Use the 6-digit code to log into the web dashboard\n");
        }
    }
    Ok(())
}

pub fn handle_dashboard_token(args: DashboardTokenArgs, config: &AgentGateConfig) -> Result<()> {
    let mut store = TokenStore::load(&config.tokens_file)?;
    let duration = parse_duration(&args.expires)?.unwrap_or_else(|| chrono::Duration::hours(24));
    let raw_token = store.create(
        &args.name,
        "standard",
        Some(duration),
        None,
        Some("admin".to_string()),
        None,
    )?;

    let has_tls = config.certs_dir.join("cert.pem").exists() && config.certs_dir.join("key.pem").exists();
    let proto = if has_tls { "https" } else { "http" };
    let host = format!("{}://{}:{}", proto, config.listen_addr, config.listen_port);

    println!("\n==========================================================");
    println!("             🚪 AgentGate Dashboard Access");
    println!("==========================================================");
    println!("  Daemon Host URL:  {}", host);
    println!("  Dashboard Token:  {}", raw_token);
    println!("  Expires in:       {}", args.expires);
    println!();
    println!("  Docker Run (Standalone Dashboard Container):");
    println!("    docker run -d -p 3000:3000 ghcr.io/lawrencemwangi496-design/agentgate-dashboard:latest");
    println!();
    println!("  Then open http://localhost:3000 in your browser and connect using the credentials above.");
    println!("==========================================================\n");

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
        let pid_opt = find_running_daemon(config);
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

fn prompt_policy_selection(config: &AgentGateConfig) -> Result<String> {
    use std::io::Write;

    let store = PolicyStore::load(&config.policies_dir).ok();
    let mut policies: Vec<Policy> = store
        .map(|s| s.list().into_iter().cloned().collect())
        .unwrap_or_default();

    if policies.is_empty() {
        let home = dirs::home_dir().unwrap_or_default();
        let home_policies = home.join(".agentgate").join("policies");
        let fallback_dirs: [&Path; 3] = [
            Path::new("policies"),
            Path::new("/etc/agentgate/policies"),
            home_policies.as_path(),
        ];
        for dir in &fallback_dirs {
            if let Ok(s) = PolicyStore::load(dir) {
                let list = s.list();
                if !list.is_empty() {
                    policies = list.into_iter().cloned().collect();
                    break;
                }
            }
        }
    }

    println!("\nSelect Policy for this token:");
    if !policies.is_empty() {
        policies.sort_by(|a, b| {
            if a.name == "standard" {
                std::cmp::Ordering::Less
            } else if b.name == "standard" {
                std::cmp::Ordering::Greater
            } else {
                a.name.cmp(&b.name)
            }
        });

        for (i, p) in policies.iter().enumerate() {
            let desc = if p.description.trim().is_empty() {
                String::new()
            } else {
                format!(" - {}", p.description.trim())
            };
            if p.name == "standard" {
                println!(
                    "  \x1b[1m{})\x1b[0m \x1b[1;32m{}\x1b[0m (default){}",
                    i + 1,
                    p.name,
                    desc
                );
            } else {
                println!(
                    "  \x1b[1m{})\x1b[0m \x1b[1;36m{}\x1b[0m{}",
                    i + 1,
                    p.name,
                    desc
                );
            }
        }
        println!("  \x1b[1mC)\x1b[0m Custom policy name (enter manually)");
        print!(
            "\nSelect policy [1-{}, default: standard, 'b' to cancel]: ",
            policies.len()
        );
    } else {
        println!("  (No policies found in {})", config.policies_dir.display());
        print!("Policy for this token [default: standard (all commands with guardrails), 'b' to cancel]: ");
    }
    std::io::stdout().flush()?;

    let mut pol = String::new();
    std::io::stdin().read_line(&mut pol)?;
    let pol_trim = pol.trim();
    if pol_trim == "b" || pol_trim == "back" || pol_trim == "cancel" {
        bail!("Cancelled");
    }

    if pol_trim.is_empty() {
        return Ok(if !policies.is_empty() {
            policies[0].name.clone()
        } else {
            "standard".to_string()
        });
    }

    if let Ok(num) = pol_trim.parse::<usize>()
        && (1..=policies.len()).contains(&num)
    {
        return Ok(policies[num - 1].name.clone());
    }

    if pol_trim.eq_ignore_ascii_case("c") || pol_trim.eq_ignore_ascii_case("custom") {
        print!("Enter custom policy name: ");
        std::io::stdout().flush()?;
        let mut custom = String::new();
        std::io::stdin().read_line(&mut custom)?;
        let custom_trim = custom.trim();
        if custom_trim.is_empty() {
            return Ok("standard".to_string());
        }
        return Ok(custom_trim.to_string());
    }

    Ok(pol_trim.to_string())
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

            let policy = match prompt_policy_selection(config) {
                Ok(p) => p,
                Err(_) => {
                    println!("Cancelled.\n");
                    return Ok(());
                }
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
                user_mode: false,
                os_user: None,
                tier: None,
                actions: None,
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
        let policy = match prompt_policy_selection(config) {
            Ok(p) => p,
            Err(_) => {
                println!("Cancelled.\n");
                return Ok(());
            }
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
        let raw_token = store.create(&token_name, &policy, duration, None, None, None)?;
        store.save()?;

        println!("\n🔑 Access Token Created:");
        println!("  \x1b[1;33m{}\x1b[0m", raw_token);
        println!("  Policy: {}", policy);

        // Auto-configure local client credentials so interactive shell works immediately
        let _ = crate::client::save_client_config(&format!("https://127.0.0.1:{}", port), &raw_token, true);
        println!("  ✓ Local client configured (interactive shell is ready to use)");
    } else {
        println!("\n👉 To create an access token anytime, run:");
        println!("   agentgate token create --name my-agent --policy standard");
    }

    println!("\n\x1b[1;36m👉 ON YOUR LAPTOP / CLIENT PC:\x1b[0m");
    println!("   Connect with: agentgate login --server https://<SERVER_IP>:{} --token <TOKEN>", port);
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
        Ok(r) => {
            println!(
                " \x1b[33m⚠️ Server responded with HTTP status {}.\x1b[0m",
                r.status()
            );
        }
        Err(e) => {
            println!(" \x1b[33m⚠️ Server unreachable or connection refused.\x1b[0m");
            println!("   \x1b[1;33m💡 Error details:\x1b[0m {}", e);
            if e.is_connect() {
                println!("   \x1b[36m👉 Tip:\x1b[0m If AgentGate is running on the remote host, make sure it was");
                println!("          started with \x1b[1;32m--remote / 0.0.0.0\x1b[0m (all interfaces) rather than 127.0.0.1,");
                println!("          and verify port {} is open in the server's firewall.", port);
            }
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
