use agentgate::cli::{
    self, InitArgs, LogsArgs, PolicyCommand, ServeArgs, StartArgs, StatusArgs, TokenCommand,
    TotpCommand,
};
use agentgate::config::AgentGateConfig;
use agentgate::server;
use anyhow::Result;
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "agentgated",
    about = "AgentGate Host Daemon & Security Engine — authoritatively executes scoped commands with zero sudo passwords",
    version = env!("CARGO_PKG_VERSION")
)]
pub struct DaemonCli {
    /// Address to listen on (default: 127.0.0.1, or configured)
    #[arg(long, global = true)]
    pub listen: Option<String>,

    /// Port to listen on (default: 7991, or configured)
    #[arg(long, global = true)]
    pub port: Option<u16>,

    /// Path to custom configuration file or directory
    #[arg(long, global = true)]
    pub config: Option<std::path::PathBuf>,

    #[command(subcommand)]
    pub command: Option<DaemonCommands>,
}

#[derive(Subcommand)]
pub enum DaemonCommands {
    /// Run the AgentGate host server in the foreground (for systemd, Docker, or debugging)
    Serve(ServeArgs),

    /// Start the AgentGate host daemon in the background
    Start(StartArgs),

    /// Stop the running AgentGate host daemon
    Stop,

    /// Restart the running AgentGate host daemon
    Restart(StartArgs),

    /// Check daemon status, health, sockets, and loaded policies
    Status(StatusArgs),

    /// Manage agent authentication tokens
    Token(TokenCommand),

    /// Manage execution policies and rules
    Policy(PolicyCommand),

    /// Manage TOTP 2FA secret for dashboard authentication
    Totp(TotpCommand),

    /// Generate a dashboard access token and print connection instructions
    #[command(name = "dashboard-token", alias = "dashboard")]
    DashboardToken(cli::DashboardTokenArgs),

    /// Activate Emergency Lockdown (instantly freeze all agent executions)
    Lockdown,

    /// Release Emergency Lockdown (resume normal operations)
    Unlock,

    /// View command execution audit logs
    Audit(LogsArgs),

    /// Initialize configuration directories, default policies, and certificates
    Init(InitArgs),
}

#[tokio::main]
async fn main() -> Result<()> {
    // Install default Rustls crypto provider
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing::Level::INFO.into()),
        )
        .with_target(false)
        .init();

    let cli = DaemonCli::parse();
    let mut config = AgentGateConfig::load_with_path(cli.config.as_deref())?;

    if let Some(l) = cli.listen {
        config.listen_addr = l;
    }
    if let Some(p) = cli.port {
        config.listen_port = p;
    }

    match cli.command {
        Some(DaemonCommands::Init(args)) => {
            cli::handle_init(args, &config)?;
        }
        Some(DaemonCommands::Start(args)) => {
            cli::handle_start(args, &config)?;
        }
        Some(DaemonCommands::Stop) => {
            cli::handle_stop(&config)?;
        }
        Some(DaemonCommands::Restart(args)) => {
            cli::handle_restart(args, &config)?;
        }
        Some(DaemonCommands::Serve(args)) => {
            let listen_addr = if args.remote {
                "0.0.0.0".to_string()
            } else if args.local {
                "127.0.0.1".to_string()
            } else {
                args.listen.unwrap_or(config.listen_addr.clone())
            };
            let listen_port = args.port.unwrap_or(config.listen_port);
            config.listen_addr = listen_addr;
            config.listen_port = listen_port;

            let my_pid = std::process::id() as i32;
            if let Some(existing_pid) = cli::read_pid(&config.pid_file).filter(|&p| p != my_pid) {
                anyhow::bail!(
                    "AgentGate Host Daemon is already running (PID: {}). Stop it first with: agentgated stop",
                    existing_pid
                );
            }

            let _ = std::fs::write(&config.pid_file, my_pid.to_string());
            let res = server::run_server(&config, args.tls_cert, args.tls_key, !args.no_tls).await;
            if cli::read_pid(&config.pid_file) == Some(my_pid) {
                let _ = std::fs::remove_file(&config.pid_file);
            }
            res?;
        }
        Some(DaemonCommands::Status(args)) => {
            cli::handle_status(args, &config)?;
        }
        Some(DaemonCommands::Token(cmd)) => {
            cli::handle_token(cmd.command, &config)?;
        }
        Some(DaemonCommands::Policy(cmd)) => {
            cli::handle_policy(cmd.command, &config)?;
        }
        Some(DaemonCommands::Lockdown) => {
            println!("🚨 Triggering Emergency Lockdown...");
            let socket_path = config.socket_path.clone();
            if socket_path.exists() {
                let client = reqwest::Client::new();
                let url = format!("http://{}:{}/v1/admin/lockdown", config.listen_addr, config.listen_port);
                match client.post(&url).send().await {
                    Ok(res) if res.status().is_success() => {
                        println!("✅ Emergency Lockdown is now ACTIVE. All agent execution suspended.");
                    }
                    _ => {
                        println!("⚠️ Could not reach running daemon via HTTP. If daemon is running, check status with: agentgated status");
                    }
                }
            } else {
                println!("⚠️ AgentGate Host Daemon does not appear to be running.");
            }
        }
        Some(DaemonCommands::Unlock) => {
            println!("🟢 Releasing Emergency Lockdown...");
            let client = reqwest::Client::new();
            let url = format!("http://{}:{}/v1/admin/unlock", config.listen_addr, config.listen_port);
            match client.post(&url).send().await {
                Ok(res) if res.status().is_success() => {
                    println!("✅ Emergency Lockdown RELEASED. Operations restored to normal.");
                }
                _ => {
                    println!("⚠️ Could not reach running daemon via HTTP. If daemon is running, check status with: agentgated status");
                }
            }
        }
        Some(DaemonCommands::Totp(cmd)) => {
            cli::handle_totp(cmd.command, &config)?;
        }
        Some(DaemonCommands::DashboardToken(args)) => {
            cli::handle_dashboard_token(args, &config)?;
        }
        Some(DaemonCommands::Audit(args)) => {
            cli::handle_logs(args, &config)?;
        }
        None => {
            let my_pid = std::process::id() as i32;
            if let Some(existing_pid) = cli::read_pid(&config.pid_file).filter(|&p| p != my_pid) {
                anyhow::bail!(
                    "AgentGate Host Daemon is already running (PID: {}). Stop it first with: agentgated stop",
                    existing_pid
                );
            }

            let _ = std::fs::write(&config.pid_file, my_pid.to_string());
            let has_tls = config.certs_dir.join("cert.pem").exists() && config.certs_dir.join("key.pem").exists();
            let res = server::run_server(&config, None, None, has_tls).await;
            if cli::read_pid(&config.pid_file) == Some(my_pid) {
                let _ = std::fs::remove_file(&config.pid_file);
            }
            res?;
        }
    }

    Ok(())
}
