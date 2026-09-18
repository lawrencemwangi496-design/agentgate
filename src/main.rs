use agentgate::cli::{self, Cli, Commands};
use agentgate::config::AgentGateConfig;
use agentgate::server;

use anyhow::Result;
use clap::Parser;

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

    let cli = Cli::parse();
    let mut config = AgentGateConfig::load()?;

    match cli.command {
        Some(Commands::Init(args)) => {
            cli::handle_init(args, &config)?;
        }
        Some(Commands::Start(args)) => {
            cli::handle_start(args, &config)?;
        }
        Some(Commands::Stop) => {
            cli::handle_stop(&config)?;
        }
        Some(Commands::Restart(args)) => {
            cli::handle_restart(args, &config)?;
        }
        Some(Commands::Serve(args)) => {
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
                    "AgentGate daemon is already running (PID: {}). Stop it first with: agentgate stop",
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
        Some(Commands::Status(args)) => {
            cli::handle_status(args, &config)?;
        }
        Some(Commands::Exec(args)) => {
            agentgate::client::handle_exec(
                args.command,
                args.server,
                args.token,
                args.json,
                args.quiet,
            )
            .await?;
        }
        Some(Commands::Shell(args)) => {
            agentgate::client::handle_shell(args.server, args.token, &config).await?;
        }
        Some(Commands::Menu) => {
            cli::handle_main_menu(&config).await?;
        }
        Some(Commands::Login(args)) => {
            agentgate::client::handle_login(args.server, args.token, args.insecure).await?;
        }
        Some(Commands::Logout) => {
            agentgate::client::handle_logout()?;
        }
        Some(Commands::Whoami) => {
            agentgate::client::handle_whoami().await?;
        }
        Some(Commands::Guide) => {
            agentgate::client::handle_guide()?;
        }
        Some(Commands::Mcp) => {
            agentgate::client::handle_mcp().await?;
        }
        Some(Commands::Token(cmd)) => {
            cli::handle_token(cmd.command, &config)?;
        }
        Some(Commands::Policy(cmd)) => {
            cli::handle_policy(cmd.command, &config)?;
        }
        Some(Commands::Logs(args)) => {
            cli::handle_logs(args, &config)?;
        }
        None => {
            use std::io::IsTerminal;
            if std::io::stdin().is_terminal() {
                cli::handle_main_menu(&config).await?;
            } else {
                use clap::CommandFactory;
                let _ = Cli::command().print_help();
                println!();
            }
        }
    }

    Ok(())
}
