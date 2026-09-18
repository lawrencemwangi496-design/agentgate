mod audit;
mod auth;
mod cli;
mod config;
mod executor;
mod policy;
mod server;

use anyhow::Result;
use clap::Parser;
use cli::{Cli, Commands};
use config::AgentGateConfig;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::timeout;

#[tokio::main]
async fn main() -> Result<()> {
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
        Commands::Init => {
            cli::handle_init(&config)?;
        }
        Commands::Serve(args) => {
            config.listen_addr = args.listen;
            config.listen_port = args.port;

            server::run_server(&config, !args.no_tls).await?;
        }
        Commands::Status(args) => {
            let addr = format!("{}:{}", args.host, args.port);
            match timeout(Duration::from_secs(2), TcpStream::connect(&addr)).await {
                Ok(Ok(_)) => {
                    println!("🟢 AgentGate daemon is RUNNING and listening on {}", addr);
                }
                _ => {
                    println!("🔴 AgentGate daemon is NOT running on {}", addr);
                    println!("Start it with: agentgate serve");
                }
            }
        }
        Commands::Token(cmd) => {
            cli::handle_token(cmd.command, &config)?;
        }
        Commands::Policy(cmd) => {
            cli::handle_policy(cmd.command, &config)?;
        }
        Commands::Logs(args) => {
            cli::handle_logs(args, &config)?;
        }
    }

    Ok(())
}
