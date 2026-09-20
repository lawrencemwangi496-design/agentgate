use agentgate::cli::{ActionArgs, ExecArgs, LoginArgs, ShellArgs};
use agentgate::client;
use agentgate::config::AgentGateConfig;
use anyhow::Result;
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "agentgate",
    about = "AgentGate Delivery Client — secure execution bridge for AI agents and developers",
    version = env!("CARGO_PKG_VERSION")
)]
pub struct ClientCli {
    #[command(subcommand)]
    pub command: Option<ClientCommands>,

    /// Direct command shorthand (e.g. `agentgate uptime` or `agentgate "docker ps"`)
    #[arg(trailing_var_arg = true)]
    pub raw_command: Vec<String>,
}

#[derive(Subcommand)]
pub enum ClientCommands {
    /// Execute an authorized command on the host (e.g. `agentgate exec uptime`)
    #[command(name = "exec", alias = "run")]
    Exec(ExecArgs),

    /// Execute a named multi-step action defined in a policy
    #[command(name = "action", alias = "act")]
    Action(ActionArgs),

    /// Interactive terminal shell to execute commands directly
    #[command(name = "shell", aliases = ["console", "connect", "sh"])]
    Shell(ShellArgs),

    /// Log in client with server endpoint and access token
    Login(LoginArgs),

    /// Log out client and remove saved credentials
    Logout,

    /// Show current client authentication status
    Whoami,

    /// Check host daemon connectivity and latency
    #[command(alias = "ping")]
    Status,

    /// Print AI agent instruction guide and system prompt rules
    Guide,

    /// Start Model Context Protocol server for native AI tool calling
    Mcp,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Install default Rustls crypto provider
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let cli = ClientCli::parse();

    match cli.command {
        Some(ClientCommands::Exec(args)) => {
            client::handle_exec(
                args.command,
                args.server,
                args.token,
                args.cwd,
                args.json,
                args.quiet,
            )
            .await?;
        }
        Some(ClientCommands::Action(args)) => {
            client::handle_action(args).await?;
        }
        Some(ClientCommands::Shell(args)) => {
            let config = AgentGateConfig::load().unwrap_or_else(|_| {
                // Fallback config if not found
                AgentGateConfig::load().unwrap()
            });
            client::handle_shell(args.server, args.token, &config).await?;
        }
        Some(ClientCommands::Login(args)) => {
            client::handle_login(args.server, args.token, args.insecure).await?;
        }
        Some(ClientCommands::Logout) => {
            client::handle_logout()?;
        }
        Some(ClientCommands::Whoami) => {
            client::handle_whoami().await?;
        }
        Some(ClientCommands::Status) => {
            client::handle_whoami().await?;
        }
        Some(ClientCommands::Guide) => {
            client::handle_guide()?;
        }
        Some(ClientCommands::Mcp) => {
            client::handle_mcp().await?;
        }
        None => {
            if !cli.raw_command.is_empty() {
                let first = cli.raw_command[0].to_lowercase();
                if ["start", "stop", "restart", "serve", "init", "lockdown", "unlock"].contains(&first.as_str()) {
                    eprintln!("⚠️  '{}' is a host daemon command.", first);
                    eprintln!("💡 To manage the host daemon, run: agentgated {}", first);
                    std::process::exit(1);
                } else if ["token", "tokens", "policy", "policies", "audit", "logs", "sudoers"].contains(&first.as_str()) {
                    eprintln!("⚠️  '{}' is a host management command.", first);
                    eprintln!("💡 To configure host policies and tokens, run: agentgated {}", first);
                    std::process::exit(1);
                }

                // Execute raw command shorthand
                client::handle_exec(
                    cli.raw_command,
                    None,
                    None,
                    None,
                    false,
                    false,
                )
                .await?;
            } else {
                use clap::CommandFactory;
                let _ = ClientCli::command().print_help();
                println!();
            }
        }
    }

    Ok(())
}
