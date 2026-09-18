use crate::audit::AuditLogger;
use crate::auth::TokenStore;
use crate::config::AgentGateConfig;
use crate::policy::{Policy, PolicyRule, PolicyStore};
use crate::server::cert;
use anyhow::{bail, Context, Result};
use clap::{Args, Parser, Subcommand};
use std::fs;
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
    Init,

    /// Start the AgentGate daemon server
    Serve(ServeArgs),

    /// Check daemon status and health
    Status(StatusArgs),

    /// Manage authentication tokens for AI agents
    Token(TokenCommand),

    /// Manage command execution policies
    Policy(PolicyCommand),

    /// View audit logs of executed and blocked commands
    Logs(LogsArgs),
}

#[derive(Args)]
pub struct ServeArgs {
    /// Address to listen on
    #[arg(long, default_value = "127.0.0.1")]
    pub listen: String,

    /// Port to listen on
    #[arg(long, default_value_t = 7991)]
    pub port: u16,

    /// Run as plain HTTP without TLS
    #[arg(long, default_value_t = false)]
    pub no_tls: bool,
}

#[derive(Args)]
pub struct StatusArgs {
    /// Address of running daemon
    #[arg(long, default_value = "127.0.0.1")]
    pub host: String,

    /// Port of running daemon
    #[arg(long, default_value_t = 7991)]
    pub port: u16,

    /// Use HTTPS
    #[arg(long, default_value_t = true)]
    pub tls: bool,
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
    #[tabled(rename = "EXPIRES AT")]
    expires_at: String,
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

pub fn handle_init(config: &AgentGateConfig) -> Result<()> {
    AgentGateConfig::init()?;

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
    println!("  agentgate serve\n");
    println!("To create your first token:");
    println!("  agentgate token create --name my-agent --policy read-only\n");

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
                Some(parse_duration(&exp_str)?)
            } else {
                None
            };

            let raw_token = store.create(&name, &policy, duration)?;

            println!("\n✅ Token created successfully!");
            println!("----------------------------------------------------------------------");
            println!("NAME:       {}", name);
            println!("POLICY:     {}", policy);
            println!(
                "EXPIRES:    {}",
                duration
                    .map(|d| format!("in {} seconds", d.num_seconds()))
                    .unwrap_or_else(|| "Never".to_string())
            );
            println!("TOKEN:      {}", raw_token);
            println!("----------------------------------------------------------------------");
            println!("⚠️  Save this token now! It will NOT be shown again.");
            println!("\nExample cURL for your AI agent:");
            println!(
                "curl -k -X POST https://127.0.0.1:7991/v1/exec \\\n  \
                -H \"Authorization: Bearer {}\" \\\n  \
                -H \"Content-Type: application/json\" \\\n  \
                -d '{{\"command\": \"uptime\"}}'\n",
                raw_token
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
                    expires_at: t
                        .expires_at
                        .map(|dt| dt.format("%Y-%m-%d %H:%M").to_string())
                        .unwrap_or_else(|| "Never".to_string()),
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

fn parse_duration(s: &str) -> Result<chrono::Duration> {
    let s = s.trim().to_lowercase();
    if let Some(hours) = s.strip_suffix('h') {
        let h: i64 = hours.parse().context("Invalid hours format")?;
        Ok(chrono::Duration::hours(h))
    } else if let Some(days) = s.strip_suffix('d') {
        let d: i64 = days.parse().context("Invalid days format")?;
        Ok(chrono::Duration::days(d))
    } else if let Some(mins) = s.strip_suffix('m') {
        let m: i64 = mins.parse().context("Invalid minutes format")?;
        Ok(chrono::Duration::minutes(m))
    } else if let Some(secs) = s.strip_suffix('s') {
        let sec: i64 = secs.parse().context("Invalid seconds format")?;
        Ok(chrono::Duration::seconds(sec))
    } else {
        bail!("Unknown duration format '{}'. Use e.g. '24h', '7d', '30m'", s);
    }
}
