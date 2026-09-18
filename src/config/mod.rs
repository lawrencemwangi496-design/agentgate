use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use tracing::info;

/// Configuration for AgentGate
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentGateConfig {
    pub config_dir: PathBuf,
    pub policies_dir: PathBuf,
    pub tokens_file: PathBuf,
    pub certs_dir: PathBuf,
    pub logs_dir: PathBuf,
    pub listen_addr: String,
    pub listen_port: u16,
}

impl AgentGateConfig {
    /// Load config, creating directories if needed
    pub fn load() -> Result<Self> {
        let config_dir = Self::get_config_dir()?;

        let config = Self {
            policies_dir: config_dir.join("policies"),
            tokens_file: config_dir.join("tokens.yaml"),
            certs_dir: config_dir.join("certs"),
            logs_dir: config_dir.join("logs"),
            config_dir,
            listen_addr: "127.0.0.1".to_string(),
            listen_port: 7991,
        };

        // Create directories if needed
        fs::create_dir_all(&config.config_dir).context("Failed to create config_dir")?;
        fs::create_dir_all(&config.policies_dir).context("Failed to create policies_dir")?;
        fs::create_dir_all(&config.certs_dir).context("Failed to create certs_dir")?;
        fs::create_dir_all(&config.logs_dir).context("Failed to create logs_dir")?;

        Ok(config)
    }

    /// Initialize first-time setup (create dirs, default config)
    pub fn init() -> Result<Self> {
        let config = Self::load()?;
        
        info!("Initialized AgentGate configuration at {}", config.config_dir.display());
        info!("Created directory: {}", config.policies_dir.display());
        info!("Created directory: {}", config.certs_dir.display());
        info!("Created directory: {}", config.logs_dir.display());
        info!("Tokens file expected at: {}", config.tokens_file.display());
        
        // Also print to stdout as requested for init commands
        println!("Initialized AgentGate configuration at {}", config.config_dir.display());
        println!("Created directories:");
        println!("  - {}", config.policies_dir.display());
        println!("  - {}", config.certs_dir.display());
        println!("  - {}", config.logs_dir.display());
        println!("Tokens file expected at: {}", config.tokens_file.display());

        Ok(config)
    }

    /// Get the TLS cert path
    pub fn tls_cert_path(&self) -> PathBuf {
        self.certs_dir.join("cert.pem")
    }

    /// Get the TLS key path
    pub fn tls_key_path(&self) -> PathBuf {
        self.certs_dir.join("key.pem")
    }

    /// Determine the base configuration directory based on effective UID
    fn get_config_dir() -> Result<PathBuf> {
        if Self::is_root() {
            Ok(PathBuf::from("/etc/agentgate"))
        } else {
            let home = dirs::home_dir().context("Could not find home directory")?;
            Ok(home.join(".config").join("agentgate"))
        }
    }

    /// Check if the process is running as root (euid == 0) safely without unsafe code
    fn is_root() -> bool {
        // Read /proc/self/status which is standard on Linux to safely get euid
        if let Ok(content) = fs::read_to_string("/proc/self/status") {
            for line in content.lines() {
                if line.starts_with("Uid:") {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    // Uid: real effective saved_set filesystem
                    if parts.len() >= 3 && parts[2] == "0" {
                        return true;
                    }
                }
            }
        }
        false
    }
}
