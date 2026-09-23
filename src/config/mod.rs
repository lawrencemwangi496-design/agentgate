use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use tracing::info;

/// Configuration for AgentGate
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentGateConfig {
    pub config_dir: PathBuf,
    pub config_file: PathBuf,
    pub client_file: PathBuf,
    pub policies_dir: PathBuf,
    pub tokens_file: PathBuf,
    pub certs_dir: PathBuf,
    pub logs_dir: PathBuf,
    pub pid_file: PathBuf,
    pub socket_path: PathBuf,
    pub listen_addr: String,
    pub listen_port: u16,
    pub allowed_origins: Vec<String>,
    pub dashboard: Option<DashboardConfig>,
    pub totp_file: PathBuf,
}

const fn default_session_expiry_hours() -> u64 {
    24
}

const fn default_totp_enabled() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DashboardConfig {
    #[serde(default = "default_session_expiry_hours")]
    pub session_expiry_hours: u64,
    #[serde(default = "default_totp_enabled")]
    pub totp_enabled: bool,
}

impl Default for DashboardConfig {
    fn default() -> Self {
        Self {
            session_expiry_hours: default_session_expiry_hours(),
            totp_enabled: default_totp_enabled(),
        }
    }
}

#[derive(Debug, Deserialize, Serialize, Default)]
struct DaemonConfigFile {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub listen: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allowed_origins: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dashboard: Option<DashboardConfig>,
}

impl AgentGateConfig {
    /// Load config, creating directories if needed
    pub fn load() -> Result<Self> {
        Self::load_with_path(None)
    }

    /// Load config with optional custom config path or directory
    pub fn load_with_path(custom_path: Option<&std::path::Path>) -> Result<Self> {
        let (config_dir, config_file) = if let Some(path) = custom_path {
            if path.is_dir() {
                (path.to_path_buf(), path.join("config.yaml"))
            } else {
                let dir = path
                    .parent()
                    .unwrap_or_else(|| std::path::Path::new("."))
                    .to_path_buf();
                (dir, path.to_path_buf())
            }
        } else {
            let dir = Self::get_config_dir()?;
            let file = dir.join("config.yaml");
            (dir, file)
        };
        let client_file = config_dir.join("client.yaml");

        let mut listen_addr = "127.0.0.1".to_string();
        let mut listen_port = 7991u16;
        let mut allowed_origins = Vec::new();
        let mut dashboard: Option<DashboardConfig> = None;

        // 1. Read from config.yaml if present
        if let Ok(Some(parsed)) = fs::read_to_string(&config_file)
            .map(|c| serde_yaml::from_str::<DaemonConfigFile>(&c).ok())
        {
            if let Some(l) = parsed.listen {
                listen_addr = l;
            }
            if let Some(p) = parsed.port {
                listen_port = p;
            }
            if let Some(origins) = parsed.allowed_origins {
                allowed_origins = origins;
            }
            if let Some(dash) = parsed.dashboard {
                dashboard = Some(dash);
            }
        }

        // 2. Override from environment variables if set
        if let Some(env_listen) = std::env::var("AGENTGATE_LISTEN")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
        {
            listen_addr = env_listen;
        }
        if let Some(p) = std::env::var("AGENTGATE_PORT")
            .ok()
            .and_then(|p| p.trim().parse::<u16>().ok())
        {
            listen_port = p;
        }
        if let Some(env_origins) = std::env::var("AGENTGATE_CORS_ORIGIN")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
        {
            allowed_origins = env_origins
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
        }

        let socket_path = if let Ok(s) = std::env::var("AGENTGATE_SOCKET") {
            PathBuf::from(s)
        } else if Self::is_root() {
            PathBuf::from("/run/agentgate.sock")
        } else {
            config_dir.join("agentgated.sock")
        };

        let totp_file = config_dir.join("totp.yaml");

        let config = Self {
            policies_dir: config_dir.join("policies"),
            tokens_file: config_dir.join("tokens.yaml"),
            certs_dir: config_dir.join("certs"),
            logs_dir: config_dir.join("logs"),
            pid_file: config_dir.join("agentgate.pid"),
            socket_path,
            config_file,
            client_file,
            config_dir,
            listen_addr,
            listen_port,
            allowed_origins,
            dashboard,
            totp_file,
        };

        // Create directories if needed
        fs::create_dir_all(&config.config_dir).context("Failed to create config_dir")?;
        fs::create_dir_all(&config.policies_dir).context("Failed to create policies_dir")?;
        fs::create_dir_all(&config.certs_dir).context("Failed to create certs_dir")?;
        fs::create_dir_all(&config.logs_dir).context("Failed to create logs_dir")?;

        Ok(config)
    }

    /// Initialize first-time setup (create dirs, default config)
    pub fn init(initial_port: Option<u16>, initial_listen: Option<String>) -> Result<Self> {
        let mut config = Self::load()?;

        if let Some(p) = initial_port {
            config.listen_port = p;
        }
        let has_custom_listen = initial_listen.is_some();
        if let Some(l) = initial_listen {
            config.listen_addr = l;
        }

        // Write default config.yaml if not already present
        if !config.config_file.exists() {
            let yaml_content = format!(
                "# AgentGate Daemon Configuration\n\
                 # Address to bind to (use \"127.0.0.1\" for local machine, \"0.0.0.0\" for network access)\n\
                 listen: \"{}\"\n\n\
                 # Port to listen on (default: 7991). Change this if port 7991 is used by another service.\n\
                 port: {}\n",
                config.listen_addr, config.listen_port
            );
            fs::write(&config.config_file, yaml_content)
                .with_context(|| format!("Failed to write config file {:?}", config.config_file))?;
        } else if initial_port.is_some() || has_custom_listen {
            let yaml_content = format!(
                "# AgentGate Daemon Configuration\n\
                 # Address to bind to (use \"127.0.0.1\" for local machine, \"0.0.0.0\" for network access)\n\
                 listen: \"{}\"\n\n\
                 # Port to listen on (default: 7991). Change this if port 7991 is used by another service.\n\
                 port: {}\n",
                config.listen_addr, config.listen_port
            );
            fs::write(&config.config_file, yaml_content)
                .with_context(|| format!("Failed to write config file {:?}", config.config_file))?;
        }

        info!(
            "Initialized AgentGate configuration at {}",
            config.config_dir.display()
        );
        info!("Created directory: {}", config.policies_dir.display());
        info!("Created directory: {}", config.certs_dir.display());
        info!("Created directory: {}", config.logs_dir.display());
        info!("Configuration file: {}", config.config_file.display());
        info!("Tokens file expected at: {}", config.tokens_file.display());

        // Print user-friendly setup confirmation
        println!(
            "Initialized AgentGate configuration at {}",
            config.config_dir.display()
        );
        println!("  - Config file: {}", config.config_file.display());
        println!("  - Policies:    {}", config.policies_dir.display());
        println!("  - Certs:       {}", config.certs_dir.display());
        println!("  - Logs:        {}", config.logs_dir.display());
        println!("  - Tokens:      {}", config.tokens_file.display());
        println!("  - Listen Host: {}", config.listen_addr);
        println!("  - Listen Port: {}", config.listen_port);

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
        if let Ok(dir) = std::env::var("AGENTGATE_CONFIG_DIR") {
            return Ok(PathBuf::from(dir));
        }
        if Self::is_root() {
            Ok(PathBuf::from("/etc/agentgate"))
        } else {
            let home = dirs::home_dir().context("Could not find home directory")?;
            Ok(home.join(".config").join("agentgate"))
        }
    }

    /// Get default socket path for client connection
    pub fn default_socket_path() -> PathBuf {
        if let Ok(s) = std::env::var("AGENTGATE_SOCKET") {
            return PathBuf::from(s);
        }
        if Self::is_root() {
            PathBuf::from("/run/agentgate.sock")
        } else if let Some(home) = dirs::home_dir() {
            home.join(".config").join("agentgate").join("agentgated.sock")
        } else {
            PathBuf::from("/tmp/agentgated.sock")
        }
    }

    /// Check if current process or config is running with root permissions
    pub fn is_running_as_root() -> bool {
        Self::is_root()
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
