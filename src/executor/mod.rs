use anyhow::{bail, Result};
use std::time::Instant;
use tokio::process::Command;
use tokio::time::timeout;
use std::time::Duration;

/// Result of parsing a command string
#[derive(Debug, Clone)]
pub struct ParsedCommand {
    pub binary: String,      // e.g., "systemctl"
    pub args: Vec<String>,   // e.g., ["restart", "nginx"]
    #[allow(dead_code)]
    pub raw: String,         // the original command string
}

/// Result of executing a command
#[derive(Debug, Clone, serde::Serialize)]
pub struct ExecResult {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
    pub duration_ms: u64,
}

/// Shell metacharacters that indicate injection attempts
const SHELL_METACHARACTERS: &[char] = &[';', '&', '|', '`', '$', '(', ')', '>', '<', '\n', '\r'];

impl ParsedCommand {
    /// Parse a command string into binary + args.
    /// Returns Err if the string contains shell metacharacters.
    /// Does NOT use a shell — splits on whitespace.
    pub fn parse(command: &str) -> Result<Self> {
        for &meta in SHELL_METACHARACTERS {
            if command.contains(meta) {
                bail!("command contains disallowed shell metacharacter: '{}'", meta);
            }
        }

        let mut tokens = command.split_whitespace();
        let binary = match tokens.next() {
            Some(b) => b.to_string(),
            None => bail!("command is empty"),
        };

        let args: Vec<String> = tokens.map(|s| s.to_string()).collect();

        Ok(Self {
            binary,
            args,
            raw: command.to_string(),
        })
    }
}

/// Execute a parsed command using tokio::process::Command (NOT via shell).
/// - The binary is looked up via PATH
/// - Arguments are passed as an array (never interpolated into a shell string)
/// - Output is captured
/// - Has a timeout
pub async fn execute(cmd: &ParsedCommand, timeout_secs: u64) -> Result<ExecResult> {
    let start = Instant::now();

    let mut child = Command::new(&cmd.binary);
    child.args(&cmd.args);

    let future = child.output();
    let output = match timeout(Duration::from_secs(timeout_secs), future).await {
        Ok(Ok(out)) => out,
        Ok(Err(e)) => bail!("failed to execute process: {}", e),
        Err(_) => bail!("command execution timed out after {} seconds", timeout_secs),
    };

    let duration_ms = start.elapsed().as_millis() as u64;
    
    // Default exit code to -1 if killed by signal (on Unix)
    let exit_code = output.status.code().unwrap_or(-1);

    Ok(ExecResult {
        exit_code,
        stdout: String::from_utf8_lossy(&output.stdout).to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).to_string(),
        duration_ms,
    })
}
