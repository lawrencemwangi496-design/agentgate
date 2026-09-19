use anyhow::{Context, Result, bail};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant};
use tokio::io::AsyncReadExt;
use tokio::process::Command;
use tokio::time::timeout;

/// Shell metacharacters and control characters that indicate injection attempts
const SHELL_METACHARACTERS: &[char] = &[
    ';', '&', '|', '`', '$', '(', ')', '>', '<', '\n', '\r', '\0',
];

/// Maximum allowed output per stream (5 MB) to prevent RAM exhaustion / DoS
pub const MAX_OUTPUT_BYTES: usize = 5 * 1024 * 1024;

/// Trusted system directories for binary execution. Prevents PATH manipulation.
const TRUSTED_PATHS: &[&str] = &[
    "/usr/local/bin",
    "/usr/local/sbin",
    "/usr/bin",
    "/usr/sbin",
    "/bin",
    "/sbin",
];

/// Result of parsing a command string
#[derive(Debug, Clone)]
pub struct ParsedCommand {
    pub binary: String,       // Base binary name (e.g. "systemctl")
    pub binary_path: PathBuf, // Absolute resolved path in trusted directories
    pub args: Vec<String>,    // Arguments parsed with quotes preserved
    #[allow(dead_code)]
    pub raw: String,
}

/// Result of executing a command
#[derive(Debug, Clone, serde::Serialize)]
pub struct ExecResult {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
    pub duration_ms: u64,
    pub truncated: bool,
}

impl ParsedCommand {
    /// Parse a command string into binary + args.
    /// - Checks for shell metacharacters and null bytes
    /// - Uses POSIX quote-aware splitting (handles "foo bar" correctly)
    /// - Rejects directory traversal in arguments ('..')
    /// - Resolves binary exclusively against trusted system directories
    pub fn parse(command: &str) -> Result<Self> {
        let trimmed = command.trim();
        if trimmed.is_empty() {
            bail!("command is empty");
        }

        // 1. Check for shell metacharacters & null bytes
        for &meta in SHELL_METACHARACTERS {
            if trimmed.contains(meta) {
                bail!(
                    "command contains disallowed shell metacharacter: '{:?}'",
                    meta
                );
            }
        }

        // 2. Quote-aware tokenization using shlex
        let tokens = shlex::split(trimmed)
            .ok_or_else(|| anyhow::anyhow!("command contains unclosed quotes or syntax error"))?;

        if tokens.is_empty() {
            bail!("command is empty after tokenization");
        }

        let raw_binary = &tokens[0];
        let args = tokens[1..].to_vec();

        // 3. Block directory traversal in arguments
        for arg in &args {
            if arg == ".." || arg.starts_with("../") || arg.contains("/../") || arg.ends_with("/..")
            {
                bail!(
                    "argument '{}' contains disallowed directory traversal ('..')",
                    arg
                );
            }
        }

        // 4. Resolve binary exclusively in trusted system directories
        let (base_binary_name, binary_path) = Self::resolve_trusted_binary(raw_binary)?;

        Ok(Self {
            binary: base_binary_name,
            binary_path,
            args,
            raw: trimmed.to_string(),
        })
    }

    /// Resolve a binary name to an absolute path inside trusted system directories.
    /// Refuses relative paths, user paths, or arbitrary directories.
    fn resolve_trusted_binary(binary: &str) -> Result<(String, PathBuf)> {
        let path = Path::new(binary);

        // If an absolute path is provided, it must reside in one of the trusted directories
        if path.is_absolute() {
            let parent = path.parent().and_then(|p| p.to_str()).unwrap_or("");
            if !TRUSTED_PATHS.contains(&parent) {
                bail!(
                    "binary path '{}' is outside trusted system directories ({:?})",
                    binary,
                    TRUSTED_PATHS
                );
            }
            if !path.is_file() {
                bail!("binary '{}' does not exist or is not a file", binary);
            }
            let file_name = path
                .file_name()
                .and_then(|f| f.to_str())
                .ok_or_else(|| anyhow::anyhow!("invalid binary filename"))?;
            return Ok((file_name.to_string(), path.to_path_buf()));
        }

        // If binary contains relative path slashes (e.g. ./bin/foo), reject it
        if binary.contains('/') {
            bail!("relative binary path '{}' is not permitted", binary);
        }

        // Search exclusively in trusted system directories
        for &dir in TRUSTED_PATHS {
            let candidate = Path::new(dir).join(binary);
            if candidate.is_file() {
                return Ok((binary.to_string(), candidate));
            }
        }

        bail!(
            "binary '{}' not found in trusted system directories ({:?})",
            binary,
            TRUSTED_PATHS
        );
    }
}

/// Resolve the UID, GID, and home directory of a Unix username
pub fn resolve_os_user(username: &str) -> Result<(u32, u32, PathBuf)> {
    #[cfg(unix)]
    {
        use std::ffi::CString;
        let c_user = CString::new(username)
            .map_err(|_| anyhow::anyhow!("Invalid username containing null bytes"))?;
        let pwd = unsafe { libc::getpwnam(c_user.as_ptr()) };
        if pwd.is_null() {
            bail!("System user '{}' does not exist on this machine", username);
        }
        let (uid, gid, home) = unsafe {
            let home_cstr = std::ffi::CStr::from_ptr((*pwd).pw_dir);
            let home_str = home_cstr.to_string_lossy().into_owned();
            ((*pwd).pw_uid, (*pwd).pw_gid, PathBuf::from(home_str))
        };
        Ok((uid, gid, home))
    }
    #[cfg(not(unix))]
    {
        bail!("Per-token OS users are only supported on Unix systems");
    }
}

/// Execute a parsed command with hardened security controls:
/// - Executes the resolved binary directly without shell
/// - Strips environment variables (env_clear) to prevent secret leakage
/// - Injects minimal, sanitized standard environment
/// - Enforces non-interactive stdin (Stdio::null)
/// - Drops privileges to dedicated per-token OS user (uid, gid, empty groups) if configured
/// - Enforces strict output size limit (5MB) to prevent RAM exhaustion
/// - Kills child process if execution timeout expires
pub async fn execute(
    cmd: &ParsedCommand,
    timeout_secs: u64,
    os_user: Option<&str>,
    cwd: Option<&str>,
) -> Result<ExecResult> {
    let start = Instant::now();

    let mut builder = Command::new(&cmd.binary_path);
    builder.args(&cmd.args);

    // 1. Determine user identity & isolate OS privileges
    let default_user = std::env::var("USER").unwrap_or_else(|_| "agentgate".to_string());
    let default_home = dirs::home_dir()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_else(|| "/tmp".to_string());

    let (target_user, target_home) = if let Some(user) = os_user {
        let (uid, gid, home) = resolve_os_user(user)?;
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            builder.as_std_mut().uid(uid).gid(gid);
            unsafe {
                builder.as_std_mut().pre_exec(move || {
                    // Strict privilege drop order: setgroups(0, NULL) -> setgid -> setuid
                    // If root, clear all supplementary groups and switch IDs
                    if libc::geteuid() == 0 {
                        if libc::setgroups(0, std::ptr::null()) != 0 {
                            return Err(std::io::Error::last_os_error());
                        }
                        if libc::setgid(gid) != 0 {
                            return Err(std::io::Error::last_os_error());
                        }
                        if libc::setuid(uid) != 0 {
                            return Err(std::io::Error::last_os_error());
                        }
                    }
                    Ok(())
                });
            }
        }
        (user.to_string(), home.to_string_lossy().to_string())
    } else {
        (default_user, default_home)
    };

    // 2. Working Directory Selection
    if let Some(dir) = cwd {
        builder.current_dir(dir);
    } else {
        builder.current_dir(&target_home);
    }

    // 3. Environment Sanitization
    builder.env_clear();
    builder.env("PATH", "/usr/local/bin:/usr/local/sbin:/usr/bin:/usr/sbin:/bin:/sbin");
    builder.env("LANG", "C.UTF-8");
    builder.env("TERM", "dumb");
    builder.env("USER", &target_user);
    builder.env("HOME", &target_home);

    // 4. Prevent interactive input hanging
    builder.stdin(Stdio::null());
    builder.stdout(Stdio::piped());
    builder.stderr(Stdio::piped());

    // 5. Spawn child process
    let mut child = builder
        .spawn()
        .with_context(|| format!("Failed to spawn process {:?}", cmd.binary_path))?;

    let mut stdout_pipe = child.stdout.take().expect("stdout piped");
    let mut stderr_pipe = child.stderr.take().expect("stderr piped");

    // 4. Asynchronously read streams with strict size cap
    let read_stdout = async move {
        let mut buf = Vec::new();
        let mut chunk = [0u8; 8192];
        let mut truncated = false;
        loop {
            match stdout_pipe.read(&mut chunk).await {
                Ok(0) => break,
                Ok(n) => {
                    if buf.len() + n > MAX_OUTPUT_BYTES {
                        let keep = MAX_OUTPUT_BYTES.saturating_sub(buf.len());
                        buf.extend_from_slice(&chunk[..keep]);
                        truncated = true;
                        break;
                    } else {
                        buf.extend_from_slice(&chunk[..n]);
                    }
                }
                Err(_) => break,
            }
        }
        (buf, truncated)
    };

    let read_stderr = async move {
        let mut buf = Vec::new();
        let mut chunk = [0u8; 8192];
        let mut truncated = false;
        loop {
            match stderr_pipe.read(&mut chunk).await {
                Ok(0) => break,
                Ok(n) => {
                    if buf.len() + n > MAX_OUTPUT_BYTES {
                        let keep = MAX_OUTPUT_BYTES.saturating_sub(buf.len());
                        buf.extend_from_slice(&chunk[..keep]);
                        truncated = true;
                        break;
                    } else {
                        buf.extend_from_slice(&chunk[..n]);
                    }
                }
                Err(_) => break,
            }
        }
        (buf, truncated)
    };

    // 5. Execute with timeout and kill on timeout
    let exec_future = async {
        let (status_res, (stdout_bytes, stdout_trunc), (stderr_bytes, stderr_trunc)) =
            tokio::join!(child.wait(), read_stdout, read_stderr);
        (
            status_res,
            stdout_bytes,
            stderr_bytes,
            stdout_trunc || stderr_trunc,
        )
    };

    let (status_res, stdout_bytes, stderr_bytes, was_truncated) =
        match timeout(Duration::from_secs(timeout_secs), exec_future).await {
            Ok(res) => res,
            Err(_) => {
                let _ = child.kill().await;
                bail!(
                    "command execution timed out after {} seconds (process killed)",
                    timeout_secs
                );
            }
        };

    let status = status_res.context("Failed to wait on child process")?;
    let duration_ms = start.elapsed().as_millis() as u64;
    let exit_code = status.code().unwrap_or(-1);

    Ok(ExecResult {
        exit_code,
        stdout: String::from_utf8_lossy(&stdout_bytes).to_string(),
        stderr: String::from_utf8_lossy(&stderr_bytes).to_string(),
        duration_ms,
        truncated: was_truncated,
    })
}
