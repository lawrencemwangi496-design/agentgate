use anyhow::{Context, Result, bail};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

/// GTFOBins & shell escape binaries strictly disallowed from sudoers grants
const DISALLOWED_SUDO_BINARIES: &[&str] = &[
    "sh", "bash", "zsh", "dash", "csh", "tcsh", "ksh",
    "python", "python3", "perl", "ruby", "node", "php", "lua",
    "vim", "vi", "nvim", "nano", "emacs", "ed",
    "less", "more", "view",
    "find", "xargs", "awk", "gawk", "sed", "env", "tee", "git",
    "tar", "zip", "unzip", "curl", "wget", "nc", "ncat", "netcat", "socat",
];

/// Validates that a sudoers command is an exact command with exact arguments and no shell escape hazards
pub fn validate_command_for_sudo(cmd_str: &str) -> Result<()> {
    let trimmed = cmd_str.trim();
    if trimmed.is_empty() {
        bail!("Sudo command cannot be empty");
    }

    // 1. Never allow wildcards in sudo commands
    if trimmed.contains('*') {
        bail!(
            "Disallowed wildcard in sudo command '{}'. Sudo grants must specify exact arguments.",
            trimmed
        );
    }

    // 2. Reject shell metacharacters, commas (sudoers separator), and backslashes
    for c in &[';', '&', '|', '`', '$', '(', ')', '>', '<', '\n', '\r', ',', '\\'] {
        if trimmed.contains(*c) {
            bail!("Disallowed metacharacter '{}' in sudo command '{}'", c, trimmed);
        }
    }

    // 3. Extract binary token and verify fully-qualified path and argument specification
    let parts: Vec<&str> = trimmed.split_whitespace().collect();
    if parts.is_empty() {
        bail!("Sudo command cannot be empty");
    }

    let binary_token = parts[0];
    if binary_token == "ALL" {
        bail!("Disallowed 'ALL' in command position for sudoers grant.");
    }
    if !binary_token.starts_with('/') {
        bail!(
            "Sudo command '{}' must specify a fully-qualified absolute path (e.g. /usr/bin/{}).",
            binary_token,
            binary_token
        );
    }

    let binary_name = binary_token.rsplit('/').next().unwrap_or(binary_token);
    if binary_name == "ALL" {
        bail!("Disallowed 'ALL' in command position for sudoers grant.");
    }

    if DISALLOWED_SUDO_BINARIES.contains(&binary_name) {
        bail!(
            "Binary '{}' has known shell escape capabilities (GTFOBins) and cannot be granted in sudoers.",
            binary_name
        );
    }

    // 4. Require exact arguments (in sudoers, a binary with no args specified matches ANY args)
    if parts.len() < 2 && !trimmed.ends_with(r#""""#) {
        bail!(
            "Sudo command '{}' must specify exact arguments (e.g. '{} arg1'). In sudoers, specifying a binary without arguments allows execution with arbitrary arguments.",
            trimmed,
            binary_token
        );
    }

    // 5. Special check: systemctl edit opens an interactive editor
    if binary_name == "systemctl" && trimmed.contains("edit") {
        bail!("'systemctl edit' opens an editor with shell escape and cannot be granted via sudoers.");
    }

    Ok(())
}

/// Generates a validated sudoers file content from a list of exact command strings
pub fn generate_sudoers_content(os_user: &str, commands: &[String]) -> Result<String> {
    if commands.is_empty() {
        bail!("No commands specified for sudoers grant");
    }

    for cmd in commands {
        validate_command_for_sudo(cmd)?;
    }

    let joined_cmds = commands.join(", ");
    let content = format!(
        "# AgentGate narrow sudoers policy for user {}\n\
         # Automatically generated - DO NOT EDIT MANUALLY\n\
         {} ALL=(root) NOPASSWD: {}\n",
        os_user, os_user, joined_cmds
    );

    Ok(content)
}

/// Helper to resolve a binary name to a fully qualified path
fn resolve_binary_path(binary: &str) -> Option<PathBuf> {
    if binary.starts_with('/') {
        let p = PathBuf::from(binary);
        if p.exists() {
            return Some(p);
        }
        return None;
    }

    let search_paths = [
        "/usr/bin",
        "/bin",
        "/usr/sbin",
        "/sbin",
        "/usr/local/bin",
        "/usr/local/sbin",
    ];
    for dir in &search_paths {
        let candidate = Path::new(dir).join(binary);
        if candidate.exists() {
            return Some(candidate);
        }
    }

    None
}

/// Generates minimal sudoers entries from an AgentGate policy
pub fn generate_sudoers_from_policy(
    policy: &crate::policy::Policy,
    os_user: &str,
) -> Result<String> {
    let mut exact_commands = Vec::new();

    // Use rules or allow
    let rules = if !policy.rules.is_empty() {
        &policy.rules
    } else {
        &policy.allow
    };

    if rules.is_empty() {
        bail!("Policy '{}' contains no allowed rules to generate sudoers from", policy.name);
    }

    for rule in rules {
        // Hard rule: Never allow wildcards in sudoers commands or arguments
        if rule.command.contains('*') || rule.args.iter().any(|a| a.contains('*')) {
            bail!(
                "Policy rule '{} {:?}' contains wildcards '*' which are strictly prohibited in sudoers grants.",
                rule.command,
                rule.args
            );
        }

        let full_path = resolve_binary_path(&rule.command)
            .ok_or_else(|| anyhow::anyhow!("Could not resolve path for binary '{}'", rule.command))?;
        let full_path_str = full_path.to_string_lossy();

        let cmd_string = if rule.args.is_empty() {
            // In sudoers, specifying `""` means strictly NO arguments are permitted
            format!("{} \"\"", full_path_str)
        } else {
            format!("{} {}", full_path_str, rule.args.join(" "))
        };

        validate_command_for_sudo(&cmd_string)?;
        exact_commands.push(cmd_string);
    }

    generate_sudoers_content(os_user, &exact_commands)
}

/// Helper to find visudo binary across standard system paths
pub fn find_visudo() -> PathBuf {
    for p in ["/usr/sbin/visudo", "/sbin/visudo", "/usr/bin/visudo"] {
        let path = Path::new(p);
        if path.exists() {
            return path.to_path_buf();
        }
    }
    PathBuf::from("visudo")
}

/// Safely installs a sudoers fragment to /etc/sudoers.d/ after visudo syntax verification
pub fn install_sudoers_fragment(token_name: &str, content: &str) -> Result<PathBuf> {
    let target_dir = Path::new("/etc/sudoers.d");
    if let Err(e) = fs::create_dir_all(target_dir) {
        bail!("Failed to access /etc/sudoers.d (requires root privileges): {}", e);
    }

    let target_path = target_dir.join(format!("agentgate-{}", token_name));

    // Write to a temporary hidden dotfile directly inside /etc/sudoers.d/
    // Sudoers parser automatically ignores dotfiles.
    // Writing in the same directory enables atomic rename (same filesystem, eliminating TOCTOU).
    let temp_path = target_dir.join(format!(".agentgate_tmp_{}_{}", token_name, uuid::Uuid::new_v4()));
    fs::write(&temp_path, content)
        .with_context(|| format!("Failed to write temporary sudoers file at {:?}", temp_path))?;

    // Sudoers files MUST be mode 0440
    let _ = fs::set_permissions(&temp_path, fs::Permissions::from_mode(0o440));

    // Validate syntax with visudo -cf
    let visudo_bin = find_visudo();
    let visudo_check = Command::new(&visudo_bin)
        .args(["-cf", temp_path.to_str().unwrap()])
        .output();

    match visudo_check {
        Ok(output) if output.status.success() => {
            // Validation passed! Atomically rename within /etc/sudoers.d/
            if let Err(e) = fs::rename(&temp_path, &target_path) {
                let _ = fs::remove_file(&temp_path);
                bail!("Failed to atomically rename sudoers file to {:?} (requires root privileges): {}", target_path, e);
            }

            let _ = fs::set_permissions(&target_path, fs::Permissions::from_mode(0o440));
            Ok(target_path)
        }
        Ok(output) => {
            let _ = fs::remove_file(&temp_path);
            let stderr = String::from_utf8_lossy(&output.stderr);
            bail!("visudo syntax verification failed:\n{}", stderr);
        }
        Err(e) => {
            let _ = fs::remove_file(&temp_path);
            bail!("Failed to execute 'visudo' ({:?}) for syntax verification: {}", visudo_bin, e);
        }
    }
}

/// Removes a sudoers fragment on token revocation
pub fn remove_sudoers_fragment(token_name: &str) -> Result<bool> {
    let target_path = Path::new("/etc/sudoers.d").join(format!("agentgate-{}", token_name));
    if target_path.exists() {
        fs::remove_file(&target_path)
            .with_context(|| format!("Failed to remove sudoers file at {:?}", target_path))?;
        Ok(true)
    } else {
        Ok(false)
    }
}
