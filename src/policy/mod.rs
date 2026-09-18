use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

/// A single rule within a policy
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PolicyRule {
    pub command: String,   // e.g., "systemctl"
    pub args: Vec<String>, // e.g., ["restart", "nginx"] — supports "*" wildcard
}

fn default_true() -> bool {
    true
}

/// A complete policy supporting both allowed scopes and safety guardrails (deny rules)
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Policy {
    pub name: String,
    pub description: String,
    #[serde(default = "default_true")]
    pub guardrails: bool,
    #[serde(default)]
    pub allow: Vec<PolicyRule>,
    #[serde(default)]
    pub deny: Vec<PolicyRule>,
    #[serde(default)]
    pub rules: Vec<PolicyRule>,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            name: String::new(),
            description: String::new(),
            guardrails: true,
            allow: Vec::new(),
            deny: Vec::new(),
            rules: Vec::new(),
        }
    }
}

/// The policy store loads all .yaml files from the policies directory
pub struct PolicyStore {
    policies: Vec<Policy>,
    dir: PathBuf,
}

impl PolicyStore {
    /// Load all policies from the directory
    pub fn load(dir: &Path) -> anyhow::Result<Self> {
        let mut policies = Vec::new();
        if dir.exists() && dir.is_dir() {
            for entry in fs::read_dir(dir)? {
                let entry = entry?;
                let path = entry.path();
                if path.is_file()
                    && path
                        .extension()
                        .is_some_and(|ext| ext == "yaml" || ext == "yml")
                {
                    let content = fs::read_to_string(&path)?;
                    let policy: Policy = serde_yaml::from_str(&content)?;
                    policies.push(policy);
                }
            }
        } else {
            // Create dir if it doesn't exist
            fs::create_dir_all(dir)?;
        }

        Ok(Self {
            policies,
            dir: dir.to_path_buf(),
        })
    }

    /// Get a policy by name
    pub fn get(&self, name: &str) -> Option<&Policy> {
        self.policies.iter().find(|p| p.name == name)
    }

    /// List all policy names
    pub fn list(&self) -> Vec<&Policy> {
        self.policies.iter().collect()
    }

    /// Save a new policy to disk
    pub fn save_policy(&mut self, policy: &Policy) -> anyhow::Result<()> {
        let path = self.dir.join(format!("{}.yaml", policy.name));
        let content = serde_yaml::to_string(policy)?;
        fs::write(path, content)?;

        // Update in-memory store
        if let Some(existing) = self.policies.iter_mut().find(|p| p.name == policy.name) {
            *existing = policy.clone();
        } else {
            self.policies.push(policy.clone());
        }

        Ok(())
    }

    /// Delete a policy
    pub fn delete_policy(&mut self, name: &str) -> anyhow::Result<bool> {
        let path = self.dir.join(format!("{}.yaml", name));
        if path.exists() {
            fs::remove_file(path)?;
            self.policies.retain(|p| p.name != name);
            Ok(true)
        } else {
            Ok(false)
        }
    }
}

impl Policy {
    /// Check if a given command and args are permitted by this policy:
    /// 1. Deny list ALWAYS takes precedence: If any rule in `deny` matches, returns `false`.
    /// 2. Allow list check: If any rule in `allow` (or legacy `rules`) matches, returns `true`.
    /// 3. If neither matches, returns `false`.
    pub fn matches(&self, command: &str, args: &[String]) -> bool {
        // 1. Hardened semantic guardrails (active by default, can be set to false if user explicitly wants)
        if self.guardrails && is_hardened_destructive_guardrail(command, args) {
            return false;
        }

        // 2. Custom deny rules check
        for rule in &self.deny {
            if matches_single_rule(rule, command, args) {
                return false;
            }
        }

        // 3. Allow rules check
        let allow_rules = if !self.allow.is_empty() {
            &self.allow
        } else {
            &self.rules
        };

        for rule in allow_rules {
            if matches_single_rule(rule, command, args) {
                return true;
            }
        }

        false
    }
}

/// Normalize a target path by collapsing duplicate slashes and relative "." components
fn normalize_path_str(p: &str) -> String {
    let mut parts = Vec::new();
    for seg in p.split('/') {
        if seg.is_empty() || seg == "." {
            continue;
        }
        parts.push(seg);
    }
    if p.starts_with('/') {
        format!("/{}", parts.join("/"))
    } else {
        parts.join("/")
    }
}

fn is_dangerous_wipe_target(arg: &str) -> bool {
    let trimmed = arg.trim();
    if trimmed == "/" || trimmed == "/*" || trimmed == "~" || trimmed == "~/*" {
        return true;
    }
    let norm = normalize_path_str(trimmed);
    norm == "/" || norm == "/*" || norm == "/root" || norm == "/etc" || norm == "/bin" || norm == "/usr" || norm == "/var"
}

/// Hardened semantic check for destructive actions (prevents flag-splitting & flag-permutation bypasses)
pub fn is_hardened_destructive_guardrail(command: &str, args: &[String]) -> bool {
    let cmd_base = command.rsplit('/').next().unwrap_or(command);

    // 1. Recursive destructive filesystem wipes: rm
    if cmd_base == "rm" {
        let has_recursion = args.iter().any(|a| {
            a == "-r"
                || a == "-R"
                || a == "--recursive"
                || (a.starts_with('-') && !a.starts_with("--") && (a.contains('r') || a.contains('R')))
        });
        let has_dangerous_target = args.iter().any(|a| is_dangerous_wipe_target(a));
        if has_recursion && has_dangerous_target {
            return true;
        }
    }

    // 2. Disk formatting & raw partition writes
    if cmd_base.starts_with("mkfs")
        || cmd_base == "dd"
        || cmd_base == "fdisk"
        || cmd_base == "parted"
        || cmd_base == "wipefs"
    {
        return true;
    }

    // 3. System shutdowns, poweroffs, and reboots
    if cmd_base == "shutdown" || cmd_base == "reboot" || cmd_base == "poweroff" || cmd_base == "halt" {
        return true;
    }
    if cmd_base == "init" && args.iter().any(|a| a == "0" || a == "6") {
        return true;
    }

    // 4. User account tamper & lockout
    if cmd_base == "passwd" || cmd_base == "chpasswd" || cmd_base == "userdel" || cmd_base == "groupdel" {
        return true;
    }

    // 5. Reading shadow password files with any viewer
    let readers = ["cat", "less", "more", "head", "tail", "grep", "sed", "awk", "strings", "xxd", "hexdump", "cp", "mv"];
    if readers.contains(&cmd_base) {
        if args.iter().any(|a| a.contains("shadow") || a.contains("/etc/shadow") || a.contains("/etc/gshadow")) {
            return true;
        }
    }

    // 6. Root permission sabotage
    if cmd_base == "chmod" {
        let has_recursion = args.iter().any(|a| a == "-R" || (a.starts_with('-') && !a.starts_with("--") && a.contains('R')));
        let has_bad_mode = args.iter().any(|a| a == "777" || a == "000");
        let has_dangerous_target = args.iter().any(|a| is_dangerous_wipe_target(a));
        if has_recursion && has_bad_mode && has_dangerous_target {
            return true;
        }
    }

    false
}

/// Helper to match a single PolicyRule against a command and args
fn matches_single_rule(rule: &PolicyRule, command: &str, args: &[String]) -> bool {
    // Check command matching (supports "*", exact match, or prefix wildcard like "mkfs*")
    let cmd_matches = if rule.command == "*" {
        true
    } else if rule.command.ends_with('*') {
        let prefix = &rule.command[..rule.command.len() - 1];
        command.starts_with(prefix)
    } else {
        rule.command == command
    };

    if !cmd_matches {
        return false;
    }

    // If command is wildcard and rule has no specific args, it matches everything
    if rule.command == "*" && rule.args.is_empty() {
        return true;
    }

    let rule_args_len = rule.args.len();

    // If rule args are empty, provided args must be empty
    if rule_args_len == 0 {
        return args.is_empty();
    }

    let has_trailing_star = rule.args.last().map(|s| s.as_str()) == Some("*");

    // If no trailing wildcard, length must match
    if !has_trailing_star && args.len() != rule_args_len {
        return false;
    }

    // If trailing wildcard, provided args must be at least rule_args_len - 1
    if has_trailing_star && args.len() < rule_args_len - 1 {
        return false;
    }

    for (i, rule_arg) in rule.args.iter().enumerate() {
        if rule_arg == "*" {
            if i == rule_args_len - 1 {
                return true;
            }
            continue;
        }

        // Wildcard containment: "*keyword*"
        if rule_arg.starts_with('*') && rule_arg.ends_with('*') && rule_arg.len() > 2 {
            let sub = &rule_arg[1..rule_arg.len() - 1];
            if let Some(arg) = args.get(i) {
                if !arg.contains(sub) {
                    return false;
                }
            } else {
                return false;
            }
            continue;
        }

        // Wildcard prefix: "prefix*"
        if rule_arg.ends_with('*') && rule_arg.len() > 1 {
            let prefix = &rule_arg[..rule_arg.len() - 1];
            if let Some(arg) = args.get(i) {
                if !arg.starts_with(prefix) {
                    return false;
                }
            } else {
                return false;
            }
            continue;
        }

        // Exact match
        if let Some(arg) = args.get(i) {
            if arg != rule_arg {
                return false;
            }
        } else {
            return false;
        }
    }

    true
}

/// Default guardrail deny rules attached to all newly generated policies
pub fn default_guardrails() -> Vec<PolicyRule> {
    vec![
        // Destructive filesystem wipes
        PolicyRule { command: "rm".to_string(), args: vec!["-rf".to_string(), "/*".to_string()] },
        PolicyRule { command: "rm".to_string(), args: vec!["-rf".to_string(), "/".to_string()] },
        PolicyRule { command: "rm".to_string(), args: vec!["-fr".to_string(), "/*".to_string()] },
        PolicyRule { command: "rm".to_string(), args: vec!["-fr".to_string(), "/".to_string()] },
        PolicyRule { command: "rm".to_string(), args: vec!["-r".to_string(), "/*".to_string()] },
        PolicyRule { command: "rm".to_string(), args: vec!["-r".to_string(), "/".to_string()] },
        PolicyRule { command: "rm".to_string(), args: vec!["-rf".to_string(), "~".to_string()] },
        PolicyRule { command: "rm".to_string(), args: vec!["-rf".to_string(), "~/*".to_string()] },
        // Disk formatting & raw block writes
        PolicyRule { command: "mkfs*".to_string(), args: vec!["*".to_string()] },
        PolicyRule { command: "dd".to_string(), args: vec!["*".to_string()] },
        PolicyRule { command: "fdisk".to_string(), args: vec!["*".to_string()] },
        PolicyRule { command: "parted".to_string(), args: vec!["*".to_string()] },
        PolicyRule { command: "wipefs".to_string(), args: vec!["*".to_string()] },
        // Shutdown & reboot
        PolicyRule { command: "shutdown".to_string(), args: vec!["*".to_string()] },
        PolicyRule { command: "reboot".to_string(), args: vec!["*".to_string()] },
        PolicyRule { command: "poweroff".to_string(), args: vec!["*".to_string()] },
        PolicyRule { command: "halt".to_string(), args: vec!["*".to_string()] },
        PolicyRule { command: "init".to_string(), args: vec!["0".to_string()] },
        PolicyRule { command: "init".to_string(), args: vec!["6".to_string()] },
        // Passwords & lockout
        PolicyRule { command: "passwd".to_string(), args: vec!["*".to_string()] },
        PolicyRule { command: "chpasswd".to_string(), args: vec!["*".to_string()] },
        PolicyRule { command: "userdel".to_string(), args: vec!["*".to_string()] },
        // System-wide permission wrecking
        PolicyRule { command: "chmod".to_string(), args: vec!["-R".to_string(), "777".to_string(), "/".to_string()] },
        PolicyRule { command: "chmod".to_string(), args: vec!["-R".to_string(), "000".to_string(), "/".to_string()] },
        // Dangerous shadow password reads
        PolicyRule { command: "cat".to_string(), args: vec!["*shadow*".to_string()] },
        PolicyRule { command: "cat".to_string(), args: vec!["/etc/shadow".to_string()] },
        PolicyRule { command: "cat".to_string(), args: vec!["/etc/gshadow".to_string()] },
    ]
}
