use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

/// A single rule within a policy
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PolicyRule {
    pub command: String,   // e.g., "systemctl"
    pub args: Vec<String>, // e.g., ["restart", "nginx"] — supports "*" wildcard
}

/// A complete policy supporting both allowed scopes and safety guardrails (deny rules)
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Policy {
    pub name: String,
    pub description: String,
    #[serde(default)]
    pub allow: Vec<PolicyRule>,
    #[serde(default)]
    pub deny: Vec<PolicyRule>,
    #[serde(default)]
    pub rules: Vec<PolicyRule>,
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
        // 1. Guardrails: Deny rules check
        for rule in &self.deny {
            if matches_single_rule(rule, command, args) {
                return false;
            }
        }

        // 2. Allow rules check
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
