use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

/// A single rule within a policy
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PolicyRule {
    pub command: String,   // e.g., "systemctl"
    pub args: Vec<String>, // e.g., ["restart", "nginx"] — supports "*" wildcard
}

/// A complete policy
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Policy {
    pub name: String,
    pub description: String,
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
    /// Check if a given command (binary) and args match any rule in this policy.
    /// The command is the base name of the binary (e.g., "systemctl").
    /// Args are the arguments as a slice of strings.
    ///
    /// Matching rules:
    /// - rule.command must exactly match the command binary name
    /// - rule.args is matched positionally against the provided args
    /// - "*" in a rule arg position matches any single arg value
    /// - If rule.args is empty, the command is allowed with NO arguments only
    /// - The number of rule args must match the number of provided args
    ///   (unless the last rule arg is "*" which can match remaining args)
    pub fn matches(&self, command: &str, args: &[String]) -> bool {
        for rule in &self.rules {
            if rule.command != command {
                continue;
            }

            let rule_args_len = rule.args.len();

            // If rule.args is empty, provided args must be empty
            if rule_args_len == 0 {
                if args.is_empty() {
                    return true;
                }
                continue;
            }

            let has_trailing_star = rule.args.last().map(|s| s.as_str()) == Some("*");

            // If no trailing star, exact length match required
            if !has_trailing_star && args.len() != rule_args_len {
                continue;
            }

            // If trailing star, provided args must have at least rule_args_len - 1
            if has_trailing_star && args.len() < rule_args_len - 1 {
                continue;
            }

            let mut is_match = true;
            for (i, rule_arg) in rule.args.iter().enumerate() {
                if rule_arg == "*" {
                    // It's a wildcard
                    if i == rule_args_len - 1 {
                        // Trailing wildcard matches everything remaining, so we're good
                        break;
                    }
                    // Else, it matches the current single arg, which exists because we checked lengths
                } else {
                    // Exact match required
                    if let Some(arg) = args.get(i) {
                        if arg != rule_arg {
                            is_match = false;
                            break;
                        }
                    } else {
                        is_match = false;
                        break;
                    }
                }
            }

            if is_match {
                return true;
            }
        }

        false
    }
}
