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

/// An action template with multiple steps
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct PolicyAction {
    pub steps: Vec<String>,
    #[serde(default = "default_true")]
    pub stop_on_failure: bool,
    #[serde(default)]
    pub description: Option<String>,
}

impl PolicyAction {
    /// Extracts all unique placeholder names declared in this action's steps
    pub fn declared_placeholders(&self) -> std::collections::HashSet<String> {
        let mut placeholders = std::collections::HashSet::new();
        for step in &self.steps {
            let mut chars = step.chars().peekable();
            while let Some(c) = chars.next() {
                if c == '{' {
                    let mut name = String::new();
                    while let Some(&inner) = chars.peek() {
                        if inner == '}' {
                            chars.next();
                            if !name.is_empty() {
                                placeholders.insert(name);
                            }
                            break;
                        } else if inner == '{' {
                            break;
                        } else {
                            name.push(inner);
                            chars.next();
                        }
                    }
                }
            }
        }
        placeholders
    }

    /// Renders steps by substituting template parameters in a single pass with strict validation:
    /// - Rejects missing required parameters
    /// - Rejects unexpected / undeclared parameters
    /// - Rejects whitespace, quotes, leading dashes (flag injection), and shell metacharacters
    /// - Rejects values exceeding 128 characters
    /// - Single-pass substitution prevents recursive re-substitution ({other})
    pub fn render_steps(
        &self,
        params: &std::collections::HashMap<String, String>,
    ) -> anyhow::Result<Vec<String>> {
        let declared = self.declared_placeholders();

        // 1. Check for missing required parameters
        for required in &declared {
            if !params.contains_key(required) {
                anyhow::bail!("Missing required action parameter: '{}'", required);
            }
        }

        // 2. Check for unexpected / undeclared parameters
        for supplied in params.keys() {
            if !declared.contains(supplied) {
                anyhow::bail!("Unexpected parameter '{}' not declared in action steps", supplied);
            }
        }

        // 3. Strict value validation on each supplied parameter
        for (k, v) in params {
            if v.len() > 128 {
                anyhow::bail!("Parameter '{}' exceeds maximum allowed length of 128 characters", k);
            }
            if v.is_empty() {
                anyhow::bail!("Parameter '{}' cannot be empty", k);
            }
            // Reject leading dash (prevents flag injection like --all-tags, --privileged, -v)
            if v.starts_with('-') {
                anyhow::bail!("Parameter '{}' cannot start with a dash '-' to prevent flag injection", k);
            }
            // Reject whitespace (prevents argument splitting: a value must remain a single token)
            if v.chars().any(|c| c.is_whitespace()) {
                anyhow::bail!("Parameter '{}' cannot contain whitespace", k);
            }
            // Reject quotes (prevents quote breaking)
            if v.contains('\'') || v.contains('"') {
                anyhow::bail!("Parameter '{}' cannot contain quotation marks", k);
            }
            // Reject shell metacharacters, commas, backslashes
            for c in &[';', '&', '|', '`', '$', '(', ')', '>', '<', '\n', '\r', ',', '\\'] {
                if v.contains(*c) {
                    anyhow::bail!("Parameter '{}' contains disallowed character '{}'", k, c);
                }
            }
        }

        // 4. Single-pass template substitution to prevent re-substitution
        let mut rendered = Vec::with_capacity(self.steps.len());
        for step in &self.steps {
            let mut result = String::with_capacity(step.len());
            let mut chars = step.chars().peekable();

            while let Some(c) = chars.next() {
                if c == '{' {
                    let mut key = String::new();
                    let mut closed = false;
                    while let Some(&inner) = chars.peek() {
                        if inner == '}' {
                            chars.next();
                            closed = true;
                            break;
                        } else if inner == '{' {
                            break;
                        } else {
                            key.push(inner);
                            chars.next();
                        }
                    }
                    if closed && let Some(val) = params.get(&key) {
                        result.push_str(val);
                    } else {
                        result.push('{');
                        result.push_str(&key);
                        if closed {
                            result.push('}');
                        }
                    }
                } else {
                    result.push(c);
                }
            }
            rendered.push(result);
        }

        Ok(rendered)
    }
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
    #[serde(default)]
    pub actions: std::collections::HashMap<String, PolicyAction>,
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
            actions: std::collections::HashMap::new(),
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
    /// Retrieve a named action from this policy
    pub fn get_action(&self, name: &str) -> Option<&PolicyAction> {
        self.actions.get(name)
    }

    /// Check if a given command and args are permitted by this policy:
    /// 1. Deny list ALWAYS takes precedence: If any rule in `deny` matches, returns `false`.
    /// 2. Allow list check: If any rule in `allow` (or legacy `rules`) matches, returns `true`.
    /// 3. If neither matches, returns `false`.
    pub fn matches(&self, command: &str, args: &[String]) -> bool {
        let cmd_base = command.rsplit('/').next().unwrap_or(command);

        // 1. Hardened semantic guardrails (active by default, can be set to false if user explicitly wants)
        if self.guardrails && is_hardened_destructive_guardrail(cmd_base, args) {
            return false;
        }

        // 2. Custom deny rules check
        for rule in &self.deny {
            if matches_single_rule(rule, command, cmd_base, args) {
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
            if matches_single_rule(rule, command, cmd_base, args) {
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

    // Hardened system-critical root mountpoints & top-level directories
    const PROTECTED_TARGETS: &[&str] = &[
        "/",
        "/root",
        "/etc",
        "/bin",
        "/usr",
        "/var",
        "/boot",
        "/lib",
        "/lib64",
        "/sbin",
        "/home",
        "/opt",
        "/srv",
        "/mnt",
    ];

    for &target in PROTECTED_TARGETS {
        if norm == target || norm == format!("{}/*", target) {
            return true;
        }
    }

    // AgentGate's own configuration, token, policy, and audit log directories
    if norm == "/etc/agentgate"
        || norm.starts_with("/etc/agentgate/")
        || norm == "/var/log/agentgate"
        || norm.starts_with("/var/log/agentgate/")
        || norm == "~/.config/agentgate"
        || norm.starts_with("~/.config/agentgate/")
        || norm == "~/.agentgate"
        || norm.starts_with("~/.agentgate/")
    {
        return true;
    }

    // Protect AgentGate's user config directory dynamically if home dir is resolved
    if let Some(user_home) = dirs::home_dir() {
        let agentgate_user_cfg = user_home.join(".config").join("agentgate");
        let agentgate_user_cfg_str = agentgate_user_cfg.to_string_lossy();
        let norm_agentgate = normalize_path_str(&agentgate_user_cfg_str);
        if norm == norm_agentgate || norm.starts_with(&format!("{}/", norm_agentgate)) {
            return true;
        }
    }

    false
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
    if readers.contains(&cmd_base)
        && args.iter().any(|a| a.contains("shadow") || a.contains("/etc/shadow") || a.contains("/etc/gshadow"))
    {
        return true;
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
fn matches_single_rule(rule: &PolicyRule, command: &str, cmd_base: &str, args: &[String]) -> bool {
    let rule_base = rule.command.rsplit('/').next().unwrap_or(&rule.command);

    // Check command matching (supports "*", exact path match, binary basename match, or prefix wildcard like "mkfs*")
    let cmd_matches = if rule.command == "*" {
        true
    } else if rule.command.ends_with('*') {
        let prefix = &rule.command[..rule.command.len() - 1];
        command.starts_with(prefix) || cmd_base.starts_with(prefix)
    } else {
        rule.command == command || rule_base == cmd_base
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
