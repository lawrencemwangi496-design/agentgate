//! Known Limitations & Security Boundaries
//!
//! These tests explicitly document and verify the architectural boundaries
//! and known limitations of AgentGate:
//!
//! 1. Interpreters & Turing-Complete Binaries:
//!    If an interpreter (python3, perl, bash, node) is allowed in a policy,
//!    an agent can execute arbitrary logic. "Zero Shell" prevents shell *parser*
//!    injection (e.g. pipes, backticks, metacharacters), NOT the inherent capabilities
//!    of the binary itself. Therefore, running without OS user isolation is a "seatbelt",
//!    not a security sandbox.
//!
//! 2. Denylist Inadequacy for Untrusted Execution:
//!    Semantic guardrails successfully stop argument variations like `rm -r -f /`
//!    and `rm --recursive /`, but cannot inspect internal code passed to interpreters.
//!    Hard security against untrusted agents requires OS user separation (`--user-mode`)
//!    or actions-only tokens.
//!
//! 3. Sudoers Shell Escapes (GTFOBins):
//!    Narrow sudoers entries must never include GTFOBins binaries.
//!    `validate_command_for_sudo` strictly rejects these.
//!
//! 4. Actions-Only Pipeline Containment:
//!    When arbitrary command execution is unacceptable (e.g. automated CI/CD),
//!    tokens restricted to named actions (`can_exec() == false`) eliminate
//!    arbitrary binary invocation entirely.

use agentgate::auth::StoredToken;
use agentgate::policy::{Policy, PolicyRule};
use agentgate::sudoers::validate_command_for_sudo;
use chrono::Utc;

#[test]
fn boundary_1_interpreters_are_not_sandboxed_at_exec_layer() {
    // Demonstration: A policy that permits `python3` permits running python scripts.
    // AgentGate prevents shell metacharacters like ';' or '|' from being injected into the args,
    // but the python process itself can execute any Python code permitted to the OS user.
    let policy = Policy {
        name: "dev-agent".to_string(),
        description: "Development tools allowed".to_string(),
        guardrails: true,
        allow: vec![PolicyRule {
            command: "python3".to_string(),
            args: vec!["*".to_string()],
        }],
        deny: vec![],
        rules: vec![],
        actions: std::collections::HashMap::new(),
    };

    // The command itself is allowed by policy
    assert!(policy.matches("python3", &["-c".to_string(), "print('hello')".to_string()]));

    // Why OS user isolation is mandatory:
    // If running as root without `--user-mode`, python3 runs as root.
    // With `--user-mode`, python3 runs with unprivileged UID/GID (e.g. ag-developer).
}

#[test]
fn boundary_2_guardrails_catch_argument_permutations_of_known_binaries() {
    // Standard semantic guardrails normalize arguments and catch flag reordering
    // for known destructive system binaries (rm, mkfs, dd, reboot, etc.)
    let policy = Policy {
        name: "agent-seatbelt".to_string(),
        description: "Broad access with destructive guardrails".to_string(),
        guardrails: true,
        allow: vec![PolicyRule {
            command: "*".to_string(),
            args: vec!["*".to_string()],
        }],
        deny: vec![],
        rules: vec![],
        actions: std::collections::HashMap::new(),
    };

    // Flag splitting & permuted options are caught:
    assert!(!policy.matches("rm", &["-r".to_string(), "-f".to_string(), "/".to_string()]));
    assert!(!policy.matches("rm", &["--recursive".to_string(), "--force".to_string(), "/".to_string()]));
    assert!(!policy.matches("/bin/rm", &["-rf".to_string(), "/*".to_string()]));
    assert!(!policy.matches("rm", &["-rf".to_string(), "/boot".to_string()]));
    assert!(!policy.matches("rm", &["-rf".to_string(), "/etc/agentgate".to_string()]));

    // Safe commands are allowed:
    assert!(policy.matches("rm", &["-f".to_string(), "/tmp/test.log".to_string()]));
    assert!(policy.matches("git", &["status".to_string()]));
}

#[test]
fn boundary_3_gtfobins_must_be_strictly_rejected_from_sudoers() {
    // Sudoers validation must never grant sudo to tools that have shell escapes
    assert!(validate_command_for_sudo("/usr/bin/vim /etc/hosts").is_err());
    assert!(validate_command_for_sudo("/usr/bin/find / -name x").is_err());
    assert!(validate_command_for_sudo("/usr/bin/python3 script.py").is_err());
    assert!(validate_command_for_sudo("/bin/bash").is_err());
    assert!(validate_command_for_sudo("/usr/bin/less /var/log/syslog").is_err());

    // Only safe, exact binaries with explicit arguments pass
    assert!(validate_command_for_sudo("/usr/bin/systemctl restart nginx").is_ok());
}

#[test]
fn boundary_4_actions_only_tokens_completely_eliminate_arbitrary_exec() {
    // For CI/CD, tokens restricted to actions cannot execute arbitrary binaries
    let ci_token = StoredToken {
        name: "github-actions-deploy".to_string(),
        hash: "dummyhash".to_string(),
        policy: "pipeline".to_string(),
        created_at: Utc::now(),
        expires_at: None,
        last_used_at: None,
        os_user: Some("ag-pipeline".to_string()),
        tier: Some("ops".to_string()),
        actions: Some(vec!["deploy".to_string()]),
    };

    // Exec is completely disabled:
    assert!(!ci_token.can_exec());
    // Only pre-approved action templates can run:
    assert!(ci_token.can_run_action("deploy"));
    assert!(!ci_token.can_run_action("arbitrary_action"));
}
