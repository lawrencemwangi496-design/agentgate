pub mod cert;
pub mod rate_limit;
pub mod throttler;

pub use rate_limit::RequestRateLimiter;
pub use throttler::AuthThrottler;

use crate::audit::{AuditEntry, AuditLogger, AuditResult};
use crate::auth::TokenStore;
use crate::config::AgentGateConfig;
use crate::executor::{self, ParsedCommand};
use crate::policy::PolicyStore;
use anyhow::{Context, Result};
use axum::{
    Json, Router,
    extract::{ConnectInfo, Path, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use axum_server::tls_rustls::RustlsConfig;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::Arc;
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;
use tracing::{error, info, warn};

#[derive(Clone)]
pub struct AppState {
    pub tokens_file: std::path::PathBuf,
    pub policies_dir: std::path::PathBuf,
    pub audit_logger: Arc<AuditLogger>,
    pub trusted_proxies: Vec<String>,
    pub auth_throttler: AuthThrottler,
    pub rate_limiter: RequestRateLimiter,
}

#[derive(Serialize, Deserialize)]
pub struct ExecRequest {
    pub command: String,
    #[serde(default)]
    pub cwd: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ExecSuccessResponse {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
    pub duration_ms: u64,
    pub truncated: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ErrorResponse {
    pub error: String,
    pub message: String,
    pub exit_code: i32,
}

#[derive(Debug, Serialize)]
pub struct HealthResponse {
    pub status: String,
    pub version: String,
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct ActionRequest {
    #[serde(default)]
    pub params: std::collections::HashMap<String, String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct StepResult {
    pub step: String,
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
    pub duration_ms: u64,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ActionResponse {
    pub action: String,
    pub success: bool,
    pub total_duration_ms: u64,
    pub steps: Vec<StepResult>,
}

/// Helper function to create the Axum router with security layers applied
pub fn create_router(config: &AgentGateConfig, state: AppState) -> Router {
    let mut app = Router::new()
        .route("/", get(console_handler))
        .route("/console", get(console_handler))
        .route("/health", get(health_handler))
        .route("/v1/health", get(health_handler))
        .route("/v1/exec", post(exec_handler))
        .route("/v1/action/{name}", post(action_handler));

    // Hardened CORS: Default to NO CORS headers.
    // Cross-origin browser requests are strictly denied by the browser's Same-Origin Policy.
    // Only enable if explicit trusted origins are configured.
    if !config.allowed_origins.is_empty() {
        let mut origins = Vec::new();
        for o in &config.allowed_origins {
            if let Ok(val) = o.parse::<axum::http::HeaderValue>() {
                origins.push(val);
            }
        }
        if !origins.is_empty() {
            let cors = CorsLayer::new()
                .allow_origin(origins)
                .allow_methods([axum::http::Method::GET, axum::http::Method::POST])
                .allow_headers([
                    axum::http::header::AUTHORIZATION,
                    axum::http::header::CONTENT_TYPE,
                ]);
            app = app.layer(cors);
        }
    }

    let rate_limiter = state.rate_limiter.clone();
    let rate_limit_layer = axum::middleware::from_fn(
        move |req: axum::extract::Request, next: axum::middleware::Next| {
            let limiter = rate_limiter.clone();
            async move {
                let peer_ip = req
                    .extensions()
                    .get::<ConnectInfo<SocketAddr>>()
                    .map(|ci| ci.0.ip())
                    .unwrap_or_else(|| std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));

                if let Err(retry_after) = limiter.check_rate_limit(&peer_ip) {
                    let err_json = serde_json::json!({
                        "error": "rate_limited",
                        "message": format!(
                            "Rate limit exceeded. Please wait {} second(s) before retrying.",
                            retry_after
                        ),
                        "exit_code": 1,
                    });
                    return Response::builder()
                        .status(StatusCode::TOO_MANY_REQUESTS)
                        .header(header::CONTENT_TYPE, "application/json")
                        .header(header::RETRY_AFTER, retry_after.to_string())
                        .body(axum::body::Body::from(err_json.to_string()))
                        .unwrap_or_else(|_| StatusCode::TOO_MANY_REQUESTS.into_response());
                }

                next.run(req).await
            }
        },
    );

    app.layer(rate_limit_layer)
        .layer(axum::extract::DefaultBodyLimit::max(64 * 1024)) // 64KB max request body — blocks large payload exhaustion
        .layer(tower::limit::ConcurrencyLimitLayer::new(128)) // 128 concurrent connection limit — blocks bot DDoS hammering
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

pub async fn run_server(
    config: &AgentGateConfig,
    custom_cert: Option<std::path::PathBuf>,
    custom_key: Option<std::path::PathBuf>,
    use_tls: bool,
) -> Result<()> {
    let audit_logger = Arc::new(AuditLogger::new(config.logs_dir.clone()));
    let state = AppState {
        tokens_file: config.tokens_file.clone(),
        policies_dir: config.policies_dir.clone(),
        audit_logger,
        trusted_proxies: vec!["127.0.0.1".to_string(), "::1".to_string()],
        auth_throttler: AuthThrottler::default(),
        rate_limiter: RequestRateLimiter::default(),
    };

    let app = create_router(config, state);

    let addr: SocketAddr = format!("{}:{}", config.listen_addr, config.listen_port)
        .parse()
        .context("Invalid listen address or port")?;

    // Check port availability before binding for crystal clear error messages
    if let Err(e) = std::net::TcpListener::bind(addr) {
        if e.kind() == std::io::ErrorKind::AddrInUse {
            anyhow::bail!(
                "Port {} is already in use by another process on {}.\n💡 Change the port using: agentgate start --port <PORT>\n   or set: export AGENTGATE_PORT=<PORT>",
                config.listen_port,
                config.listen_addr
            );
        } else {
            anyhow::bail!("Cannot bind to {}: {}", addr, e);
        }
    }

    // Background update checker: checks GitHub releases every 60 minutes and logs notice (can be disabled via env var)
    if !std::env::var("AGENTGATE_DISABLE_UPDATE_CHECK")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
    {
        tokio::spawn(async move {
        let client = match reqwest::Client::builder()
            .user_agent("AgentGate-UpdateChecker")
            .timeout(std::time::Duration::from_secs(10))
            .build()
        {
            Ok(c) => c,
            Err(_) => return,
        };

        // Wait 2 minutes after boot before checking
        tokio::time::sleep(tokio::time::Duration::from_secs(120)).await;

        loop {
            if let Ok(res) = client
                .get("https://api.github.com/repos/lawrencemwangi496-design/agentgate/releases/latest")
                .send()
                .await
                && let Ok(json) = res.json::<serde_json::Value>().await
                && let Some(tag) = json.get("tag_name").and_then(|t| t.as_str())
            {
                let current_ver = format!("v{}", env!("CARGO_PKG_VERSION"));
                if tag != current_ver && !tag.is_empty() {
                    tracing::info!(
                        "📢 New AgentGate release available: {} (current: {}). Run 'agentgate update' to upgrade.",
                        tag, current_ver
                    );
                }
            }
            tokio::time::sleep(tokio::time::Duration::from_secs(3600)).await;
        }
    });
    }

    if use_tls {
        let (cert_path, key_path) = match (custom_cert, custom_key) {
            (Some(c), Some(k)) => (c, k),
            _ => {
                let cp = config.tls_cert_path();
                let kp = config.tls_key_path();
                cert::ensure_self_signed_cert(&cp, &kp)?;
                (cp, kp)
            }
        };

        let rustls_config = RustlsConfig::from_pem_file(&cert_path, &key_path)
            .await
            .context("Failed to load TLS certificates")?;

        info!("AgentGate server listening on https://{} (TLS)", addr);
        println!("🔒 AgentGate server listening on https://{}", addr);

        axum_server::bind_rustls(addr, rustls_config)
            .serve(app.into_make_service_with_connect_info::<SocketAddr>())
            .await
            .context("Server error")?;
    } else {
        info!("AgentGate server listening on http://{} (plain HTTP)", addr);
        println!("🔓 AgentGate server listening on http://{}", addr);

        let listener = tokio::net::TcpListener::bind(addr)
            .await
            .context("Failed to bind TCP listener")?;

        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .context("Server error")?;
    }

    Ok(())
}

async fn console_handler() -> axum::response::Html<&'static str> {
    axum::response::Html(include_str!("../web/console.html"))
}

async fn health_handler() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
    })
}

/// Resolve the client IP address securely:
/// - Uses the real peer socket IP as the ground truth.
/// - Only trusts X-Forwarded-For / X-Real-IP if the peer socket address is a trusted proxy.
/// - If forwarded differs from peer, logs both: "<forwarded> (via <peer>)".
pub fn resolve_client_ip(
    peer_addr: SocketAddr,
    headers: &HeaderMap,
    trusted_proxies: &[String],
) -> String {
    let peer_ip = peer_addr.ip().to_string();
    let is_trusted = trusted_proxies.iter().any(|tp| tp == &peer_ip);

    if !is_trusted {
        // Untrusted peer: completely ignore forwarded headers to prevent spoofing
        return peer_ip;
    }

    // Peer is trusted proxy: check for forwarded header
    let forwarded_opt = headers
        .get("x-forwarded-for")
        .or_else(|| headers.get("x-real-ip"))
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.split(',').next())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());

    if let Some(fwd) = forwarded_opt {
        if fwd != peer_ip {
            format!("{} (via {})", fwd, peer_ip)
        } else {
            peer_ip
        }
    } else {
        peer_ip
    }
}

async fn exec_handler(
    State(state): State<AppState>,
    ConnectInfo(peer_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(payload): Json<ExecRequest>,
) -> Response {
    let peer_ip = peer_addr.ip();
    let remote_addr = resolve_client_ip(peer_addr, &headers, &state.trusted_proxies);

    // 0. Check per-IP lockout to prevent audit log bloat and brute-force token exhaustion
    if let Some(remaining) = state.auth_throttler.check_lockout(&peer_ip) {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(ErrorResponse {
                error: "too_many_requests".to_string(),
                message: format!(
                    "Too many authentication failures. Locked out for {} seconds",
                    remaining.as_secs().max(1)
                ),
                exit_code: -1,
            }),
        )
            .into_response();
    }

    let command_raw = payload.command.trim();

    // 1. Authenticate Bearer Token
    let auth_header = match headers.get(header::AUTHORIZATION) {
        Some(h) => match h.to_str() {
            Ok(s) => s,
            Err(_) => {
                state.auth_throttler.record_failure(peer_ip);
                return (
                    StatusCode::UNAUTHORIZED,
                    Json(ErrorResponse {
                        error: "unauthorized".to_string(),
                        message: "Invalid Authorization header encoding".to_string(),
                        exit_code: -1,
                    }),
                )
                    .into_response();
            }
        },
        None => {
            state.auth_throttler.record_failure(peer_ip);
            return (
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse {
                    error: "unauthorized".to_string(),
                    message: "Missing Authorization header with Bearer token".to_string(),
                    exit_code: -1,
                }),
            )
                .into_response();
        }
    };

    let token_str = if let Some(token) = auth_header.strip_prefix("Bearer ") {
        token.trim()
    } else {
        state.auth_throttler.record_failure(peer_ip);
        return (
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse {
                error: "unauthorized".to_string(),
                message: "Authorization header must be in format 'Bearer <token>'".to_string(),
                exit_code: -1,
            }),
        )
            .into_response();
    };

    // Validate token against TokenStore
    let stored_token = {
        let mut store = match TokenStore::load(&state.tokens_file) {
            Ok(s) => s,
            Err(e) => {
                error!("Failed to load token store: {}", e);
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse {
                        error: "server_error".to_string(),
                        message: "Failed to read token store".to_string(),
                        exit_code: -1,
                    }),
                )
                    .into_response();
            }
        };

        match store.validate(token_str) {
            Ok(Some(t)) => {
                state.auth_throttler.record_success(&peer_ip);
                t
            }
            Ok(None) => {
                state.auth_throttler.record_failure(peer_ip);
                let _ = state.audit_logger.log(&AuditEntry {
                    timestamp: Utc::now(),
                    token_name: "unauthenticated".to_string(),
                    command: command_raw.to_string(),
                    policy: "none".to_string(),
                    result: AuditResult::Denied,
                    reason: Some("Invalid or expired token".to_string()),
                    exit_code: Some(-1),
                    duration_ms: Some(0),
                    remote_addr: remote_addr.clone(),
                });
                return (
                    StatusCode::UNAUTHORIZED,
                    Json(ErrorResponse {
                        error: "unauthorized".to_string(),
                        message: "Invalid or expired token".to_string(),
                        exit_code: -1,
                    }),
                )
                    .into_response();
            }
            Err(e) => {
                error!("Error validating token: {}", e);
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse {
                        error: "server_error".to_string(),
                        message: "Internal validation failure".to_string(),
                        exit_code: -1,
                    }),
                )
                    .into_response();
            }
        }
    };

    // Verify token is authorized for arbitrary execution (not restricted to named actions)
    if !stored_token.can_exec() {
        warn!(
            "Token '{}' is restricted to named actions only and cannot invoke arbitrary exec",
            stored_token.name
        );
        let _ = state.audit_logger.log(&AuditEntry {
            timestamp: Utc::now(),
            token_name: stored_token.name.clone(),
            command: command_raw.to_string(),
            policy: stored_token.policy.clone(),
            result: AuditResult::Denied,
            reason: Some("Token is restricted to named actions only and cannot invoke exec".to_string()),
            exit_code: Some(1),
            duration_ms: Some(0),
            remote_addr: remote_addr.clone(),
        });
        return (
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: "forbidden".to_string(),
                message: format!(
                    "Token '{}' is restricted to named actions only and cannot execute arbitrary commands.",
                    stored_token.name
                ),
                exit_code: 1,
            }),
        )
            .into_response();
    }

    // 2. Parse command and check for shell injection characters
    let parsed_cmd = match ParsedCommand::parse(command_raw) {
        Ok(cmd) => cmd,
        Err(e) => {
            let reason = e.to_string();
            warn!(
                "Injection blocked from token '{}' ({}): {}",
                stored_token.name, remote_addr, reason
            );
            let _ = state.audit_logger.log(&AuditEntry {
                timestamp: Utc::now(),
                token_name: stored_token.name.clone(),
                command: command_raw.to_string(),
                policy: stored_token.policy.clone(),
                result: AuditResult::InjectionBlocked,
                reason: Some(reason.clone()),
                exit_code: Some(-1),
                duration_ms: Some(0),
                remote_addr: remote_addr.clone(),
            });
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "injection_blocked".to_string(),
                    message: reason,
                    exit_code: -1,
                }),
            )
                .into_response();
        }
    };

    // Check if command is shell builtin `cd`
    if parsed_cmd.binary == "cd" {
        let target_dir = parsed_cmd.args.first().map(|s| s.as_str()).unwrap_or("~");
        let expanded = if target_dir == "~" {
            dirs::home_dir().unwrap_or_else(|| std::path::PathBuf::from("/tmp"))
        } else {
            std::path::PathBuf::from(target_dir)
        };

        if expanded.is_dir() {
            let _ = state.audit_logger.log(&AuditEntry {
                timestamp: Utc::now(),
                token_name: stored_token.name.clone(),
                command: command_raw.to_string(),
                policy: stored_token.policy.clone(),
                result: AuditResult::Allowed,
                reason: None,
                exit_code: Some(0),
                duration_ms: Some(0),
                remote_addr: remote_addr.clone(),
            });
            return (
                StatusCode::OK,
                Json(ExecSuccessResponse {
                    exit_code: 0,
                    stdout: format!("Directory exists: {}. In AgentGate, use the 'cwd' parameter (or 'agentgate exec --cwd <path> <cmd>') to run commands within a directory.\n", expanded.display()),
                    stderr: String::new(),
                    duration_ms: 0,
                    truncated: false,
                }),
            )
                .into_response();
        } else {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "directory_not_found".to_string(),
                    message: format!("cd: no such file or directory: {}", target_dir),
                    exit_code: 1,
                }),
            )
                .into_response();
        }
    }

    // 3. Check command against the token's Policy
    let is_allowed = {
        let policy_store = match PolicyStore::load(&state.policies_dir) {
            Ok(ps) => ps,
            Err(e) => {
                error!("Failed to load policy store: {}", e);
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse {
                        error: "server_error".to_string(),
                        message: "Failed to read policy store".to_string(),
                        exit_code: -1,
                    }),
                )
                    .into_response();
            }
        };

        match policy_store.get(&stored_token.policy) {
            Some(policy) => policy.matches(&parsed_cmd.binary, &parsed_cmd.args),
            None => {
                let reason = format!("Policy '{}' not found", stored_token.policy);
                let _ = state.audit_logger.log(&AuditEntry {
                    timestamp: Utc::now(),
                    token_name: stored_token.name.clone(),
                    command: command_raw.to_string(),
                    policy: stored_token.policy.clone(),
                    result: AuditResult::Denied,
                    reason: Some(reason.clone()),
                    exit_code: Some(-1),
                    duration_ms: Some(0),
                    remote_addr: remote_addr.clone(),
                });
                return (
                    StatusCode::FORBIDDEN,
                    Json(ErrorResponse {
                        error: "policy_not_found".to_string(),
                        message: reason,
                        exit_code: -1,
                    }),
                )
                    .into_response();
            }
        }
    };

    if !is_allowed {
        let reason = format!(
            "command '{}' is not allowed by policy '{}'",
            command_raw, stored_token.policy
        );
        let _ = state.audit_logger.log(&AuditEntry {
            timestamp: Utc::now(),
            token_name: stored_token.name.clone(),
            command: command_raw.to_string(),
            policy: stored_token.policy.clone(),
            result: AuditResult::Denied,
            reason: Some(reason.clone()),
            exit_code: Some(-1),
            duration_ms: Some(0),
            remote_addr: remote_addr.clone(),
        });
        return (
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: "command_denied".to_string(),
                message: reason,
                exit_code: -1,
            }),
        )
            .into_response();
    }

    // 4. Validate optional cwd
    let cwd_path = if let Some(ref dir) = payload.cwd {
        let p = std::path::Path::new(dir);
        if !p.is_dir() {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "invalid_cwd".to_string(),
                    message: format!("Working directory does not exist: {}", dir),
                    exit_code: 1,
                }),
            )
                .into_response();
        }
        Some(dir.as_str())
    } else {
        None
    };

    // 5. Execute command safely via executor (no shell, with timeout, per-token OS user, and cwd)
    let exec_res = match executor::execute(&parsed_cmd, 30, stored_token.os_user.as_deref(), cwd_path).await {
        Ok(res) => res,
        Err(e) => {
            let reason = format!("Execution error: {}", e);
            let _ = state.audit_logger.log(&AuditEntry {
                timestamp: Utc::now(),
                token_name: stored_token.name.clone(),
                command: command_raw.to_string(),
                policy: stored_token.policy.clone(),
                result: AuditResult::Error,
                reason: Some(reason.clone()),
                exit_code: Some(-1),
                duration_ms: Some(0),
                remote_addr: remote_addr.clone(),
            });
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "execution_failed".to_string(),
                    message: reason,
                    exit_code: -1,
                }),
            )
                .into_response();
        }
    };

    // 5. Log audit entry for successful / evaluated execution
    let _ = state.audit_logger.log(&AuditEntry {
        timestamp: Utc::now(),
        token_name: stored_token.name,
        command: command_raw.to_string(),
        policy: stored_token.policy,
        result: AuditResult::Allowed,
        reason: None,
        exit_code: Some(exec_res.exit_code),
        duration_ms: Some(exec_res.duration_ms),
        remote_addr,
    });

    (
        StatusCode::OK,
        Json(ExecSuccessResponse {
            exit_code: exec_res.exit_code,
            stdout: exec_res.stdout,
            stderr: exec_res.stderr,
            duration_ms: exec_res.duration_ms,
            truncated: exec_res.truncated,
        }),
    )
        .into_response()
}

async fn action_handler(
    State(state): State<AppState>,
    ConnectInfo(peer_addr): ConnectInfo<SocketAddr>,
    Path(action_name): Path<String>,
    headers: HeaderMap,
    payload: Option<Json<ActionRequest>>,
) -> Response {
    let peer_ip = peer_addr.ip();
    let remote_addr = resolve_client_ip(peer_addr, &headers, &state.trusted_proxies);

    // 0. Check lockout
    if let Some(remaining) = state.auth_throttler.check_lockout(&peer_ip) {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(ErrorResponse {
                error: "too_many_requests".to_string(),
                message: format!(
                    "Too many authentication failures. Locked out for {} seconds",
                    remaining.as_secs().max(1)
                ),
                exit_code: -1,
            }),
        )
            .into_response();
    }

    // 1. Authenticate Bearer Token
    let auth_header = match headers.get(header::AUTHORIZATION) {
        Some(h) => match h.to_str() {
            Ok(s) => s,
            Err(_) => {
                state.auth_throttler.record_failure(peer_ip);
                return (
                    StatusCode::UNAUTHORIZED,
                    Json(ErrorResponse {
                        error: "unauthorized".to_string(),
                        message: "Invalid Authorization header encoding".to_string(),
                        exit_code: -1,
                    }),
                )
                    .into_response();
            }
        },
        None => {
            state.auth_throttler.record_failure(peer_ip);
            return (
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse {
                    error: "unauthorized".to_string(),
                    message: "Missing Authorization header with Bearer token".to_string(),
                    exit_code: -1,
                }),
            )
                .into_response();
        }
    };

    let token_str = if let Some(token) = auth_header.strip_prefix("Bearer ") {
        token.trim()
    } else {
        state.auth_throttler.record_failure(peer_ip);
        return (
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse {
                error: "unauthorized".to_string(),
                message: "Authorization header must be in format 'Bearer <token>'".to_string(),
                exit_code: -1,
            }),
        )
            .into_response();
    };

    let stored_token = {
        let mut store = match TokenStore::load(&state.tokens_file) {
            Ok(s) => s,
            Err(e) => {
                error!("Failed to load token store: {}", e);
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse {
                        error: "server_error".to_string(),
                        message: "Failed to read token store".to_string(),
                        exit_code: -1,
                    }),
                )
                    .into_response();
            }
        };

        match store.validate(token_str) {
            Ok(Some(t)) => {
                state.auth_throttler.record_success(&peer_ip);
                t
            }
            Ok(None) => {
                state.auth_throttler.record_failure(peer_ip);
                let _ = state.audit_logger.log(&AuditEntry {
                    timestamp: Utc::now(),
                    token_name: "unauthenticated".to_string(),
                    command: format!("action:{}", action_name),
                    policy: "none".to_string(),
                    result: AuditResult::Denied,
                    reason: Some("Invalid or expired token".to_string()),
                    exit_code: Some(-1),
                    duration_ms: Some(0),
                    remote_addr: remote_addr.clone(),
                });
                return (
                    StatusCode::UNAUTHORIZED,
                    Json(ErrorResponse {
                        error: "unauthorized".to_string(),
                        message: "Invalid or expired token".to_string(),
                        exit_code: -1,
                    }),
                )
                    .into_response();
            }
            Err(e) => {
                error!("Error validating token: {}", e);
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse {
                        error: "server_error".to_string(),
                        message: "Internal validation failure".to_string(),
                        exit_code: -1,
                    }),
                )
                    .into_response();
            }
        }
    };

    // 2. Check action authorization
    if !stored_token.can_run_action(&action_name) {
        warn!(
            "Token '{}' is not authorized to execute action '{}'",
            stored_token.name, action_name
        );
        let _ = state.audit_logger.log(&AuditEntry {
            timestamp: Utc::now(),
            token_name: stored_token.name.clone(),
            command: format!("action:{}", action_name),
            policy: stored_token.policy.clone(),
            result: AuditResult::Denied,
            reason: Some(format!("Token is not authorized to run action '{}'", action_name)),
            exit_code: Some(1),
            duration_ms: Some(0),
            remote_addr: remote_addr.clone(),
        });
        return (
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: "forbidden".to_string(),
                message: format!(
                    "Token '{}' is not authorized to execute action '{}'",
                    stored_token.name, action_name
                ),
                exit_code: 1,
            }),
        )
            .into_response();
    }

    // 3. Load policy from store
    let policy_store = match PolicyStore::load(&state.policies_dir) {
        Ok(s) => s,
        Err(e) => {
            error!("Failed to load policy store: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "server_error".to_string(),
                    message: "Failed to load policy store".to_string(),
                    exit_code: -1,
                }),
            )
                .into_response();
        }
    };

    let policy = match policy_store.get(&stored_token.policy) {
        Some(p) => p,
        None => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "policy_not_found".to_string(),
                    message: format!("Policy '{}' not found", stored_token.policy),
                    exit_code: -1,
                }),
            )
                .into_response();
        }
    };

    let action = match policy.get_action(&action_name) {
        Some(a) => a,
        None => {
            return (
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: "action_not_found".to_string(),
                    message: format!(
                        "Action '{}' is not defined in policy '{}'",
                        action_name, stored_token.policy
                    ),
                    exit_code: 1,
                }),
            )
                .into_response();
        }
    };

    let params = payload.map(|Json(p)| p.params).unwrap_or_default();
    let rendered_steps = match action.render_steps(&params) {
        Ok(s) => s,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "invalid_parameters".to_string(),
                    message: e.to_string(),
                    exit_code: -1,
                }),
            )
                .into_response();
        }
    };

    let start_total = std::time::Instant::now();
    let mut step_results = Vec::new();
    let mut all_success = true;

    for step in rendered_steps {
        let parsed_cmd = match ParsedCommand::parse(&step) {
            Ok(c) => c,
            Err(e) => {
                let reason = e.to_string();
                let _ = state.audit_logger.log(&AuditEntry {
                    timestamp: Utc::now(),
                    token_name: stored_token.name.clone(),
                    command: step.clone(),
                    policy: stored_token.policy.clone(),
                    result: AuditResult::InjectionBlocked,
                    reason: Some(reason.clone()),
                    exit_code: Some(-1),
                    duration_ms: Some(0),
                    remote_addr: remote_addr.clone(),
                });
                return (
                    StatusCode::BAD_REQUEST,
                    Json(ErrorResponse {
                        error: "injection_blocked".to_string(),
                        message: reason,
                        exit_code: -1,
                    }),
                )
                    .into_response();
            }
        };

        if policy.guardrails && crate::policy::is_hardened_destructive_guardrail(&parsed_cmd.binary, &parsed_cmd.args) {
            let reason = "Destructive guardrail violation in action step".to_string();
            let _ = state.audit_logger.log(&AuditEntry {
                timestamp: Utc::now(),
                token_name: stored_token.name.clone(),
                command: step.clone(),
                policy: stored_token.policy.clone(),
                result: AuditResult::Denied,
                reason: Some(reason.clone()),
                exit_code: Some(1),
                duration_ms: Some(0),
                remote_addr: remote_addr.clone(),
            });
            return (
                StatusCode::FORBIDDEN,
                Json(ErrorResponse {
                    error: "guardrail_blocked".to_string(),
                    message: reason,
                    exit_code: 1,
                }),
            )
                .into_response();
        }

        let exec_res = match executor::execute(&parsed_cmd, 60, stored_token.os_user.as_deref(), None).await {
            Ok(r) => r,
            Err(e) => {
                let reason = e.to_string();
                let _ = state.audit_logger.log(&AuditEntry {
                    timestamp: Utc::now(),
                    token_name: stored_token.name.clone(),
                    command: step.clone(),
                    policy: stored_token.policy.clone(),
                    result: AuditResult::Error,
                    reason: Some(reason.clone()),
                    exit_code: Some(-1),
                    duration_ms: Some(0),
                    remote_addr: remote_addr.clone(),
                });
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse {
                        error: "execution_failed".to_string(),
                        message: reason,
                        exit_code: -1,
                    }),
                )
                    .into_response();
            }
        };

        let is_ok = exec_res.exit_code == 0;
        let _ = state.audit_logger.log(&AuditEntry {
            timestamp: Utc::now(),
            token_name: stored_token.name.clone(),
            command: step.clone(),
            policy: stored_token.policy.clone(),
            result: if is_ok { AuditResult::Allowed } else { AuditResult::Denied },
            reason: None,
            exit_code: Some(exec_res.exit_code),
            duration_ms: Some(exec_res.duration_ms),
            remote_addr: remote_addr.clone(),
        });

        step_results.push(StepResult {
            step,
            exit_code: exec_res.exit_code,
            stdout: exec_res.stdout,
            stderr: exec_res.stderr,
            duration_ms: exec_res.duration_ms,
        });

        if !is_ok {
            all_success = false;
            if action.stop_on_failure {
                break;
            }
        }
    }

    (
        StatusCode::OK,
        Json(ActionResponse {
            action: action_name,
            success: all_success,
            total_duration_ms: start_total.elapsed().as_millis() as u64,
            steps: step_results,
        }),
    )
        .into_response()
}
