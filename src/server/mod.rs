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
    extract::{ConnectInfo, Path, Query, State},
    http::{HeaderMap, StatusCode, header},
    response::{
        IntoResponse, Response,
        sse::{Event, KeepAlive, Sse},
    },
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActiveExecution {
    pub id: String,
    pub pid: Option<u32>,
    pub command: String,
    pub token_name: String,
    pub remote_addr: String,
    pub started_at: chrono::DateTime<Utc>,
}

#[derive(Clone)]
pub struct AppState {
    pub tokens_file: std::path::PathBuf,
    pub policies_dir: std::path::PathBuf,
    pub config_dir: std::path::PathBuf,
    pub audit_logger: Arc<AuditLogger>,
    pub trusted_proxies: Vec<String>,
    pub auth_throttler: AuthThrottler,
    pub rate_limiter: RequestRateLimiter,
    pub lockdown_mode: Arc<std::sync::atomic::AtomicBool>,
    pub active_executions: Arc<tokio::sync::RwLock<std::collections::HashMap<String, ActiveExecution>>>,
    pub shutdown_tx: Arc<tokio::sync::broadcast::Sender<()>>,
    pub start_time: chrono::DateTime<Utc>,
    pub totp_file: std::path::PathBuf,
    pub session_manager: Arc<crate::dashboard::session::SessionManager>,
    pub dashboard_config: Option<crate::config::DashboardConfig>,
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
        .route("/dashboard", get(console_handler))
        .route("/health", get(health_handler))
        .route("/v1/health", get(health_handler))
        .route("/v1/exec", post(exec_handler))
        .route("/v1/action/{name}", post(action_handler))
        .route("/v1/policies", get(policies_handler))
        .route("/v1/admin/status", get(admin_status_handler))
        .route("/v1/admin/lockdown", post(admin_lockdown_handler))
        .route("/v1/admin/unlock", post(admin_unlock_handler))
        .route("/v1/admin/executions", get(admin_executions_handler))
        .route("/v1/admin/kill/{id}", post(admin_kill_handler))
        .route("/v1/admin/shutdown", post(admin_shutdown_handler))
        .route("/v1/admin/restart", post(admin_restart_handler))
        .route("/v1/admin/tokens", get(admin_tokens_handler).post(admin_token_create_handler))
        .route("/v1/admin/tokens/revoke/{name}", post(admin_token_revoke_handler))
        .route("/v1/admin/stream", get(admin_stream_handler))
        .route("/v1/auth/totp", post(auth_totp_handler))
        .route("/v1/auth/totp/setup", get(auth_totp_setup_get_handler).post(auth_totp_setup_post_handler))
        .route("/v1/auth/logout", post(auth_logout_handler))
        .route("/v1/auth/me", get(auth_me_handler))
        .route("/v1/admin/files", get(admin_files_list_handler))
        .route("/v1/admin/files/{*path}", get(admin_file_read_handler).put(admin_file_write_handler).delete(admin_file_delete_handler));

    // CORS configuration: Support explicit origins or wildcard "*"
    if !config.allowed_origins.is_empty() {
        let cors = if config.allowed_origins.iter().any(|o| o == "*") {
            CorsLayer::new()
                .allow_origin(tower_http::cors::Any)
                .allow_methods([
                    axum::http::Method::GET,
                    axum::http::Method::POST,
                    axum::http::Method::PUT,
                    axum::http::Method::DELETE,
                    axum::http::Method::OPTIONS,
                ])
                .allow_headers([
                    axum::http::header::AUTHORIZATION,
                    axum::http::header::CONTENT_TYPE,
                    axum::http::header::ACCEPT,
                    axum::http::header::CACHE_CONTROL,
                ])
        } else {
            let mut origins = Vec::new();
            for o in &config.allowed_origins {
                if let Ok(val) = o.parse::<axum::http::HeaderValue>() {
                    origins.push(val);
                }
            }
            CorsLayer::new()
                .allow_origin(origins)
                .allow_methods([
                    axum::http::Method::GET,
                    axum::http::Method::POST,
                    axum::http::Method::PUT,
                    axum::http::Method::DELETE,
                    axum::http::Method::OPTIONS,
                ])
                .allow_headers([
                    axum::http::header::AUTHORIZATION,
                    axum::http::header::CONTENT_TYPE,
                    axum::http::header::ACCEPT,
                    axum::http::header::CACHE_CONTROL,
                ])
        };
        app = app.layer(cors);
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
    let (shutdown_tx, _) = tokio::sync::broadcast::channel(8);
    let shutdown_tx = Arc::new(shutdown_tx);

    let session_manager = Arc::new(crate::dashboard::session::SessionManager::new());
    let dashboard_config = config.dashboard.clone();

    let state = AppState {
        tokens_file: config.tokens_file.clone(),
        policies_dir: config.policies_dir.clone(),
        config_dir: config.config_dir.clone(),
        audit_logger,
        trusted_proxies: vec!["127.0.0.1".to_string(), "::1".to_string()],
        auth_throttler: AuthThrottler::default(),
        rate_limiter: RequestRateLimiter::default(),
        lockdown_mode: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        active_executions: Arc::new(tokio::sync::RwLock::new(std::collections::HashMap::new())),
        shutdown_tx: shutdown_tx.clone(),
        start_time: Utc::now(),
        totp_file: config.totp_file.clone(),
        session_manager,
        dashboard_config,
    };

    let app = create_router(config, state);

    // 1. Start local Unix Domain Socket listener in background task
    let unix_socket_path = config.socket_path.clone();
    let unix_app = app.clone();
    let mut unix_shutdown_rx = shutdown_tx.subscribe();
    tokio::spawn(async move {
        if let Err(e) = run_unix_socket(unix_app, unix_socket_path, &mut unix_shutdown_rx).await {
            error!("Unix domain socket listener error: {}", e);
        }
    });

    // 2. Start TCP / TLS listener for network / remote access
    let addr: SocketAddr = format!("{}:{}", config.listen_addr, config.listen_port)
        .parse()
        .context("Invalid listen address or port")?;

    // Check port availability before binding for crystal clear error messages
    if let Err(e) = std::net::TcpListener::bind(addr) {
        if e.kind() == std::io::ErrorKind::AddrInUse {
            anyhow::bail!(
                "Port {} is already in use by another process on {}.\n💡 Change the port using: agentgated start --port <PORT>\n   or set: export AGENTGATE_PORT=<PORT>",
                config.listen_port,
                config.listen_addr
            );
        } else {
            anyhow::bail!("Cannot bind to {}: {}", addr, e);
        }
    }

    let mut tcp_shutdown_rx = shutdown_tx.subscribe();

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

        info!("AgentGate Host server listening on https://{} (TLS)", addr);
        println!("🔒 Host network listener: https://{}", addr);

        tokio::select! {
            res = axum_server::bind_rustls(addr, rustls_config)
                .serve(app.into_make_service_with_connect_info::<SocketAddr>()) => {
                res.context("Server error")?;
            }
            _ = tcp_shutdown_rx.recv() => {
                info!("TCP TLS server stopping via shutdown signal");
            }
        }
    } else {
        info!("AgentGate Host server listening on http://{} (plain HTTP)", addr);
        println!("🔓 Host network listener: http://{}", addr);

        let listener = tokio::net::TcpListener::bind(addr)
            .await
            .context("Failed to bind TCP listener")?;

        tokio::select! {
            res = axum::serve(
                listener,
                app.into_make_service_with_connect_info::<SocketAddr>(),
            ) => {
                res.context("Server error")?;
            }
            _ = tcp_shutdown_rx.recv() => {
                info!("TCP plain server stopping via shutdown signal");
            }
        }
    }

    // Clean up socket and pid files on exit
    let _ = std::fs::remove_file(&config.socket_path);
    let _ = std::fs::remove_file(&config.pid_file);

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

#[derive(Clone, Debug)]
pub struct ClientPeer {
    pub ip: String,
    pub is_socket: bool,
}

impl<S> axum::extract::FromRequestParts<S> for ClientPeer
where
    S: Send + Sync,
{
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        _state: &S,
    ) -> std::result::Result<Self, Self::Rejection> {
        if let Some(connect_info) = parts.extensions.get::<ConnectInfo<SocketAddr>>() {
            Ok(ClientPeer {
                ip: connect_info.0.ip().to_string(),
                is_socket: false,
            })
        } else {
            Ok(ClientPeer {
                ip: "127.0.0.1".to_string(),
                is_socket: true,
            })
        }
    }
}

async fn exec_handler(
    State(state): State<AppState>,
    client_peer: ClientPeer,
    headers: HeaderMap,
    Json(payload): Json<ExecRequest>,
) -> Response {
    let peer_ip: std::net::IpAddr = client_peer.ip.parse().unwrap_or_else(|_| "127.0.0.1".parse().unwrap());
    let remote_addr = if client_peer.is_socket {
        "unix-socket".to_string()
    } else {
        client_peer.ip.clone()
    };

    // 0. Check Emergency Lockdown
    if state.lockdown_mode.load(std::sync::atomic::Ordering::SeqCst) {
        return (
            StatusCode::LOCKED,
            Json(ErrorResponse {
                error: "emergency_lockdown".to_string(),
                message: "AgentGate Host is currently in EMERGENCY LOCKDOWN mode. All command execution is suspended.".to_string(),
                exit_code: -1,
            }),
        )
            .into_response();
    }

    // Check per-IP lockout to prevent audit log bloat and brute-force token exhaustion
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

    // 4. Validate optional cwd: must be an absolute path and resolve to an existing directory
    let cwd_canonical = if let Some(ref dir) = payload.cwd {
        let p = std::path::Path::new(dir);
        if !p.is_absolute() {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "invalid_cwd".to_string(),
                    message: format!("Working directory must be an absolute path: {}", dir),
                    exit_code: 1,
                }),
            )
                .into_response();
        }
        match std::fs::canonicalize(p) {
            Ok(canonical) => {
                if !canonical.is_dir() {
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(ErrorResponse {
                            error: "invalid_cwd".to_string(),
                            message: format!("Working directory is not a directory: {}", dir),
                            exit_code: 1,
                        }),
                    )
                        .into_response();
                }
                Some(canonical)
            }
            Err(_) => {
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
        }
    } else {
        None
    };

    let cwd_path = cwd_canonical.as_ref().map(|p| p.to_string_lossy());
    let cwd_str = cwd_path.as_deref();

    // 5. Execute command safely via executor with live process tracking
    let exec_id = uuid::Uuid::new_v4().to_string();
    {
        let mut active_map = state.active_executions.write().await;
        active_map.insert(
            exec_id.clone(),
            ActiveExecution {
                id: exec_id.clone(),
                pid: None,
                command: command_raw.to_string(),
                token_name: stored_token.name.clone(),
                remote_addr: remote_addr.clone(),
                started_at: Utc::now(),
            },
        );
    }

    let active_map_clone = state.active_executions.clone();
    let exec_id_cb = exec_id.clone();
    let exec_res = match executor::execute_tracked(
        &parsed_cmd,
        30,
        stored_token.os_user.as_deref(),
        cwd_str,
        move |pid| {
            let active_map_clone = active_map_clone.clone();
            let exec_id_cb = exec_id_cb.clone();
            tokio::spawn(async move {
                let mut map = active_map_clone.write().await;
                if let Some(entry) = map.get_mut(&exec_id_cb) {
                    entry.pid = Some(pid);
                }
            });
        },
    )
    .await
    {
        Ok(res) => {
            state.active_executions.write().await.remove(&exec_id);
            res
        }
        Err(e) => {
            state.active_executions.write().await.remove(&exec_id);
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
    client_peer: ClientPeer,
    Path(action_name): Path<String>,
    headers: HeaderMap,
    payload: Option<Json<ActionRequest>>,
) -> Response {
    let peer_ip: std::net::IpAddr = client_peer.ip.parse().unwrap_or_else(|_| "127.0.0.1".parse().unwrap());
    let remote_addr = if client_peer.is_socket {
        "unix-socket".to_string()
    } else {
        client_peer.ip.clone()
    };

    // 0. Check Emergency Lockdown
    if state.lockdown_mode.load(std::sync::atomic::Ordering::SeqCst) {
        return (
            StatusCode::LOCKED,
            Json(ErrorResponse {
                error: "emergency_lockdown".to_string(),
                message: "AgentGate Host is currently in EMERGENCY LOCKDOWN mode. All action execution is suspended.".to_string(),
                exit_code: -1,
            }),
        )
            .into_response();
    }

    // Check lockout
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

/// Run Axum server over local Unix Domain Socket
async fn run_unix_socket(
    app: Router,
    socket_path: std::path::PathBuf,
    shutdown_rx: &mut tokio::sync::broadcast::Receiver<()>,
) -> Result<()> {
    if socket_path.exists() {
        let _ = std::fs::remove_file(&socket_path);
    }
    if let Some(parent) = socket_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }

    let listener = tokio::net::UnixListener::bind(&socket_path)
        .with_context(|| format!("Failed to bind Unix socket at {}", socket_path.display()))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o660));
    }

    info!("AgentGate Host listening on local Unix socket: {}", socket_path.display());
    println!("🚪 Local Unix socket: {}", socket_path.display());

    loop {
        tokio::select! {
            accept_res = listener.accept() => {
                match accept_res {
                    Ok((stream, _)) => {
                        let io = hyper_util::rt::TokioIo::new(stream);
                        let tower_service = app.clone();
                        tokio::spawn(async move {
                            let builder = hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new());
                            let hyper_service = hyper_util::service::TowerToHyperService::new(tower_service);
                            let _ = builder.serve_connection(io, hyper_service).await;
                        });
                    }
                    Err(e) => {
                        warn!("Unix socket accept error: {}", e);
                    }
                }
            }
            _ = shutdown_rx.recv() => {
                info!("Unix socket server stopping via shutdown signal");
                break;
            }
        }
    }

    let _ = std::fs::remove_file(&socket_path);
    Ok(())
}

fn authenticate_admin(
    headers: &HeaderMap,
    client_peer: &ClientPeer,
    state: &AppState,
) -> std::result::Result<String, (StatusCode, Json<ErrorResponse>)> {
    if client_peer.is_socket {
        return Ok("local-admin".to_string());
    }

    if let Some(h) = headers.get(header::AUTHORIZATION).and_then(|v| v.to_str().ok()) {
        if let Some(token) = h.strip_prefix("Bearer ") {
            let token = token.trim();
            if token.starts_with("dash_") {
                if let Ok(claims) = state.session_manager.validate_token(token) {
                    return Ok(claims.email);
                }
            } else if token.starts_with("ag_") {
                if let Ok(mut store) = TokenStore::load(&state.tokens_file) {
                    if let Ok(Some(t)) = store.validate(token) {
                        return Ok(t.name);
                    }
                }
            }
        }
    }

    if let Ok(store) = TokenStore::load(&state.tokens_file) {
        if store.list().is_empty() {
            return Ok("initial-setup".to_string());
        }
    }

    Err((
        StatusCode::UNAUTHORIZED,
        Json(ErrorResponse {
            error: "unauthorized".to_string(),
            message: "Unauthorized access to admin API".to_string(),
            exit_code: 1,
        }),
    ))
}

#[derive(Debug, Deserialize)]
pub struct StreamQuery {
    pub token: Option<String>,
}

struct ReceiverStream<T> {
    inner: tokio::sync::mpsc::Receiver<T>,
}

impl<T> futures_core::Stream for ReceiverStream<T> {
    type Item = T;

    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<T>> {
        self.inner.poll_recv(cx)
    }
}

async fn admin_stream_handler(
    State(state): State<AppState>,
    Query(query): Query<StreamQuery>,
    client_peer: ClientPeer,
    headers: HeaderMap,
) -> Response {
    let is_auth = if let Some(t) = query.token.filter(|t| !t.is_empty()) {
        let mut valid = false;
        if t.starts_with("dash_") {
            valid = state.session_manager.validate_token(&t).is_ok();
        } else if t.starts_with("ag_") {
            if let Ok(mut store) = TokenStore::load(&state.tokens_file) {
                valid = store.validate(&t).map(|res| res.is_some()).unwrap_or(false);
            }
        }
        valid
    } else {
        authenticate_admin(&headers, &client_peer, &state).is_ok()
    };

    if !is_auth {
        return (StatusCode::UNAUTHORIZED, "Unauthorized stream connection").into_response();
    }

    let (tx, rx) = tokio::sync::mpsc::channel::<std::result::Result<Event, std::convert::Infallible>>(64);

    tokio::spawn(async move {
        let mut audit_rx = state.audit_logger.subscribe();
        let mut ticker = tokio::time::interval(std::time::Duration::from_secs(2));

        loop {
            tokio::select! {
                res = audit_rx.recv() => {
                    if let Ok(entry) = res {
                        let json = serde_json::to_string(&entry).unwrap_or_default();
                        if tx.send(Ok(Event::default().event("audit").data(json))).await.is_err() {
                            break;
                        }
                    }
                }
                _ = ticker.tick() => {
                    let is_locked = state.lockdown_mode.load(std::sync::atomic::Ordering::Relaxed);
                    let active = state.active_executions.read().await.values().cloned().collect::<Vec<_>>();
                    let uptime = Utc::now().signed_duration_since(state.start_time).num_seconds();
                    let payload = serde_json::json!({
                        "lockdown": is_locked,
                        "active_executions": active,
                        "uptime_seconds": uptime,
                    });
                    if tx.send(Ok(Event::default().event("heartbeat").data(payload.to_string()))).await.is_err() {
                        break;
                    }
                }
            }
        }
    });

    Sse::new(ReceiverStream { inner: rx }).keep_alive(KeepAlive::default()).into_response()
}

async fn admin_status_handler(
    State(state): State<AppState>,
    client_peer: ClientPeer,
    headers: HeaderMap,
) -> Response {
    if let Err(e) = authenticate_admin(&headers, &client_peer, &state) {
        return e.into_response();
    }



    let is_locked = state.lockdown_mode.load(std::sync::atomic::Ordering::Relaxed);
    let active_count = state.active_executions.read().await.len();
    let policies_count = PolicyStore::load(&state.policies_dir).map(|p| p.list().len()).unwrap_or(0);
    let tokens_count = TokenStore::load(&state.tokens_file).map(|t| t.list().len()).unwrap_or(0);
    let uptime = Utc::now().signed_duration_since(state.start_time).num_seconds();

    Json(serde_json::json!({
        "status": if is_locked { "lockdown" } else { "operational" },
        "lockdown": is_locked,
        "version": env!("CARGO_PKG_VERSION"),
        "uptime_seconds": uptime,
        "active_executions": active_count,
        "policies_count": policies_count,
        "tokens_count": tokens_count,
    })).into_response()
}

async fn admin_lockdown_handler(
    State(state): State<AppState>,
    client_peer: ClientPeer,
    headers: HeaderMap,
) -> Response {
    if let Err(e) = authenticate_admin(&headers, &client_peer, &state) {
        return e.into_response();
    }



    state.lockdown_mode.store(true, std::sync::atomic::Ordering::SeqCst);
    warn!("🚨 Emergency Lockdown ACTIVATED by administrator");
    Json(serde_json::json!({
        "status": "lockdown_active",
        "message": "Emergency lockdown enabled. All command and action execution is suspended."
    })).into_response()
}

async fn admin_unlock_handler(
    State(state): State<AppState>,
    client_peer: ClientPeer,
    headers: HeaderMap,
) -> Response {
    if let Err(e) = authenticate_admin(&headers, &client_peer, &state) {
        return e.into_response();
    }



    state.lockdown_mode.store(false, std::sync::atomic::Ordering::SeqCst);
    info!("🟢 Emergency Lockdown RELEASED by administrator");
    Json(serde_json::json!({
        "status": "operational",
        "message": "Emergency lockdown released. Operations restored to normal."
    })).into_response()
}

async fn admin_executions_handler(
    State(state): State<AppState>,
    client_peer: ClientPeer,
    headers: HeaderMap,
) -> Response {
    if let Err(e) = authenticate_admin(&headers, &client_peer, &state) {
        return e.into_response();
    }



    let map = state.active_executions.read().await;
    let list: Vec<ActiveExecution> = map.values().cloned().collect();
    Json(list).into_response()
}

async fn admin_kill_handler(
    State(state): State<AppState>,
    Path(id): Path<String>,
    client_peer: ClientPeer,
    headers: HeaderMap,
) -> Response {
    if let Err(e) = authenticate_admin(&headers, &client_peer, &state) {
        return e.into_response();
    }



    let map = state.active_executions.read().await;
    if let Some(entry) = map.get(&id) {
        if let Some(pid) = entry.pid {
            #[cfg(unix)]
            unsafe {
                libc::kill(pid as i32, libc::SIGKILL);
            }
            warn!("Admin killed execution {} (PID {})", id, pid);
            return Json(serde_json::json!({
                "status": "killed",
                "id": id,
                "pid": pid,
                "command": entry.command
            })).into_response();
        }
    }

    (StatusCode::NOT_FOUND, Json(serde_json::json!({
        "error": "not_found",
        "message": format!("Execution '{}' not found or has already terminated", id)
    }))).into_response()
}

async fn admin_shutdown_handler(
    State(state): State<AppState>,
    client_peer: ClientPeer,
    headers: HeaderMap,
) -> Response {
    if let Err(e) = authenticate_admin(&headers, &client_peer, &state) {
        return e.into_response();
    }



    warn!("🛑 Shutdown request received from admin interface. Stopping Host Daemon...");
    let tx = state.shutdown_tx.clone();
    tokio::spawn(async move {
        tokio::time::sleep(tokio::time::Duration::from_millis(150)).await;
        let _ = tx.send(());
    });

    Json(serde_json::json!({
        "status": "shutting_down",
        "message": "Host Daemon is shutting down cleanly."
    })).into_response()
}

async fn admin_tokens_handler(
    State(state): State<AppState>,
    client_peer: ClientPeer,
    headers: HeaderMap,
) -> Response {
    if let Err(e) = authenticate_admin(&headers, &client_peer, &state) {
        return e.into_response();
    }



    match TokenStore::load(&state.tokens_file) {
        Ok(store) => Json(store.list()).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))).into_response(),
    }
}

#[derive(Debug, Deserialize)]
pub struct CreateTokenRequest {
    pub name: String,
    pub policy: String,
    pub expires_days: Option<i64>,
    pub os_user: Option<String>,
    pub tier: Option<String>,
    pub actions: Option<Vec<String>>,
}

async fn admin_token_create_handler(
    State(state): State<AppState>,
    client_peer: ClientPeer,
    headers: HeaderMap,
    Json(payload): Json<CreateTokenRequest>,
) -> Response {
    if let Err(e) = authenticate_admin(&headers, &client_peer, &state) {
        return e.into_response();
    }



    let mut store = match TokenStore::load(&state.tokens_file) {
        Ok(s) => s,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))).into_response(),
    };

    let expires_in = payload.expires_days.map(chrono::Duration::days);
    match store.create(
        &payload.name,
        &payload.policy,
        expires_in,
        payload.os_user,
        payload.tier,
        payload.actions,
    ) {
        Ok(raw_token) => {
            if let Err(e) = store.save() {
                return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))).into_response();
            }
            (StatusCode::CREATED, Json(serde_json::json!({
                "status": "created",
                "name": payload.name,
                "policy": payload.policy,
                "token": raw_token
            }))).into_response()
        }
        Err(e) => (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": e.to_string()}))).into_response(),
    }
}

async fn admin_token_revoke_handler(
    State(state): State<AppState>,
    Path(name): Path<String>,
    client_peer: ClientPeer,
    headers: HeaderMap,
) -> Response {
    if let Err(e) = authenticate_admin(&headers, &client_peer, &state) {
        return e.into_response();
    }



    let mut store = match TokenStore::load(&state.tokens_file) {
        Ok(s) => s,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))).into_response(),
    };

    match store.revoke(&name) {
        Ok(true) => {
            let _ = store.save();
            Json(serde_json::json!({"status": "revoked", "token_name": name})).into_response()
        }
        Ok(false) => (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "Token not found"}))).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))).into_response(),
    }
}

async fn policies_handler(State(state): State<AppState>) -> Response {
    match PolicyStore::load(&state.policies_dir) {
        Ok(store) => Json(store.list()).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))).into_response(),
    }
}

// --- Auth Endpoints (RFC 6238 TOTP Authenticator & Session) ---

#[derive(Deserialize)]
pub struct AuthTotpRequest {
    pub code: String,
}

pub async fn auth_totp_handler(
    State(state): State<AppState>,
    Json(req): Json<AuthTotpRequest>,
) -> Response {
    let secret = match crate::dashboard::load_totp_secret(&state.totp_file) {
        Ok(Some(s)) => s,
        _ => {
            return (
                StatusCode::PRECONDITION_REQUIRED,
                Json(serde_json::json!({
                    "error": "totp_not_configured",
                    "message": "TOTP is not configured on this host. Run setup first."
                })),
            )
                .into_response();
        }
    };

    let now_secs = Utc::now().timestamp() as u64;
    match crate::dashboard::verify_totp(&secret, &req.code, now_secs) {
        Ok(true) => {
            let expiry_hours = state
                .dashboard_config
                .as_ref()
                .map(|c| c.session_expiry_hours)
                .unwrap_or(24);
            let token = state.session_manager.create_token("admin", expiry_hours);
            let expires_at = Utc::now() + chrono::Duration::hours(expiry_hours as i64);

            Json(serde_json::json!({
                "token": token,
                "email": "admin",
                "expires_at": expires_at.to_rfc3339()
            }))
            .into_response()
        }
        _ => (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({
                "error": "invalid_code",
                "message": "Invalid or expired 6-digit TOTP code."
            })),
        )
            .into_response(),
    }
}

pub async fn auth_totp_setup_get_handler(
    State(state): State<AppState>,
) -> Response {
    if let Ok(Some(_)) = crate::dashboard::load_totp_secret(&state.totp_file) {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "error": "already_configured",
                "message": "TOTP is already configured on this host."
            })),
        )
            .into_response();
    }

    let secret = crate::dashboard::generate_secret();
    let uri = crate::dashboard::generate_otpauth_uri(&secret, "AgentGate", "admin");

    Json(serde_json::json!({
        "secret": secret,
        "uri": uri
    }))
    .into_response()
}

#[derive(Deserialize)]
pub struct AuthTotpSetupRequest {
    pub secret: String,
    pub code: String,
}

pub async fn auth_totp_setup_post_handler(
    State(state): State<AppState>,
    Json(req): Json<AuthTotpSetupRequest>,
) -> Response {
    if let Ok(Some(_)) = crate::dashboard::load_totp_secret(&state.totp_file) {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "error": "already_configured",
                "message": "TOTP is already configured on this host."
            })),
        )
            .into_response();
    }

    let now_secs = Utc::now().timestamp() as u64;
    match crate::dashboard::verify_totp(&req.secret, &req.code, now_secs) {
        Ok(true) => {
            if let Err(e) = crate::dashboard::save_totp_secret(&state.totp_file, &req.secret) {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({
                        "error": "save_failed",
                        "message": format!("Failed to save TOTP secret: {}", e)
                    })),
                )
                    .into_response();
            }

            let expiry_hours = state
                .dashboard_config
                .as_ref()
                .map(|c| c.session_expiry_hours)
                .unwrap_or(24);
            let token = state.session_manager.create_token("admin", expiry_hours);
            let expires_at = Utc::now() + chrono::Duration::hours(expiry_hours as i64);

            Json(serde_json::json!({
                "token": token,
                "email": "admin",
                "expires_at": expires_at.to_rfc3339()
            }))
            .into_response()
        }
        _ => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "verification_failed",
                "message": "The code does not match the secret. Check your authenticator app time."
            })),
        )
            .into_response(),
    }
}

pub async fn admin_restart_handler(
    State(state): State<AppState>,
    client_peer: ClientPeer,
    headers: HeaderMap,
) -> Response {
    if let Err(e) = authenticate_admin(&headers, &client_peer, &state) {
        return e.into_response();
    }

    info!("Remote daemon restart requested by admin");
    let tx = state.shutdown_tx.clone();
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_millis(400)).await;
        let _ = tx.send(());
    });

    Json(serde_json::json!({
        "status": "restarting",
        "message": "Daemon shutdown signal sent. Restarting process."
    }))
    .into_response()
}

pub async fn auth_logout_handler(
    State(state): State<AppState>,
    client_peer: ClientPeer,
    headers: HeaderMap,
) -> Response {
    if let Err(e) = authenticate_admin(&headers, &client_peer, &state) {
        return e.into_response();
    }
    (StatusCode::OK, Json(serde_json::json!({"status": "ok"}))).into_response()
}

pub async fn auth_me_handler(
    State(state): State<AppState>,
    client_peer: ClientPeer,
    headers: HeaderMap,
) -> Response {
    let auth_res = authenticate_admin(&headers, &client_peer, &state);
    match auth_res {
        Ok(email) => {
            let expires_at = if let Some(h) = headers.get(header::AUTHORIZATION).and_then(|v| v.to_str().ok()) {
                if let Some(token) = h.strip_prefix("Bearer ") {
                    if let Ok(claims) = state.session_manager.validate_token(token.trim()) {
                        claims.expires_at.to_rfc3339()
                    } else {
                        "".to_string()
                    }
                } else {
                    "".to_string()
                }
            } else {
                "".to_string()
            };
            
            Json(serde_json::json!({
                "email": email,
                "expires_at": expires_at
            })).into_response()
        },
        Err(e) => e.into_response()
    }
}

// --- File Management Endpoints ---

fn resolve_safe_path(base_dir: &std::path::Path, req_path: &str) -> Option<std::path::PathBuf> {
    if req_path.starts_with('/') || req_path.contains("..") {
        return None;
    }
    let resolved = base_dir.join(req_path);
    if resolved.starts_with(base_dir) {
        Some(resolved)
    } else {
        None
    }
}

#[derive(Serialize)]
pub struct FileInfo {
    pub path: String,
    pub size_bytes: u64,
    pub modified: String,
}

pub async fn admin_files_list_handler(
    State(state): State<AppState>,
    client_peer: ClientPeer,
    headers: HeaderMap,
) -> Response {
    if let Err(e) = authenticate_admin(&headers, &client_peer, &state) {
        return e.into_response();
    }

    let mut files = Vec::new();
    let dirs_to_scan = vec![
        ("", state.config_dir.clone()),
        ("policies", state.policies_dir.clone()),
    ];

    for (prefix, dir_path) in dirs_to_scan {
        if let Ok(entries) = std::fs::read_dir(&dir_path) {
            for entry in entries.flatten() {
                if let Ok(metadata) = entry.metadata() {
                    if metadata.is_file() {
                        let name = entry.file_name().to_string_lossy().to_string();
                        let rel_path = if prefix.is_empty() { name } else { format!("{}/{}", prefix, name) };
                        let modified = metadata.modified()
                            .map(|st| chrono::DateTime::<Utc>::from(st).to_rfc3339())
                            .unwrap_or_default();
                        
                        files.push(FileInfo {
                            path: rel_path,
                            size_bytes: metadata.len(),
                            modified,
                        });
                    }
                }
            }
        }
    }

    Json(files).into_response()
}

pub async fn admin_file_read_handler(
    State(state): State<AppState>,
    Path(path): Path<String>,
    client_peer: ClientPeer,
    headers: HeaderMap,
) -> Response {
    if let Err(e) = authenticate_admin(&headers, &client_peer, &state) {
        return e.into_response();
    }

    let full_path = match resolve_safe_path(&state.config_dir, &path) {
        Some(p) => p,
        None => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "Invalid path"}))).into_response(),
    };

    if !full_path.exists() || !full_path.is_file() {
        return (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "File not found"}))).into_response();
    }

    let metadata = match std::fs::metadata(&full_path) {
        Ok(m) => m,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": "Cannot read metadata"}))).into_response(),
    };

    if metadata.len() > 64 * 1024 {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "File too large"}))).into_response();
    }

    let content = match std::fs::read_to_string(&full_path) {
        Ok(c) => c,
        Err(_) => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "Cannot read as text (may be binary)"}))).into_response(),
    };

    Json(serde_json::json!({
        "path": path,
        "content": content,
        "size_bytes": metadata.len()
    })).into_response()
}

#[derive(Deserialize)]
pub struct FileWriteRequest {
    content: String,
}

pub async fn admin_file_write_handler(
    State(state): State<AppState>,
    Path(path): Path<String>,
    client_peer: ClientPeer,
    headers: HeaderMap,
    Json(req): Json<FileWriteRequest>,
) -> Response {
    if let Err(e) = authenticate_admin(&headers, &client_peer, &state) {
        return e.into_response();
    }

    if req.content.len() > 64 * 1024 {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "Content too large (max 64KB)"}))).into_response();
    }

    let full_path = match resolve_safe_path(&state.config_dir, &path) {
        Some(p) => p,
        None => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "Invalid path"}))).into_response(),
    };

    if let Some(parent) = full_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }

    if let Err(e) = std::fs::write(&full_path, &req.content) {
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": format!("Failed to write: {}", e)}))).into_response();
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&full_path, std::fs::Permissions::from_mode(0o600));
    }

    Json(serde_json::json!({"status": "ok", "path": path})).into_response()
}

pub async fn admin_file_delete_handler(
    State(state): State<AppState>,
    Path(path): Path<String>,
    client_peer: ClientPeer,
    headers: HeaderMap,
) -> Response {
    if let Err(e) = authenticate_admin(&headers, &client_peer, &state) {
        return e.into_response();
    }

    if path == "config.yaml" || path == "tokens.yaml" {
        return (StatusCode::FORBIDDEN, Json(serde_json::json!({"error": "Protected file cannot be deleted"}))).into_response();
    }

    let full_path = match resolve_safe_path(&state.config_dir, &path) {
        Some(p) => p,
        None => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "Invalid path"}))).into_response(),
    };

    if !full_path.exists() {
        return (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "File not found"}))).into_response();
    }

    if let Err(e) = std::fs::remove_file(&full_path) {
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": format!("Failed to delete: {}", e)}))).into_response();
    }

    Json(serde_json::json!({"status": "ok"})).into_response()
}
