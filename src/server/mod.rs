pub mod cert;

use crate::audit::{AuditEntry, AuditLogger, AuditResult};
use crate::auth::TokenStore;
use crate::config::AgentGateConfig;
use crate::executor::{self, ParsedCommand};
use crate::policy::PolicyStore;
use anyhow::{Context, Result};
use axum::{
    extract::State,
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use axum_server::tls_rustls::RustlsConfig;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::Arc;
use tower_http::cors::{Any, CorsLayer};
use tower_http::trace::TraceLayer;
use tracing::{error, info, warn};

#[derive(Clone)]
pub struct AppState {
    pub tokens_file: std::path::PathBuf,
    pub policies_dir: std::path::PathBuf,
    pub audit_logger: Arc<AuditLogger>,
}

#[derive(Debug, Deserialize)]
pub struct ExecRequest {
    pub command: String,
}

#[derive(Debug, Serialize)]
pub struct ExecSuccessResponse {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
    pub duration_ms: u64,
    pub truncated: bool,
}

#[derive(Debug, Serialize)]
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
    };

    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    let app = Router::new()
        .route("/health", get(health_handler))
        .route("/v1/health", get(health_handler))
        .route("/v1/exec", post(exec_handler))
        .layer(cors)
        .layer(axum::extract::DefaultBodyLimit::max(64 * 1024)) // 64KB max request body — blocks large payload exhaustion
        .layer(tower::limit::ConcurrencyLimitLayer::new(128)) // 128 concurrent connection limit — blocks bot DDoS hammering
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    let addr: SocketAddr = format!("{}:{}", config.listen_addr, config.listen_port)
        .parse()
        .context("Invalid listen address or port")?;

    // Check port availability before binding for crystal clear error messages
    if let Err(e) = std::net::TcpListener::bind(addr) {
        if e.kind() == std::io::ErrorKind::AddrInUse {
            anyhow::bail!(
                "Port {} is already in use by another process on {}.\n💡 Change the port using: agentgate start --port <PORT>\n   or set: export AGENTGATE_PORT=<PORT>",
                config.listen_port, config.listen_addr
            );
        } else {
            anyhow::bail!("Cannot bind to {}: {}", addr, e);
        }
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

async fn health_handler() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
    })
}

async fn exec_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<ExecRequest>,
) -> Response {
    let remote_addr = headers
        .get("x-forwarded-for")
        .or_else(|| headers.get("x-real-ip"))
        .and_then(|h| h.to_str().ok())
        .unwrap_or("127.0.0.1")
        .to_string();

    let command_raw = payload.command.trim();

    // 1. Authenticate Bearer Token
    let auth_header = match headers.get(header::AUTHORIZATION) {
        Some(h) => match h.to_str() {
            Ok(s) => s,
            Err(_) => {
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
            Ok(Some(t)) => t,
            Ok(None) => {
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

    // 4. Execute command safely via executor (no shell, with timeout)
    let exec_res = match executor::execute(&parsed_cmd, 30).await {
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
