use crate::{
    AppState,
    errors::AppError,
    models::{ApiResponse, ChangePasswordRequest, Claims, LoginRequest, LoginResponse},
    services::AuthService,
    utils::get_jwt_secret,
};
use axum::{
    Json,
    extract::{ConnectInfo, State},
    http::StatusCode,
    response::IntoResponse,
};
use jsonwebtoken::{EncodingKey, Header, encode};
use std::net::SocketAddr;

/// 登录处理
pub async fn login(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(payload): Json<LoginRequest>,
) -> Result<impl IntoResponse, AppError> {
    let username = payload.username.clone();
    let client_ip = addr.ip();
    tracing::info!(username = %username, ip = %client_ip, "login attempt");

    // 检查 rate limit
    if let Err(msg) = state.rate_limiter.check_login_attempt(client_ip) {
        tracing::warn!(username = %username, ip = %client_ip, "login blocked by rate limiter");
        return Err(AppError::AuthenticationError(msg));
    }

    let (config_username, password_hash, jwt_secret) = {
        let auth = state.auth_config.read();
        (
            auth.username.clone(),
            auth.password_hash.clone(),
            auth.secret.clone(),
        )
    };

    // 验证用户名和密码
    match AuthService::verify_credentials(
        &payload.username,
        &payload.password,
        &config_username,
        &password_hash,
    ) {
        Ok(()) => {
            tracing::info!(username = %username, ip = %client_ip, "credentials verified successfully");
            // 验证成功，清除失败记录
            state.rate_limiter.record_login_success(client_ip);
        }
        Err(e) => {
            tracing::warn!(username = %username, ip = %client_ip, error = %e, "credentials verification failed");
            // 记录登录失败
            state.rate_limiter.record_login_failure(client_ip);
            return Err(e);
        }
    }

    // 生成 JWT token
    let exp = (std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 86400 * 7) as usize; // 7天有效期

    let claims = Claims {
        sub: payload.username.clone(),
        exp,
    };

    let jwt_secret = get_jwt_secret(jwt_secret);
    let token = match encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(jwt_secret.as_bytes()),
    ) {
        Ok(token) => {
            tracing::debug!(username = %username, token_length = token.len(), "JWT token generated");
            token
        }
        Err(e) => {
            let error_msg = format!("Failed to encode token: {}", e);
            tracing::error!(username = %username, error = %error_msg, "JWT encoding failed");
            return Err(AppError::InternalError(error_msg));
        }
    };

    tracing::info!(username = %username, ip = %client_ip, "login successful");
    Ok((
        StatusCode::OK,
        Json(ApiResponse::success(LoginResponse { token })),
    ))
}

/// 修改密码
pub async fn change_password(
    State(state): State<AppState>,
    Json(payload): Json<ChangePasswordRequest>,
) -> Result<impl IntoResponse, AppError> {
    let new_username = payload.new_username.clone();
    tracing::info!(new_username = %new_username, "change_password request received");

    let (current_username, current_password_hash) = {
        let auth = state.auth_config.read();
        (auth.username.clone(), auth.password_hash.clone())
    };

    // 验证旧密码并更新配置
    tracing::debug!(current_username = %current_username, "verifying old password");
    let new_auth = match AuthService::update_config(
        &payload.old_password,
        &payload.new_username,
        &payload.new_password,
        &current_username,
        &current_password_hash,
    ) {
        Ok(config) => {
            tracing::info!(new_username = %new_username, "password update config validated");
            config
        }
        Err(e) => {
            tracing::warn!(new_username = %new_username, error = %e, "password update validation failed");
            return Err(e);
        }
    };

    // 保存到文件
    match AuthService::save_config(&new_auth) {
        Ok(()) => {
            tracing::info!(new_username = %new_username, "auth config persisted to file");
        }
        Err(e) => {
            tracing::error!(new_username = %new_username, error = %e, "failed to persist auth config");
            return Err(e);
        }
    }

    // 更新内存中的配置
    {
        let mut auth = state.auth_config.write();
        auth.username = new_auth.username.clone();
        auth.password_hash = new_auth.password_hash.clone();
        tracing::debug!(new_username = %new_auth.username, "in-memory auth config updated");
    }

    tracing::info!(new_username = %new_username, "password changed successfully");
    Ok((
        StatusCode::OK,
        Json(ApiResponse::<serde_json::Value>::success_with_message(
            "密码修改成功",
        )),
    ))
}
