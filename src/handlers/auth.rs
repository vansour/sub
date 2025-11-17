use crate::{
    errors::AppError,
    models::{ChangePasswordRequest, Claims, LoginRequest, LoginResponse},
    services::AuthService,
    utils::get_jwt_secret,
    AppState,
};
use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use jsonwebtoken::{encode, EncodingKey, Header};

/// 登录处理
pub async fn login(
    State(state): State<AppState>,
    Json(payload): Json<LoginRequest>,
) -> Result<impl IntoResponse, AppError> {
    tracing::info!("login attempt for username: {}", payload.username);

    let (username, password_hash, jwt_secret) = {
        let auth = state.auth_config.read();
        (
            auth.username.clone(),
            auth.password_hash.clone(),
            auth.secret.clone(),
        )
    };

    // 验证用户名和密码
    AuthService::verify_credentials(
        &payload.username,
        &payload.password,
        &username,
        &password_hash,
    )?;

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
    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(jwt_secret.as_bytes()),
    )
    .map_err(|e| AppError::InternalError(format!("Failed to encode token: {}", e)))?;

    tracing::info!("login successful for username: {}", payload.username);
    Ok((StatusCode::OK, Json(LoginResponse { token })))
}

/// 修改密码
pub async fn change_password(
    State(state): State<AppState>,
    Json(payload): Json<ChangePasswordRequest>,
) -> Result<impl IntoResponse, AppError> {
    tracing::info!("change_password called");

    let (current_username, current_password_hash) = {
        let auth = state.auth_config.read();
        (auth.username.clone(), auth.password_hash.clone())
    };

    // 验证旧密码并更新配置
    let new_auth = AuthService::update_config(
        &payload.old_password,
        &payload.new_username,
        &payload.new_password,
        &current_username,
        &current_password_hash,
    )?;

    // 保存到文件
    AuthService::save_config(&new_auth)?;

    // 更新内存中的配置
    {
        let mut auth = state.auth_config.write();
        auth.username = new_auth.username;
        auth.password_hash = new_auth.password_hash;
    }

    tracing::info!("password changed successfully");
    Ok((
        StatusCode::OK,
        Json(serde_json::json!({"message": "Password changed successfully"})),
    ))
}
