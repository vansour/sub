use crate::models::Claims;
use crate::utils::get_jwt_secret;
use axum::{
    extract::Request,
    http::{header, StatusCode},
    middleware::Next,
    response::Response,
};
use jsonwebtoken::{decode, DecodingKey, Validation};

/// 验证 JWT Token 的中间件
pub async fn auth_middleware(req: Request, next: Next) -> Result<Response, StatusCode> {
    // 从环境变量读取 JWT secret
    let secret = get_jwt_secret("change-me-insecure-default".to_string());

    // 从 header 获取 token
    let token = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));

    let uri = req.uri().to_string();
    let method = req.method().to_string();

    if let Some(token) = token {
        match decode::<Claims>(
            token,
            &DecodingKey::from_secret(secret.as_bytes()),
            &Validation::default(),
        ) {
            Ok(decoded) => {
                let username = &decoded.claims.sub;
                tracing::debug!(
                    username = %username,
                    method = %method,
                    uri = %uri,
                    "token validation successful"
                );
                return Ok(next.run(req).await);
            }
            Err(e) => {
                tracing::warn!(
                    method = %method,
                    uri = %uri,
                    error = %e,
                    "token validation failed"
                );
            }
        }
    } else {
        tracing::warn!(
            method = %method,
            uri = %uri,
            "no token provided in authorization header"
        );
    }

    Err(StatusCode::UNAUTHORIZED)
}
