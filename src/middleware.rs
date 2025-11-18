use crate::metrics;
use crate::models::Claims;
use crate::AppState;
use axum::{
    extract::{Request, State},
    http::{header, StatusCode},
    middleware::Next,
    response::Response,
};
use jsonwebtoken::{decode, DecodingKey, Validation};

/// 验证 JWT Token 的中间件
pub async fn auth_middleware(
    State(state): State<AppState>,
    req: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    // 从 AppState 读取配置的 JWT secret
    let jwt_secret = {
        let auth = state.auth_config.read();
        tracing::debug!(
            secret_len = auth.secret.len(),
            "read secret from auth config"
        );
        auth.secret.clone()
    };

    // 不要调用 get_jwt_secret，直接使用从配置中读取的值
    if jwt_secret.is_empty() {
        tracing::error!("JWT secret is empty in auth config");
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }

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
            &DecodingKey::from_secret(jwt_secret.as_bytes()),
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

/// 记录 HTTP 请求指标的中间件
pub async fn metrics_middleware(req: Request, next: Next) -> Response {
    let method = req.method().to_string();
    let path = req.uri().path().to_string();

    metrics::inc_http_requests_in_flight(&method, &path);
    let start = std::time::Instant::now();

    let response = next.run(req).await;

    let duration = start.elapsed().as_secs_f64();
    let status_code = response.status().as_u16();

    metrics::record_http_request(&method, &path, status_code, duration);
    metrics::dec_http_requests_in_flight(&method, &path);

    response
}
