use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;

#[derive(Debug)]
pub enum AppError {
    /// 验证错误
    ValidationError(String),
    /// 认证错误
    AuthenticationError(String),
    /// 资源未找到
    NotFound(String),
    /// 资源冲突
    Conflict(String),
    /// 内部服务器错误
    InternalError(String),
    /// 外部服务错误
    ExternalServiceError(String),
}

#[derive(Serialize)]
struct ErrorResponseBody {
    error: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    details: Option<String>,
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, error_message, details) = match self {
            AppError::ValidationError(msg) => {
                (StatusCode::BAD_REQUEST, "验证失败".to_string(), Some(msg))
            }
            AppError::AuthenticationError(msg) => {
                (StatusCode::UNAUTHORIZED, "认证失败".to_string(), Some(msg))
            }
            AppError::NotFound(msg) => (StatusCode::NOT_FOUND, "资源未找到".to_string(), Some(msg)),
            AppError::Conflict(msg) => (StatusCode::CONFLICT, "资源冲突".to_string(), Some(msg)),
            AppError::InternalError(msg) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "服务器内部错误".to_string(),
                Some(msg),
            ),
            AppError::ExternalServiceError(msg) => (
                StatusCode::BAD_GATEWAY,
                "外部服务错误".to_string(),
                Some(msg),
            ),
        };

        let body = ErrorResponseBody {
            error: error_message,
            details,
        };

        (status, Json(body)).into_response()
    }
}

impl From<anyhow::Error> for AppError {
    fn from(err: anyhow::Error) -> Self {
        AppError::InternalError(err.to_string())
    }
}

impl From<std::io::Error> for AppError {
    fn from(err: std::io::Error) -> Self {
        AppError::InternalError(format!("IO错误: {}", err))
    }
}

impl From<toml::de::Error> for AppError {
    fn from(err: toml::de::Error) -> Self {
        AppError::InternalError(format!("配置解析错误: {}", err))
    }
}

impl From<toml::ser::Error> for AppError {
    fn from(err: toml::ser::Error) -> Self {
        AppError::InternalError(format!("配置序列化错误: {}", err))
    }
}

impl std::fmt::Display for AppError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AppError::ValidationError(msg) => write!(f, "Validation error: {}", msg),
            AppError::AuthenticationError(msg) => write!(f, "Authentication error: {}", msg),
            AppError::NotFound(msg) => write!(f, "Not found: {}", msg),
            AppError::Conflict(msg) => write!(f, "Conflict: {}", msg),
            AppError::InternalError(msg) => write!(f, "Internal error: {}", msg),
            AppError::ExternalServiceError(msg) => write!(f, "External service error: {}", msg),
        }
    }
}

pub type AppResult<T> = Result<T, AppError>;
