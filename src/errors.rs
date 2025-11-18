use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};

use crate::models::{ApiResponse, ErrorDetail};

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
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, error_detail) = match self {
            AppError::ValidationError(msg) => (
                StatusCode::BAD_REQUEST,
                ErrorDetail::validation("request", msg),
            ),
            AppError::AuthenticationError(msg) => {
                (StatusCode::UNAUTHORIZED, ErrorDetail::authentication(msg))
            }
            AppError::NotFound(msg) => (StatusCode::NOT_FOUND, ErrorDetail::not_found("资源", msg)),
            AppError::Conflict(msg) => (StatusCode::CONFLICT, ErrorDetail::conflict(msg)),
            AppError::InternalError(msg) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                ErrorDetail::internal_error(msg),
            ),
        };

        let body: ApiResponse<()> = ApiResponse {
            code: status.as_u16() as i32,
            message: error_detail.message,
            data: None,
            timestamp: chrono::Local::now().timestamp(),
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
        }
    }
}

pub type AppResult<T> = Result<T, AppError>;

/// 安全的数据库错误处理辅助函数
/// 在生产环境中隐藏敏感的错误详情，仅记录到日志
pub fn handle_db_error(operation: &str, error: impl std::fmt::Display) -> AppError {
    // 记录详细错误到日志（包含敏感信息）
    tracing::error!(
        operation = operation,
        error = %error,
        "Database operation failed"
    );

    // 返回通用错误消息（不包含敏感信息）
    #[cfg(debug_assertions)]
    {
        // 开发环境：返回详细错误便于调试
        AppError::InternalError(format!("{}: {}", operation, error))
    }

    #[cfg(not(debug_assertions))]
    {
        // 生产环境：返回通用错误，避免信息泄露
        AppError::InternalError(format!("Database operation failed: {}", operation))
    }
}
