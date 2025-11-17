use serde::{Deserialize, Serialize};

/// 统一的 API 响应包装器
#[derive(Debug, Serialize)]
pub struct ApiResponse<T> {
    /// 响应码: 0 表示成功，非 0 表示失败
    pub code: i32,
    /// 响应消息
    pub message: String,
    /// 响应数据
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<T>,
    /// 时间戳 (Unix 秒)
    pub timestamp: i64,
}

impl<T: Serialize> ApiResponse<T> {
    /// 创建成功响应
    pub fn success(data: T) -> Self {
        Self {
            code: 0,
            message: "成功".to_string(),
            data: Some(data),
            timestamp: chrono::Local::now().timestamp(),
        }
    }

    /// 创建成功响应（不带数据）
    pub fn success_with_message(message: impl Into<String>) -> Self {
        Self {
            code: 0,
            message: message.into(),
            data: None,
            timestamp: chrono::Local::now().timestamp(),
        }
    }
}

/// 错误响应详情
#[derive(Debug, Serialize)]
pub struct ErrorDetail {
    /// 错误代码
    pub code: String,
    /// 错误描述
    pub message: String,
    /// 可选的详细信息
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<String>,
    /// 可选的验证错误（用于 422 错误）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub validation_errors: Option<Vec<ValidationError>>,
}

/// 验证错误详情
#[derive(Debug, Serialize, Clone)]
pub struct ValidationError {
    /// 字段名
    pub field: String,
    /// 错误信息
    pub message: String,
}

impl ErrorDetail {
    /// 创建验证错误
    pub fn validation(field: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: "VALIDATION_ERROR".to_string(),
            message: "输入验证失败".to_string(),
            details: None,
            validation_errors: Some(vec![ValidationError {
                field: field.into(),
                message: message.into(),
            }]),
        }
    }

    /// 创建认证错误
    pub fn authentication(message: impl Into<String>) -> Self {
        Self {
            code: "AUTHENTICATION_ERROR".to_string(),
            message: message.into(),
            details: None,
            validation_errors: None,
        }
    }

    /// 创建未找到错误
    pub fn not_found(resource: impl Into<String>, identifier: impl Into<String>) -> Self {
        Self {
            code: "NOT_FOUND".to_string(),
            message: format!("{}不存在: {}", resource.into(), identifier.into()),
            details: None,
            validation_errors: None,
        }
    }

    /// 创建冲突错误
    pub fn conflict(message: impl Into<String>) -> Self {
        Self {
            code: "CONFLICT".to_string(),
            message: message.into(),
            details: None,
            validation_errors: None,
        }
    }

    /// 创建内部错误
    pub fn internal_error(message: impl Into<String>) -> Self {
        Self {
            code: "INTERNAL_ERROR".to_string(),
            message: message.into(),
            details: None,
            validation_errors: None,
        }
    }

    /// 创建外部服务错误
    pub fn external_service_error(service: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: "EXTERNAL_SERVICE_ERROR".to_string(),
            message: format!("{}: {}", service.into(), message.into()),
            details: None,
            validation_errors: None,
        }
    }
}

/// JWT Claims
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claims {
    pub sub: String,
    pub exp: usize,
}

/// 登录请求
#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

/// 登录响应
#[derive(Debug, Serialize)]
pub struct LoginResponse {
    pub token: String,
}

/// 修改密码请求
#[derive(Debug, Deserialize)]
pub struct ChangePasswordRequest {
    pub old_password: String,
    pub new_username: String,
    pub new_password: String,
}

/// 创建用户请求
#[derive(Debug, Deserialize)]
pub struct CreateRequest {
    pub username: String,
    pub urls: Vec<String>,
    /// 是否允许覆盖已存在的用户，默认为 false
    #[serde(default)]
    pub allow_overwrite: bool,
}

/// 创建用户响应
#[derive(Debug, Serialize)]
pub struct CreateResponse {
    pub username: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub accepted_count: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rejected_count: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rejected_urls: Option<Vec<RejectedUrl>>,
}

/// 用户信息响应
#[derive(Debug, Serialize)]
pub struct InfoResponse {
    pub username: String,
    pub urls: Vec<String>,
}

/// 用户基本信息
#[derive(Debug, Serialize, Clone)]
pub struct UserInfo {
    pub username: String,
    pub urls: Vec<String>,
}

/// 用户列表响应
#[derive(Debug, Serialize)]
pub struct UsersResponse {
    pub users: Vec<UserInfo>,
}

/// 被拒绝的 URL
#[derive(Debug, Clone, Serialize)]
pub struct RejectedUrl {
    pub url: String,
    pub reason: String,
}

/// URL 验证结果
#[derive(Debug, Clone)]
pub struct UrlValidationResult {
    pub valid_urls: Vec<String>,
    pub rejected: Vec<RejectedUrl>,
}

/// 用户数据（内存存储）
#[derive(Debug, Clone)]
pub struct UserData {
    pub urls: Vec<String>,
    pub order: usize,
}

/// 重新排序请求
#[derive(Debug, Deserialize)]
pub struct ReorderRequest {
    pub usernames: Vec<String>,
}
