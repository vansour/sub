use serde::{Deserialize, Serialize};

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
