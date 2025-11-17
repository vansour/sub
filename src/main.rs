use std::{net::SocketAddr, time::Duration};

use axum::{
    Json, Router,
    extract::Path,
    extract::State,
    http::{Request, StatusCode, header},
    middleware::{self, Next},
    response::IntoResponse,
    routing::{get, post},
};
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation, decode, encode};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;

mod config;
mod log;

// 输入限制常量
const MAX_USERNAME_LENGTH: usize = 100;
const MAX_URL_LENGTH: usize = 2048;
const MAX_URLS_PER_USER: usize = 50;
const MIN_URL_LENGTH: usize = 10;

/// 验证 URL 是否有效
/// 检查: scheme 必须是 http/https, 长度限制, 不能为空白
fn is_valid_url(url: &str) -> bool {
    // 检查长度
    if url.len() < MIN_URL_LENGTH || url.len() > MAX_URL_LENGTH {
        return false;
    }

    // 检查是否为空白
    if url.trim().is_empty() {
        return false;
    }

    // 验证 URL 格式和 scheme
    if let Ok(parsed) = url::Url::parse(url) {
        let scheme = parsed.scheme();
        (scheme == "http" || scheme == "https") && parsed.host().is_some()
    } else {
        false
    }
}

#[derive(Debug, Clone)]
struct UrlValidationResult {
    valid_urls: Vec<String>,
    rejected: Vec<RejectedUrl>,
}

#[derive(Debug, Clone, Serialize)]
struct RejectedUrl {
    url: String,
    reason: String,
}

#[derive(Debug, Clone)]
struct UserData {
    urls: Vec<String>,
    order: usize,
}

/// 验证并清洗 URL 列表
/// 返回去重后的有效 URL 和被拒绝的 URL 列表
fn validate_and_sanitize_urls(urls: Vec<String>) -> UrlValidationResult {
    let mut valid_urls = Vec::new();
    let mut rejected = Vec::new();
    let mut seen = std::collections::HashSet::new();

    for url in urls {
        let trimmed = url.trim().to_string();

        // 检查空字符串
        if trimmed.is_empty() {
            rejected.push(RejectedUrl {
                url: url.clone(),
                reason: "Empty or whitespace-only URL".to_string(),
            });
            continue;
        }

        // 检查长度
        if trimmed.len() < MIN_URL_LENGTH {
            rejected.push(RejectedUrl {
                url: trimmed.clone(),
                reason: format!("URL too short (min {} chars)", MIN_URL_LENGTH),
            });
            continue;
        }

        if trimmed.len() > MAX_URL_LENGTH {
            rejected.push(RejectedUrl {
                url: trimmed.clone(),
                reason: format!("URL too long (max {} chars)", MAX_URL_LENGTH),
            });
            continue;
        }

        // 检查重复
        if seen.contains(&trimmed) {
            rejected.push(RejectedUrl {
                url: trimmed.clone(),
                reason: "Duplicate URL".to_string(),
            });
            continue;
        }

        // 验证 URL 格式
        if !is_valid_url(&trimmed) {
            rejected.push(RejectedUrl {
                url: trimmed.clone(),
                reason: "Invalid URL format or unsupported scheme (must be http/https)".to_string(),
            });
            continue;
        }

        seen.insert(trimmed.clone());
        valid_urls.push(trimmed);
    }

    UrlValidationResult {
        valid_urls,
        rejected,
    }
}

#[derive(Clone)]
struct AppState {
    /// map username -> UserData (urls + order)
    store: Arc<RwLock<HashMap<String, UserData>>>,
    data_file_path: String,
    auth_config: Arc<RwLock<config::AuthConfig>>,
}

// JWT Claims
#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    exp: usize,
}

// 登录请求
#[derive(Deserialize)]
struct LoginRequest {
    username: String,
    password: String,
}

// 登录响应
#[derive(Serialize)]
struct LoginResponse {
    token: String,
}

// 修改密码请求
#[derive(Deserialize)]
struct ChangePasswordRequest {
    old_password: String,
    new_username: String,
    new_password: String,
}

// 哈希密码
// 确保应用状态满足跨线程要求（未调用，仅用于编译期校验）
fn _assert_app_state_send_sync() {
    fn assert_traits<T: Send + Sync>() {}
    assert_traits::<AppState>();
}

#[derive(Deserialize)]
struct CreateRequest {
    username: String,
    urls: Vec<String>,
    /// 是否允许覆盖已存在的用户，默认为 false
    #[serde(default)]
    allow_overwrite: bool,
}

#[derive(Serialize)]
struct CreateResponse {
    username: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    accepted_count: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    rejected_count: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    rejected_urls: Option<Vec<RejectedUrl>>,
}

#[derive(Serialize)]
struct InfoResponse {
    username: String,
    urls: Vec<String>,
}

#[derive(Serialize)]
struct UserInfo {
    username: String,
    urls: Vec<String>,
}

#[derive(Serialize)]
struct UsersResponse {
    users: Vec<UserInfo>,
}

// 登录处理
async fn login(
    State(state): State<AppState>,
    Json(payload): Json<LoginRequest>,
) -> impl IntoResponse {
    tracing::info!("login attempt for username: {}", payload.username);

    let auth = state.auth_config.read();

    // 验证用户名和密码（配置文件中存储明文）
    if payload.username != auth.username || payload.password != auth.password {
        tracing::warn!("login failed for username: {}", payload.username);
        return (
            axum::http::StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error": "Invalid username or password"})),
        )
            .into_response();
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

    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(auth.secret.as_bytes()),
    )
    .unwrap();

    tracing::info!("login successful for username: {}", payload.username);
    (axum::http::StatusCode::OK, Json(LoginResponse { token })).into_response()
}

// 验证 token 中间件
async fn auth_middleware(
    State(state): State<AppState>,
    req: Request<axum::body::Body>,
    next: Next,
) -> axum::response::Response {
    // 先读取 secret,然后释放锁
    let secret = {
        let auth = state.auth_config.read();
        auth.secret.clone()
    };

    // 从 header 获取 token
    let token = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));

    if let Some(token) = token {
        match decode::<Claims>(
            token,
            &DecodingKey::from_secret(secret.as_bytes()),
            &Validation::default(),
        ) {
            Ok(_) => return next.run(req).await,
            Err(e) => {
                tracing::warn!("token validation failed: {}", e);
            }
        }
    }

    StatusCode::UNAUTHORIZED.into_response()
}

// 修改密码
async fn change_password(
    State(state): State<AppState>,
    Json(payload): Json<ChangePasswordRequest>,
) -> impl IntoResponse {
    tracing::info!("change_password called");

    let mut auth = state.auth_config.write();

    // 验证旧密码（配置文件中存储明文）
    if payload.old_password != auth.password {
        tracing::warn!("change_password failed: incorrect old password");
        return (
            axum::http::StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error": "Incorrect old password"})),
        )
            .into_response();
    }

    // 更新用户名和密码
    auth.username = payload.new_username.clone();
    auth.password = payload.new_password.clone();

    // 持久化到配置文件
    if let Err(e) = save_auth_config(&auth) {
        tracing::error!("failed to save auth config: {}", e);
        return (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "Failed to save configuration"})),
        )
            .into_response();
    }

    tracing::info!("password changed successfully");
    (
        axum::http::StatusCode::OK,
        Json(serde_json::json!({"message": "Password changed successfully"})),
    )
        .into_response()
}

// 保存认证配置到文件
fn save_auth_config(auth: &config::AuthConfig) -> anyhow::Result<()> {
    use std::io::Write;

    // 读取现有配置
    let content = std::fs::read_to_string("config/config.toml")?;
    let mut config: toml::Value = toml::from_str(&content)?;

    // 更新 auth 部分
    if let Some(auth_section) = config.get_mut("auth").and_then(|v| v.as_table_mut()) {
        auth_section.insert(
            "username".to_string(),
            toml::Value::String(auth.username.clone()),
        );
        auth_section.insert(
            "password".to_string(),
            toml::Value::String(auth.password.clone()),
        );
    }

    // 写回文件
    let toml_string = toml::to_string_pretty(&config)?;
    let mut file = std::fs::File::create("config/config.toml")?;
    file.write_all(toml_string.as_bytes())?;
    file.sync_all()?;

    Ok(())
}

/// 健康检查接口
async fn healthz() -> impl IntoResponse {
    (
        axum::http::StatusCode::OK,
        Json(serde_json::json!({
            "status": "healthy",
            "timestamp": std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
        })),
    )
}

async fn index() -> impl IntoResponse {
    match tokio::fs::read_to_string("web/index.html").await {
        Ok(content) => (axum::http::StatusCode::OK, axum::response::Html(content)).into_response(),
        Err(err) => {
            tracing::error!("failed to read index.html: {}", err);
            let error_html = r#"<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>服务错误 - sub</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            margin: 0;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: #333;
        }
        .error-container {
            background: white;
            border-radius: 12px;
            padding: 40px;
            max-width: 500px;
            text-align: center;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
        }
        .error-icon {
            font-size: 64px;
            margin-bottom: 20px;
        }
        h1 {
            color: #e74c3c;
            margin: 0 0 10px 0;
        }
        p {
            color: #666;
            line-height: 1.6;
        }
        .retry-btn {
            margin-top: 20px;
            padding: 12px 24px;
            background: #667eea;
            color: white;
            border: none;
            border-radius: 6px;
            cursor: pointer;
            font-size: 16px;
            transition: background 0.3s;
        }
        .retry-btn:hover {
            background: #5568d3;
        }
        .error-details {
            margin-top: 20px;
            padding: 10px;
            background: #f8f9fa;
            border-radius: 6px;
            font-size: 12px;
            color: #666;
            word-break: break-word;
        }
    </style>
</head>
<body>
    <div class="error-container">
        <div class="error-icon">⚠️</div>
        <h1>服务暂时不可用</h1>
        <p>抱歉，页面加载失败。这可能是由于服务器配置问题导致的。</p>
        <p>请稍后重试，或联系管理员。</p>
        <button class="retry-btn" onclick="location.reload()">刷新页面</button>
        <div class="error-details">
            错误信息: 无法加载主页面文件
        </div>
    </div>
</body>
</html>"#;
            (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                axum::response::Html(error_html),
            )
                .into_response()
        }
    }
}

async fn create_json(
    State(state): State<AppState>,
    Json(payload): Json<CreateRequest>,
) -> impl IntoResponse {
    tracing::info!(
        "create_json called: username = {}, url_count = {}, allow_overwrite = {}",
        payload.username,
        payload.urls.len(),
        payload.allow_overwrite
    );

    // 验证用户名
    let username = payload.username.trim().to_string();
    if username.is_empty() {
        return (
            axum::http::StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "Username cannot be empty"
            })),
        )
            .into_response();
    }

    if username.len() > MAX_USERNAME_LENGTH {
        return (
            axum::http::StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "Username too long",
                "max_length": MAX_USERNAME_LENGTH
            })),
        )
            .into_response();
    }

    // 检查 URL 数量限制
    if payload.urls.len() > MAX_URLS_PER_USER {
        return (
            axum::http::StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "Too many URLs",
                "max_urls": MAX_URLS_PER_USER,
                "provided": payload.urls.len()
            })),
        )
            .into_response();
    }

    // 验证并清洗 URL
    let validation_result = validate_and_sanitize_urls(payload.urls);

    if !validation_result.rejected.is_empty() {
        tracing::warn!(
            "rejected {} invalid/duplicate URLs for user: {}",
            validation_result.rejected.len(),
            username
        );
    }

    if validation_result.valid_urls.is_empty() {
        tracing::warn!("no valid urls provided for user: {}", username);
        return (
            axum::http::StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "No valid URLs provided",
                "rejected_count": validation_result.rejected.len(),
                "rejected_urls": validation_result.rejected
            })),
        )
            .into_response();
    }

    // 检查用户是否已存在，并根据 allow_overwrite 决定是否覆盖
    {
        let mut map = state.store.write();
        if map.contains_key(&username) && !payload.allow_overwrite {
            tracing::warn!(
                "user '{}' already exists and allow_overwrite is false, rejecting request",
                username
            );
            return (
                axum::http::StatusCode::CONFLICT,
                Json(serde_json::json!({
                    "error": "User already exists",
                    "username": username,
                    "hint": "Set allow_overwrite to true to update existing user"
                })),
            )
                .into_response();
        }

        // 如果是新用户，分配新的 order（最大值+1）；如果是覆盖，保留原 order
        let order = if let Some(existing) = map.get(&username) {
            existing.order
        } else {
            map.values().map(|d| d.order).max().unwrap_or(0) + 1
        };

        map.insert(
            username.clone(),
            UserData {
                urls: validation_result.valid_urls.clone(),
                order,
            },
        );
    }

    // 同步持久化，失败时返回 500 错误
    if let Err(e) = persist_data(&state) {
        tracing::error!("failed to persist data: {}", e);
        return (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "error": "Failed to persist data",
                "details": e.to_string()
            })),
        )
            .into_response();
    }

    tracing::info!(
        "user link updated: username = {}, accepted = {}, rejected = {}",
        username,
        validation_result.valid_urls.len(),
        validation_result.rejected.len()
    );

    let response = CreateResponse {
        username: username.clone(),
        accepted_count: Some(validation_result.valid_urls.len()),
        rejected_count: if validation_result.rejected.is_empty() {
            None
        } else {
            Some(validation_result.rejected.len())
        },
        rejected_urls: if validation_result.rejected.is_empty() {
            None
        } else {
            Some(validation_result.rejected)
        },
    };

    (axum::http::StatusCode::OK, Json(response)).into_response()
}

async fn info(State(state): State<AppState>, Path(username): Path<String>) -> impl IntoResponse {
    tracing::info!("info called: username = {}", username);
    let map = state.store.read();
    if let Some(user_data) = map.get(&username) {
        let body = Json(InfoResponse {
            username,
            urls: user_data.urls.clone(),
        });
        (axum::http::StatusCode::OK, body).into_response()
    } else {
        axum::http::StatusCode::NOT_FOUND.into_response()
    }
}

/// 获取所有用户列表
async fn list_users(State(state): State<AppState>) -> Json<UsersResponse> {
    tracing::info!("list_users called");
    let map = state.store.read();
    let mut users: Vec<(usize, UserInfo)> = map
        .iter()
        .map(|(username, user_data)| {
            (
                user_data.order,
                UserInfo {
                    username: username.clone(),
                    urls: user_data.urls.clone(),
                },
            )
        })
        .collect();
    // 按 order 排序
    users.sort_by_key(|(order, _)| *order);
    let users: Vec<UserInfo> = users.into_iter().map(|(_, user)| user).collect();
    Json(UsersResponse { users })
}

/// 删除用户
async fn delete_user(
    State(state): State<AppState>,
    Path(username): Path<String>,
) -> impl IntoResponse {
    tracing::info!("delete_user called: username = {}", username);

    let removed = {
        let mut map = state.store.write();
        map.remove(&username).is_some()
    };

    if removed {
        // 同步持久化，失败时返回 500 错误
        if let Err(e) = persist_data(&state) {
            tracing::error!("failed to persist data after deletion: {}", e);
            return (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": "Failed to persist data after deletion",
                    "details": e.to_string()
                })),
            )
                .into_response();
        }

        tracing::info!("user deleted: {}", username);
        axum::http::StatusCode::OK.into_response()
    } else {
        tracing::warn!("user not found for deletion: {}", username);
        axum::http::StatusCode::NOT_FOUND.into_response()
    }
}

#[derive(Deserialize)]
struct ReorderRequest {
    usernames: Vec<String>,
}

/// 更新用户顺序
async fn reorder_users(
    State(state): State<AppState>,
    Json(payload): Json<ReorderRequest>,
) -> impl IntoResponse {
    tracing::info!("reorder_users called: {} users", payload.usernames.len());

    {
        let mut map = state.store.write();

        // 更新每个用户的 order
        for (new_order, username) in payload.usernames.iter().enumerate() {
            if let Some(user_data) = map.get_mut(username) {
                user_data.order = new_order + 1;
                tracing::debug!("updated order for {}: {}", username, new_order + 1);
            }
        }
    }

    // 持久化
    if let Err(e) = persist_data(&state) {
        tracing::error!("failed to persist data after reorder: {}", e);
        return (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "error": "Failed to persist order changes",
                "details": e.to_string()
            })),
        )
            .into_response();
    }

    tracing::info!("user order updated successfully");
    (
        axum::http::StatusCode::OK,
        Json(serde_json::json!({
            "message": "Order updated successfully"
        })),
    )
        .into_response()
}

/// 访问用户：获取所有链接的内容并合并返回
/// 使用并发请求、重试策略和并发限制优化性能
async fn redirect_short(
    State(state): State<AppState>,
    Path(username): Path<String>,
) -> impl IntoResponse {
    tracing::info!("fetch user content called: username = {}", username);
    let urls = {
        let map = state.store.read();
        if let Some(user_data) = map.get(&username) {
            user_data.urls.clone()
        } else {
            tracing::info!("user not found: {}", username);
            return (axum::http::StatusCode::NOT_FOUND, "User not found").into_response();
        }
    };

    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .user_agent("sub/0.1")
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("failed to build http client: {}", e);
            return axum::http::StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    // 并发抓取所有 URL，每个 URL 最多重试 2 次
    const MAX_RETRIES: usize = 2;
    const MAX_CONCURRENT: usize = 10;

    let client = Arc::new(client);
    let semaphore = Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT));

    let fetch_tasks: Vec<_> = urls
        .iter()
        .map(|url| {
            let url = url.clone();
            let client = Arc::clone(&client);
            let semaphore = Arc::clone(&semaphore);

            tokio::spawn(async move {
                // 获取并发许可
                let _permit = semaphore.acquire().await.ok()?;

                let mut attempt = 0;
                while attempt <= MAX_RETRIES {
                    attempt += 1;
                    match client.get(&url).send().await {
                        Ok(resp) => match resp.error_for_status() {
                            Ok(ok_resp) => match ok_resp.text().await {
                                Ok(text) => {
                                    tracing::info!(
                                        "fetched content from {} ({} bytes, attempt {})",
                                        url,
                                        text.len(),
                                        attempt
                                    );
                                    return Some(text);
                                }
                                Err(e) => {
                                    tracing::warn!(
                                        "failed to read response body from {} (attempt {}): {}",
                                        url,
                                        attempt,
                                        e
                                    );
                                }
                            },
                            Err(e) => {
                                tracing::warn!(
                                    "non-success status from {} (attempt {}): {}",
                                    url,
                                    attempt,
                                    e
                                );
                            }
                        },
                        Err(e) => {
                            tracing::warn!(
                                "request failed for {} (attempt {}): {}",
                                url,
                                attempt,
                                e
                            );
                        }
                    }

                    // 重试前等待一小段时间（指数退避）
                    if attempt <= MAX_RETRIES {
                        let backoff_ms = 100 * (1 << (attempt - 1)); // 100ms, 200ms
                        tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
                    }
                }
                None
            })
        })
        .collect();

    // 等待所有任务完成
    let results = futures::future::join_all(fetch_tasks).await;

    // 收集成功的结果
    let bodies: Vec<String> = results
        .into_iter()
        .filter_map(|r| r.ok().flatten())
        .collect();

    if bodies.is_empty() {
        tracing::warn!("no content fetched for user: {}", username);
        return (
            axum::http::StatusCode::BAD_GATEWAY,
            "Failed to fetch content from provided URLs",
        )
            .into_response();
    }

    tracing::info!(
        "successfully fetched {}/{} URLs for user: {}",
        bodies.len(),
        urls.len(),
        username
    );
    let combined_content = bodies.join("\n");
    (axum::http::StatusCode::OK, combined_content).into_response()
}

/// 从 data.toml 加载数据到内存
fn load_data(state: &AppState) -> anyhow::Result<()> {
    use std::fs;

    let path = &state.data_file_path;
    if !std::path::Path::new(path).exists() {
        tracing::info!("data file not found, starting with empty store");
        return Ok(());
    }

    let content = fs::read_to_string(path)?;
    let data: toml::Value = toml::from_str(&content)?;

    if let Some(links) = data.get("links").and_then(|v| v.as_array()) {
        let mut map = state.store.write();
        for (index, link) in links.iter().enumerate() {
            if let (Some(username), Some(urls)) = (
                link.get("username").and_then(|v| v.as_str()),
                link.get("urls").and_then(|v| v.as_array()),
            ) {
                let url_list: Vec<String> = urls
                    .iter()
                    .filter_map(|u| u.as_str().map(String::from))
                    .collect();
                if !url_list.is_empty() {
                    // 读取 order 字段，如果不存在则使用索引
                    let order = link
                        .get("order")
                        .and_then(|v| v.as_integer())
                        .map(|v| v as usize)
                        .unwrap_or(index + 1);

                    map.insert(
                        username.to_string(),
                        UserData {
                            urls: url_list,
                            order,
                        },
                    );
                    tracing::info!("loaded user: {} (order: {})", username, order);
                }
            }
        }
        tracing::info!("loaded {} users from data file", map.len());
    }

    Ok(())
}

/// 将内存中的短链映射写入 data.toml
/// 使用临时文件 + 原子 rename 确保数据完整性
fn persist_data(state: &AppState) -> anyhow::Result<()> {
    use std::io::Write;

    let map = state.store.read();
    let mut items: Vec<(String, UserData)> =
        map.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
    // 按 order 排序
    items.sort_by_key(|(_, data)| data.order);

    let mut toml = String::new();
    for (username, user_data) in items {
        toml.push_str("[[links]]\n");
        toml.push_str(&format!("order = {}\n", user_data.order));
        toml.push_str(&format!("username = \"{}\"\n", username));
        toml.push_str("urls = [");
        for (i, u) in user_data.urls.iter().enumerate() {
            if i > 0 {
                toml.push_str(", ");
            }
            toml.push_str(&format!("\"{}\"", u));
        }
        toml.push_str("]\n\n");
    }

    let path = &state.data_file_path;
    if let Some(parent) = std::path::Path::new(path).parent() {
        std::fs::create_dir_all(parent)?;
    }

    // 使用临时文件写入，然后原子性地 rename
    let tmp_path = format!("{}.tmp.{}", path, std::process::id());
    {
        let mut file = std::fs::File::create(&tmp_path)?;
        file.write_all(toml.as_bytes())?;
        file.sync_all()?; // 确保数据刷新到磁盘
    }

    // 原子性地替换目标文件
    std::fs::rename(&tmp_path, path)?;
    Ok(())
}

// 静态资源（CSS/JS）通过 `/static/*` 路由暴露，见 main 中 router 配置

#[tokio::main]
async fn main() {
    // 加载配置
    let cfg = config::AppConfig::load().expect("failed to load config/config.toml");

    // 初始化日志，确保在 Docker 和日志文件中都能查看
    log::init_logging(&cfg.log);
    tracing::info!("starting sub service");
    let state = AppState {
        store: Arc::new(RwLock::new(HashMap::new())),
        data_file_path: cfg.data.data_file_path.clone(),
        auth_config: Arc::new(RwLock::new(cfg.auth.clone())),
    };

    // 从文件加载已存在的数据
    if let Err(e) = load_data(&state) {
        tracing::error!("failed to load data: {}", e);
    }

    let addr: SocketAddr = format!("{}:{}", cfg.server.host, cfg.server.port)
        .parse()
        .expect("invalid server host/port in config");

    // 需要认证的路由
    let protected_routes = Router::new()
        .route("/api/create", post(create_json))
        .route("/api/users", get(list_users))
        .route("/api/reorder", post(reorder_users))
        .route("/api/delete/{username}", axum::routing::delete(delete_user))
        .route("/api/change-password", post(change_password))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            auth_middleware,
        ));

    let app = Router::new()
        .route("/", get(index))
        .route("/healthz", get(healthz))
        .route("/api/login", post(login))
        .route("/api/info/{code}", get(info))
        .route("/{code}", get(redirect_short))
        .merge(protected_routes)
        .nest_service("/static", tower_http::services::ServeDir::new("web"))
        .with_state(state);

    tracing::info!("Listening on {}", addr);
    axum::serve(tokio::net::TcpListener::bind(addr).await.unwrap(), app)
        .await
        .unwrap();
}
