use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use std::time::Duration;

use crate::{
    errors::AppError,
    models::{CreateRequest, CreateResponse, InfoResponse, ReorderRequest, UsersResponse},
    services::{DataService, UrlService},
    AppState,
};

/// 创建或更新用户
pub async fn create_user(
    State(state): State<AppState>,
    Json(payload): Json<CreateRequest>,
) -> Result<impl IntoResponse, AppError> {
    tracing::info!(
        "create_user called: username = {}, url_count = {}, allow_overwrite = {}",
        payload.username,
        payload.urls.len(),
        payload.allow_overwrite
    );

    // 验证用户名
    let username = UrlService::validate_username(&payload.username)?;

    // 验证 URL 列表
    let (valid_urls, rejected_urls) =
        UrlService::validate_urls_with_rejection(payload.urls, &username);

    if valid_urls.is_empty() {
        return Err(AppError::ValidationError(
            "No valid URLs provided".to_string(),
        ));
    }

    // 创建或更新用户
    {
        let mut map = state.store.write();

        if map.contains_key(&username) && !payload.allow_overwrite {
            tracing::warn!(
                "user '{}' already exists and allow_overwrite is false, rejecting request",
                username
            );
            return Err(AppError::Conflict(format!(
                "User '{}' already exists",
                username
            )));
        }

        // 如果是新用户，分配新的 order；如果是覆盖，保留原 order
        let order = if let Some(existing) = map.get(&username) {
            existing.order
        } else {
            map.values().map(|d| d.order).max().unwrap_or(0) + 1
        };

        map.insert(
            username.clone(),
            crate::models::UserData {
                urls: valid_urls.clone(),
                order,
            },
        );
    }

    // 同步持久化
    let data_service = DataService::new(state.store.clone(), state.data_file_path.clone());
    data_service.persist()?;

    tracing::info!(
        "user link updated: username = {}, accepted = {}, rejected = {}",
        username,
        valid_urls.len(),
        rejected_urls.len()
    );

    let response = CreateResponse {
        username: username.clone(),
        accepted_count: Some(valid_urls.len()),
        rejected_count: if rejected_urls.is_empty() {
            None
        } else {
            Some(rejected_urls.len())
        },
        rejected_urls: if rejected_urls.is_empty() {
            None
        } else {
            Some(rejected_urls)
        },
    };

    Ok((StatusCode::OK, Json(response)))
}

/// 获取用户信息
pub async fn get_user_info(
    State(state): State<AppState>,
    Path(username): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    tracing::info!("get_user_info called: username = {}", username);

    let map = state.store.read();
    if let Some(user_data) = map.get(&username) {
        let body = Json(InfoResponse {
            username,
            urls: user_data.urls.clone(),
        });
        Ok((StatusCode::OK, body).into_response())
    } else {
        Err(AppError::NotFound(format!("User '{}' not found", username)))
    }
}

/// 获取所有用户列表
pub async fn list_users(State(state): State<AppState>) -> impl IntoResponse {
    tracing::info!("list_users called");

    let data_service = DataService::new(state.store.clone(), state.data_file_path.clone());
    let users = data_service.get_all_users();

    Json(UsersResponse { users })
}

/// 删除用户
pub async fn delete_user(
    State(state): State<AppState>,
    Path(username): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    tracing::info!("delete_user called: username = {}", username);

    let removed = {
        let mut map = state.store.write();
        map.remove(&username).is_some()
    };

    if !removed {
        return Err(AppError::NotFound(format!("User '{}' not found", username)));
    }

    // 同步持久化
    let data_service = DataService::new(state.store.clone(), state.data_file_path.clone());
    data_service.persist()?;

    tracing::info!("user deleted: {}", username);
    Ok((StatusCode::OK, Json(serde_json::json!({}))))
}

/// 重新排序用户
pub async fn reorder_users(
    State(state): State<AppState>,
    Json(payload): Json<ReorderRequest>,
) -> Result<impl IntoResponse, AppError> {
    tracing::info!("reorder_users called: {} users", payload.usernames.len());

    {
        let mut map = state.store.write();
        for (new_order, username) in payload.usernames.iter().enumerate() {
            if let Some(user_data) = map.get_mut(username) {
                user_data.order = new_order + 1;
                tracing::debug!("updated order for {}: {}", username, new_order + 1);
            }
        }
    }

    // 持久化
    let data_service = DataService::new(state.store.clone(), state.data_file_path.clone());
    data_service.persist()?;

    tracing::info!("user order updated successfully");
    Ok((
        StatusCode::OK,
        Json(serde_json::json!({
            "message": "Order updated successfully"
        })),
    ))
}

/// 访问用户：获取所有链接的内容并合并返回
pub async fn redirect_short(
    State(state): State<AppState>,
    Path(username): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    tracing::info!("redirect_short called: username = {}", username);

    let urls = {
        let map = state.store.read();
        if let Some(user_data) = map.get(&username) {
            user_data.urls.clone()
        } else {
            tracing::info!("user not found: {}", username);
            return Err(AppError::NotFound(format!("User '{}' not found", username)));
        }
    };

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .connect_timeout(Duration::from_secs(10))
        .user_agent("sub/0.1")
        .danger_accept_invalid_certs(false)
        .tcp_keepalive(Duration::from_secs(60))
        .pool_idle_timeout(Duration::from_secs(90))
        .build()
        .map_err(|e| {
            AppError::ExternalServiceError(format!("Failed to build HTTP client: {}", e))
        })?;

    // 并发抓取所有 URL，每个 URL 最多重试 2 次
    const MAX_RETRIES: usize = 2;
    const MAX_CONCURRENT: usize = 10;

    let client = std::sync::Arc::new(client);
    let semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT));

    let fetch_tasks: Vec<_> = urls
        .iter()
        .map(|url| {
            let url = url.clone();
            let client = std::sync::Arc::clone(&client);
            let semaphore = std::sync::Arc::clone(&semaphore);

            tokio::spawn(async move {
                let _permit = semaphore.acquire().await.ok()?;

                let mut attempt = 0;
                let mut last_error = String::new();

                while attempt <= MAX_RETRIES {
                    attempt += 1;
                    match client.get(&url).send().await {
                        Ok(resp) => match resp.error_for_status() {
                            Ok(ok_resp) => match ok_resp.text().await {
                                Ok(text) => {
                                    if attempt > 1 {
                                        tracing::info!(
                                            "fetched content from {} ({} bytes, succeeded on attempt {})",
                                            url,
                                            text.len(),
                                            attempt
                                        );
                                    } else {
                                        tracing::debug!(
                                            "fetched content from {} ({} bytes)",
                                            url,
                                            text.len()
                                        );
                                    }
                                    return Some(text);
                                }
                                Err(e) => {
                                    last_error = format!("failed to read response body: {}", e);
                                }
                            },
                            Err(e) => {
                                last_error = format!("non-success status: {}", e);
                            }
                        },
                        Err(e) => {
                            last_error = format!("request error: {}", e);
                        }
                    }

                    if attempt <= MAX_RETRIES {
                        let backoff_ms = 200 * (1 << (attempt - 1));
                        tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
                    }
                }

                tracing::warn!(
                    "failed to fetch {} after {} attempts, last error: {}",
                    url,
                    MAX_RETRIES + 1,
                    last_error
                );
                None
            })
        })
        .collect();

    let results = futures::future::join_all(fetch_tasks).await;

    let bodies: Vec<String> = results
        .into_iter()
        .filter_map(|r| r.ok().flatten())
        .collect();

    if bodies.is_empty() {
        tracing::warn!("no content fetched for user: {}", username);
        return Err(AppError::ExternalServiceError(
            "Failed to fetch content from provided URLs".to_string(),
        ));
    }

    tracing::info!(
        "successfully fetched {}/{} URLs for user: {}",
        bodies.len(),
        urls.len(),
        username
    );

    let combined_content = bodies.join("\n");
    Ok((StatusCode::OK, combined_content))
}
