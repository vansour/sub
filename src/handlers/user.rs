use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use std::time::Duration;

use crate::{
    errors::AppError,
    models::{
        ApiResponse, CreateRequest, CreateResponse, InfoResponse, ReorderRequest, UsersResponse,
    },
    services::{DataService, UrlService},
    AppState,
};

/// 创建或更新用户
pub async fn create_user(
    State(state): State<AppState>,
    Json(payload): Json<CreateRequest>,
) -> Result<impl IntoResponse, AppError> {
    let username = payload.username.clone();
    tracing::info!(
        username = %username,
        url_count = payload.urls.len(),
        allow_overwrite = payload.allow_overwrite,
        "create_user request received"
    );

    // 验证用户名
    let username = match UrlService::validate_username(&payload.username) {
        Ok(u) => {
            tracing::debug!(username = %u, "username validated successfully");
            u
        }
        Err(e) => {
            tracing::warn!(username = %payload.username, error = %e, "username validation failed");
            return Err(e);
        }
    };

    // 验证 URL 列表
    let (valid_urls, rejected_urls) =
        UrlService::validate_urls_with_rejection(payload.urls, &username);

    tracing::debug!(
        username = %username,
        valid_count = valid_urls.len(),
        rejected_count = rejected_urls.len(),
        "URL validation completed"
    );

    if valid_urls.is_empty() {
        tracing::warn!(username = %username, "no valid URLs provided");
        return Err(AppError::ValidationError(
            "No valid URLs provided".to_string(),
        ));
    }

    // 创建或更新用户
    {
        let mut map = state.store.write();

        if map.contains_key(&username) && !payload.allow_overwrite {
            tracing::warn!(
                username = %username,
                "user already exists and allow_overwrite is false"
            );
            return Err(AppError::Conflict(format!(
                "User '{}' already exists",
                username
            )));
        }

        // 如果是新用户，分配新的 order；如果是覆盖，保留原 order
        let order = if let Some(existing) = map.get(&username) {
            let old_order = existing.order;
            tracing::debug!(username = %username, order = old_order, "preserving existing order");
            old_order
        } else {
            let new_order = map.values().map(|d| d.order).max().unwrap_or(0) + 1;
            tracing::debug!(username = %username, order = new_order, "assigned new order");
            new_order
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
    match data_service.persist() {
        Ok(()) => {
            tracing::info!(
                username = %username,
                accepted_count = valid_urls.len(),
                rejected_count = rejected_urls.len(),
                "user link created/updated and persisted successfully"
            );
        }
        Err(e) => {
            tracing::error!(username = %username, error = %e, "failed to persist user data");
            return Err(e);
        }
    }

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

    Ok((StatusCode::OK, Json(ApiResponse::success(response))))
}

/// 获取用户信息
pub async fn get_user_info(
    State(state): State<AppState>,
    Path(username): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    tracing::debug!(username = %username, "get_user_info request received");

    let map = state.store.read();
    if let Some(user_data) = map.get(&username) {
        tracing::debug!(
            username = %username,
            url_count = user_data.urls.len(),
            "user info retrieved successfully"
        );
        let response = InfoResponse {
            username,
            urls: user_data.urls.clone(),
        };
        Ok((StatusCode::OK, Json(ApiResponse::success(response))).into_response())
    } else {
        tracing::warn!(username = %username, "user not found");
        Err(AppError::NotFound(format!("User '{}' not found", username)))
    }
}

/// 获取所有用户列表
pub async fn list_users(State(state): State<AppState>) -> impl IntoResponse {
    tracing::debug!("list_users request received");

    let data_service = DataService::new(state.store.clone(), state.data_file_path.clone());
    let users = data_service.get_all_users();

    tracing::info!(user_count = users.len(), "user list retrieved successfully");
    let response = UsersResponse { users };
    Json(ApiResponse::success(response))
}

/// 删除用户
pub async fn delete_user(
    State(state): State<AppState>,
    Path(username): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    tracing::info!(username = %username, "delete_user request received");

    let removed = {
        let mut map = state.store.write();
        map.remove(&username).is_some()
    };

    if !removed {
        tracing::warn!(username = %username, "user not found for deletion");
        return Err(AppError::NotFound(format!("User '{}' not found", username)));
    }

    // 同步持久化
    let data_service = DataService::new(state.store.clone(), state.data_file_path.clone());
    match data_service.persist() {
        Ok(()) => {
            tracing::info!(username = %username, "user deleted and persisted successfully");
        }
        Err(e) => {
            tracing::error!(username = %username, error = %e, "failed to persist after deletion");
            return Err(e);
        }
    }

    Ok((
        StatusCode::OK,
        Json(ApiResponse::<serde_json::Value>::success_with_message(
            "用户删除成功",
        )),
    ))
}

/// 重新排序用户
pub async fn reorder_users(
    State(state): State<AppState>,
    Json(payload): Json<ReorderRequest>,
) -> Result<impl IntoResponse, AppError> {
    tracing::info!(
        user_count = payload.usernames.len(),
        "reorder_users request received"
    );

    {
        let mut map = state.store.write();
        for (new_order, username) in payload.usernames.iter().enumerate() {
            if let Some(user_data) = map.get_mut(username) {
                let order_value = new_order + 1;
                user_data.order = order_value;
                tracing::debug!(username = %username, order = order_value, "order updated");
            } else {
                tracing::warn!(username = %username, "user not found during reorder");
            }
        }
    }

    // 持久化
    let data_service = DataService::new(state.store.clone(), state.data_file_path.clone());
    match data_service.persist() {
        Ok(()) => {
            tracing::info!("user reorder persisted successfully");
        }
        Err(e) => {
            tracing::error!(error = %e, "failed to persist reorder");
            return Err(e);
        }
    }

    Ok((
        StatusCode::OK,
        Json(ApiResponse::<serde_json::Value>::success_with_message(
            "排序更新成功",
        )),
    ))
}

/// 访问用户：获取所有链接的内容并合并返回
pub async fn redirect_short(
    State(state): State<AppState>,
    Path(username): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    tracing::info!(username = %username, "redirect_short request received");

    let urls = {
        let map = state.store.read();
        if let Some(user_data) = map.get(&username) {
            tracing::debug!(
                username = %username,
                url_count = user_data.urls.len(),
                "user found with URLs"
            );
            user_data.urls.clone()
        } else {
            tracing::warn!(username = %username, "user not found");
            return Err(AppError::NotFound(format!("User '{}' not found", username)));
        }
    };

    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .connect_timeout(Duration::from_secs(10))
        .user_agent("sub/0.1")
        .danger_accept_invalid_certs(false)
        .tcp_keepalive(Duration::from_secs(60))
        .pool_idle_timeout(Duration::from_secs(90))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            let error_msg = format!("Failed to build HTTP client: {}", e);
            tracing::error!(username = %username, error = %error_msg, "HTTP client build failed");
            return Err(AppError::ExternalServiceError(error_msg));
        }
    };

    // 并发抓取所有 URL，每个 URL 最多重试 2 次
    const MAX_RETRIES: usize = 2;
    const MAX_CONCURRENT: usize = 10;

    let client = std::sync::Arc::new(client);
    let semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT));

    tracing::debug!(
        username = %username,
        url_count = urls.len(),
        max_concurrent = MAX_CONCURRENT,
        max_retries = MAX_RETRIES,
        "starting concurrent URL fetches"
    );

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
                                            url = %url,
                                            content_size = text.len(),
                                            attempt = attempt,
                                            "URL fetched successfully (with retry)"
                                        );
                                    } else {
                                        tracing::debug!(
                                            url = %url,
                                            content_size = text.len(),
                                            "URL fetched successfully"
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
                        tracing::debug!(
                            url = %url,
                            attempt = attempt,
                            backoff_ms = backoff_ms,
                            "retrying after backoff"
                        );
                        tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
                    }
                }

                tracing::warn!(
                    url = %url,
                    attempts = MAX_RETRIES + 1,
                    error = %last_error,
                    "failed to fetch URL after all retries"
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
        tracing::error!(
            username = %username,
            total_urls = urls.len(),
            successful = bodies.len(),
            "all URL fetches failed"
        );
        return Err(AppError::ExternalServiceError(
            "Failed to fetch content from provided URLs".to_string(),
        ));
    }

    tracing::info!(
        username = %username,
        successful_count = bodies.len(),
        total_count = urls.len(),
        combined_size = bodies.iter().map(|b| b.len()).sum::<usize>(),
        "URL fetching completed successfully"
    );

    let combined_content = bodies.join("\n");
    Ok((StatusCode::OK, combined_content))
}
