use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use std::time::Duration;

use crate::{
    AppState,
    errors::{AppError, handle_db_error},
    models::{
        ApiResponse, CreateRequest, CreateResponse, InfoResponse, ReorderRequest, UserInfo,
        UsersResponse,
    },
    services::UrlService,
};

/// 从数据库获取用户数据
async fn get_user_data(
    state: &AppState,
    username: &str,
) -> Result<crate::models::UserData, AppError> {
    match state.db.get_user(username).await {
        Ok(Some(db_user)) => Ok(crate::models::UserData {
            urls: db_user.urls,
            order: db_user.order_index as usize,
        }),
        Ok(None) => Err(AppError::NotFound(format!("User '{}' not found", username))),
        Err(e) => Err(handle_db_error("get_user", e)),
    }
}

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
    let (valid_urls, rejected_urls) = UrlService::validate_urls_with_rejection(
        payload.urls,
        &username,
        state.security_config.allow_localhost,
        state.security_config.allow_private_ips,
    );

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

    // 检查用户是否已存在
    let user_exists = state
        .db
        .user_exists(&username)
        .await
        .map_err(|e| handle_db_error("user_exists", e))?;

    if user_exists && !payload.allow_overwrite {
        tracing::warn!(
            username = %username,
            "user already exists and allow_overwrite is false"
        );
        return Err(AppError::Conflict(format!(
            "User '{}' already exists",
            username
        )));
    }

    // 获取 order（保留现有 order 或分配新的）
    let order = if let Some(existing) = state
        .db
        .get_user(&username)
        .await
        .map_err(|e| handle_db_error("get_user", e))?
    {
        existing.order_index
    } else {
        // 新用户，获取最大 order + 1
        let max_order = state
            .db
            .get_all_users()
            .await
            .map_err(|e| handle_db_error("get_all_users", e))?
            .iter()
            .map(|u| u.order_index)
            .max()
            .unwrap_or(0);
        max_order + 1
    };

    // 保存到数据库
    state
        .db
        .upsert_user(&username, &valid_urls, order)
        .await
        .map_err(|e| handle_db_error("upsert_user", e))?;

    tracing::info!(
        username = %username,
        accepted_count = valid_urls.len(),
        rejected_count = rejected_urls.len(),
        "user created/updated successfully"
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

    Ok((StatusCode::OK, Json(ApiResponse::success(response))))
}

/// 获取用户信息
pub async fn get_user_info(
    State(state): State<AppState>,
    Path(username): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    tracing::debug!(username = %username, "get_user_info request received");

    let user_data = get_user_data(&state, &username).await?;

    tracing::debug!(
        username = %username,
        url_count = user_data.urls.len(),
        "user info retrieved successfully"
    );

    let response = InfoResponse {
        username,
        urls: user_data.urls,
    };

    Ok((StatusCode::OK, Json(ApiResponse::success(response))))
}

/// 获取所有用户列表
pub async fn list_users(State(state): State<AppState>) -> Result<impl IntoResponse, AppError> {
    tracing::debug!("list_users request received");

    // 从数据库获取所有用户
    let db_users = state
        .db
        .get_all_users()
        .await
        .map_err(|e| handle_db_error("get_all_users", e))?;

    // 转换为 API 响应格式
    let users: Vec<UserInfo> = db_users
        .into_iter()
        .map(|db_user| UserInfo {
            username: db_user.username,
            urls: db_user.urls,
        })
        .collect();

    tracing::info!(user_count = users.len(), "user list retrieved successfully");
    let response = UsersResponse { users };
    Ok(Json(ApiResponse::success(response)))
}

/// 删除用户
pub async fn delete_user(
    State(state): State<AppState>,
    Path(username): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    tracing::info!(username = %username, "delete_user request received");

    // 从数据库删除
    let deleted = state
        .db
        .delete_user(&username)
        .await
        .map_err(|e| handle_db_error("delete_user", e))?;

    if !deleted {
        tracing::warn!(username = %username, "user not found for deletion");
        return Err(AppError::NotFound(format!("User '{}' not found", username)));
    }

    tracing::info!(username = %username, "user deleted successfully");

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

    // 构建 username -> new_order 的映射
    let order_map: std::collections::HashMap<String, i64> = payload
        .usernames
        .iter()
        .enumerate()
        .map(|(idx, username)| (username.clone(), (idx + 1) as i64))
        .collect();

    // 更新数据库中的排序
    state
        .db
        .update_user_orders(&order_map)
        .await
        .map_err(|e| handle_db_error("update_user_orders", e))?;

    tracing::info!("user reorder completed successfully");

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

    let user_data = get_user_data(&state, &username).await?;
    let urls = user_data.urls;

    tracing::debug!(
        username = %username,
        url_count = urls.len(),
        "user found with URLs"
    );

    // 使用共享的 HTTP 客户端
    let client = &state.http_client;
    let config = &state.http_client_config;

    // 从配置中读取参数
    let max_retries = config.max_retries;
    let max_concurrent = config.max_concurrent;
    let total_timeout_secs = config.total_timeout_secs;
    let backoff_base_ms = config.backoff_base_ms;

    let semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(max_concurrent));

    tracing::debug!(
        username = %username,
        url_count = urls.len(),
        max_concurrent = max_concurrent,
        max_retries = max_retries,
        total_timeout_secs = total_timeout_secs,
        "starting concurrent URL fetches"
    );

    let fetch_tasks: Vec<_> = urls
        .iter()
        .map(|url| {
            let url = url.clone();
            let client = client.clone();
            let semaphore = std::sync::Arc::clone(&semaphore);

            tokio::spawn(async move {
                let _permit = semaphore.acquire().await.ok()?;

                let mut attempt = 0;
                let mut last_error = String::new();

                while attempt <= max_retries {
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

                    if attempt <= max_retries {
                        let backoff_ms = backoff_base_ms * (1 << (attempt - 1));
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
                    attempts = max_retries + 1,
                    error = %last_error,
                    "failed to fetch URL after all retries"
                );
                None
            })
        })
        .collect();

    // 使用 timeout 包装整个抓取过程，防止长时间阻塞
    let results = match tokio::time::timeout(
        Duration::from_secs(total_timeout_secs),
        futures::future::join_all(fetch_tasks),
    )
    .await
    {
        Ok(results) => results,
        Err(_) => {
            tracing::error!(
                username = %username,
                timeout_secs = total_timeout_secs,
                "URL fetching timed out"
            );
            return Err(AppError::InternalError(
                "Request timeout: URL fetching took too long".to_string(),
            ));
        }
    };

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
        return Err(AppError::InternalError(
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
