use crate::errors::AppError;
use crate::errors::AppResult;
use crate::utils::{validate_and_sanitize_urls, MAX_URLS_PER_USER, MAX_USERNAME_LENGTH};

pub struct UrlService;

impl UrlService {
    /// 验证用户名
    pub fn validate_username(username: &str) -> AppResult<String> {
        let trimmed = username.trim().to_string();

        if trimmed.is_empty() {
            return Err(AppError::ValidationError(
                "Username cannot be empty".to_string(),
            ));
        }

        if trimmed.len() > MAX_USERNAME_LENGTH {
            return Err(AppError::ValidationError(format!(
                "Username too long (max {} chars)",
                MAX_USERNAME_LENGTH
            )));
        }

        Ok(trimmed)
    }

    /// 获取完整的验证结果（包括被拒绝的 URL）
    pub fn validate_urls_with_rejection(
        urls: Vec<String>,
        username: &str,
    ) -> (Vec<String>, Vec<crate::models::RejectedUrl>) {
        // 检查 URL 数量限制
        if urls.len() > MAX_URLS_PER_USER {
            return (Vec::new(), vec![]);
        }

        // 验证并清洗 URL
        let validation_result = validate_and_sanitize_urls(urls);

        if !validation_result.rejected.is_empty() {
            tracing::warn!(
                "rejected {} invalid/duplicate URLs for user: {}",
                validation_result.rejected.len(),
                username
            );
        }

        (validation_result.valid_urls, validation_result.rejected)
    }
}
