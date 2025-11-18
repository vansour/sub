use crate::errors::AppError;
use crate::errors::AppResult;
use crate::utils::{
    MAX_URLS_PER_USER, is_valid_username, sanitize_url, validate_and_sanitize_urls,
};

pub struct UrlService;

impl UrlService {
    /// 验证用户名
    pub fn validate_username(username: &str) -> AppResult<String> {
        let trimmed = username.trim().to_string();

        // 使用增强的验证逻辑
        if let Err(msg) = is_valid_username(&trimmed) {
            tracing::warn!(username = %trimmed, reason = %msg, "Username validation failed");
            return Err(AppError::ValidationError(msg));
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
            tracing::warn!(
                username = %username,
                url_count = urls.len(),
                max_allowed = MAX_URLS_PER_USER,
                "URL count exceeds limit"
            );
            return (Vec::new(), vec![]);
        }

        // 清洗 URL（移除危险字符）
        let sanitized_urls: Vec<String> = urls.iter().map(|u| sanitize_url(u)).collect();

        // 验证并清洗 URL
        let validation_result = validate_and_sanitize_urls(sanitized_urls);

        if !validation_result.rejected.is_empty() {
            tracing::warn!(
                username = %username,
                rejected_count = validation_result.rejected.len(),
                "Some URLs were rejected during validation"
            );
        }

        (validation_result.valid_urls, validation_result.rejected)
    }
}
