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
        allow_localhost: bool,
        allow_private_ips: bool,
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
        let validation_result =
            validate_and_sanitize_urls(sanitized_urls, allow_localhost, allow_private_ips);

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_username() {
        // 有效的用户名
        assert!(UrlService::validate_username("user123").is_ok());
        assert!(UrlService::validate_username("test_user").is_ok());
        assert!(UrlService::validate_username("my-app").is_ok());

        // 无效的用户名
        assert!(UrlService::validate_username("a").is_err()); // 太短
        assert!(UrlService::validate_username("123user").is_err()); // 以数字开头
        assert!(UrlService::validate_username("admin").is_err()); // 保留关键字
        assert!(UrlService::validate_username("user@name").is_err()); // 非法字符
        assert!(UrlService::validate_username("user--name").is_err()); // 连续中划线
    }

    #[test]
    fn test_validate_urls_with_rejection() {
        let urls = vec![
            "https://example.com".to_string(),
            "http://localhost:8080".to_string(), // 应该被拒绝（默认不允许 localhost）
            "https://example.com".to_string(),   // 重复
            "invalid".to_string(),               // 无效 URL
            "https://192.168.1.1".to_string(),   // 私有 IP（默认不允许）
        ];

        let (valid, rejected) =
            UrlService::validate_urls_with_rejection(urls, "testuser", false, false);

        assert_eq!(valid.len(), 1); // 只有第一个有效
        assert_eq!(rejected.len(), 4); // 4 个被拒绝
        assert_eq!(valid[0], "https://example.com");
    }

    #[test]
    fn test_validate_urls_allow_localhost() {
        let urls = vec![
            "http://localhost:8080".to_string(),
            "https://example.com".to_string(),
        ];

        let (valid, rejected) =
            UrlService::validate_urls_with_rejection(urls, "testuser", true, false);

        assert_eq!(valid.len(), 2); // 两个都有效
        assert_eq!(rejected.len(), 0);
    }

    #[test]
    fn test_validate_urls_too_many() {
        let urls: Vec<String> = (0..60)
            .map(|i| format!("https://example{}.com", i))
            .collect();

        let (valid, _rejected) =
            UrlService::validate_urls_with_rejection(urls, "testuser", false, false);

        assert_eq!(valid.len(), 0); // 超过限制，全部拒绝
    }
}
