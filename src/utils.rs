use crate::errors::{AppError, AppResult};
use crate::models::{RejectedUrl, UrlValidationResult};

// 输入限制常量
pub const MAX_USERNAME_LENGTH: usize = 100;
pub const MAX_URL_LENGTH: usize = 2048;
pub const MAX_URLS_PER_USER: usize = 50;
pub const MIN_URL_LENGTH: usize = 10;

/// 验证 URL 是否有效
/// 检查: scheme 必须是 http/https, 长度限制, 不能为空白
pub fn is_valid_url(url: &str) -> bool {
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

/// 验证并清洗 URL 列表
/// 返回去重后的有效 URL 和被拒绝的 URL 列表
pub fn validate_and_sanitize_urls(urls: Vec<String>) -> UrlValidationResult {
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

/// 哈希密码
pub fn hash_password(password: &str) -> AppResult<String> {
    bcrypt::hash(password, bcrypt::DEFAULT_COST)
        .map_err(|e| AppError::InternalError(format!("Failed to hash password: {}", e)))
}

/// 验证密码
pub fn verify_password(password: &str, hash: &str) -> bool {
    bcrypt::verify(password, hash).unwrap_or(false)
}

/// 获取JWT secret，优先从环境变量读取
pub fn get_jwt_secret(default_secret: String) -> String {
    std::env::var("JWT_SECRET").unwrap_or_else(|_| {
        tracing::warn!(
            "JWT_SECRET environment variable not set, using secret from config file. \
             This is not recommended for production!"
        );
        default_secret
    })
}
