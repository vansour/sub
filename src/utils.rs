use crate::errors::{AppError, AppResult};
use crate::models::{RejectedUrl, UrlValidationResult};

// 输入限制常量
pub const MAX_USERNAME_LENGTH: usize = 100;
pub const MIN_USERNAME_LENGTH: usize = 2;
pub const MAX_URL_LENGTH: usize = 2048;
pub const MAX_URLS_PER_USER: usize = 50;
pub const MIN_URL_LENGTH: usize = 10;

/// 保留的用户名（不允许使用）
const RESERVED_USERNAMES: &[&str] = &[
    "admin",
    "root",
    "api",
    "static",
    "assets",
    "public",
    "health",
    "healthz",
    "metrics",
    "login",
    "logout",
    "system",
    "config",
    "settings",
    "favicon.ico",
    "robots.txt",
];

/// 危险的 URL 字符（用于检测潜在的注入攻击）
const DANGEROUS_URL_PATTERNS: &[&str] = &["javascript:", "data:", "vbscript:", "file:", "about:"];

/// 验证用户名是否合法
/// 规则：
/// - 只允许字母、数字、下划线、中划线
/// - 不允许以数字或中划线开头
/// - 不允许使用保留关键字
pub fn is_valid_username(username: &str) -> Result<(), String> {
    // 检查长度
    if username.len() < MIN_USERNAME_LENGTH {
        return Err(format!(
            "Username too short (min {} characters)",
            MIN_USERNAME_LENGTH
        ));
    }

    if username.len() > MAX_USERNAME_LENGTH {
        return Err(format!(
            "Username too long (max {} characters)",
            MAX_USERNAME_LENGTH
        ));
    }

    // 检查字符集：只允许 a-z, A-Z, 0-9, _, -
    if !username
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        return Err(
            "Username can only contain letters, numbers, underscores, and hyphens".to_string(),
        );
    }

    // 不允许以数字或中划线开头
    if let Some(first_char) = username.chars().next() {
        if first_char.is_ascii_digit() || first_char == '-' {
            return Err("Username cannot start with a number or hyphen".to_string());
        }
    }

    // 检查是否为保留关键字
    let username_lower = username.to_lowercase();
    if RESERVED_USERNAMES.contains(&username_lower.as_str()) {
        return Err(format!(
            "Username '{}' is reserved and cannot be used",
            username
        ));
    }

    // 不允许连续的中划线或下划线
    if username.contains("--") || username.contains("__") {
        return Err("Username cannot contain consecutive hyphens or underscores".to_string());
    }

    // 不允许以中划线或下划线结尾
    if username.ends_with('-') || username.ends_with('_') {
        return Err("Username cannot end with a hyphen or underscore".to_string());
    }

    Ok(())
}

/// 验证 URL 是否有效
/// 检查: scheme 必须是 http/https, 长度限制, 不能为空白, 不包含危险字符
pub fn is_valid_url(url: &str) -> bool {
    // 检查长度
    if url.len() < MIN_URL_LENGTH || url.len() > MAX_URL_LENGTH {
        return false;
    }

    // 检查是否为空白
    if url.trim().is_empty() {
        return false;
    }

    // 检查危险模式
    let url_lower = url.to_lowercase();
    for pattern in DANGEROUS_URL_PATTERNS {
        if url_lower.contains(pattern) {
            return false;
        }
    }

    // 验证 URL 格式和 scheme
    if let Ok(parsed) = url::Url::parse(url) {
        let scheme = parsed.scheme();
        if scheme != "http" && scheme != "https" {
            return false;
        }

        // 检查是否有有效的 host
        if parsed.host().is_none() {
            return false;
        }

        // 检查 host 是否为 localhost 或私有 IP（防止 SSRF 攻击）
        if let Some(host) = parsed.host_str() {
            let host_lower = host.to_lowercase();

            // 检查环境变量配置（默认阻止）
            let allow_localhost = std::env::var("ALLOW_LOCALHOST")
                .unwrap_or_else(|_| "false".to_string())
                .to_lowercase()
                == "true";
            let allow_private_ips = std::env::var("ALLOW_PRIVATE_IPS")
                .unwrap_or_else(|_| "false".to_string())
                .to_lowercase()
                == "true";

            // 阻止访问 localhost（除非明确允许）
            if !allow_localhost
                && (host_lower == "localhost"
                    || host_lower == "127.0.0.1"
                    || host_lower == "::1"
                    || host_lower.starts_with("127."))
            {
                return false;
            }

            // 阻止访问私有 IP 段（除非明确允许）
            if !allow_private_ips
                && (host_lower.starts_with("10.")
                    || host_lower.starts_with("192.168.")
                    || host_lower.starts_with("172.16.")
                    || host_lower.starts_with("172.17.")
                    || host_lower.starts_with("172.18.")
                    || host_lower.starts_with("172.19.")
                    || host_lower.starts_with("172.20.")
                    || host_lower.starts_with("172.21.")
                    || host_lower.starts_with("172.22.")
                    || host_lower.starts_with("172.23.")
                    || host_lower.starts_with("172.24.")
                    || host_lower.starts_with("172.25.")
                    || host_lower.starts_with("172.26.")
                    || host_lower.starts_with("172.27.")
                    || host_lower.starts_with("172.28.")
                    || host_lower.starts_with("172.29.")
                    || host_lower.starts_with("172.30.")
                    || host_lower.starts_with("172.31."))
            {
                return false;
            }
        }

        true
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

/// 清洗 URL，移除潜在的危险字符
pub fn sanitize_url(url: &str) -> String {
    url.trim()
        // 移除两端空白
        .trim()
        // 规范化空白字符
        .replace(['\r', '\n', '\t'], "")
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

/// 获取 JWT secret（直接使用配置中已加载的值）
pub fn get_jwt_secret(secret: String) -> String {
    secret
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_usernames() {
        assert!(is_valid_username("user123").is_ok());
        assert!(is_valid_username("test_user").is_ok());
        assert!(is_valid_username("my-username").is_ok());
        assert!(is_valid_username("User_Name-123").is_ok());
    }

    #[test]
    fn test_invalid_usernames() {
        // 太短
        assert!(is_valid_username("a").is_err());

        // 以数字开头
        assert!(is_valid_username("123user").is_err());

        // 以中划线开头
        assert!(is_valid_username("-user").is_err());

        // 包含非法字符
        assert!(is_valid_username("user@name").is_err());
        assert!(is_valid_username("user name").is_err());
        assert!(is_valid_username("user.name").is_err());

        // 保留关键字
        assert!(is_valid_username("admin").is_err());
        assert!(is_valid_username("api").is_err());
        assert!(is_valid_username("static").is_err());

        // 连续符号
        assert!(is_valid_username("user--name").is_err());
        assert!(is_valid_username("user__name").is_err());

        // 以符号结尾
        assert!(is_valid_username("user-").is_err());
        assert!(is_valid_username("user_").is_err());
    }

    #[test]
    fn test_url_validation() {
        // 有效的 URL
        assert!(is_valid_url("https://example.com"));
        assert!(is_valid_url("http://example.com/path"));
        assert!(is_valid_url("https://sub.example.com:8080/path?query=1"));

        // 无效的 URL
        assert!(!is_valid_url("javascript:alert(1)"));
        assert!(!is_valid_url("data:text/html,<script>alert(1)</script>"));
        assert!(!is_valid_url("file:///etc/passwd"));
        assert!(!is_valid_url("ftp://example.com"));
        assert!(!is_valid_url("too short"));
    }

    #[test]
    fn test_ssrf_protection() {
        // 默认情况下应该阻止 localhost
        std::env::remove_var("ALLOW_LOCALHOST");
        assert!(!is_valid_url("http://localhost:8080"));
        assert!(!is_valid_url("http://127.0.0.1"));
        assert!(!is_valid_url("http://127.0.0.1:8080"));

        // 默认情况下应该阻止私有 IP
        std::env::remove_var("ALLOW_PRIVATE_IPS");
        assert!(!is_valid_url("http://192.168.1.1"));
        assert!(!is_valid_url("http://10.0.0.1"));
        assert!(!is_valid_url("http://172.16.0.1"));
    }

    #[test]
    fn test_url_sanitization() {
        assert_eq!(
            sanitize_url("  https://example.com  "),
            "https://example.com"
        );
        assert_eq!(sanitize_url("https://example.com\n"), "https://example.com");
        assert_eq!(
            sanitize_url("https://example.com\r\n"),
            "https://example.com"
        );
        assert_eq!(sanitize_url("https://example.com\t"), "https://example.com");
    }
}
