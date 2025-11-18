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
    if let Some(first_char) = username.chars().next()
        && (first_char.is_ascii_digit() || first_char == '-')
    {
        return Err("Username cannot start with a number or hyphen".to_string());
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

/// 验证 URL 是否有效（带安全配置）
pub fn is_valid_url_with_security(
    url: &str,
    allow_localhost: bool,
    allow_private_ips: bool,
) -> bool {
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
        // 使用 host() 而不是 host_str() 来正确处理 IPv6 地址
        let host_lower = if let Some(host) = parsed.host() {
            match host {
                url::Host::Domain(domain) => domain.to_lowercase(),
                url::Host::Ipv4(ip) => ip.to_string(),
                url::Host::Ipv6(ip) => ip.to_string(),
            }
        } else {
            return false;
        };

        // 阻止访问 localhost（除非明确允许）
        if !allow_localhost
            && (host_lower == "localhost"
                || host_lower == "127.0.0.1"
                || host_lower == "::1"
                || host_lower.starts_with("127."))
        {
            return false;
        }

        // 阻止访问私有 IP 段和保留地址（除非明确允许）
        if !allow_private_ips {
            // RFC 1918 私有网络
            if host_lower.starts_with("10.")
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
                || host_lower.starts_with("172.31.")
            {
                return false;
            }

            // Link-Local 地址 (169.254.0.0/16)
            if host_lower.starts_with("169.254.") {
                return false;
            }

            // 保留地址和特殊用途地址
            if host_lower.starts_with("0.")  // 0.0.0.0/8
                    || host_lower == "0.0.0.0"
                    || host_lower.starts_with("224.")  // 224.0.0.0/4 组播
                    || host_lower.starts_with("225.")
                    || host_lower.starts_with("226.")
                    || host_lower.starts_with("227.")
                    || host_lower.starts_with("228.")
                    || host_lower.starts_with("229.")
                    || host_lower.starts_with("230.")
                    || host_lower.starts_with("231.")
                    || host_lower.starts_with("232.")
                    || host_lower.starts_with("233.")
                    || host_lower.starts_with("234.")
                    || host_lower.starts_with("235.")
                    || host_lower.starts_with("236.")
                    || host_lower.starts_with("237.")
                    || host_lower.starts_with("238.")
                    || host_lower.starts_with("239.")
                    || host_lower.starts_with("240.")  // 240.0.0.0/4 保留
                    || host_lower.starts_with("255.")
            // 广播
            {
                return false;
            }

            // IPv6 私有和特殊地址
            if host_lower.starts_with("fc")  // fc00::/7 唯一本地地址
                    || host_lower.starts_with("fd")
                    || host_lower.starts_with("fe80:")  // fe80::/10 链路本地
                    || host_lower.starts_with("ff")  // ff00::/8 组播
                    || host_lower == "::"
            // 未指定地址
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
pub fn validate_and_sanitize_urls(
    urls: Vec<String>,
    allow_localhost: bool,
    allow_private_ips: bool,
) -> UrlValidationResult {
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
        if !is_valid_url_with_security(&trimmed, allow_localhost, allow_private_ips) {
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
        assert!(is_valid_url_with_security(
            "https://example.com",
            false,
            false
        ));
        assert!(is_valid_url_with_security(
            "http://example.com/path",
            false,
            false
        ));
        assert!(is_valid_url_with_security(
            "https://sub.example.com:8080/path?query=1",
            false,
            false
        ));

        // 无效的 URL
        assert!(!is_valid_url_with_security(
            "javascript:alert(1)",
            false,
            false
        ));
        assert!(!is_valid_url_with_security(
            "data:text/html,<script>alert(1)</script>",
            false,
            false
        ));
        assert!(!is_valid_url_with_security(
            "file:///etc/passwd",
            false,
            false
        ));
        assert!(!is_valid_url_with_security(
            "ftp://example.com",
            false,
            false
        ));
        assert!(!is_valid_url_with_security("too short", false, false));
    }

    #[test]
    fn test_ssrf_protection() {
        // 默认情况下应该阻止 localhost
        assert!(!is_valid_url_with_security(
            "http://localhost:8080",
            false,
            false
        ));
        assert!(!is_valid_url_with_security(
            "http://127.0.0.1",
            false,
            false
        ));
        assert!(!is_valid_url_with_security(
            "http://127.0.0.1:8080",
            false,
            false
        ));

        // 允许 localhost 时应该通过
        assert!(is_valid_url_with_security(
            "http://localhost:8080",
            true,
            false
        ));

        // 默认情况下应该阻止私有 IP
        assert!(!is_valid_url_with_security(
            "http://192.168.1.1",
            false,
            false
        ));
        assert!(!is_valid_url_with_security("http://10.0.0.1", false, false));
        assert!(!is_valid_url_with_security(
            "http://172.16.0.1",
            false,
            false
        ));

        // 允许私有 IP 时应该通过
        assert!(is_valid_url_with_security(
            "http://192.168.1.1",
            false,
            true
        ));

        // 测试 Link-Local 地址阻止
        assert!(!is_valid_url_with_security(
            "http://169.254.1.1",
            false,
            false
        ));
        assert!(!is_valid_url_with_security(
            "http://169.254.169.254",
            false,
            false
        )); // AWS metadata

        // 测试保留地址阻止
        assert!(!is_valid_url_with_security("http://0.0.0.0", false, false));
        assert!(!is_valid_url_with_security("http://0.1.2.3", false, false));

        // 测试组播地址阻止
        assert!(!is_valid_url_with_security(
            "http://224.0.0.1",
            false,
            false
        ));
        assert!(!is_valid_url_with_security(
            "http://239.255.255.255",
            false,
            false
        ));

        // 测试广播和保留地址
        assert!(!is_valid_url_with_security(
            "http://255.255.255.255",
            false,
            false
        ));
        assert!(!is_valid_url_with_security(
            "http://240.0.0.1",
            false,
            false
        ));

        // 测试 IPv6 私有地址阻止
        assert!(!is_valid_url_with_security(
            "http://[fc00::1]",
            false,
            false
        )); // ULA
        assert!(!is_valid_url_with_security(
            "http://[fd00::1]",
            false,
            false
        )); // ULA
        assert!(!is_valid_url_with_security(
            "http://[fe80::1]",
            false,
            false
        )); // Link-Local
        assert!(!is_valid_url_with_security(
            "http://[ff00::1]",
            false,
            false
        )); // Multicast
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
