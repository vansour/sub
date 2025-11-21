use serde::Deserialize;

/// 运行环境，用于区分开发/测试/生产
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AppEnv {
    Development,
    Test,
    Production,
}

impl AppEnv {
    fn current() -> Self {
        let env = std::env::var("APP_ENV")
            .or_else(|_| std::env::var("RUST_ENV"))
            .unwrap_or_else(|_| "development".to_string())
            .to_lowercase();

        match env.as_str() {
            "prod" | "production" => AppEnv::Production,
            "test" | "testing" => AppEnv::Test,
            _ => AppEnv::Development,
        }
    }

    fn is_production(&self) -> bool {
        matches!(self, AppEnv::Production)
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
}

/// 安全配置
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct SecurityConfig {
    /// 是否允许访问私有 IP（防止 SSRF 攻击）
    #[serde(default)]
    pub allow_private_ips: bool,
    /// 是否允许访问 localhost
    #[serde(default)]
    pub allow_localhost: bool,
}

/// HTTP 客户端配置
#[derive(Debug, Clone, Deserialize)]
pub struct HttpClientConfig {
    /// 每个 URL 最大重试次数
    #[serde(default = "default_max_retries")]
    pub max_retries: usize,
    /// 最大并发请求数
    #[serde(default = "default_max_concurrent")]
    pub max_concurrent: usize,
    /// 总超时时间（秒）
    #[serde(default = "default_total_timeout_secs")]
    pub total_timeout_secs: u64,
    /// 重试退避初始延迟（毫秒）
    #[serde(default = "default_backoff_base_ms")]
    pub backoff_base_ms: u64,
    /// 单个请求超时（秒）
    #[serde(default = "default_request_timeout_secs")]
    pub request_timeout_secs: u64,
    /// 连接超时（秒）
    #[serde(default = "default_connect_timeout_secs")]
    pub connect_timeout_secs: u64,
    /// 连接池空闲超时（秒）
    #[serde(default = "default_pool_idle_timeout_secs")]
    pub pool_idle_timeout_secs: u64,
    /// 每个主机最大空闲连接数
    #[serde(default = "default_pool_max_idle_per_host")]
    pub pool_max_idle_per_host: usize,
}

fn default_max_retries() -> usize {
    2
}
fn default_max_concurrent() -> usize {
    10
}
fn default_total_timeout_secs() -> u64 {
    30
}
fn default_backoff_base_ms() -> u64 {
    200
}
fn default_request_timeout_secs() -> u64 {
    30
}
fn default_connect_timeout_secs() -> u64 {
    10
}
fn default_pool_idle_timeout_secs() -> u64 {
    90
}
fn default_pool_max_idle_per_host() -> usize {
    10
}

impl Default for HttpClientConfig {
    fn default() -> Self {
        Self {
            max_retries: default_max_retries(),
            max_concurrent: default_max_concurrent(),
            total_timeout_secs: default_total_timeout_secs(),
            backoff_base_ms: default_backoff_base_ms(),
            request_timeout_secs: default_request_timeout_secs(),
            connect_timeout_secs: default_connect_timeout_secs(),
            pool_idle_timeout_secs: default_pool_idle_timeout_secs(),
            pool_max_idle_per_host: default_pool_max_idle_per_host(),
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct AuthConfig {
    pub username: String,
    /// 密码哈希值（bcrypt）
    #[serde(alias = "password")] // 向后兼容旧的明文密码字段
    pub password_hash: String,
    /// JWT secret (优先从环境变量读取，其次从配置文件，最后自动生成)
    #[serde(default)]
    pub secret: String,
}

/// Rate Limiting 配置
#[derive(Debug, Deserialize, Clone)]
pub struct RateLimitConfig {
    /// 登录尝试限制：每个 IP 每分钟最多尝试次数
    #[serde(default = "default_login_attempts")]
    pub login_attempts_per_minute: u32,
    /// 登录失败后的锁定时长（秒）
    #[serde(default = "default_lockout_duration")]
    pub login_lockout_duration_secs: u64,
    /// API 请求限制：每个 IP 每秒最多请求次数
    #[serde(default = "default_api_requests_per_second")]
    pub api_requests_per_second: u32,
    /// 全局 API 请求限制：每秒最多请求次数
    #[serde(default = "default_global_requests_per_second")]
    pub global_requests_per_second: u32,
}

fn default_login_attempts() -> u32 {
    5
}
fn default_lockout_duration() -> u64 {
    300
}
fn default_api_requests_per_second() -> u32 {
    10
}
fn default_global_requests_per_second() -> u32 {
    100
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            login_attempts_per_minute: default_login_attempts(),
            login_lockout_duration_secs: default_lockout_duration(),
            api_requests_per_second: default_api_requests_per_second(),
            global_requests_per_second: default_global_requests_per_second(),
        }
    }
}

/// 生成随机 JWT Secret (32 字节的 hex 编码，64 个字符)
fn generate_jwt_secret() -> String {
    use rand::{RngCore, rng};
    use std::fmt::Write;

    let mut random_bytes = [0u8; 32];
    let mut rng = rng();
    rng.fill_bytes(&mut random_bytes);

    let mut hex_string = String::with_capacity(64);
    for byte in &random_bytes {
        let _ = write!(hex_string, "{:02x}", byte);
    }
    hex_string
}

/// 验证 JWT Secret 强度（至少 32 字节熵，并且字符有一定复杂度）
fn validate_jwt_secret(secret: &str) -> Result<(), String> {
    // Secret 应该至少 32 字节（64 个十六进制字符或 32+ 个普通字符）
    if secret.len() < 32 {
        return Err(format!(
            "JWT secret too short ({} chars). Minimum 32 characters required for security.",
            secret.len()
        ));
    }

    // 要求包含多种字符类型，以提升熵
    let has_lower = secret.chars().any(|c| c.is_ascii_lowercase());
    let has_upper = secret.chars().any(|c| c.is_ascii_uppercase());
    let has_digit = secret.chars().any(|c| c.is_ascii_digit());
    let has_other = secret.chars().any(|c| !c.is_ascii_alphanumeric());

    let classes = has_lower as u8 + has_upper as u8 + has_digit as u8 + has_other as u8;
    if classes < 2 {
        return Err(
            "JWT secret too weak: please use a mix of letters, digits or symbols.".to_string(),
        );
    }

    // 检查是否为默认/示例值（完整匹配或明显的弱密码模式）
    let weak_secrets = [
        "secret",
        "change-me",
        "change-me-to-a-strong-random-secret-in-production",
        "jwt_secret",
        "your-secret-key",
        "your_secret_key",
        "please-change-this",
    ];

    let secret_lower = secret.to_lowercase();
    // 完全匹配弱密码
    if weak_secrets.contains(&secret_lower.as_str()) {
        return Err(
            "JWT secret appears to be a default/example value. Please use a strong random secret."
                .to_string(),
        );
    }

    // 检查是否只包含简单的重复模式或明显弱密码
    if secret_lower == "jwt_secret_key"
        || secret_lower.starts_with("secret")
            && secret_lower.len() < 40
            && !secret_lower.chars().any(|c| c.is_ascii_digit())
    {
        return Err(
            "JWT secret appears to be too simple. Please use a strong random secret.".to_string(),
        );
    }

    Ok(())
}

/// 内置的管理员凭证（开发/测试使用，生产环境必须通过环境变量提供）
const ADMIN_USERNAME: &str = "admin";
const ADMIN_PASSWORD: &str = "admin"; // 仅在非生产环境下作为默认值

#[derive(Debug, Deserialize, Clone)]
pub struct AppConfig {
    pub server: ServerConfig,
    pub auth: AuthConfig,
    #[serde(default)]
    pub rate_limit: RateLimitConfig,
    #[serde(default)]
    pub security: SecurityConfig,
    #[serde(default)]
    pub http_client: HttpClientConfig,
}

impl AppConfig {
    /// 从配置文件和数据库加载配置
    pub async fn load(db: &crate::db::Database) -> anyhow::Result<Self> {
        let env = AppEnv::current();

        // 从 config.toml 加载基本配置，如果不存在或格式不对则使用内置默认值
        let mut cfg = match std::fs::read_to_string("config/config.toml") {
            Ok(content) => match toml::from_str::<AppConfig>(&content) {
                Ok(c) => c,
                    Err(e) => {
                        // Parsing failed — keep this quiet under normal runs (debug level)
                        tracing::debug!(error = %e, "Failed to parse config/config.toml, falling back to defaults");
                    Self::with_defaults(env)?
                }
            },
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "Failed to read config/config.toml, falling back to defaults",
                );
                Self::with_defaults(env)?
            }
        };

        // 从数据库加载认证配置（优先级高于 config.toml）
        if let Some(auth_config) = Self::load_auth_from_db(db).await? {
            tracing::info!("Using authentication config from database");
            cfg.auth = auth_config;
        } else {
            // 数据库中没有，检查 config.toml 中的配置
            if !cfg.auth.password_hash.starts_with("$2") {
                // bcrypt 哈希以 $2a$, $2b$, $2y$ 开头
                tracing::warn!(
                    "Detected plain-text password in config.toml, migrating to database"
                );
                // 哈希明文密码
                let hash = bcrypt::hash(&cfg.auth.password_hash, bcrypt::DEFAULT_COST)
                    .map_err(|e| anyhow::anyhow!("Failed to hash password: {}", e))?;
                cfg.auth.password_hash = hash;
            }
            // 保存到数据库
            Self::save_auth_to_db(db, &cfg.auth).await?;
            tracing::info!("Migrated authentication config to database");
        }

        // 从数据库获取 JWT Secret
        cfg.auth.secret = Self::get_jwt_secret_from_db(db).await?;

        Ok(cfg)
    }

    /// 从数据库加载认证配置
    async fn load_auth_from_db(db: &crate::db::Database) -> anyhow::Result<Option<AuthConfig>> {
        let username = db.get_config("auth_username").await?;
        let password_hash = db.get_config("auth_password_hash").await?;

        if let (Some(username), Some(password_hash)) = (username, password_hash) {
            Ok(Some(AuthConfig {
                username,
                password_hash,
                secret: String::new(), // 将在 load() 中填充
            }))
        } else {
            Ok(None)
        }
    }

    /// 保存认证配置到数据库
    async fn save_auth_to_db(db: &crate::db::Database, auth: &AuthConfig) -> anyhow::Result<()> {
        db.set_config("auth_username", &auth.username).await?;
        db.set_config("auth_password_hash", &auth.password_hash)
            .await?;
        tracing::debug!(
            username = %auth.username,
            "Saved authentication config to database"
        );
        Ok(())
    }

    /// 从数据库获取或生成 JWT Secret
    async fn get_jwt_secret_from_db(db: &crate::db::Database) -> anyhow::Result<String> {
        // 1. 尝试从环境变量读取
        if let Some(secret) = Self::try_env_secret()? {
            let _ = db.set_config("jwt_secret", &secret).await;
            return Ok(secret);
        }

        // 2. 尝试从数据库读取
        if let Some(secret) = Self::try_db_secret(db).await? {
            return Ok(secret);
        }

        // 3. 尝试从配置文件迁移
        if let Some(secret) = Self::try_migrate_from_config(db).await? {
            return Ok(secret);
        }

        // 4. 生成新的 secret 并保存到数据库
        Self::generate_and_save_secret(db).await
    }

    /// 尝试从环境变量获取 JWT secret
    fn try_env_secret() -> anyhow::Result<Option<String>> {
        if let Ok(secret) = std::env::var("JWT_SECRET")
            && !secret.is_empty()
            && secret != "change-me-to-a-strong-random-secret-in-production"
        {
            validate_jwt_secret(&secret)
                .map_err(|e| anyhow::anyhow!("Invalid JWT_SECRET from environment: {}", e))?;
            tracing::info!("Using JWT_SECRET from environment variable");
            return Ok(Some(secret));
        }
        Ok(None)
    }

    /// 尝试从数据库获取 JWT secret
    async fn try_db_secret(db: &crate::db::Database) -> anyhow::Result<Option<String>> {
        if let Some(secret) = db.get_config("jwt_secret").await?
            && !secret.is_empty()
        {
            if validate_jwt_secret(&secret).is_ok() {
                tracing::info!("Using JWT_SECRET from database");
                return Ok(Some(secret));
            } else {
                tracing::warn!("Existing JWT_SECRET in database is weak, will regenerate");
            }
        }
        Ok(None)
    }

    /// 尝试从配置文件迁移 JWT secret
    async fn try_migrate_from_config(db: &crate::db::Database) -> anyhow::Result<Option<String>> {
        if let Ok(content) = std::fs::read_to_string("config/config.toml")
            && let Ok(config) = toml::from_str::<toml::Value>(&content)
            && let Some(secret) = config
                .get("auth")
                .and_then(|v| v.get("secret"))
                .and_then(|v| v.as_str())
            && !secret.is_empty()
            && validate_jwt_secret(secret).is_ok()
        {
            tracing::info!("Migrating JWT_SECRET from config.toml to database");
            db.set_config("jwt_secret", secret).await?;
            return Ok(Some(secret.to_string()));
        }
        Ok(None)
    }

    /// 生成新的 JWT secret 并保存到数据库
    async fn generate_and_save_secret(db: &crate::db::Database) -> anyhow::Result<String> {
        let new_secret = generate_jwt_secret();
        tracing::info!("Generated new random JWT_SECRET and saving to database");
        db.set_config("jwt_secret", &new_secret).await?;
        Ok(new_secret)
    }

    /// 使用内置默认凭证创建配置
    fn with_defaults(env: AppEnv) -> anyhow::Result<Self> {
        // 生产环境强制从环境变量读取初始管理员账号和密码
        let (username, password) = if env.is_production() {
            let username = std::env::var("ADMIN_USERNAME").map_err(|_| {
                anyhow::anyhow!(
                    "ADMIN_USERNAME must be set in production to avoid insecure default admin account",
                )
            })?;

            let password = std::env::var("ADMIN_PASSWORD").map_err(|_| {
                anyhow::anyhow!(
                    "ADMIN_PASSWORD must be set in production to avoid insecure default admin account",
                )
            })?;

            tracing::info!(
                username = %username,
                "Using admin credentials from environment in production",
            );
            (username, password)
        } else {
                // Avoid noisy warnings about defaults in non-production by using debug level
                tracing::debug!("Using built-in default admin credentials (admin/admin) in non-production environment");
            (ADMIN_USERNAME.to_string(), ADMIN_PASSWORD.to_string())
        };

        let password_hash = bcrypt::hash(&password, bcrypt::DEFAULT_COST)
            .map_err(|e| anyhow::anyhow!("Failed to hash password: {}", e))?;

        Ok(AppConfig {
            server: ServerConfig {
                host: std::env::var("SERVER_HOST").unwrap_or_else(|_| "0.0.0.0".to_string()),
                port: std::env::var("SERVER_PORT")
                    .ok()
                    .and_then(|v| v.parse::<u16>().ok())
                    .unwrap_or(8080),
            },
            auth: AuthConfig {
                username,
                password_hash,
                secret: String::new(), // 将在 load() 中填充
            },
            rate_limit: RateLimitConfig::default(),
            security: SecurityConfig::default(),
            http_client: HttpClientConfig::default(),
        })
    }

    /// 更新认证配置（用于密码修改）
    pub async fn update_auth(db: &crate::db::Database, auth: &AuthConfig) -> anyhow::Result<()> {
        Self::save_auth_to_db(db, auth).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_jwt_secret_validation() {
        // 测试太短的 secret
        assert!(validate_jwt_secret("short").is_err());
        assert!(validate_jwt_secret("12345678901234567890123").is_err()); // 23 chars

        // 测试弱 secret（默认值）
        assert!(validate_jwt_secret("secret").is_err());
        assert!(validate_jwt_secret("change-me").is_err());
        assert!(validate_jwt_secret("change-me-to-a-strong-random-secret-in-production").is_err());
        assert!(validate_jwt_secret("jwt_secret").is_err());

        // 测试有效的 secret（至少 32 字符）
        assert!(validate_jwt_secret("a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6").is_ok());
        assert!(
            validate_jwt_secret("this-is-a-very-long-and-strong-random-secret-key-for-jwt").is_ok()
        );

        // 测试生成的 secret 格式（64 个十六进制字符）
        let generated = generate_jwt_secret();
        assert_eq!(generated.len(), 64);
        assert!(generated.chars().all(|c| c.is_ascii_hexdigit()));
        assert!(validate_jwt_secret(&generated).is_ok());
    }

    #[test]
    fn test_generate_jwt_secret_randomness() {
        // 生成多个 secret，确保它们都不相同（随机性测试）
        let secret1 = generate_jwt_secret();
        let secret2 = generate_jwt_secret();
        let secret3 = generate_jwt_secret();

        assert_ne!(secret1, secret2);
        assert_ne!(secret2, secret3);
        assert_ne!(secret1, secret3);
    }
}
