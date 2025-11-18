use serde::Deserialize;

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

/// 生成随机 JWT Secret (32 字节的 hex 编码)
fn generate_jwt_secret() -> String {
    use rand::RngCore;
    use std::fmt::Write;

    let mut random_bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut random_bytes);

    let mut hex_string = String::with_capacity(64);
    for byte in &random_bytes {
        let _ = write!(hex_string, "{:02x}", byte);
    }
    hex_string
}

/// 内置的管理员凭证（生产环境建议使用环境变量覆盖）
const ADMIN_USERNAME: &str = "admin";
const ADMIN_PASSWORD: &str = "admin"; // 启动时会被 hash 化

#[derive(Debug, Deserialize, Clone)]
pub struct AppConfig {
    pub server: ServerConfig,
    pub auth: AuthConfig,
    #[serde(default)]
    pub rate_limit: RateLimitConfig,
    #[serde(default)]
    pub security: SecurityConfig,
}

impl AppConfig {
    /// 从配置文件和数据库加载配置
    pub async fn load(db: &crate::db::Database) -> anyhow::Result<Self> {
        // 从 config.toml 加载基本配置，如果不存在或格式不对则使用内置默认值
        let mut cfg = match std::fs::read_to_string("config/config.toml") {
            Ok(content) => match toml::from_str::<AppConfig>(&content) {
                Ok(c) => c,
                Err(_) => Self::with_defaults()?,
            },
            Err(_) => Self::with_defaults()?,
        };

        // 检测并迁移明文密码到哈希密码
        if !cfg.auth.password_hash.starts_with("$2") {
            // bcrypt 哈希以 $2a$, $2b$, $2y$ 开头
            eprintln!(
                "Warning: Detected plain-text password in config. Migrating to bcrypt hash..."
            );
            // 哈希明文密码
            match bcrypt::hash(&cfg.auth.password_hash, bcrypt::DEFAULT_COST) {
                Ok(hash) => {
                    cfg.auth.password_hash = hash;
                    // 保存哈希后的配置
                    if let Err(e) = cfg.save_auth_config() {
                        eprintln!("Warning: Failed to save hashed password to config: {}", e);
                    } else {
                        eprintln!("Successfully migrated password to bcrypt hash.");
                    }
                }
                Err(e) => {
                    eprintln!("Error: Failed to hash password: {}", e);
                    return Err(anyhow::anyhow!("Failed to hash password: {}", e));
                }
            }
        }

        // 从数据库获取 JWT Secret
        cfg.auth.secret = Self::get_jwt_secret_from_db(db).await?;

        Ok(cfg)
    }

    /// 从数据库获取或生成 JWT Secret
    async fn get_jwt_secret_from_db(db: &crate::db::Database) -> anyhow::Result<String> {
        // 1. 环境变量优先（支持用户自定义）
        if let Ok(secret) = std::env::var("JWT_SECRET") {
            if !secret.is_empty() && secret != "change-me-to-a-strong-random-secret-in-production" {
                tracing::info!("Using JWT_SECRET from environment variable");
                // 保存到数据库以便下次使用
                let _ = db.set_config("jwt_secret", &secret).await;
                return Ok(secret);
            }
        }

        // 2. 尝试从数据库读取
        if let Some(secret) = db.get_config("jwt_secret").await? {
            if !secret.is_empty() {
                tracing::info!("Using JWT_SECRET from database");
                return Ok(secret);
            }
        }

        // 3. 尝试从旧的 config.toml 迁移
        if let Ok(content) = std::fs::read_to_string("config/config.toml") {
            if let Ok(config) = toml::from_str::<toml::Value>(&content) {
                if let Some(secret) = config
                    .get("auth")
                    .and_then(|v| v.get("secret"))
                    .and_then(|v| v.as_str())
                {
                    if !secret.is_empty() {
                        tracing::info!("Migrating JWT_SECRET from config.toml to database");
                        db.set_config("jwt_secret", secret).await?;
                        return Ok(secret.to_string());
                    }
                }
            }
        }

        // 4. 生成新的 secret 并保存到数据库
        let new_secret = generate_jwt_secret();
        tracing::info!("Generated new random JWT_SECRET and saving to database");
        db.set_config("jwt_secret", &new_secret).await?;

        Ok(new_secret)
    }

    /// 使用内置默认凭证创建配置
    fn with_defaults() -> anyhow::Result<Self> {
        let password_hash = bcrypt::hash(ADMIN_PASSWORD, bcrypt::DEFAULT_COST)
            .map_err(|e| anyhow::anyhow!("Failed to hash password: {}", e))?;

        Ok(AppConfig {
            server: ServerConfig {
                host: "0.0.0.0".to_string(),
                port: 8080,
            },
            auth: AuthConfig {
                username: ADMIN_USERNAME.to_string(),
                password_hash,
                secret: String::new(), // 将在 load() 中填充
            },
            rate_limit: RateLimitConfig::default(),
            security: SecurityConfig::default(),
        })
    }

    /// 保存认证配置（用于密码迁移）
    fn save_auth_config(&self) -> anyhow::Result<()> {
        use std::io::Write;

        let content = std::fs::read_to_string("config/config.toml")?;
        let mut config: toml::Value = toml::from_str(&content)?;

        if let Some(auth_section) = config.get_mut("auth").and_then(|v| v.as_table_mut()) {
            auth_section.insert(
                "username".to_string(),
                toml::Value::String(self.auth.username.clone()),
            );
            auth_section.insert(
                "password_hash".to_string(),
                toml::Value::String(self.auth.password_hash.clone()),
            );
            // 移除旧的明文密码字段
            auth_section.remove("password");
        }

        let toml_string = toml::to_string_pretty(&config)?;
        let mut file = std::fs::File::create("config/config.toml")?;
        file.write_all(toml_string.as_bytes())?;
        file.sync_all()?;

        Ok(())
    }
}
