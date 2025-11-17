use serde::Deserialize;

#[derive(Debug, Deserialize, Clone)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
}

#[derive(Debug, Deserialize, Clone)]
pub struct LogConfig {
    #[serde(rename = "logFilePath")]
    pub log_file_path: String,
    pub level: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct DataConfig {
    #[serde(rename = "dataFilePath")]
    pub data_file_path: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct AuthConfig {
    pub username: String,
    /// 密码哈希值（bcrypt）
    #[serde(alias = "password")] // 向后兼容旧的明文密码字段
    pub password_hash: String,
    /// JWT secret
    pub secret: String,
}

/// 内置的管理员凭证（生产环境建议使用环境变量覆盖）
const ADMIN_USERNAME: &str = "admin";
const ADMIN_PASSWORD: &str = "admin"; // 启动时会被 hash 化

/// 生成随机 JWT Secret (32 字节的 hex 编码)
fn generate_jwt_secret() -> String {
    use rand::RngCore;
    use std::fmt::Write;

    // 生成 32 字节的随机数据
    let mut random_bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut random_bytes);

    // 转换为 hex 字符串
    let mut hex_string = String::with_capacity(64);
    for byte in &random_bytes {
        let _ = write!(hex_string, "{:02x}", byte);
    }
    hex_string
}

/// 获取 JWT Secret，优先级：环境变量 > config.toml > 自动生成并保存
fn get_jwt_secret() -> anyhow::Result<String> {
    // 1. 环境变量优先
    if let Ok(secret) = std::env::var("JWT_SECRET") {
        return Ok(secret);
    }

    // 2. 尝试从 config.toml 读取
    if let Ok(content) = std::fs::read_to_string("config/config.toml") {
        if let Ok(config) = toml::from_str::<toml::Value>(&content) {
            if let Some(secret) = config
                .get("auth")
                .and_then(|v| v.get("secret"))
                .and_then(|v| v.as_str())
            {
                if !secret.is_empty() {
                    return Ok(secret.to_string());
                }
            }
        }
    }

    // 3. 生成新的 secret 并保存
    let new_secret = generate_jwt_secret();
    eprintln!("Generated new JWT secret and saved to config.toml");
    save_jwt_secret(&new_secret)?;

    Ok(new_secret)
}

/// 保存 JWT Secret 到 config.toml
fn save_jwt_secret(secret: &str) -> anyhow::Result<()> {
    use std::io::Write;

    let config_path = "config/config.toml";

    // 读取现有配置或创建新配置
    let mut config = if std::path::Path::new(config_path).exists() {
        let content = std::fs::read_to_string(config_path)?;
        toml::from_str::<toml::Value>(&content)
            .unwrap_or_else(|_| toml::Value::Table(Default::default()))
    } else {
        toml::Value::Table(Default::default())
    };

    // 确保 auth section 存在并设置 secret
    config
        .as_table_mut()
        .unwrap()
        .entry("auth".to_string())
        .or_insert_with(|| toml::Value::Table(Default::default()))
        .as_table_mut()
        .unwrap()
        .insert(
            "secret".to_string(),
            toml::Value::String(secret.to_string()),
        );

    // 写入文件
    let toml_string = toml::to_string_pretty(&config)?;
    let mut file = std::fs::File::create(config_path)?;
    file.write_all(toml_string.as_bytes())?;
    file.sync_all()?;

    Ok(())
}

#[derive(Debug, Deserialize, Clone)]
pub struct AppConfig {
    pub server: ServerConfig,
    pub log: LogConfig,
    pub data: DataConfig,
    pub auth: AuthConfig,
}

impl AppConfig {
    pub fn load() -> anyhow::Result<Self> {
        // 首先尝试从 config.toml 加载，如果不存在或格式不对则使用内置默认值
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

        // 获取或生成 JWT Secret
        cfg.auth.secret = get_jwt_secret()?;

        Ok(cfg)
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
            log: LogConfig {
                log_file_path: "/app/logs/v-ui.log".to_string(),
                level: "info".to_string(),
            },
            data: DataConfig {
                data_file_path: "/app/data/data.toml".to_string(),
            },
            auth: AuthConfig {
                username: ADMIN_USERNAME.to_string(),
                password_hash,
                secret: String::new(), // 将在 load() 中填充
            },
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
