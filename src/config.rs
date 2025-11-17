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
    /// JWT secret（建议使用环境变量 JWT_SECRET 覆盖）
    #[serde(default = "default_secret")]
    pub secret: String,
}

fn default_secret() -> String {
    "change-me-insecure-default".to_string()
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
        let content = std::fs::read_to_string("config/config.toml")?;
        let mut cfg: AppConfig = toml::from_str(&content)?;

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

        Ok(cfg)
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
