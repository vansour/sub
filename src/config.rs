use config::{Config, ConfigError, File};
use serde::Deserialize;

#[derive(Debug, Deserialize, Clone)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
}

#[derive(Debug, Deserialize, Clone)]
pub struct LogConfig {
    // 对应 config.toml 中的 logFilePath
    #[serde(rename = "logFilePath")]
    pub log_file_path: String,
    pub level: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct AppConfig {
    pub server: ServerConfig,
    pub log: LogConfig,
}

impl AppConfig {
    pub fn load() -> Result<Self, ConfigError> {
        // 构建配置，读取 config/config.toml
        let s = Config::builder()
            .add_source(File::with_name("config/config.toml"))
            .build()?;

        s.try_deserialize()
    }
}
