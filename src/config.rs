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
    pub password: String,
    pub secret: String,
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
        let cfg: AppConfig = toml::from_str(&content)?;
        Ok(cfg)
    }
}
