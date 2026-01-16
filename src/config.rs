// use config::{Config, ConfigError, File};
use serde::Deserialize;
use std::env;

#[derive(Debug, Deserialize, Clone)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    pub secret_key: String,
    pub cookie_secure: bool,
    pub concurrent_requests: usize,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            host: "0.0.0.0".to_string(),
            port: 8080,
            secret_key: "r8q2938h948h203984h203984h23984h23984h203984h2398h42938h429384h2"
                .to_string(),
            cookie_secure: false,
            concurrent_requests: 10,
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct LogConfig {
    pub log_file_path: String,
    pub level: String,
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            log_file_path: "app.log".to_string(),
            level: "info".to_string(),
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct AppConfig {
    pub server: ServerConfig,
    pub log: LogConfig,
}

impl AppConfig {
    pub fn load() -> Result<Self, String> {
        let default_secret = "r8q2938h948h203984h203984h23984h23984h203984h2398h42938h429384h2"; // 64+ chars
        let mut secret_key = env::var("SECRET_KEY").unwrap_or_else(|_| default_secret.to_string());

        if secret_key.len() < 32 {
            // tracing might not be initialized yet, using eprintln
            eprintln!(
                "WARNING: SECRET_KEY is too short ({} chars). Using default key.",
                secret_key.len()
            );
            secret_key = default_secret.to_string();
        }

        let server = ServerConfig {
            host: env::var("HOST").unwrap_or_else(|_| "0.0.0.0".to_string()),
            port: env::var("PORT")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(8080),
            secret_key,
            cookie_secure: env::var("COOKIE_SECURE")
                .map(|v| v == "true")
                .unwrap_or(false),
            concurrent_requests: env::var("CONCURRENT_REQUESTS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(10),
        };

        let log = LogConfig {
            log_file_path: env::var("LOG_FILE").unwrap_or_else(|_| "app.log".to_string()),
            level: env::var("LOG_LEVEL").unwrap_or_else(|_| "info".to_string()),
        };

        Ok(AppConfig { server, log })
    }
}
