use crate::config;
use crate::errors::{AppError, AppResult};
use crate::metrics;
use crate::utils::{hash_password, verify_password};
use std::io::Write;

// 常量时间 dummy hash，用于防止时序攻击
lazy_static::lazy_static! {
    static ref DUMMY_PASSWORD_HASH: String = {
        bcrypt::hash("dummy_password_for_timing_attack_prevention", bcrypt::DEFAULT_COST)
            .unwrap_or_else(|_| "$2b$12$dummyhashfortimingattackprevention".to_string())
    };
}

pub struct AuthService;

impl AuthService {
    /// 验证用户名和密码
    pub fn verify_credentials(
        username: &str,
        password: &str,
        config_username: &str,
        config_password_hash: &str,
    ) -> AppResult<()> {
        // 验证用户名
        if username != config_username {
            tracing::warn!("login failed for username: {} (user not found)", username);
            // 为了防止时序攻击，即使用户名不存在也进行哈希验证
            let _ = verify_password(password, &DUMMY_PASSWORD_HASH);
            metrics::record_auth_attempt(false);
            return Err(AppError::AuthenticationError(
                "Invalid username or password".to_string(),
            ));
        }

        // 验证密码
        if !verify_password(password, config_password_hash) {
            tracing::warn!(
                "login failed for username: {} (incorrect password)",
                username
            );
            metrics::record_auth_attempt(false);
            return Err(AppError::AuthenticationError(
                "Invalid username or password".to_string(),
            ));
        }

        tracing::info!("login successful for username: {}", username);
        metrics::record_auth_attempt(true);
        Ok(())
    }

    /// 更新认证配置（用户名和密码）
    pub fn update_config(
        old_password: &str,
        new_username: &str,
        new_password: &str,
        _current_username: &str,
        current_password_hash: &str,
    ) -> AppResult<config::AuthConfig> {
        // 验证旧密码
        if !verify_password(old_password, current_password_hash) {
            tracing::warn!("change_password failed: incorrect old password");
            return Err(AppError::AuthenticationError(
                "Incorrect old password".to_string(),
            ));
        }

        // 哈希新密码
        let new_password_hash = hash_password(new_password)?;

        Ok(config::AuthConfig {
            username: new_username.to_string(),
            password_hash: new_password_hash,
            secret: "".to_string(), // 不更新 secret
        })
    }

    /// 保存认证配置到文件
    pub fn save_config(auth: &config::AuthConfig) -> AppResult<()> {
        tracing::debug!(username = %auth.username, "saving auth config to file");

        // 读取现有配置
        let content = match std::fs::read_to_string("config/config.toml") {
            Ok(c) => {
                tracing::debug!("config.toml read successfully");
                c
            }
            Err(e) => {
                tracing::error!(error = %e, "failed to read config.toml");
                return Err(e.into());
            }
        };

        let mut config: toml::Value = match toml::from_str(&content) {
            Ok(c) => {
                tracing::debug!("config.toml parsed successfully");
                c
            }
            Err(e) => {
                tracing::error!(error = %e, "failed to parse config.toml");
                return Err(e.into());
            }
        };

        // 更新 auth 部分
        if let Some(auth_section) = config.get_mut("auth").and_then(|v| v.as_table_mut()) {
            auth_section.insert(
                "username".to_string(),
                toml::Value::String(auth.username.clone()),
            );
            auth_section.insert(
                "password_hash".to_string(),
                toml::Value::String(auth.password_hash.clone()),
            );
            // 移除旧的明文密码字段（如果存在）
            auth_section.remove("password");
            tracing::debug!(username = %auth.username, "auth config updated in memory");
        }

        // 写回文件
        let toml_string = match toml::to_string_pretty(&config) {
            Ok(s) => {
                tracing::debug!(size_bytes = s.len(), "TOML serialized successfully");
                s
            }
            Err(e) => {
                tracing::error!(error = %e, "failed to serialize TOML");
                return Err(e.into());
            }
        };

        match std::fs::File::create("config/config.toml") {
            Ok(mut file) => {
                if let Err(e) = file.write_all(toml_string.as_bytes()) {
                    tracing::error!(error = %e, "failed to write to config.toml");
                    return Err(e.into());
                }
                if let Err(e) = file.sync_all() {
                    tracing::error!(error = %e, "failed to sync config.toml to disk");
                    return Err(e.into());
                }
                tracing::info!(username = %auth.username, "auth config saved successfully");
                Ok(())
            }
            Err(e) => {
                tracing::error!(error = %e, "failed to create config.toml");
                Err(e.into())
            }
        }
    }
}
