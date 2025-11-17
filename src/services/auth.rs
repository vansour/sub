use crate::config;
use crate::errors::{AppError, AppResult};
use crate::utils::{hash_password, verify_password};
use std::io::Write;

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
            let _ = verify_password(password, "$2b$12$dummy.hash.to.prevent.timing.attack.here");
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
            return Err(AppError::AuthenticationError(
                "Invalid username or password".to_string(),
            ));
        }

        tracing::info!("login successful for username: {}", username);
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
        // 读取现有配置
        let content = std::fs::read_to_string("config/config.toml")?;
        let mut config: toml::Value = toml::from_str(&content)?;

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
        }

        // 写回文件
        let toml_string = toml::to_string_pretty(&config)?;
        let mut file = std::fs::File::create("config/config.toml")?;
        file.write_all(toml_string.as_bytes())?;
        file.sync_all()?;

        tracing::info!("auth config saved successfully");
        Ok(())
    }
}
