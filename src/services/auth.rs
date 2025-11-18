use crate::config;
use crate::errors::{AppError, AppResult};
use crate::metrics;
use crate::utils::{hash_password, verify_password};
use std::sync::OnceLock;

// 常量时间 dummy hash，用于防止时序攻击
static DUMMY_PASSWORD_HASH: OnceLock<String> = OnceLock::new();

fn get_dummy_password_hash() -> &'static str {
    DUMMY_PASSWORD_HASH.get_or_init(|| {
        bcrypt::hash(
            "dummy_password_for_timing_attack_prevention",
            bcrypt::DEFAULT_COST,
        )
        .unwrap_or_else(|_| "$2b$12$dummyhashfortimingattackprevention".to_string())
    })
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
            let _ = verify_password(password, get_dummy_password_hash());
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verify_credentials_success() {
        let password = "test_password";
        let hash = crate::utils::hash_password(password).unwrap();

        let result = AuthService::verify_credentials("admin", password, "admin", &hash);
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_credentials_wrong_username() {
        let password = "test_password";
        let hash = crate::utils::hash_password(password).unwrap();

        let result = AuthService::verify_credentials("wrong", password, "admin", &hash);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_credentials_wrong_password() {
        let password = "test_password";
        let hash = crate::utils::hash_password(password).unwrap();

        let result = AuthService::verify_credentials("admin", "wrong", "admin", &hash);
        assert!(result.is_err());
    }

    #[test]
    fn test_update_config() {
        let old_password = "old_pass";
        let old_hash = crate::utils::hash_password(old_password).unwrap();

        let result =
            AuthService::update_config(old_password, "new_admin", "new_pass", "admin", &old_hash);

        assert!(result.is_ok());
        let config = result.unwrap();
        assert_eq!(config.username, "new_admin");
        assert!(crate::utils::verify_password(
            "new_pass",
            &config.password_hash
        ));
    }

    #[test]
    fn test_update_config_wrong_old_password() {
        let old_password = "old_pass";
        let old_hash = crate::utils::hash_password(old_password).unwrap();

        let result = AuthService::update_config(
            "wrong_old_pass",
            "new_admin",
            "new_pass",
            "admin",
            &old_hash,
        );

        assert!(result.is_err());
    }
}
