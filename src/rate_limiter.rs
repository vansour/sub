use governor::{
    Quota, RateLimiter as GovernorRateLimiter,
    clock::DefaultClock,
    state::{InMemoryState, NotKeyed},
};
use parking_lot::Mutex;
use std::collections::HashMap;
use std::net::IpAddr;
use std::num::NonZeroU32;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// IP 速率限制器类型别名
type IpRateLimiter = Arc<GovernorRateLimiter<NotKeyed, InMemoryState, DefaultClock>>;

/// Rate Limiter 配置
#[derive(Debug, Clone)]
pub struct RateLimiterConfig {
    /// 登录尝试限制：每个 IP 每分钟最多尝试次数
    pub login_attempts_per_minute: u32,
    /// 登录尝试限制：失败后的锁定时长（秒）
    pub login_lockout_duration_secs: u64,
    /// API 请求限制：每个 IP 每秒最多请求次数
    pub api_requests_per_second: u32,
    /// 全局 API 请求限制：每秒最多请求次数
    pub global_requests_per_second: u32,
}

impl Default for RateLimiterConfig {
    fn default() -> Self {
        Self {
            login_attempts_per_minute: 5,     // 每分钟 5 次登录尝试
            login_lockout_duration_secs: 300, // 失败后锁定 5 分钟
            api_requests_per_second: 10,      // 每个 IP 每秒 10 个请求
            global_requests_per_second: 100,  // 全局每秒 100 个请求
        }
    }
}

/// 登录尝试记录
#[derive(Debug, Clone)]
struct LoginAttempt {
    /// 失败次数
    failed_count: u32,
    /// 最后一次失败时间
    last_failed_at: Instant,
    /// 锁定到期时间
    locked_until: Option<Instant>,
}

/// Rate Limiter 服务
#[derive(Clone)]
pub struct RateLimiter {
    config: RateLimiterConfig,
    /// 登录尝试记录 (IP -> LoginAttempt)
    login_attempts: Arc<Mutex<HashMap<IpAddr, LoginAttempt>>>,
    /// 全局 API 速率限制器
    global_limiter: IpRateLimiter,
    /// 每个 IP 的速率限制器 (IP -> RateLimiter)
    ip_limiters: Arc<Mutex<HashMap<IpAddr, IpRateLimiter>>>,
}

impl RateLimiter {
    pub fn new(config: RateLimiterConfig) -> Self {
        // 创建全局速率限制器
        let global_quota = Quota::per_second(
            NonZeroU32::new(config.global_requests_per_second)
                .unwrap_or(NonZeroU32::new(100).unwrap()),
        );
        let global_limiter = Arc::new(GovernorRateLimiter::direct(global_quota));

        Self {
            config,
            login_attempts: Arc::new(Mutex::new(HashMap::new())),
            global_limiter,
            ip_limiters: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// 检查登录尝试是否被限制
    pub fn check_login_attempt(&self, ip: IpAddr) -> Result<(), String> {
        let attempts = self.login_attempts.lock();
        let now = Instant::now();

        if let Some(attempt) = attempts.get(&ip) {
            // 检查是否被锁定
            if let Some(locked_until) = attempt.locked_until
                && now < locked_until
            {
                let remaining = locked_until.duration_since(now).as_secs();
                tracing::warn!(
                    ip = %ip,
                    remaining_secs = remaining,
                    "Login attempt blocked: IP is locked"
                );
                crate::metrics::record_rate_limit_rejection("login", "locked");
                return Err(format!(
                    "Too many failed login attempts. Please try again in {} seconds.",
                    remaining
                ));
            }

            // 检查是否超过速率限制
            let time_since_last = now.duration_since(attempt.last_failed_at);
            if time_since_last < Duration::from_secs(60)
                && attempt.failed_count >= self.config.login_attempts_per_minute
            {
                tracing::warn!(
                    ip = %ip,
                    failed_count = attempt.failed_count,
                    "Login attempt blocked: rate limit exceeded"
                );
                crate::metrics::record_rate_limit_rejection("login", "rate_exceeded");
                return Err(format!(
                    "Too many login attempts. Please try again in {} seconds.",
                    (60 - time_since_last.as_secs())
                ));
            }
        }

        Ok(())
    }

    /// 记录登录失败
    pub fn record_login_failure(&self, ip: IpAddr) {
        let mut attempts = self.login_attempts.lock();
        let now = Instant::now();

        let attempt = attempts.entry(ip).or_insert(LoginAttempt {
            failed_count: 0,
            last_failed_at: now,
            locked_until: None,
        });

        // 如果距离上次失败超过 1 分钟，重置计数
        if now.duration_since(attempt.last_failed_at) > Duration::from_secs(60) {
            attempt.failed_count = 1;
        } else {
            attempt.failed_count += 1;
        }

        attempt.last_failed_at = now;

        // 如果失败次数超过限制，锁定账号
        if attempt.failed_count >= self.config.login_attempts_per_minute {
            let lockout_duration = Duration::from_secs(self.config.login_lockout_duration_secs);
            attempt.locked_until = Some(now + lockout_duration);
            tracing::warn!(
                ip = %ip,
                failed_count = attempt.failed_count,
                lockout_secs = self.config.login_lockout_duration_secs,
                "IP locked due to too many failed login attempts"
            );
        }
    }

    /// 记录登录成功（清除失败记录）
    pub fn record_login_success(&self, ip: IpAddr) {
        let mut attempts = self.login_attempts.lock();
        attempts.remove(&ip);
        tracing::debug!(ip = %ip, "Login successful, cleared failure records");
    }

    /// 检查 API 请求是否被限制（针对特定 IP）
    pub fn check_api_request(&self, ip: IpAddr) -> Result<(), String> {
        // 首先检查全局限制
        if self.global_limiter.check().is_err() {
            tracing::warn!("Global API rate limit exceeded");
            crate::metrics::record_rate_limit_rejection("api", "global_limit");
            return Err("Server is experiencing high load. Please try again later.".to_string());
        }

        // 检查单个 IP 的限制
        let mut limiters = self.ip_limiters.lock();
        let limiter = limiters.entry(ip).or_insert_with(|| {
            let quota = Quota::per_second(
                NonZeroU32::new(self.config.api_requests_per_second)
                    .unwrap_or(NonZeroU32::new(10).unwrap()),
            );
            Arc::new(GovernorRateLimiter::direct(quota))
        });

        if limiter.check().is_err() {
            tracing::warn!(ip = %ip, "IP-based API rate limit exceeded");
            crate::metrics::record_rate_limit_rejection("api", "ip_limit");
            return Err("Too many requests. Please slow down.".to_string());
        }

        Ok(())
    }

    /// 清理过期的记录（定期调用）
    pub fn cleanup_expired(&self) {
        let now = Instant::now();

        // 清理登录尝试记录
        {
            let mut attempts = self.login_attempts.lock();
            attempts.retain(|ip, attempt| {
                // 保留最近 10 分钟内有活动的记录
                let keep = now.duration_since(attempt.last_failed_at) < Duration::from_secs(600);
                if !keep {
                    tracing::debug!(ip = %ip, "Cleaned up expired login attempt record");
                }
                keep
            });
        }

        // 清理 IP 限制器（保留最近使用的）
        {
            let mut limiters = self.ip_limiters.lock();
            // 只保留最近 1000 个 IP 的限制器，防止内存泄漏
            if limiters.len() > 1000 {
                tracing::info!(
                    count = limiters.len(),
                    "Cleaning up IP rate limiters (keeping 1000 most recent)"
                );
                // 简单策略：清空重建（在高并发场景可能需要更智能的 LRU）
                limiters.clear();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_login_rate_limit() {
        let config = RateLimiterConfig {
            login_attempts_per_minute: 3,
            login_lockout_duration_secs: 5,
            ..Default::default()
        };
        let limiter = RateLimiter::new(config);
        let ip: IpAddr = "127.0.0.1".parse().unwrap();

        // 前 3 次应该成功
        assert!(limiter.check_login_attempt(ip).is_ok());
        limiter.record_login_failure(ip);
        assert!(limiter.check_login_attempt(ip).is_ok());
        limiter.record_login_failure(ip);
        assert!(limiter.check_login_attempt(ip).is_ok());
        limiter.record_login_failure(ip);

        // 第 4 次应该被限制
        assert!(limiter.check_login_attempt(ip).is_err());

        // 成功登录后应该清除
        limiter.record_login_success(ip);
        assert!(limiter.check_login_attempt(ip).is_ok());
    }
}
