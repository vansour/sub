use lazy_static::lazy_static;
use prometheus::{HistogramVec, IntCounterVec, IntGauge, IntGaugeVec, Registry};

/// 初始化 Prometheus 指标
pub fn init_metrics() -> Registry {
    let registry = Registry::new();

    // 注册所有指标
    registry
        .register(Box::new(HTTP_REQUESTS_TOTAL.clone()))
        .expect("failed to register HTTP_REQUESTS_TOTAL");

    registry
        .register(Box::new(HTTP_REQUEST_DURATION_SECONDS.clone()))
        .expect("failed to register HTTP_REQUEST_DURATION_SECONDS");

    registry
        .register(Box::new(HTTP_REQUESTS_IN_FLIGHT.clone()))
        .expect("failed to register HTTP_REQUESTS_IN_FLIGHT");

    registry
        .register(Box::new(HTTP_ERRORS_TOTAL.clone()))
        .expect("failed to register HTTP_ERRORS_TOTAL");

    registry
        .register(Box::new(DB_OPERATIONS_TOTAL.clone()))
        .expect("failed to register DB_OPERATIONS_TOTAL");

    registry
        .register(Box::new(DB_OPERATION_DURATION_SECONDS.clone()))
        .expect("failed to register DB_OPERATION_DURATION_SECONDS");

    registry
        .register(Box::new(AUTH_ATTEMPTS_TOTAL.clone()))
        .expect("failed to register AUTH_ATTEMPTS_TOTAL");

    registry
        .register(Box::new(ACTIVE_USERS_COUNT.clone()))
        .expect("failed to register ACTIVE_USERS_COUNT");

    registry
        .register(Box::new(RATE_LIMIT_REJECTIONS_TOTAL.clone()))
        .expect("failed to register RATE_LIMIT_REJECTIONS_TOTAL");

    registry
}

lazy_static! {
    /// HTTP 请求总数
    pub static ref HTTP_REQUESTS_TOTAL: IntCounterVec = IntCounterVec::new(
        prometheus::Opts::new("http_requests_total", "Total HTTP requests"),
        &["method", "path", "status"]
    ).expect("failed to create HTTP_REQUESTS_TOTAL");

    /// HTTP 请求延迟（秒）
    pub static ref HTTP_REQUEST_DURATION_SECONDS: HistogramVec = HistogramVec::new(
        prometheus::HistogramOpts::new("http_request_duration_seconds", "HTTP request duration in seconds")
            .buckets(vec![0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 2.0, 5.0]),
        &["method", "path"]
    ).expect("failed to create HTTP_REQUEST_DURATION_SECONDS");

    /// 进行中的 HTTP 请求数
    pub static ref HTTP_REQUESTS_IN_FLIGHT: IntGaugeVec = IntGaugeVec::new(
        prometheus::Opts::new("http_requests_in_flight", "Number of HTTP requests in flight"),
        &["method", "path"]
    ).expect("failed to create HTTP_REQUESTS_IN_FLIGHT");

    /// HTTP 错误总数
    pub static ref HTTP_ERRORS_TOTAL: IntCounterVec = IntCounterVec::new(
        prometheus::Opts::new("http_errors_total", "Total HTTP errors"),
        &["method", "path", "error_type"]
    ).expect("failed to create HTTP_ERRORS_TOTAL");

    /// 数据库操作总数
    pub static ref DB_OPERATIONS_TOTAL: IntCounterVec = IntCounterVec::new(
        prometheus::Opts::new("db_operations_total", "Total database operations"),
        &["operation", "result"]
    ).expect("failed to create DB_OPERATIONS_TOTAL");

    /// 数据库操作延迟（秒）
    pub static ref DB_OPERATION_DURATION_SECONDS: HistogramVec = HistogramVec::new(
        prometheus::HistogramOpts::new("db_operation_duration_seconds", "Database operation duration in seconds")
            .buckets(vec![0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0]),
        &["operation"]
    ).expect("failed to create DB_OPERATION_DURATION_SECONDS");

    /// 认证尝试总数
    pub static ref AUTH_ATTEMPTS_TOTAL: IntCounterVec = IntCounterVec::new(
        prometheus::Opts::new("auth_attempts_total", "Total authentication attempts"),
        &["result"]
    ).expect("failed to create AUTH_ATTEMPTS_TOTAL");

    /// 活跃用户数
    pub static ref ACTIVE_USERS_COUNT: IntGauge = IntGauge::new(
        "active_users_count",
        "Number of active users"
    ).expect("failed to create ACTIVE_USERS_COUNT");

    /// 速率限制拒绝次数
    pub static ref RATE_LIMIT_REJECTIONS_TOTAL: IntCounterVec = IntCounterVec::new(
        prometheus::Opts::new("rate_limit_rejections_total", "Total rate limit rejections"),
        &["type", "reason"]
    ).expect("failed to create RATE_LIMIT_REJECTIONS_TOTAL");
}

/// 健康检查状态
#[derive(Debug, Clone, serde::Serialize)]
pub struct HealthStatus {
    pub status: String,
    pub timestamp: String,
    pub version: String,
    pub checks: HealthChecks,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct HealthChecks {
    pub data_storage: CheckResult,
    pub system_resources: CheckResult,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct CheckResult {
    pub status: String,
    pub message: Option<String>,
    pub latency_ms: u64,
}

impl CheckResult {
    pub fn ok(latency_ms: u64) -> Self {
        Self {
            status: "healthy".to_string(),
            message: None,
            latency_ms,
        }
    }

    pub fn unhealthy(message: String, latency_ms: u64) -> Self {
        Self {
            status: "unhealthy".to_string(),
            message: Some(message),
            latency_ms,
        }
    }
}

/// 记录 HTTP 请求
pub fn record_http_request(method: &str, path: &str, status_code: u16, duration_secs: f64) {
    HTTP_REQUESTS_TOTAL
        .with_label_values(&[method, path, &status_code.to_string()])
        .inc();

    HTTP_REQUEST_DURATION_SECONDS
        .with_label_values(&[method, path])
        .observe(duration_secs);

    if status_code >= 400 {
        let error_type = if status_code >= 500 {
            "server_error"
        } else {
            "client_error"
        };
        HTTP_ERRORS_TOTAL
            .with_label_values(&[method, path, error_type])
            .inc();
    }
}

/// 增加进行中的请求计数
pub fn inc_http_requests_in_flight(method: &str, path: &str) {
    HTTP_REQUESTS_IN_FLIGHT
        .with_label_values(&[method, path])
        .inc();
}

/// 减少进行中的请求计数
pub fn dec_http_requests_in_flight(method: &str, path: &str) {
    HTTP_REQUESTS_IN_FLIGHT
        .with_label_values(&[method, path])
        .dec();
}

/// 记录数据库操作指标
#[allow(dead_code)]
pub fn record_db_operation(operation: &str, success: bool, duration_secs: f64) {
    let result = if success { "success" } else { "failure" };
    DB_OPERATIONS_TOTAL
        .with_label_values(&[operation, result])
        .inc();

    DB_OPERATION_DURATION_SECONDS
        .with_label_values(&[operation])
        .observe(duration_secs);
}

/// 记录认证尝试
pub fn record_auth_attempt(success: bool) {
    let result = if success { "success" } else { "failure" };
    AUTH_ATTEMPTS_TOTAL.with_label_values(&[result]).inc();
}

/// 设置活跃用户数
#[allow(dead_code)]
pub fn set_active_users(count: i64) {
    ACTIVE_USERS_COUNT.set(count);
}

/// 记录速率限制拒绝
pub fn record_rate_limit_rejection(limit_type: &str, reason: &str) {
    RATE_LIMIT_REJECTIONS_TOTAL
        .with_label_values(&[limit_type, reason])
        .inc();
}
