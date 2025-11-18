use prometheus::{HistogramVec, IntCounterVec, IntGauge, IntGaugeVec, Registry};
use std::sync::OnceLock;

/// 初始化 Prometheus 指标
pub fn init_metrics() -> Registry {
    let registry = Registry::new();

    // 注册所有指标（先初始化再注册）
    registry
        .register(Box::new(get_http_requests_total().clone()))
        .expect("failed to register HTTP_REQUESTS_TOTAL");

    registry
        .register(Box::new(get_http_request_duration_seconds().clone()))
        .expect("failed to register HTTP_REQUEST_DURATION_SECONDS");

    registry
        .register(Box::new(get_http_requests_in_flight().clone()))
        .expect("failed to register HTTP_REQUESTS_IN_FLIGHT");

    registry
        .register(Box::new(get_http_errors_total().clone()))
        .expect("failed to register HTTP_ERRORS_TOTAL");

    registry
        .register(Box::new(get_db_operations_total().clone()))
        .expect("failed to register DB_OPERATIONS_TOTAL");

    registry
        .register(Box::new(get_db_operation_duration_seconds().clone()))
        .expect("failed to register DB_OPERATION_DURATION_SECONDS");

    registry
        .register(Box::new(get_auth_attempts_total().clone()))
        .expect("failed to register AUTH_ATTEMPTS_TOTAL");

    registry
        .register(Box::new(get_active_users_count().clone()))
        .expect("failed to register ACTIVE_USERS_COUNT");

    registry
        .register(Box::new(get_rate_limit_rejections_total().clone()))
        .expect("failed to register RATE_LIMIT_REJECTIONS_TOTAL");

    registry
}

/// HTTP 请求总数
pub static HTTP_REQUESTS_TOTAL: OnceLock<IntCounterVec> = OnceLock::new();

/// HTTP 请求延迟（秒）
pub static HTTP_REQUEST_DURATION_SECONDS: OnceLock<HistogramVec> = OnceLock::new();

/// 进行中的 HTTP 请求数
pub static HTTP_REQUESTS_IN_FLIGHT: OnceLock<IntGaugeVec> = OnceLock::new();

/// HTTP 错误总数
pub static HTTP_ERRORS_TOTAL: OnceLock<IntCounterVec> = OnceLock::new();

/// 数据库操作总数
pub static DB_OPERATIONS_TOTAL: OnceLock<IntCounterVec> = OnceLock::new();

/// 数据库操作延迟（秒）
pub static DB_OPERATION_DURATION_SECONDS: OnceLock<HistogramVec> = OnceLock::new();

/// 认证尝试总数
pub static AUTH_ATTEMPTS_TOTAL: OnceLock<IntCounterVec> = OnceLock::new();

/// 活跃用户数
pub static ACTIVE_USERS_COUNT: OnceLock<IntGauge> = OnceLock::new();

/// 速率限制拒绝次数
pub static RATE_LIMIT_REJECTIONS_TOTAL: OnceLock<IntCounterVec> = OnceLock::new();

// 初始化所有指标的辅助函数
fn get_http_requests_total() -> &'static IntCounterVec {
    HTTP_REQUESTS_TOTAL.get_or_init(|| {
        IntCounterVec::new(
            prometheus::Opts::new("http_requests_total", "Total HTTP requests"),
            &["method", "path", "status"],
        )
        .expect("failed to create HTTP_REQUESTS_TOTAL")
    })
}

fn get_http_request_duration_seconds() -> &'static HistogramVec {
    HTTP_REQUEST_DURATION_SECONDS.get_or_init(|| {
        HistogramVec::new(
            prometheus::HistogramOpts::new(
                "http_request_duration_seconds",
                "HTTP request duration in seconds",
            )
            .buckets(vec![0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 2.0, 5.0]),
            &["method", "path"],
        )
        .expect("failed to create HTTP_REQUEST_DURATION_SECONDS")
    })
}

fn get_http_requests_in_flight() -> &'static IntGaugeVec {
    HTTP_REQUESTS_IN_FLIGHT.get_or_init(|| {
        IntGaugeVec::new(
            prometheus::Opts::new(
                "http_requests_in_flight",
                "Number of HTTP requests in flight",
            ),
            &["method", "path"],
        )
        .expect("failed to create HTTP_REQUESTS_IN_FLIGHT")
    })
}

fn get_http_errors_total() -> &'static IntCounterVec {
    HTTP_ERRORS_TOTAL.get_or_init(|| {
        IntCounterVec::new(
            prometheus::Opts::new("http_errors_total", "Total HTTP errors"),
            &["method", "path", "error_type"],
        )
        .expect("failed to create HTTP_ERRORS_TOTAL")
    })
}

fn get_db_operations_total() -> &'static IntCounterVec {
    DB_OPERATIONS_TOTAL.get_or_init(|| {
        IntCounterVec::new(
            prometheus::Opts::new("db_operations_total", "Total database operations"),
            &["operation", "result"],
        )
        .expect("failed to create DB_OPERATIONS_TOTAL")
    })
}

fn get_db_operation_duration_seconds() -> &'static HistogramVec {
    DB_OPERATION_DURATION_SECONDS.get_or_init(|| {
        HistogramVec::new(
            prometheus::HistogramOpts::new(
                "db_operation_duration_seconds",
                "Database operation duration in seconds",
            )
            .buckets(vec![0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0]),
            &["operation"],
        )
        .expect("failed to create DB_OPERATION_DURATION_SECONDS")
    })
}

fn get_auth_attempts_total() -> &'static IntCounterVec {
    AUTH_ATTEMPTS_TOTAL.get_or_init(|| {
        IntCounterVec::new(
            prometheus::Opts::new("auth_attempts_total", "Total authentication attempts"),
            &["result"],
        )
        .expect("failed to create AUTH_ATTEMPTS_TOTAL")
    })
}

fn get_active_users_count() -> &'static IntGauge {
    ACTIVE_USERS_COUNT.get_or_init(|| {
        IntGauge::new("active_users_count", "Number of active users")
            .expect("failed to create ACTIVE_USERS_COUNT")
    })
}

fn get_rate_limit_rejections_total() -> &'static IntCounterVec {
    RATE_LIMIT_REJECTIONS_TOTAL.get_or_init(|| {
        IntCounterVec::new(
            prometheus::Opts::new("rate_limit_rejections_total", "Total rate limit rejections"),
            &["type", "reason"],
        )
        .expect("failed to create RATE_LIMIT_REJECTIONS_TOTAL")
    })
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
    get_http_requests_total()
        .with_label_values(&[method, path, &status_code.to_string()])
        .inc();

    get_http_request_duration_seconds()
        .with_label_values(&[method, path])
        .observe(duration_secs);

    if status_code >= 400 {
        let error_type = if status_code >= 500 {
            "server_error"
        } else {
            "client_error"
        };
        get_http_errors_total()
            .with_label_values(&[method, path, error_type])
            .inc();
    }
}

/// 增加进行中的请求计数
pub fn inc_http_requests_in_flight(method: &str, path: &str) {
    get_http_requests_in_flight()
        .with_label_values(&[method, path])
        .inc();
}

/// 减少进行中的请求计数
pub fn dec_http_requests_in_flight(method: &str, path: &str) {
    get_http_requests_in_flight()
        .with_label_values(&[method, path])
        .dec();
}

/// 记录认证尝试
pub fn record_auth_attempt(success: bool) {
    let result = if success { "success" } else { "failure" };
    get_auth_attempts_total().with_label_values(&[result]).inc();
}

/// 记录速率限制拒绝
pub fn record_rate_limit_rejection(limit_type: &str, reason: &str) {
    get_rate_limit_rejections_total()
        .with_label_values(&[limit_type, reason])
        .inc();
}
