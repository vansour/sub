use crate::config::AppConfig;
use actix_web::Error;
use actix_web::body::BoxBody;
use actix_web::dev::{ServiceRequest, ServiceResponse};
use actix_web::http::header::{HeaderName, HeaderValue, USER_AGENT};
use actix_web::middleware::Next;
use std::path::Path;
use std::str::FromStr;
use std::sync::Once;
use std::time::Instant;
use tracing::{Level, error, info, warn};
use tracing_subscriber::fmt::format::FmtSpan;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{Layer, fmt};
use uuid::Uuid;

/// 初始化日志系统
///
/// 1. 控制台日志 (stdout): 使用紧凑格式，方便 Docker logs 查看，不包含过多干扰信息。
/// 2. 文件日志 (file): 使用 JSON 格式，包含完整结构化信息，方便后续分析。
pub fn init_logging(config: &AppConfig) {
    static INIT: Once = Once::new();

    INIT.call_once(|| {
        // 将标准 log 库的日志重定向到 tracing
        let _ = tracing_log::LogTracer::init();

        // 解析日志级别
        let level = Level::from_str(&config.log.level).unwrap_or(Level::INFO);
        let filter = tracing_subscriber::filter::Targets::new()
            .with_target("sub", level) // 也就是当前应用的日志级别
            .with_default(Level::WARN); // 其他库（如 sqlx, hyper）默认只显示 WARN

        // --- Layer 1: 控制台输出 (Docker logs) ---
        // 使用 Compact 格式，去除时间戳（Docker 自身会打时间戳），保持整洁
        let stdout_layer = fmt::layer()
            .compact()
            .with_target(false) // 隐藏模块路径，只显示消息
            .with_file(false)
            .with_level(true)
            .with_ansi(true) // 支持颜色
            .with_filter(filter.clone());

        // --- Layer 2: 文件输出 ---
        // 解析文件路径
        let path_str = &config.log.log_file_path;
        let path = Path::new(path_str);

        // 提取目录和文件名
        let directory = path.parent().unwrap_or_else(|| Path::new("./logs"));
        let filename = path
            .file_name()
            .unwrap_or_else(|| std::ffi::OsStr::new("sub.log"));

        // 设置文件追加器 (每天轮转)
        let file_appender = tracing_appender::rolling::daily(directory, filename);
        let (non_blocking, _guard) = tracing_appender::non_blocking(file_appender);

        // 注意：_guard 必须被持有才能保证日志写入，但在 actix-web 这种长期运行的 server 中，
        // 直接泄漏它或者将其设为全局变量通常是可以接受的，或者仅依赖缓冲区刷新。
        // 这里为了简化，我们不得不泄漏 guard，否则函数结束 writer 就会关闭。
        std::mem::forget(_guard);

        // 文件日志使用 JSON 格式，包含所有字段
        let file_layer = fmt::layer()
            .json()
            .with_writer(non_blocking)
            .with_span_events(FmtSpan::CLOSE) // 记录请求结束时间
            .with_filter(filter);

        // 注册所有 Layer
        tracing_subscriber::registry()
            .with(stdout_layer)
            .with(file_layer)
            .init();
    });
}

/// Middleware: 结构化 HTTP 请求追踪
///
/// 生成 x-request-id 并记录请求耗时。
/// 替代 Actix 自带的 Logger，避免日志重复和格式混乱。
pub async fn trace_requests(
    req: ServiceRequest,
    next: Next<BoxBody>,
) -> Result<ServiceResponse<BoxBody>, Error> {
    let request_id = req
        .headers()
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .unwrap_or_else(|| Uuid::new_v4().to_string());

    let http_method = req.method().to_string();
    let http_path = req.path().to_string();
    let client_ip = req
        .connection_info()
        .realip_remote_addr()
        .unwrap_or("unknown")
        .to_string();

    let user_agent = req
        .headers()
        .get(USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("-")
        .to_string();

    // 创建 Span，包含请求上下文
    let span = tracing::info_span!(
        "http_req",
        id = %request_id,
        method = %http_method,
        path = %http_path,
        ip = %client_ip
    );

    let _enter = span.enter();
    let start_time = Instant::now();

    let mut res = next.call(req).await?;

    let duration = start_time.elapsed();
    let status_code = res.status().as_u16();

    // 注入 Request ID 到响应头
    res.headers_mut().insert(
        HeaderName::from_static("x-request-id"),
        HeaderValue::from_str(&request_id).unwrap(),
    );

    // 根据状态码决定日志级别
    match status_code {
        500..=599 => {
            error!(
                status = status_code,
                latency_ms = duration.as_millis(),
                ua = %user_agent,
                "Internal Server Error"
            );
        }
        400..=499 => {
            warn!(
                status = status_code,
                latency_ms = duration.as_millis(),
                "Client Error"
            );
        }
        _ => {
            // 对于健康检查等高频请求，可以考虑降低级别为 DEBUG
            if http_path == "/healthz" {
                tracing::debug!(status = status_code, "health check");
            } else {
                info!(
                    status = status_code,
                    latency_ms = duration.as_millis(),
                    "Finished"
                );
            }
        }
    }

    Ok(res)
}
