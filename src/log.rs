use tracing_subscriber::{fmt, fmt::format::FmtSpan, prelude::*, EnvFilter};

use crate::config::LogConfig;

/// 初始化全局日志
///
/// - 默认日志级别为 info
/// - 可通过 `config.toml` 的 [log] 配置日志级别和日志文件
/// - 同时输出到 stdout（方便 `docker logs`）和文件
/// - 支持结构化日志，包含请求相关的上下文信息
pub fn init_logging(cfg: &LogConfig) {
    // 从配置或环境变量构造日志过滤器
    let level = std::env::var("RUST_LOG").unwrap_or_else(|_| cfg.level.clone());
    let env_filter = EnvFilter::new(level);

    // 保证日志目录存在
    if let Some(parent) = std::path::Path::new(&cfg.log_file_path).parent() {
        let _ = std::fs::create_dir_all(parent);
    }

    let file_appender = tracing_appender::rolling::never(
        std::path::Path::new(&cfg.log_file_path)
            .parent()
            .unwrap_or_else(|| std::path::Path::new(".")),
        std::path::Path::new(&cfg.log_file_path)
            .file_name()
            .unwrap_or_default(),
    );
    let (non_blocking, _guard) = tracing_appender::non_blocking(file_appender);

    // stdout 日志 - 更详细的格式，支持结构化字段
    let stdout_layer = fmt::layer()
        .with_target(true)
        .with_level(true)
        .with_thread_ids(true)
        .with_thread_names(true)
        .with_span_events(FmtSpan::CLOSE)
        .with_ansi(false);

    // 文件日志 - 包含更多详细信息
    let file_layer = fmt::layer()
        .with_writer(non_blocking)
        .with_target(true)
        .with_thread_ids(true)
        .with_span_events(FmtSpan::NEW | FmtSpan::CLOSE)
        .with_ansi(false);

    tracing_subscriber::registry()
        .with(env_filter)
        .with(stdout_layer)
        .with(file_layer)
        .init();

    tracing::info!("Logging initialized with level: {}", cfg.level);
}
