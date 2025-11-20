use std::{
    net::SocketAddr,
    sync::{Arc, OnceLock},
};

use anyhow::Context;
use axum::{
    Router, middleware as axum_middleware,
    routing::{delete, get, post},
};
use parking_lot::RwLock;

mod config;
mod db;
mod errors;
mod handlers;
mod metrics;
mod middleware;
mod models;
mod rate_limiter;
mod services;
mod utils;

use db::Database;
use rate_limiter::RateLimiter;
use tokio::task::JoinHandle;

/// 全局 Prometheus 指标注册表
pub static METRICS_REGISTRY: OnceLock<parking_lot::Mutex<prometheus::Registry>> = OnceLock::new();

/// 获取或初始化 Prometheus 指标注册表
pub fn get_metrics_registry() -> &'static parking_lot::Mutex<prometheus::Registry> {
    METRICS_REGISTRY.get_or_init(|| parking_lot::Mutex::new(metrics::init_metrics()))
}

/// 应用状态
#[derive(Clone)]
pub struct AppState {
    /// 数据库连接
    pub db: Database,
    pub auth_config: Arc<RwLock<config::AuthConfig>>,
    pub rate_limiter: RateLimiter,
    /// 安全配置
    pub security_config: Arc<config::SecurityConfig>,
    /// HTTP 客户端配置
    pub http_client_config: Arc<config::HttpClientConfig>,
    /// 共享的 HTTP 客户端（用于 URL 抓取）
    pub http_client: reqwest::Client,
}

/// 验证数据库路径是否有效
fn validate_database_path(path: &str) -> anyhow::Result<()> {
    use std::path::Path;

    let db_path = Path::new(path);

    // 检查路径是否为绝对路径（推荐）
    if !db_path.is_absolute() {
        tracing::warn!(
            path = path,
            "Database path is not absolute. This may cause issues in some environments."
        );
    }

    // 检查父目录是否存在或可创建
    if let Some(parent) = db_path.parent() {
        if !parent.exists() {
            tracing::info!(
                dir = %parent.display(),
                "Database directory does not exist, will create it"
            );
            // 尝试创建目录
            std::fs::create_dir_all(parent).map_err(|e| {
                anyhow::anyhow!(
                    "Failed to create database directory '{}': {}",
                    parent.display(),
                    e
                )
            })?;
        }

        // 检查目录是否可写
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let metadata = std::fs::metadata(parent).map_err(|e| {
                anyhow::anyhow!(
                    "Failed to check permissions for '{}': {}",
                    parent.display(),
                    e
                )
            })?;
            let permissions = metadata.permissions();
            if permissions.mode() & 0o200 == 0 {
                return Err(anyhow::anyhow!(
                    "Database directory '{}' is not writable",
                    parent.display()
                ));
            }
        }
    }

    // 如果数据库文件已存在，检查是否可读写
    if db_path.exists() {
        let metadata = std::fs::metadata(db_path)
            .map_err(|e| anyhow::anyhow!("Failed to check database file '{}': {}", path, e))?;

        if metadata.is_dir() {
            return Err(anyhow::anyhow!(
                "Database path '{}' is a directory, not a file",
                path
            ));
        }

        // 检查文件是否可读写
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(db_path)
            .map_err(|e| {
                anyhow::anyhow!(
                    "Database file '{}' exists but is not readable/writable: {}",
                    path,
                    e
                )
            })?;
        drop(file);

        tracing::info!(path = path, "Database file exists and is accessible");
    }

    Ok(())
}

/// 确保应用状态满足跨线程要求
fn _assert_app_state_send_sync() {
    fn assert_traits<T: Send + Sync>() {}
    assert_traits::<AppState>();
}

fn init_tracing() {
    use tracing_subscriber::{EnvFilter, fmt};

    let env_filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info,sqlx=warn"));

    fmt()
        .with_env_filter(env_filter)
        .with_target(false)
        .with_level(true)
        .init();
}

async fn init_database() -> anyhow::Result<Database> {
    let database_path =
        std::env::var("DATABASE_PATH").unwrap_or_else(|_| "/app/data/sub.db".to_string());

    tracing::info!("Using database path: {}", database_path);

    validate_database_path(&database_path)
        .with_context(|| format!("Database path validation failed: {}", database_path))?;

    let db = Database::new(&database_path)
        .await
        .with_context(|| format!("failed to initialize database at {}", database_path))?;

    tracing::info!("Database initialized at {}", database_path);
    Ok(db)
}

async fn init_config(db: &Database) -> anyhow::Result<config::AppConfig> {
    let cfg = config::AppConfig::load(db)
        .await
        .context("failed to load config")?;

    tracing::info!("starting sub service with database backend");
    tracing::info!(
        allow_private_ips = cfg.security.allow_private_ips,
        allow_localhost = cfg.security.allow_localhost,
        "Security settings configured"
    );

    Ok(cfg)
}

fn build_http_client(cfg: &config::HttpClientConfig) -> anyhow::Result<reqwest::Client> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(cfg.request_timeout_secs))
        .connect_timeout(std::time::Duration::from_secs(cfg.connect_timeout_secs))
        .user_agent(concat!("sub/", env!("CARGO_PKG_VERSION")))
        .danger_accept_invalid_certs(false)
        .tcp_keepalive(std::time::Duration::from_secs(60))
        .pool_idle_timeout(std::time::Duration::from_secs(cfg.pool_idle_timeout_secs))
        .pool_max_idle_per_host(cfg.pool_max_idle_per_host)
        .build()
        .context("failed to create HTTP client")?;

    tracing::info!(
        request_timeout_secs = cfg.request_timeout_secs,
        connect_timeout_secs = cfg.connect_timeout_secs,
        pool_idle_timeout_secs = cfg.pool_idle_timeout_secs,
        "Shared HTTP client initialized"
    );

    Ok(client)
}

fn spawn_rate_limiter_cleanup(limiter: RateLimiter) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(300)); // 每 5 分钟清理一次
        loop {
            interval.tick().await;
            limiter.cleanup_expired();
        }
    })
}

async fn build_app_state(db: Database, cfg: config::AppConfig) -> AppState {
    let rate_limiter = RateLimiter::new(rate_limiter::RateLimiterConfig {
        login_attempts_per_minute: cfg.rate_limit.login_attempts_per_minute,
        login_lockout_duration_secs: cfg.rate_limit.login_lockout_duration_secs,
        api_requests_per_second: cfg.rate_limit.api_requests_per_second,
        global_requests_per_second: cfg.rate_limit.global_requests_per_second,
    });
    tracing::info!(
        login_attempts_per_minute = cfg.rate_limit.login_attempts_per_minute,
        lockout_duration_secs = cfg.rate_limit.login_lockout_duration_secs,
        api_requests_per_second = cfg.rate_limit.api_requests_per_second,
        global_requests_per_second = cfg.rate_limit.global_requests_per_second,
        "Rate limiter initialized"
    );

    let _cleanup_handle = spawn_rate_limiter_cleanup(rate_limiter.clone());

    let http_client = build_http_client(&cfg.http_client).expect("failed to build http client");

    AppState {
        db,
        auth_config: Arc::new(RwLock::new(cfg.auth.clone())),
        rate_limiter,
        security_config: Arc::new(cfg.security.clone()),
        http_client_config: Arc::new(cfg.http_client.clone()),
        http_client,
    }
}

fn build_router(
    state: AppState,
    cfg: &config::ServerConfig,
) -> anyhow::Result<(Router, SocketAddr)> {
    let addr: SocketAddr = format!("{}:{}", cfg.host, cfg.port)
        .parse()
        .context("invalid server host/port in config")?;

    let protected_routes = Router::new()
        .route("/api/create", post(handlers::create_user))
        .route("/api/users", get(handlers::list_users))
        .route("/api/reorder", post(handlers::reorder_users))
        .route("/api/delete/{username}", delete(handlers::delete_user))
        .route("/api/change-password", post(handlers::change_password))
        .layer(axum_middleware::from_fn_with_state(
            state.clone(),
            middleware::auth_middleware,
        ));

    let app = Router::new()
        .route("/", get(handlers::index))
        .route("/healthz", get(handlers::healthz))
        .route("/health", get(handlers::health_detailed))
        .route("/metrics", get(handlers::metrics))
        .route("/favicon.ico", get(handlers::favicon))
        .route("/api/login", post(handlers::login))
        .route("/api/info/{username}", get(handlers::get_user_info))
        .route("/{username}", get(handlers::redirect_short))
        .merge(protected_routes)
        .nest_service("/static", tower_http::services::ServeDir::new("web"))
        .layer(axum_middleware::from_fn_with_state(
            state.clone(),
            middleware::rate_limit_middleware,
        ))
        .layer(axum_middleware::from_fn(middleware::metrics_middleware))
        .with_state(state);

    Ok((app, addr))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_tracing();

    let db = init_database().await?;
    let cfg = init_config(&db).await?;
    let state = build_app_state(db, cfg.clone()).await;

    let (app, addr) = build_router(state, &cfg.server)?;

    tracing::info!("Listening on {}", addr);
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .context("failed to bind TCP listener")?;

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .context("server error")?;

    Ok(())
}
