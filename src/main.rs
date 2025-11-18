use std::{collections::HashMap, net::SocketAddr, sync::Arc};

use axum::{
    Router, middleware as axum_middleware,
    routing::{delete, get, post},
};
use lazy_static::lazy_static;
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
use models::UserData;
use rate_limiter::RateLimiter;

lazy_static! {
    /// 全局 Prometheus 指标注册表
    pub static ref METRICS_REGISTRY: parking_lot::Mutex<prometheus::Registry> =
        parking_lot::Mutex::new(metrics::init_metrics());
}

/// 应用状态
#[derive(Clone)]
pub struct AppState {
    /// 数据库连接
    pub db: Database,
    /// 内存缓存 (username -> UserData)，用于快速访问
    pub store: Arc<RwLock<HashMap<String, UserData>>>,
    pub auth_config: Arc<RwLock<config::AuthConfig>>,
    pub rate_limiter: RateLimiter,
    /// 安全配置
    pub security_config: Arc<config::SecurityConfig>,
    /// 共享的 HTTP 客户端（用于 URL 抓取）
    pub http_client: reqwest::Client,
}

/// 确保应用状态满足跨线程要求
fn _assert_app_state_send_sync() {
    fn assert_traits<T: Send + Sync>() {}
    assert_traits::<AppState>();
}

#[tokio::main]
async fn main() {
    // 先初始化基本日志（使用默认配置）
    tracing_subscriber::fmt()
        .with_target(false)
        .with_level(true)
        .init();

    // 从环境变量获取数据库路径，默认为 /app/data/sub.db
    let database_path =
        std::env::var("DATABASE_PATH").unwrap_or_else(|_| "/app/data/sub.db".to_string());

    tracing::info!("Using database path: {}", database_path);

    // 初始化数据库
    let db = Database::new(&database_path)
        .await
        .expect("failed to initialize database");
    tracing::info!("Database initialized at {}", database_path);

    // 从数据库和配置文件加载完整配置
    let cfg = config::AppConfig::load(&db)
        .await
        .expect("failed to load config");

    tracing::info!("starting sub service with database backend");

    // 日志记录安全配置
    tracing::info!(
        allow_private_ips = cfg.security.allow_private_ips,
        allow_localhost = cfg.security.allow_localhost,
        "Security settings configured"
    );

    // 创建共享的 HTTP 客户端（用于所有 URL 抓取）
    let http_client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .connect_timeout(std::time::Duration::from_secs(10))
        .user_agent(concat!("sub/", env!("CARGO_PKG_VERSION")))
        .danger_accept_invalid_certs(false)
        .tcp_keepalive(std::time::Duration::from_secs(60))
        .pool_idle_timeout(std::time::Duration::from_secs(90))
        .pool_max_idle_per_host(10)
        .build()
        .expect("failed to create HTTP client");
    tracing::info!("Shared HTTP client initialized");

    // 初始化 Rate Limiter
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

    // 启动定期清理任务
    {
        let limiter = rate_limiter.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(300)); // 每 5 分钟清理一次
            loop {
                interval.tick().await;
                limiter.cleanup_expired();
            }
        });
    }

    // 从数据库加载数据到内存缓存
    let store = Arc::new(RwLock::new(HashMap::new()));
    match db.get_all_users().await {
        Ok(users) => {
            let mut store_write = store.write();
            for user in users {
                store_write.insert(
                    user.username.clone(),
                    UserData {
                        urls: user.urls,
                        order: user.order_index as usize,
                    },
                );
            }
            tracing::info!(
                user_count = store_write.len(),
                "Loaded users into memory cache"
            );
        }
        Err(e) => {
            tracing::error!(error = %e, "Failed to load users from database");
        }
    }

    let state = AppState {
        db,
        store,
        auth_config: Arc::new(RwLock::new(cfg.auth.clone())),
        rate_limiter,
        security_config: Arc::new(cfg.security.clone()),
        http_client,
    };

    let addr: SocketAddr = format!("{}:{}", cfg.server.host, cfg.server.port)
        .parse()
        .expect("invalid server host/port in config");

    // 需要认证的路由
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

    tracing::info!("Listening on {}", addr);
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .unwrap();
}
