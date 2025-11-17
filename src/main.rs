use std::{collections::HashMap, net::SocketAddr, sync::Arc};

use axum::{
    middleware as axum_middleware,
    routing::{delete, get, post},
    Router,
};
use lazy_static::lazy_static;
use parking_lot::RwLock;

mod config;
mod errors;
mod handlers;
mod log;
mod metrics;
mod middleware;
mod models;
mod services;
mod utils;

use models::UserData;
use services::DataService;

lazy_static! {
    /// 全局 Prometheus 指标注册表
    pub static ref METRICS_REGISTRY: parking_lot::Mutex<prometheus::Registry> =
        parking_lot::Mutex::new(metrics::init_metrics());
}

/// 应用状态
#[derive(Clone)]
pub struct AppState {
    /// map username -> UserData (urls + order)
    pub store: Arc<RwLock<HashMap<String, UserData>>>,
    pub data_file_path: String,
    pub auth_config: Arc<RwLock<config::AuthConfig>>,
}

/// 确保应用状态满足跨线程要求
fn _assert_app_state_send_sync() {
    fn assert_traits<T: Send + Sync>() {}
    assert_traits::<AppState>();
}

#[tokio::main]
async fn main() {
    // 加载配置
    let cfg = config::AppConfig::load().expect("failed to load config/config.toml");

    // 初始化日志
    log::init_logging(&cfg.log);
    tracing::info!("starting sub service");

    let state = AppState {
        store: Arc::new(RwLock::new(HashMap::new())),
        data_file_path: cfg.data.data_file_path.clone(),
        auth_config: Arc::new(RwLock::new(cfg.auth.clone())),
    };

    // 从文件加载已存在的数据
    let data_service = DataService::new(state.store.clone(), state.data_file_path.clone());
    if let Err(e) = data_service.load() {
        tracing::error!("failed to load data: {}", e);
    }

    let addr: SocketAddr = format!("{}:{}", cfg.server.host, cfg.server.port)
        .parse()
        .expect("invalid server host/port in config");

    // 需要认证的路由
    let protected_routes = Router::new()
        .route("/api/create", post(handlers::create_user))
        .route("/api/users", get(handlers::list_users))
        .route("/api/reorder", post(handlers::reorder_users))
        .route("/api/delete/:username", delete(handlers::delete_user))
        .route("/api/change-password", post(handlers::change_password))
        .layer(axum_middleware::from_fn(middleware::auth_middleware));

    let app = Router::new()
        .route("/", get(handlers::index))
        .route("/healthz", get(handlers::healthz))
        .route("/health", get(handlers::health_detailed))
        .route("/metrics", get(handlers::metrics))
        .route("/favicon.ico", get(handlers::favicon))
        .route("/api/login", post(handlers::login))
        .route("/api/info/:username", get(handlers::get_user_info))
        .route("/:username", get(handlers::redirect_short))
        .merge(protected_routes)
        .nest_service("/static", tower_http::services::ServeDir::new("web"))
        .layer(axum_middleware::from_fn(middleware::metrics_middleware))
        .with_state(state);

    tracing::info!("Listening on {}", addr);
    axum::serve(tokio::net::TcpListener::bind(addr).await.unwrap(), app)
        .await
        .unwrap();
}
