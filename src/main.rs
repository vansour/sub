use actix_files::Files;
use actix_identity::IdentityMiddleware;
use actix_session::{SessionMiddleware, config::PersistentSession, storage::CookieSessionStore};
use actix_web::{
    App, HttpServer,
    cookie::{Key, time::Duration},
    web,
};
use argon2::{
    Argon2,
    password_hash::{PasswordHasher, SaltString, rand_core::OsRng},
};
use sqlx::{PgPool, Row, postgres::PgPoolOptions};

mod config;
mod error;
mod handlers;
mod log;
mod state;
mod utils;

// use error::AppError;
use state::AppState;

const DB_URL: &str = "postgres://postgres:password@db:5432/sub";

// 初始化数据库表 (恢复此函数，替代 migrate! 宏)
async fn init_db(pool: &PgPool) -> std::result::Result<(), sqlx::Error> {
    // 用户表 - 将 links 改为 JSONB
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            links JSONB NOT NULL DEFAULT '[]',
            rank INTEGER NOT NULL DEFAULT 0
        );
        "#,
    )
    .execute(pool)
    .await?;

    // 如果字段已经存在但是 TEXT 类型，尝试转换为 JSONB (适用于平滑升级)
    let col_info: Option<(String,)> = sqlx::query_as(
        "SELECT data_type FROM information_schema.columns WHERE table_name = 'users' AND column_name = 'links'"
    )
    .fetch_optional(pool)
    .await?;

    if let Some((data_type,)) = col_info
        && data_type != "jsonb"
    {
        tracing::info!("Converting users.links from {} to jsonb", data_type);
        sqlx::query("ALTER TABLE users ALTER COLUMN links TYPE JSONB USING links::JSONB")
            .execute(pool)
            .await?;
    }

    // 管理员表
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS admins (
            username TEXT PRIMARY KEY,
            password_hash TEXT NOT NULL
        );
        "#,
    )
    .execute(pool)
    .await?;

    Ok(())
}

// 确保至少有一个管理员账号
async fn ensure_admin(pool: &PgPool) {
    let count_res = sqlx::query("SELECT COUNT(*) FROM admins")
        .fetch_one(pool)
        .await;

    let count: i64 = count_res.map(|r| r.get(0)).unwrap_or(0);

    if count == 0 {
        tracing::info!("No admins found. Creating default admin.");
        let username = std::env::var("ADMIN_USER").unwrap_or_else(|_| "admin".to_string());
        let password = std::env::var("ADMIN_PASSWORD").unwrap_or_else(|_| "admin".to_string());

        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();

        let password_hash = match argon2.hash_password(password.as_bytes(), &salt) {
            Ok(h) => h.to_string(),
            Err(e) => {
                tracing::error!("Failed to hash default password: {}", e);
                return;
            }
        };

        let _ = sqlx::query("INSERT INTO admins (username, password_hash) VALUES ($1, $2)")
            .bind(&username)
            .bind(&password_hash)
            .execute(pool)
            .await;

        tracing::info!("Default admin created: {} / {}", username, password);
    }
}

#[actix_web::get("/healthz")]
async fn healthz() -> impl actix_web::Responder {
    actix_web::HttpResponse::Ok().body("ok")
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // 1. 加载配置
    println!("Loading configuration...");
    let config = match config::AppConfig::load() {
        Ok(cfg) => cfg,
        Err(e) => {
            eprintln!("Failed to load config: {}", e);
            std::process::exit(1);
        }
    };

    // 2. 初始化日志
    log::init_logging(&config);

    // 使用环境变量 DATABASE_URL（若未设置使用内置默认），因此不再在本地创建数据库文件
    let db_url = std::env::var("DATABASE_URL").unwrap_or_else(|_| DB_URL.to_string());

    // 从配置中加载或生成固定密钥
    let secret_key = Key::from(config.server.secret_key.as_bytes());

    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&db_url)
        .await
        .expect("Failed to connect to Postgres");

    // 恢复调用 init_db 而不是使用 migrate 宏
    init_db(&pool)
        .await
        .expect("Failed to initialize DB schema");

    ensure_admin(&pool).await;

    // 初始化全局共享的 HTTP 客户端
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .pool_max_idle_per_host(5)
        .build()
        .expect("Failed to create reqwest client");

    let state = web::Data::new(AppState { db: pool, client });
    let bind_addr = format!("{}:{}", config.server.host, config.server.port);
    let app_config = web::Data::new(config.clone());

    tracing::info!("Starting server at http://{} with PostgreSQL", bind_addr);

    HttpServer::new(move || {
        App::new()
            .app_data(state.clone())
            .app_data(app_config.clone())
            .wrap(actix_web::middleware::from_fn(log::trace_requests))
            .wrap(IdentityMiddleware::default())
            .wrap(
                SessionMiddleware::builder(CookieSessionStore::default(), secret_key.clone())
                    .cookie_name("sub_auth".to_owned())
                    .cookie_secure(app_config.server.cookie_secure)
                    .session_lifecycle(PersistentSession::default().session_ttl(Duration::days(7)))
                    .build(),
            )
            .service(Files::new("/static", "web"))
            .service(healthz)
            // Auth Handlers
            .service(handlers::auth::login)
            .service(handlers::auth::logout)
            .service(handlers::auth::get_me)
            .service(handlers::auth::update_account)
            // User Handlers
            .service(handlers::user::list_users)
            .service(handlers::user::create_user)
            .service(handlers::user::delete_user)
            .service(handlers::user::set_user_order)
            .service(handlers::user::get_links)
            .service(handlers::user::set_links)
            // Subscription Handlers
            .service(handlers::subscription::merged_user)
            .route(
                "/",
                web::get().to(|| async { actix_files::NamedFile::open("web/index.html") }),
            )
    })
    .bind(&bind_addr)?
    .run()
    .await
}
