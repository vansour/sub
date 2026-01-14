use actix_files::Files;
use actix_identity::{Identity, IdentityMiddleware};
use actix_session::{SessionMiddleware, config::PersistentSession, storage::CookieSessionStore};
use actix_web::{
    App,
    HttpMessage,
    HttpRequest,
    HttpResponse,
    HttpServer,
    Responder,
    cookie::{Key, time::Duration},
    delete,
    get,
    // 移除 middleware::Logger 以避免日志混乱
    post,
    put,
    web,
};
use argon2::{
    Argon2,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString, rand_core::OsRng},
};
use futures::stream::StreamExt;
use scraper::{Html, Node};
use serde::{Deserialize, Serialize};
use sqlx::{PgPool, Row, postgres::PgPoolOptions};

mod config; // 新增模块
mod log;

const DB_URL: &str = "postgres://postgres:password@db:5432/sub";
const CONCURRENT_REQUESTS_LIMIT: usize = 5;

#[derive(Debug, Clone)]
struct AppState {
    db: PgPool,
    client: reqwest::Client,
}

#[derive(Deserialize)]
struct LoginPayload {
    username: String,
    password: String,
}

#[derive(Deserialize)]
struct UpdateAccountPayload {
    new_username: String,
    new_password: String,
}

// 验证用户名是否合法
fn is_valid_username(username: &str) -> bool {
    if username.is_empty() || username.len() > 64 {
        return false;
    }
    username
        .chars()
        .all(|c| c.is_alphanumeric() || c == '_' || c == '-')
}

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
        let password = std::env::var("ADMIN_PASSWORD").unwrap_or_else(|_| "password".to_string());

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

        tracing::info!("Default admin created: {} / (hidden)", username);
    }
}

// --- 认证相关接口 ---

#[post("/api/auth/login")]
async fn login(
    req: HttpRequest,
    payload: web::Json<LoginPayload>,
    data: web::Data<AppState>,
) -> impl Responder {
    let row = sqlx::query("SELECT password_hash FROM admins WHERE username = $1")
        .bind(&payload.username)
        .fetch_optional(&data.db)
        .await;

    match row {
        Ok(Some(r)) => {
            let hash_str: String = r.get(0);
            // 优化: 安全地解析 DB 中的哈希字符串
            let parsed_hash = match PasswordHash::new(&hash_str) {
                Ok(h) => h,
                Err(e) => {
                    tracing::error!("Invalid password hash stored in DB: {}", e);
                    return HttpResponse::InternalServerError().body("Auth error");
                }
            };

            if Argon2::default()
                .verify_password(payload.password.as_bytes(), &parsed_hash)
                .is_ok()
            {
                // 优化: 处理 Identity login 失败
                if let Err(e) = Identity::login(&req.extensions(), payload.username.clone()) {
                    tracing::error!("Failed to attach identity: {}", e);
                    return HttpResponse::InternalServerError().body("Login session error");
                }
                return HttpResponse::Ok().json("Logged in");
            }
        }
        Ok(None) => {} // 用户不存在
        Err(e) => tracing::error!("Login DB error: {}", e),
    }

    HttpResponse::Unauthorized().body("Invalid credentials")
}

#[post("/api/auth/logout")]
async fn logout(id: Identity) -> impl Responder {
    id.logout();
    HttpResponse::Ok().body("Logged out")
}

#[get("/api/auth/me")]
async fn get_me(id: Option<Identity>) -> impl Responder {
    match id {
        // 优化: 处理获取 ID 时的潜在错误
        Some(id) => match id.id() {
            Ok(username) => HttpResponse::Ok().json(serde_json::json!({ "username": username })),
            Err(e) => {
                tracing::warn!("Identity found but ID is invalid: {}", e);
                HttpResponse::Unauthorized().body("Invalid session")
            }
        },
        None => HttpResponse::Unauthorized().body("Not logged in"),
    }
}

#[put("/api/auth/account")]
async fn update_account(
    id: Identity,
    payload: web::Json<UpdateAccountPayload>,
    data: web::Data<AppState>,
) -> impl Responder {
    let current_user = match id.id() {
        Ok(u) => u,
        Err(_) => return HttpResponse::Unauthorized().body("Unauthorized"),
    };

    let new_username = payload.new_username.trim();
    let new_password = payload.new_password.trim();

    if !is_valid_username(new_username) {
        return HttpResponse::BadRequest().body("Invalid username format");
    }
    if new_password.is_empty() {
        return HttpResponse::BadRequest().body("Password cannot be empty");
    }

    // Hash new password
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let password_hash = match argon2.hash_password(new_password.as_bytes(), &salt) {
        Ok(h) => h.to_string(),
        Err(e) => return HttpResponse::InternalServerError().body(format!("Hash error: {}", e)),
    };

    let result =
        sqlx::query("UPDATE admins SET username = $1, password_hash = $2 WHERE username = $3")
            .bind(new_username)
            .bind(password_hash)
            .bind(&current_user)
            .execute(&data.db)
            .await;

    match result {
        Ok(_) => {
            id.logout();
            HttpResponse::Ok().body("Account updated, please login again")
        }
        Err(e) => {
            tracing::error!("Update account error: {}", e);
            HttpResponse::InternalServerError()
                .body("Failed to update account (username might exist)")
        }
    }
}

// --- 业务接口 ---

#[get("/api/users")]
async fn list_users(_id: Identity, data: web::Data<AppState>) -> impl Responder {
    let rows = sqlx::query("SELECT username FROM users ORDER BY rank ASC")
        .fetch_all(&data.db)
        .await;

    match rows {
        Ok(rows) => {
            let list: Vec<String> = rows.iter().map(|r| r.get("username")).collect();
            HttpResponse::Ok().json(list)
        }
        Err(e) => {
            tracing::error!("Database error listing users: {}", e);
            HttpResponse::InternalServerError().body("DB Error")
        }
    }
}

#[derive(Deserialize)]
struct CreateUserPayload {
    username: String,
}

#[post("/api/users")]
async fn create_user(
    _id: Identity,
    payload: web::Json<CreateUserPayload>,
    data: web::Data<AppState>,
) -> impl Responder {
    let username = payload.username.trim().to_string();

    if !is_valid_username(&username) {
        return HttpResponse::BadRequest().body("Invalid username");
    }

    let max_rank_res = sqlx::query("SELECT MAX(rank) FROM users")
        .fetch_one(&data.db)
        .await;

    let next_rank: i64 = match max_rank_res {
        Ok(row) => row.try_get::<i64, _>(0).unwrap_or(0) + 1,
        Err(_) => 1,
    };

    let result = sqlx::query("INSERT INTO users (username, links, rank) VALUES ($1, '[]', $2)")
        .bind(&username)
        .bind(next_rank)
        .execute(&data.db)
        .await;

    match result {
        Ok(_) => {
            tracing::info!(%username, "user created");
            HttpResponse::Created().json(username)
        }
        Err(e) => {
            let msg = e.to_string().to_lowercase();
            if msg.contains("duplicate key value") || msg.contains("unique constraint") {
                HttpResponse::Conflict().body("user exists")
            } else {
                tracing::error!("Create user error: {}", e);
                HttpResponse::InternalServerError().body("DB Error")
            }
        }
    }
}

#[delete("/api/users/{username}")]
async fn delete_user(
    _id: Identity,
    path: web::Path<String>,
    data: web::Data<AppState>,
) -> impl Responder {
    let username = path.into_inner();

    let result = sqlx::query("DELETE FROM users WHERE username = $1")
        .bind(&username)
        .execute(&data.db)
        .await;

    match result {
        Ok(res) => {
            if res.rows_affected() > 0 {
                tracing::info!(%username, "user deleted");
                HttpResponse::Ok().body("deleted")
            } else {
                HttpResponse::NotFound().body("not found")
            }
        }
        Err(e) => {
            tracing::error!("Delete user error: {}", e);
            HttpResponse::InternalServerError().body("DB Error")
        }
    }
}

#[get("/api/users/{username}/links")]
async fn get_links(
    _id: Identity,
    path: web::Path<String>,
    data: web::Data<AppState>,
) -> impl Responder {
    let username = path.into_inner();

    let row = sqlx::query("SELECT links FROM users WHERE username = $1")
        .bind(&username)
        .fetch_optional(&data.db)
        .await;

    match row {
        Ok(Some(r)) => {
            let links: serde_json::Value = r.get("links");
            HttpResponse::Ok().json(links)
        }
        Ok(None) => HttpResponse::NotFound().body("user not found"),
        Err(e) => {
            tracing::error!("Get links error: {}", e);
            HttpResponse::InternalServerError().body("DB Error")
        }
    }
}

#[derive(Deserialize)]
struct LinksPayload {
    links: Vec<String>,
}

#[derive(Deserialize, Serialize)]
struct OrderPayload {
    order: Vec<String>,
}

#[put("/api/users/{username}/links")]
async fn set_links(
    _id: Identity,
    path: web::Path<String>,
    payload: web::Json<LinksPayload>,
    data: web::Data<AppState>,
) -> impl Responder {
    for link in &payload.links {
        if !link.starts_with("http://") && !link.starts_with("https://") {
            return HttpResponse::BadRequest().body(format!("Invalid URL: {}", link));
        }
    }

    let username = path.into_inner();
    let links_value = serde_json::to_value(&payload.links).unwrap_or(serde_json::json!([]));

    let result = sqlx::query("UPDATE users SET links = $1 WHERE username = $2")
        .bind(&links_value)
        .bind(&username)
        .execute(&data.db)
        .await;

    match result {
        Ok(res) => {
            if res.rows_affected() > 0 {
                HttpResponse::Ok().json(&payload.links)
            } else {
                HttpResponse::NotFound().body("user not found")
            }
        }
        Err(e) => {
            tracing::error!("Set links error: {}", e);
            HttpResponse::InternalServerError().body("DB Error")
        }
    }
}

#[put("/api/users/order")]
async fn set_user_order(
    _id: Identity,
    payload: web::Json<OrderPayload>,
    data: web::Data<AppState>,
) -> impl Responder {
    let order = &payload.order;
    if order.is_empty() {
        return HttpResponse::BadRequest().body("order must not be empty");
    }

    let mut tx = match data.db.begin().await {
        Ok(tx) => tx,
        Err(e) => return HttpResponse::InternalServerError().body(e.to_string()),
    };

    for (i, username) in order.iter().enumerate() {
        let res = sqlx::query("UPDATE users SET rank = $1 WHERE username = $2")
            .bind(i as i64)
            .bind(username)
            .execute(&mut *tx)
            .await;

        if res.is_err() {
            let _ = tx.rollback().await;
            return HttpResponse::InternalServerError().body("Failed to update order");
        }
    }

    if let Err(e) = tx.commit().await {
        tracing::error!("Commit order error: {}", e);
        return HttpResponse::InternalServerError().body("Commit failed");
    }

    tracing::info!("User order updated");
    HttpResponse::Ok().json(order)
}

#[get("/{username}")]
async fn merged_user(path: web::Path<String>, data: web::Data<AppState>) -> impl Responder {
    let username = path.into_inner();

    let row = sqlx::query("SELECT links FROM users WHERE username = $1")
        .bind(&username)
        .fetch_optional(&data.db)
        .await;

    let links: Vec<String> = match row {
        Ok(Some(r)) => {
            let val: serde_json::Value = r.get("links");
            serde_json::from_value(val).unwrap_or_default()
        }
        Ok(None) => return HttpResponse::NotFound().body("user not found"),
        Err(e) => {
            tracing::error!("Merge user db error: {}", e);
            return HttpResponse::InternalServerError().body("DB Error");
        }
    };

    if links.is_empty() {
        return HttpResponse::Ok()
            .content_type("text/plain; charset=utf-8")
            .body("");
    }

    let fetches = futures::stream::iter(links.into_iter().enumerate().map(|(idx, link)| {
        let client = data.client.clone();
        async move {
            let resp_text = match client.get(&link).send().await {
                Ok(r) => match r.text().await {
                    Ok(t) => t,
                    Err(e) => format!("<!-- failed to read body {}: {} -->", link, e),
                },
                Err(e) => format!("<!-- failed to fetch {}: {} -->", link, e),
            };
            (idx, resp_text)
        }
    }))
    .buffer_unordered(CONCURRENT_REQUESTS_LIMIT);

    let mut parts: Vec<(usize, String)> = fetches
        .then(|(idx, body)| async move {
            // 使用 web::block 处理 CPU 密集型的 HTML 解析
            let text_res = web::block(move || html_to_text(&body)).await;
            match text_res {
                Ok(text) => (idx, text),
                Err(_) => (idx, String::new()),
            }
        })
        .filter(|(_, text)| {
            let is_empty = text.trim().is_empty();
            async move { !is_empty }
        })
        .collect()
        .await;

    parts.sort_by_key(|(i, _)| *i);
    let ordered: Vec<String> = parts.into_iter().map(|(_, s)| s).collect();
    let full_text = ordered.join("\n\n");
    HttpResponse::Ok()
        .content_type("text/plain; charset=utf-8")
        .body(full_text)
}

#[get("/{username}/clash")]
async fn get_clash_config(path: web::Path<String>, req: HttpRequest) -> impl Responder {
    let username = path.into_inner();

    // Read config/clash.yaml
    let clash_config = match std::fs::read_to_string("config/clash.yaml") {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("Failed to read clash.yaml: {}", e);
            return HttpResponse::InternalServerError().body("Config file missing");
        }
    };

    // Determine base URL
    let connection_info = req.connection_info();
    let scheme = connection_info.scheme();
    let host = connection_info.host();
    let base_url = format!("{}://{}", scheme, host);

    // Replace placeholders
    let content = clash_config
        .replace("{username}", &username)
        .replace("{url}", &base_url);

    HttpResponse::Ok()
        .content_type("text/yaml; charset=utf-8")
        .body(content)
}

fn html_to_text(input: &str) -> String {
    let document = Html::parse_document(input);
    let mut buffer = String::new();
    walk_node(document.tree.root().id(), &document, &mut buffer);
    buffer.trim().to_string()
}

fn walk_node(node_id: ego_tree::NodeId, doc: &Html, buffer: &mut String) {
    let node = if let Some(n) = doc.tree.get(node_id) {
        n
    } else {
        return;
    };

    if let Node::Element(element) = node.value() {
        let tag = element.name();
        if tag == "script" || tag == "style" || tag == "head" {
            return;
        }
        if is_block_element(tag) {
            ensure_newlines(buffer, 2);
        } else if tag == "br" {
            buffer.push('\n');
        }
    }

    if let Node::Text(text) = node.value() {
        let s = text.trim();
        if !s.is_empty() {
            if buffer.ends_with(|c: char| !c.is_whitespace()) {
                buffer.push(' ');
            }
            buffer.push_str(s);
        }
    }

    for child in node.children() {
        walk_node(child.id(), doc, buffer);
    }

    if let Node::Element(element) = node.value()
        && is_block_element(element.name())
    {
        ensure_newlines(buffer, 2);
    }
}

fn ensure_newlines(buffer: &mut String, n: usize) {
    if buffer.is_empty() {
        return;
    }
    let existing_newlines = buffer.chars().rev().take_while(|c| *c == '\n').count();
    for _ in existing_newlines..n {
        buffer.push('\n');
    }
}

fn is_block_element(tag: &str) -> bool {
    matches!(
        tag,
        "address"
            | "article"
            | "aside"
            | "blockquote"
            | "canvas"
            | "dd"
            | "div"
            | "dl"
            | "dt"
            | "fieldset"
            | "figcaption"
            | "figure"
            | "footer"
            | "form"
            | "h1"
            | "h2"
            | "h3"
            | "h4"
            | "h5"
            | "h6"
            | "header"
            | "hr"
            | "li"
            | "main"
            | "nav"
            | "noscript"
            | "ol"
            | "p"
            | "pre"
            | "section"
            | "table"
            | "tfoot"
            | "ul"
            | "video"
            | "tr"
    )
}

#[get("/healthz")]
async fn healthz() -> impl Responder {
    HttpResponse::Ok().body("ok")
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // 1. 加载配置
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
            // 移除了 Actix 的 Logger 避免重复日志
            .wrap(IdentityMiddleware::default())
            .wrap(
                SessionMiddleware::builder(CookieSessionStore::default(), secret_key.clone())
                    .cookie_name("sub_auth".to_owned())
                    .cookie_secure(app_config.server.cookie_secure)
                    .session_lifecycle(PersistentSession::default().session_ttl(Duration::days(7)))
                    .build(),
            )
            .service(Files::new("/static", "web"))
            .service(login)
            .service(logout)
            .service(get_me)
            .service(update_account)
            .service(list_users)
            .service(create_user)
            .service(delete_user)
            .service(set_user_order)
            .service(get_links)
            .service(set_links)
            .service(healthz)
            .service(get_clash_config)
            .service(merged_user)
            .route(
                "/",
                web::get().to(|| async { actix_files::NamedFile::open("web/index.html") }),
            )
    })
    .bind(&bind_addr)?
    .run()
    .await
}
