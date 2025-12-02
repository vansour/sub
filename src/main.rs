use actix_files::NamedFile;
use actix_identity::{Identity, IdentityMiddleware};
use actix_session::{SessionMiddleware, config::PersistentSession, storage::CookieSessionStore};
use actix_web::{
    App, HttpMessage, HttpRequest, HttpResponse, HttpServer, Responder, Result,
    cookie::{Key, time::Duration},
    delete, get,
    middleware::Logger,
    post, put, web,
};
use argon2::{
    Argon2,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString, rand_core::OsRng},
};
use futures::stream::StreamExt;
use html_escape::decode_html_entities;
use regex::Regex;
use serde::{Deserialize, Serialize};
use sqlx::{Row, SqlitePool, sqlite::SqlitePoolOptions};
use std::path::Path;

mod log;

const DB_URL: &str = "sqlite:data/sub.db";
const CONCURRENT_REQUESTS_LIMIT: usize = 5;

#[derive(Debug)]
struct AppState {
    db: SqlitePool,
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

// 初始化数据库表
async fn init_db(pool: &SqlitePool) -> std::result::Result<(), sqlx::Error> {
    // 用户表
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            links TEXT NOT NULL DEFAULT '[]',
            rank INTEGER NOT NULL DEFAULT 0
        );
        "#,
    )
    .execute(pool)
    .await?;

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
async fn ensure_admin(pool: &SqlitePool) {
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
        let password_hash = argon2
            .hash_password(password.as_bytes(), &salt)
            .unwrap()
            .to_string();

        let _ = sqlx::query("INSERT INTO admins (username, password_hash) VALUES (?, ?)")
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
    let row = sqlx::query("SELECT password_hash FROM admins WHERE username = ?")
        .bind(&payload.username)
        .fetch_optional(&data.db)
        .await;

    match row {
        Ok(Some(r)) => {
            let hash_str: String = r.get(0);
            let parsed_hash = PasswordHash::new(&hash_str).unwrap();
            if Argon2::default()
                .verify_password(payload.password.as_bytes(), &parsed_hash)
                .is_ok()
            {
                // 登录成功，设置 Identity
                Identity::login(&req.extensions(), payload.username.clone()).unwrap();
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
        Some(id) => HttpResponse::Ok().json(serde_json::json!({ "username": id.id().unwrap() })),
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

    // Update DB (Primary key update)
    let result =
        sqlx::query("UPDATE admins SET username = ?, password_hash = ? WHERE username = ?")
            .bind(new_username)
            .bind(password_hash)
            .bind(&current_user)
            .execute(&data.db)
            .await;

    match result {
        Ok(_) => {
            // 登出用户，要求重新登录
            id.logout();
            HttpResponse::Ok().body("Account updated, please login again")
        }
        Err(e) => {
            tracing::error!("Update account error: {}", e);
            // 可能是用户名冲突
            HttpResponse::InternalServerError()
                .body("Failed to update account (username might exist)")
        }
    }
}

// --- 业务接口 ---

#[get("/")]
async fn index(req: HttpRequest) -> impl Responder {
    match NamedFile::open("web/index.html") {
        Ok(f) => f.into_response(&req),
        Err(e) => HttpResponse::InternalServerError().body(format!("open index failed: {}", e)),
    }
}

#[get("/static/{filename:.*}")]
async fn static_files(path: web::Path<String>) -> Result<NamedFile> {
    let filename = path.into_inner();
    if filename.contains("..") || filename.starts_with('/') || filename.contains('\\') {
        return Err(actix_web::error::ErrorForbidden("Invalid path"));
    }
    Ok(NamedFile::open(format!("web/{}", filename))?)
}

#[get("/api/users")]
async fn list_users(_id: Identity, data: web::Data<AppState>) -> impl Responder {
    // Identity 提取器会自动验证是否登录，未登录则返回 401
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

    let result = sqlx::query("INSERT INTO users (username, links, rank) VALUES (?, '[]', ?)")
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
            let msg = e.to_string();
            if msg.contains("UNIQUE constraint failed") || msg.contains("constraint failed") {
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

    let result = sqlx::query("DELETE FROM users WHERE username = ?")
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

    let row = sqlx::query("SELECT links FROM users WHERE username = ?")
        .bind(&username)
        .fetch_optional(&data.db)
        .await;

    match row {
        Ok(Some(r)) => {
            let links_json: String = r.get("links");
            let links: Vec<String> = serde_json::from_str(&links_json).unwrap_or_default();
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
    let links_json = serde_json::to_string(&payload.links).unwrap_or_else(|_| "[]".to_string());

    let result = sqlx::query("UPDATE users SET links = ? WHERE username = ?")
        .bind(&links_json)
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
        let res = sqlx::query("UPDATE users SET rank = ? WHERE username = ?")
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

// 公开接口，无需登录
#[get("/{username}")]
async fn merged_user(path: web::Path<String>, data: web::Data<AppState>) -> impl Responder {
    let username = path.into_inner();

    let row = sqlx::query("SELECT links FROM users WHERE username = ?")
        .bind(&username)
        .fetch_optional(&data.db)
        .await;

    let links: Vec<String> = match row {
        Ok(Some(r)) => {
            let json: String = r.get("links");
            serde_json::from_str(&json).unwrap_or_default()
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

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .unwrap();

    let fetches = futures::stream::iter(links.into_iter().enumerate().map(|(idx, link)| {
        let client = client.clone();
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
        .filter_map(|(idx, body)| async move {
            let text = html_to_text(&body);
            if text.trim().is_empty() {
                None
            } else {
                Some((idx, text))
            }
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

fn html_to_text(input: &str) -> String {
    let re_script = Regex::new(r"(?is)<(script|style)[^>]*>.*?</(script|style)>").unwrap();
    let without_scripts = re_script.replace_all(input, "");

    let pre_token = "___PRE_NL___";
    let re_pre = Regex::new(r"(?is)<pre[^>]*>(?s)(.*?)</pre>").unwrap();
    let with_pre = re_pre.replace_all(&without_scripts, |caps: &regex::Captures| {
        let inner = &caps[1];
        let encoded = inner.replace("\r\n", "\n").replace("\n", pre_token);
        format!("\n\n{}\n\n", encoded)
    });

    let re_br = Regex::new(r"(?i)<br\s*/?>").unwrap();
    let with_br = re_br.replace_all(&with_pre, "\n");

    let re_block_close = Regex::new(r"(?i)</(p|div|li|h[1-6]|tr|section|header|footer|article|blockquote|table|tbody|thead|ul|ol)>\s*").unwrap();
    let with_blocks = re_block_close.replace_all(&with_br, "\n\n");

    let re_tags = Regex::new(r"(?s)<[^>]+>").unwrap();
    let stripped = re_tags.replace_all(&with_blocks, "");

    let collapsed = stripped;
    let re_multi_nl = Regex::new(r"\n{3,}").unwrap();
    let collapsed_nl = re_multi_nl.replace_all(&collapsed, "\n\n");
    let restored = collapsed_nl.replace(pre_token, "\n");

    decode_html_entities(&restored).to_string()
}

#[get("/healthz")]
async fn healthz() -> impl Responder {
    HttpResponse::Ok().body("ok")
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let db_path = Path::new("data/sub.db");
    if let Some(dir) = db_path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }

    if !db_path.exists() {
        std::fs::File::create(db_path)?;
    }

    // 读取或生成 SESSION KEY
    let secret_key = Key::generate();

    let pool = SqlitePoolOptions::new()
        .max_connections(5)
        .connect(DB_URL)
        .await
        .expect("Failed to connect to SQLite");

    init_db(&pool)
        .await
        .expect("Failed to initialize DB schema");

    ensure_admin(&pool).await;

    let state = web::Data::new(AppState { db: pool });

    log::init_logging();
    tracing::info!("Starting server at http://0.0.0.0:8080 with SQLite");

    HttpServer::new(move || {
        App::new()
            .app_data(state.clone())
            .wrap(actix_web::middleware::from_fn(log::trace_requests))
            .wrap(Logger::new("%a \"%r\" %s %b %D \"%{User-Agent}i\""))
            // 启用 Identity 身份验证中间件
            .wrap(IdentityMiddleware::default())
            // 启用 Session 中间件
            .wrap(
                SessionMiddleware::builder(CookieSessionStore::default(), secret_key.clone())
                    .cookie_name("sub_auth".to_owned())
                    .cookie_secure(false) // 生产环境建议为 true 并配合 HTTPS
                    .session_lifecycle(PersistentSession::default().session_ttl(Duration::days(7)))
                    .build(),
            )
            .service(index)
            .service(static_files)
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
            .service(merged_user)
    })
    .bind(("0.0.0.0", 8080))?
    .run()
    .await
}
