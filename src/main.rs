use actix_files::NamedFile;
use actix_web::{
    App, HttpRequest, HttpResponse, HttpServer, Responder, Result, delete, get, middleware::Logger,
    post, put, web,
};
use futures::stream::StreamExt; // 移除了未使用的 FuturesUnordered
use html_escape::decode_html_entities;
use regex::Regex;
use serde::{Deserialize, Serialize};
use sqlx::{Row, SqlitePool, sqlite::SqlitePoolOptions};
use std::path::Path;

mod log;

// 数据库文件路径
const DB_URL: &str = "sqlite:data/sub.db";
// 限制并发抓取数
const CONCURRENT_REQUESTS_LIMIT: usize = 5;

// 修复 1: 移除了未使用的 UserRecord 结构体

#[derive(Debug)]
struct AppState {
    db: SqlitePool,
    api_key: String,
}

// 检查 API Key 的辅助函数
fn check_api(req: &HttpRequest, state: &web::Data<AppState>) -> bool {
    if let Some(q) = req.uri().query() {
        for (k, v) in url::form_urlencoded::parse(q.as_bytes()) {
            if k == "api" && v == state.api_key.as_str() {
                return true;
            }
        }
    }
    if req.headers().get("x-api-key").and_then(|h| h.to_str().ok()) == Some(state.api_key.as_str())
    {
        return true;
    }
    false
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
    Ok(())
}

#[get("/")]
async fn index(req: HttpRequest, data: web::Data<AppState>) -> impl Responder {
    if !check_api(&req, &data) {
        return HttpResponse::Forbidden().body("missing or invalid api key");
    }
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
async fn list_users(req: HttpRequest, data: web::Data<AppState>) -> impl Responder {
    if !check_api(&req, &data) {
        return HttpResponse::Forbidden().body("invalid api");
    }

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
    req: HttpRequest,
    payload: web::Json<CreateUserPayload>,
    data: web::Data<AppState>,
) -> impl Responder {
    if !check_api(&req, &data) {
        return HttpResponse::Forbidden().body("invalid api");
    }
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
    req: HttpRequest,
    path: web::Path<String>,
    data: web::Data<AppState>,
) -> impl Responder {
    if !check_api(&req, &data) {
        return HttpResponse::Forbidden().body("invalid api");
    }
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
    req: HttpRequest,
    path: web::Path<String>,
    data: web::Data<AppState>,
) -> impl Responder {
    if !check_api(&req, &data) {
        return HttpResponse::Forbidden().body("invalid api");
    }
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
    req: HttpRequest,
    path: web::Path<String>,
    payload: web::Json<LinksPayload>,
    data: web::Data<AppState>,
) -> impl Responder {
    if !check_api(&req, &data) {
        return HttpResponse::Forbidden().body("invalid api");
    }

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
    req: HttpRequest,
    payload: web::Json<OrderPayload>,
    data: web::Data<AppState>,
) -> impl Responder {
    if !check_api(&req, &data) {
        return HttpResponse::Forbidden().body("invalid api");
    }

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

    // 修复 2: 使用 stream + buffer_unordered 来应用并发限制常量
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

    let api_key = std::env::var("API").unwrap_or_else(|_| "api".into());

    let pool = SqlitePoolOptions::new()
        .max_connections(5)
        .connect(DB_URL)
        .await
        .expect("Failed to connect to SQLite");

    init_db(&pool)
        .await
        .expect("Failed to initialize DB schema");

    let state = web::Data::new(AppState { db: pool, api_key });

    log::init_logging();
    tracing::info!("Starting server at http://0.0.0.0:8080 with SQLite");

    HttpServer::new(move || {
        App::new()
            .app_data(state.clone())
            .wrap(actix_web::middleware::from_fn(log::trace_requests))
            .wrap(Logger::new("%a \"%r\" %s %b %D \"%{User-Agent}i\""))
            .service(index)
            .service(static_files)
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
