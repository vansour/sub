use actix_files::NamedFile;
use actix_web::{App, HttpResponse, HttpServer, Responder, Result, delete, get, post, put, web};
use futures::stream::{FuturesUnordered, StreamExt};
use html_escape::decode_html_entities;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs;
// Cursor imports removed (not needed)
use std::sync::Mutex;

const DATA_FILE: &str = "data/data.toml";

#[derive(Debug, Serialize, Deserialize, Clone)]
struct UserRecord {
    username: String,
    links: Vec<String>,
}

#[derive(Debug, Default)]
struct AppState {
    // preserve order in a Vec so front-end can reorder users
    users: Mutex<Vec<UserRecord>>,
    api_key: String,
}

#[derive(Serialize, Deserialize)]
struct TomlData {
    users: Vec<UserRecord>,
}

fn load_data() -> Vec<UserRecord> {
    if let Ok(s) = std::fs::read_to_string(DATA_FILE) {
        let s_trim = s.trim();
        if s_trim.is_empty() {
            return Vec::new();
        }
        match toml::from_str::<TomlData>(&s) {
            Ok(d) => d.users,
            Err(e) => {
                // try JSON fallback for backwards compatibility
                match serde_json::from_str::<Vec<UserRecord>>(&s) {
                    Ok(list) => list,
                    Err(_) => {
                        eprintln!("failed to parse data file as TOML: {}", e);
                        Vec::new()
                    }
                }
            }
        }
    } else {
        Vec::new()
    }
}

fn save_data(list: &[UserRecord]) {
    let out = TomlData {
        users: list.to_owned(),
    };
    if let Ok(s) = toml::to_string_pretty(&out) {
        let _ = fs::write(DATA_FILE, s);
    }
}

use actix_web::HttpRequest;

fn check_api(req: &HttpRequest, state: &web::Data<AppState>) -> bool {
    // Accept either query param 'api' or header 'x-api-key'
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
    Ok(NamedFile::open(format!("web/{}", filename))?)
}

#[get("/api/users")]
async fn list_users(req: HttpRequest, data: web::Data<AppState>) -> impl Responder {
    if !check_api(&req, &data) {
        return HttpResponse::Forbidden().body("invalid api");
    }
    let users = data.users.lock().unwrap();
    let list: Vec<String> = users.iter().map(|u| u.username.clone()).collect();
    HttpResponse::Ok().json(list)
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
    let mut users = data.users.lock().unwrap();
    let username = payload.username.trim().to_string();
    if username.is_empty() {
        return HttpResponse::BadRequest().body("empty username");
    }
    if users.iter().any(|u| u.username == username) {
        return HttpResponse::Conflict().body("user exists");
    }
    let rec = UserRecord {
        username: username.clone(),
        links: vec![],
    };
    users.push(rec);
    save_data(&users);
    HttpResponse::Created().json(username)
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
    let mut users = data.users.lock().unwrap();
    if let Some(pos) = users.iter().position(|u| u.username == username) {
        users.remove(pos);
        save_data(&users);
        HttpResponse::Ok().body("deleted")
    } else {
        HttpResponse::NotFound().body("not found")
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
    let users = data.users.lock().unwrap();
    if let Some(u) = users.iter().find(|u| u.username == username) {
        HttpResponse::Ok().json(u.links.clone())
    } else {
        HttpResponse::NotFound().body("user not found")
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

// preview route removed — preview is not used by the UI anymore

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
    let username = path.into_inner();
    let new_links = payload.links.clone();
    {
        let mut users = data.users.lock().unwrap();
        if let Some(u) = users.iter_mut().find(|u| u.username == username) {
            u.links = new_links.clone();
        } else {
            return HttpResponse::NotFound().body("user not found");
        }
        // save updated list
        save_data(&users);
    }
    HttpResponse::Ok().json(new_links)
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

    let order = payload.order.clone();
    if order.is_empty() {
        return HttpResponse::BadRequest().body("order must not be empty");
    }

    let mut users = data.users.lock().unwrap();
    // validate same set of usernames
    let existing: HashSet<String> = users.iter().map(|u| u.username.clone()).collect();
    let incoming: HashSet<String> = order.iter().cloned().collect();
    if existing != incoming {
        return HttpResponse::BadRequest().body("order must include exactly the same usernames");
    }

    // rebuild in requested order
    let mut reordered: Vec<UserRecord> = Vec::with_capacity(users.len());
    for name in order.iter() {
        if let Some(u) = users.iter().find(|u| &u.username == name) {
            reordered.push(u.clone());
        }
    }

    *users = reordered;
    save_data(&users);
    HttpResponse::Ok().json(order)
}

// GET /{username} returns merged content of the user's links.
#[get("/{username}")]
async fn merged_user(path: web::Path<String>, data: web::Data<AppState>) -> impl Responder {
    let username = path.into_inner();
    // take a short-lived lock to clone the user record, don't hold the MutexGuard across await points
    let user = {
        let users = data.users.lock().unwrap();
        match users.iter().find(|u| u.username == username) {
            Some(u) => u.clone(),
            None => return HttpResponse::NotFound().body("user not found"),
        }
    };

    if user.links.is_empty() {
        // return empty plain text when there are no links configured
        return HttpResponse::Ok()
            .content_type("text/plain; charset=utf-8")
            .body("");
    }

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .unwrap();

    // Run requests concurrently but preserve original order.
    // We push index information into each future so we can reorder later.
    let mut futures = FuturesUnordered::new();
    for (idx, link) in user.links.iter().enumerate() {
        let link = link.clone();
        let c = client.clone();
        futures.push(async move {
            let resp_text = match c.get(&link).send().await {
                Ok(r) => match r.text().await {
                    Ok(t) => t,
                    Err(e) => format!("<!-- failed to read body {}: {} -->", link, e),
                },
                Err(e) => format!("<!-- failed to fetch {}: {} -->", link, e),
            };
            (idx, link, resp_text)
        });
    }

    // Collect bodies with their indexes so we can sort into the original order
    let mut parts: Vec<(usize, String)> = vec![];
    while let Some((_idx, _link, body)) = futures.next().await {
        // Convert HTML to plain text without line-wrapping (large width)
        // use a large width so html2text doesn't insert forced newlines
        let text = html_to_text(&body);
        if !text.trim().is_empty() {
            parts.push((_idx, text.trim().to_string()));
        }
    }

    // Sort by original index to preserve the link order (ascending)
    parts.sort_by_key(|(i, _)| *i);
    let ordered: Vec<String> = parts.into_iter().map(|(_, s)| s).collect();
    let full_text = ordered.join("\n\n");
    HttpResponse::Ok()
        .content_type("text/plain; charset=utf-8")
        .body(full_text)
}

fn html_to_text(input: &str) -> String {
    // remove script/style blocks
    let re_script = Regex::new(r"(?is)<(script|style)[^>]*>.*?</(script|style)>").unwrap();
    let without_scripts = re_script.replace_all(input, "");

    // strip remaining tags
    let re_tags = Regex::new(r"(?s)<[^>]+>").unwrap();
    let stripped = re_tags.replace_all(&without_scripts, " ");

    // collapse whitespace and decode entities
    let re_space = Regex::new(r"\s+").unwrap();
    let joined = re_space.replace_all(&stripped, " ");
    decode_html_entities(&joined.trim()).to_string()
}
#[get("/healthz")]
async fn healthz() -> impl Responder {
    HttpResponse::Ok().body("ok")
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Ensure data directory and data file exist. Use defaults from .defaults/data if present.
    let data_path = std::path::Path::new(DATA_FILE);
    if let Some(dir) = data_path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }

    if !data_path.exists() {
        // try to copy defaults (if present)
        if std::path::Path::new(".defaults/data/data.toml").exists() {
            let _ = std::fs::copy(".defaults/data/data.toml", DATA_FILE);
        } else {
            // write an empty users table
            let _ = fs::write(DATA_FILE, "users = []\n");
        }
    }

    let map = load_data();

    // read expected API key from env: prefer API (compose), fallback to SUB_API_KEY, default to 'api'
    let api_key = std::env::var("API")
        .ok()
        .or_else(|| std::env::var("SUB_API_KEY").ok())
        .unwrap_or_else(|| "api".into());
    let state = web::Data::new(AppState {
        users: Mutex::new(map),
        api_key,
    });

    println!("Starting server at http://0.0.0.0:8080");

    HttpServer::new(move || {
        App::new()
            .app_data(state.clone())
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

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::http::StatusCode;
    use actix_web::{test, web};

    #[actix_web::test]
    async fn test_set_user_order_ok() {
        let users = vec![
            UserRecord {
                username: "alice".into(),
                links: vec![],
            },
            UserRecord {
                username: "bob".into(),
                links: vec![],
            },
            UserRecord {
                username: "charlie".into(),
                links: vec![],
            },
        ];
        let state = web::Data::new(AppState {
            users: Mutex::new(users),
            api_key: "api".into(),
        });

        let payload = OrderPayload {
            order: vec!["charlie".into(), "alice".into(), "bob".into()],
        };

        let app =
            test::init_service(App::new().app_data(state.clone()).service(set_user_order)).await;

        let req = test::TestRequest::put()
            .uri("/api/users/order?api=api")
            .set_json(&payload)
            .to_request();
        let resp = test::call_service(&app, req).await;

        // Ensure success
        assert_eq!(resp.status(), StatusCode::OK);

        // ensure internal user order changed
        let users = state.users.lock().unwrap();
        let names: Vec<String> = users.iter().map(|u| u.username.clone()).collect();
        assert_eq!(names, vec!["charlie", "alice", "bob"]);
    }

    #[actix_web::test]
    async fn test_set_user_order_bad_request() {
        let users = vec![
            UserRecord {
                username: "alice".into(),
                links: vec![],
            },
            UserRecord {
                username: "bob".into(),
                links: vec![],
            },
        ];
        let state = web::Data::new(AppState {
            users: Mutex::new(users),
            api_key: "api".into(),
        });

        // missing 'bob' in order
        let payload = OrderPayload {
            order: vec!["alice".into()],
        };
        let app =
            test::init_service(App::new().app_data(state.clone()).service(set_user_order)).await;
        let req = test::TestRequest::put()
            .uri("/api/users/order?api=api")
            .set_json(&payload)
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }
}
