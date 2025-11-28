use actix_files::NamedFile;
use actix_web::{
    App, HttpResponse, HttpServer, Responder, Result, delete, get, middleware::Logger, post, put,
    web,
};
use futures::stream::{FuturesUnordered, StreamExt};
use html_escape::decode_html_entities;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs;
// Cursor imports removed (not needed)
use std::sync::Mutex;
mod log;

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
                        tracing::error!("failed to parse data file as TOML: {}", e);
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
    tracing::info!(%username, "user created");
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
        tracing::info!(%username, "user deleted");
        HttpResponse::Ok().body("deleted")
    } else {
        tracing::warn!(%username, "user not found for delete");
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
        tracing::info!(%username, count = u.links.len(), "get_links");
        HttpResponse::Ok().json(u.links.clone())
    } else {
        tracing::warn!(%username, "get_links: user not found");
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
            tracing::warn!(%username, "set_links: user not found");
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
        tracing::warn!(expected = ?existing, incoming = ?incoming, "set_user_order: incoming order mismatch");
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
    tracing::info!(count = users.len(), "set_user_order updated");
    HttpResponse::Ok().json(order)
}

// GET /{username} returns merged content of the user's links.
#[get("/{username}")]
async fn merged_user(path: web::Path<String>, data: web::Data<AppState>) -> impl Responder {
    let username = path.into_inner();
    tracing::info!(%username, "Handling merged_user request");
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
                    Err(e) => {
                        tracing::warn!(%link, error=%e, "failed to read body");
                        format!("<!-- failed to read body {}: {} -->", link, e)
                    }
                },
                Err(e) => {
                    tracing::warn!(%link, error=%e, "failed to fetch link");
                    format!("<!-- failed to fetch {}: {} -->", link, e)
                }
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
            // Preserve spaces and tabs coming from the fetched content unchanged.
            // We still use `text.trim().is_empty()` to skip completely-empty responses
            // but we don't trim the content when storing so leading/trailing spaces/tabs
            // within the link body are kept.
            parts.push((_idx, text.to_string()));
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

    // Preserve <pre> contents (keep internal newlines). We will remove the enclosing tags
    // but keep what's inside intact so preformatted text retains line breaks.
    // We'll encode newlines inside <pre> blocks into a placeholder so later
    // trimming/collapsing won't accidentally remove leading spaces that are
    // meant to be preserved inside preformatted sections.
    let pre_token = "___PRE_NL___";
    let re_pre = Regex::new(r"(?is)<pre[^>]*>(?s)(.*?)</pre>").unwrap();
    let with_pre = re_pre.replace_all(&without_scripts, |caps: &regex::Captures| {
        let inner = &caps[1];
        // normalize CRLF and encode newlines to token
        let encoded = inner.replace("\r\n", "\n").replace("\n", pre_token);
        format!("\n\n{}\n\n", encoded)
    });

    // Convert <br> to a newline
    let re_br = Regex::new(r"(?i)<br\s*/?>").unwrap();
    let with_br = re_br.replace_all(&with_pre, "\n");

    // Treat common block-level closing tags as paragraph separators (insert blank line)
    let re_block_close = Regex::new(r"(?i)</(p|div|li|h[1-6]|tr|section|header|footer|article|blockquote|table|tbody|thead|ul|ol)>\s*").unwrap();
    let with_blocks = re_block_close.replace_all(&with_br, "\n\n");

    // strip any remaining tags (remove them entirely; block-level separators were
    // inserted previously so we don't need tag->space substitution)
    let re_tags = Regex::new(r"(?s)<[^>]+>").unwrap();
    let stripped = re_tags.replace_all(&with_blocks, "");

    // Keep spaces and tabs as they appear in the body. We intentionally do not
    // collapse multiple spaces or tabs — the client asked to preserve them.
    let collapsed = stripped;

    // collapse runs of 3+ newlines down to at most two
    let re_multi_nl = Regex::new(r"\n{3,}").unwrap();
    let collapsed_nl = re_multi_nl.replace_all(&collapsed, "\n\n");

    // restore preformatted newlines
    let restored = collapsed_nl.replace(pre_token, "\n");
    // Do NOT trim — preserve leading/trailing spaces and tabs inside content
    decode_html_entities(&restored).to_string()
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

    // read expected API key from env: prefer API (compose); default to 'api'
    let api_key = std::env::var("API").unwrap_or_else(|_| "api".into());
    let state = web::Data::new(AppState {
        users: Mutex::new(map),
        api_key,
    });

    // Initialize structured logging for Docker-friendly output
    log::init_logging();
    tracing::info!("Starting server at http://0.0.0.0:8080");

    HttpServer::new(move || {
        App::new()
            .app_data(state.clone())
            // Create a tracing span per request (adds structured fields like path, method, client IP, user-agent, request-id)
            .wrap(actix_web::middleware::from_fn(log::trace_requests))
            // Keep the actix Logger to maintain formatted request lines if desired
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

    #[actix_web::test]
    async fn test_html_to_text_preserve_br_and_pre() {
        let html_br = "<div>line1<br/>line2</div>";
        let out_br = html_to_text(html_br);
        // Expect a newline between lines (do not collapse into single line)
        assert!(out_br.contains("line1\nline2"), "got: {}", out_br);

        let html_pre = "<pre>one\n two\nthree</pre>";
        let out_pre = html_to_text(html_pre);
        // Pre should preserve internal newlines
        assert!(out_pre.contains("one\n two\nthree"), "got: {}", out_pre);
    }

    #[actix_web::test]
    async fn test_html_to_text_block_tags() {
        let html = "<p>first paragraph</p><div>second</div><p>third</p>";
        let out = html_to_text(html);
        // Expect paragraph-level separation
        assert!(out.contains("first paragraph\n\nsecond"), "got: {}", out);
        assert!(out.contains("second\n\nthird"), "got: {}", out);
    }

    #[actix_web::test]
    async fn test_html_to_text_preserve_spaces_and_tabs() {
        let html = "<div>one\t\ttwo   three</div>";
        let out = html_to_text(html);
        assert!(out.contains("one\t\ttwo   three"), "got: {}", out);

        let html2 = "<div>  leading and\ttrailing  </div>";
        let out2 = html_to_text(html2);
        // internal spaces and tabs should be preserved (we allow leading/trailing
        // to remain since user requested keeping spaces/tabs)
        assert!(out2.contains("  leading and\ttrailing  "), "got: {}", out2);
    }

    #[actix_web::test]
    async fn test_static_serves_favicon() {
        use actix_web::{App, test};
        // Initialize app with only the static_files service
        let app = test::init_service(App::new().service(static_files)).await;

        let req = test::TestRequest::with_uri("/static/favicon.ico").to_request();
        let resp = test::call_service(&app, req).await;
        // Ensure we get 200 OK for the favicon
        assert!(
            resp.status().is_success(),
            "favicon not served: {}",
            resp.status()
        );
    }

    #[actix_web::test]
    async fn test_x_request_id_header_present() {
        use actix_web::{App, test};
        // Initialize app with middleware and a route
        let app = test::init_service(
            App::new()
                .wrap(actix_web::middleware::from_fn(crate::log::trace_requests))
                .service(healthz),
        )
        .await;

        let req = test::TestRequest::get().uri("/healthz").to_request();
        let resp = test::call_service(&app, req).await;
        assert!(resp.headers().contains_key("x-request-id"));
    }
}
