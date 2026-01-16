use actix_web::{HttpResponse, Responder, get, web};
use futures::stream::StreamExt;
use reqwest::Url;
use scraper::{Html, Node};
use sqlx::Row;
use std::net::ToSocketAddrs;

use crate::config;
use crate::error::AppError;
use crate::error::AppResult;
use crate::state::AppState;

// SSRF Protection: 检查 URL 是否解析到私有地址
fn is_safe_url(url_str: &str) -> bool {
    let url = match Url::parse(url_str) {
        Ok(u) => u,
        Err(_) => return false,
    };

    let host = match url.host_str() {
        Some(h) => h,
        None => return false,
    };

    // 尝试解析主机名
    // 注意：这将执行 DNS 查询，可能会有点慢。
    // 生产环境中最好有缓存或专门的 DNS 解析器，或者使用 allowlist。
    let port = url.port_or_known_default().unwrap_or(80);
    let socket_addrs = match (host, port).to_socket_addrs() {
        Ok(iter) => iter,
        Err(_) => return false, // 无法解析也视为不安全
    };

    for addr in socket_addrs {
        let ip = addr.ip();
        if ip.is_loopback() || ip.is_unspecified() {
            return false;
        }
        match ip {
            std::net::IpAddr::V4(ipv4) => {
                // Check private ranges
                // 10.0.0.0/8
                // 172.16.0.0/12
                // 192.168.0.0/16
                // 169.254.0.0/16
                if ipv4.is_private() || ipv4.is_link_local() {
                    return false;
                }
            }
            std::net::IpAddr::V6(ipv6) => {
                if (ipv6.segments()[0] & 0xfe00) == 0xfc00 {
                    return false; // Unique local address (ULA)
                }
                if (ipv6.segments()[0] & 0xffc0) == 0xfe80 {
                    return false; // Link-local
                }
            }
        }
    }

    true
}

#[get("/{username}")]
pub async fn merged_user(
    path: web::Path<String>,
    data: web::Data<AppState>,
    config: web::Data<config::AppConfig>,
) -> AppResult<impl Responder> {
    let username = path.into_inner();

    let row = sqlx::query("SELECT links FROM users WHERE username = $1")
        .bind(&username)
        .fetch_optional(&data.db)
        .await?;

    let links: Vec<String> = match row {
        Some(r) => {
            let val: serde_json::Value = r.get("links");
            serde_json::from_value(val).unwrap_or_default()
        }
        None => return Err(AppError::NotFound("user not found".into())),
    };

    if links.is_empty() {
        return Ok(HttpResponse::Ok()
            .content_type("text/plain; charset=utf-8")
            .body(""));
    }

    let concurrent_limit = config.server.concurrent_requests;

    let fetches = futures::stream::iter(links.into_iter().enumerate().map(|(idx, link)| {
        let client = data.client.clone();
        async move {
            // SSRF Check
            if !is_safe_url(&link) {
                return (idx, format!("<!-- blocked unsafe url: {} -->", link), false);
            }

            let (body, is_html) = match client.get(&link).send().await {
                Ok(r) => {
                    let is_html = r
                        .headers()
                        .get(reqwest::header::CONTENT_TYPE)
                        .and_then(|v| v.to_str().ok())
                        .map(|v| v.contains("text/html"))
                        .unwrap_or(false);

                    match r.text().await {
                        Ok(t) => (t, is_html),
                        Err(e) => (
                            format!("<!-- failed to read body {}: {} -->", link, e),
                            false,
                        ),
                    }
                }
                Err(e) => (format!("<!-- failed to fetch {}: {} -->", link, e), false),
            };
            (idx, body, is_html)
        }
    }))
    .buffer_unordered(concurrent_limit);

    let mut parts: Vec<(usize, String)> = fetches
        .then(|(idx, body, is_html)| async move {
            if is_html {
                let text_res = web::block(move || html_to_text(&body)).await;
                match text_res {
                    Ok(text) => (idx, text),
                    Err(_) => (idx, String::new()),
                }
            } else {
                (idx, body.trim().to_string())
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
    Ok(HttpResponse::Ok()
        .content_type("text/plain; charset=utf-8")
        .body(full_text))
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
