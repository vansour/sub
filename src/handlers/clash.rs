use axum::{
    extract::Path,
    http::{HeaderMap, HeaderValue, StatusCode},
    response::Response,
};

/// 生成 Clash 配置：将 default.yaml 中的 {username} 替换为实际用户名
pub async fn clash_config(headers: HeaderMap, Path(username): Path<String>) -> Response {
    // 读取模板文件
    let template_path = "data/clash/default.yaml";
    // Try to canonicalize to help debugging logs (may fail if file missing)
    let canonical = std::path::Path::new(template_path).canonicalize();
    match build_clash_content(&headers, &username, template_path).await {
        Ok(replaced) => {
            // replaced content produced by build_clash_content

            let mut response = Response::new(replaced.into());
            *response.status_mut() = StatusCode::OK;
            response.headers_mut().insert(
                axum::http::header::CONTENT_TYPE,
                HeaderValue::from_static("text/yaml; charset=utf-8"),
            );

            response
        }
        Err(err) => {
            match canonical {
                Ok(abs) => tracing::error!(path = %abs.display(), error = %err, "failed to read clash template at path"),
                Err(_) => tracing::error!(path = template_path, error = %err, "failed to read clash template (path not canonicalizable)"),
            }
            let mut response = Response::new("failed to load clash template".into());
            *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
            response.headers_mut().insert(
                axum::http::header::CONTENT_TYPE,
                HeaderValue::from_static("text/plain; charset=utf-8"),
            );
            response
        }
    }
}

/// Build the final clash template string for a given username and request headers.
///
/// Reads the template at `template_path`, replaces `{website}` (based on headers) and
/// `{username}` and returns the final string. This helper is separated out for easier testing.
pub async fn build_clash_content(
    headers: &HeaderMap,
    username: &str,
    template_path: &str,
) -> Result<String, std::io::Error> {
    let content = tokio::fs::read_to_string(template_path).await?;

    // determine scheme: prefer X-Forwarded-Proto, then Forwarded header, fallback to http
    let scheme = headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.split(',').next())
        .map(|s| s.trim().to_lowercase())
        .or_else(|| {
            headers
                .get("forwarded")
                .and_then(|v| v.to_str().ok())
                .and_then(|f| {
                    f.split(';')
                        .find_map(|part| {
                            let p = part.trim();
                            if p.starts_with("proto=") {
                                Some(p.trim_start_matches("proto=").to_string())
                            } else {
                                None
                            }
                        })
                })
        })
        .unwrap_or_else(|| "http".to_string());

    // determine host: prefer X-Forwarded-Host then Host header
    let host = headers
        .get("x-forwarded-host")
        .or_else(|| headers.get("host"))
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "localhost".to_string());

    let base = format!("{}://{}", scheme, host);

    // replace both {website} (base url) and {username}
    let replaced = content
        .replace("{website}", &base)
        .replace("{username}", username);

    Ok(replaced)
}


#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderMap;

    #[tokio::test]
    async fn replace_website_and_username_from_forwarded_headers() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-proto", "https".parse().unwrap());
        headers.insert("x-forwarded-host", "sub.example.com".parse().unwrap());

        let body = build_clash_content(&headers, "alice", "data/clash/default.yaml")
            .await
            .unwrap();

        assert!(body.contains("https://sub.example.com/alice"));
    }

    #[tokio::test]
    async fn replace_website_with_host_header_and_default_scheme() {
        let mut headers = HeaderMap::new();
        headers.insert("host", "localhost:8080".parse().unwrap());

        let body = build_clash_content(&headers, "bob", "data/clash/default.yaml")
            .await
            .unwrap();
        // default scheme should be http when not found in x-forwarded-proto / forwarded
        assert!(body.contains("http://localhost:8080/bob"));
    }
}

/// 返回原始模板（不做 {username} 替换），便于前端预览和排查问题
pub async fn clash_template() -> Response {
    let template_path = "data/clash/default.yaml";
    let mut response = match tokio::fs::read_to_string(template_path).await {
        Ok(content) => {
            let mut resp = Response::new(content.into());
            *resp.status_mut() = StatusCode::OK;
            resp
        }
        Err(err) => {
            // include path for easier debugging
            tracing::error!("failed to read clash template {}: {}", template_path, err);
            let mut resp = Response::new("failed to load clash template".into());
            *resp.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
            resp.headers_mut().insert(
                axum::http::header::CONTENT_TYPE,
                HeaderValue::from_static("text/plain; charset=utf-8"),
            );
            resp
        }
    };

    // set content-type for success path (as yaml)
    response.headers_mut().insert(
        axum::http::header::CONTENT_TYPE,
        HeaderValue::from_static("text/yaml; charset=utf-8"),
    );

    response
}
