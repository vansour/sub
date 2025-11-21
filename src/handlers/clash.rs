use axum::{
    extract::Path,
    http::{HeaderValue, StatusCode},
    response::Response,
};

/// 生成 Clash 配置：将 default.yaml 中的 {username} 替换为实际用户名
pub async fn clash_config(Path(username): Path<String>) -> Response {
    // 读取模板文件
    let template_path = "data/clash/default.yaml";
    // Try to canonicalize to help debugging logs (may fail if file missing)
    let canonical = std::path::Path::new(template_path).canonicalize();
    match tokio::fs::read_to_string(template_path).await {
        Ok(content) => {
            let replaced = content.replace("{username}", &username);

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
