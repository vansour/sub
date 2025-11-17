use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;

/// 健康检查接口
pub async fn healthz() -> impl IntoResponse {
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "status": "healthy",
            "timestamp": std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
        })),
    )
}

/// 处理 favicon.ico 请求
pub async fn favicon() -> impl IntoResponse {
    StatusCode::NO_CONTENT
}

/// 主页
pub async fn index() -> impl IntoResponse {
    match tokio::fs::read_to_string("web/index.html").await {
        Ok(content) => (StatusCode::OK, axum::response::Html(content)).into_response(),
        Err(err) => {
            tracing::error!("failed to read index.html: {}", err);
            let error_html = r#"<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>服务错误 - sub</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            margin: 0;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: #333;
        }
        .error-container {
            background: white;
            border-radius: 12px;
            padding: 40px;
            max-width: 500px;
            text-align: center;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
        }
        .error-icon {
            font-size: 64px;
            margin-bottom: 20px;
        }
        h1 {
            color: #e74c3c;
            margin: 0 0 10px 0;
        }
        p {
            color: #666;
            line-height: 1.6;
        }
        .retry-btn {
            margin-top: 20px;
            padding: 12px 24px;
            background: #667eea;
            color: white;
            border: none;
            border-radius: 6px;
            cursor: pointer;
            font-size: 16px;
            transition: background 0.3s;
        }
        .retry-btn:hover {
            background: #5568d3;
        }
        .error-details {
            margin-top: 20px;
            padding: 10px;
            background: #f8f9fa;
            border-radius: 6px;
            font-size: 12px;
            color: #666;
            word-break: break-word;
        }
    </style>
</head>
<body>
    <div class="error-container">
        <div class="error-icon">⚠️</div>
        <h1>服务暂时不可用</h1>
        <p>抱歉，页面加载失败。这可能是由于服务器配置问题导致的。</p>
        <p>请稍后重试，或联系管理员。</p>
        <button class="retry-btn" onclick="location.reload()">刷新页面</button>
        <div class="error-details">
            错误信息: 无法加载主页面文件
        </div>
    </div>
</body>
</html>"#;
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                axum::response::Html(error_html),
            )
                .into_response()
        }
    }
}
