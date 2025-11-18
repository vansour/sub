use axum::Json;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use std::time::Instant;

use crate::metrics::{self, CheckResult, HealthChecks, HealthStatus};
use crate::models::ApiResponse;

/// 简单健康检查接口（轻量级）
pub async fn healthz() -> impl IntoResponse {
    (
        StatusCode::OK,
        Json(ApiResponse::<serde_json::Value>::success_with_message(
            "系统正常",
        )),
    )
}

/// 详细健康检查接口（包含诊断信息）
pub async fn health_detailed() -> impl IntoResponse {
    let start = Instant::now();
    let mut overall_status = "healthy";

    // 检查数据存储
    let storage_check = check_data_storage().await;
    if storage_check.status != "healthy" {
        overall_status = "degraded";
    }

    // 检查系统资源
    let resources_check = check_system_resources().await;
    if resources_check.status != "healthy" {
        overall_status = "degraded";
    }

    let health_status = HealthStatus {
        status: overall_status.to_string(),
        timestamp: chrono::Local::now().to_rfc3339(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        checks: HealthChecks {
            data_storage: storage_check,
            system_resources: resources_check,
        },
    };

    let duration = start.elapsed().as_secs_f64();
    let status_code = match overall_status {
        "healthy" => StatusCode::OK,
        _ => StatusCode::SERVICE_UNAVAILABLE,
    };

    metrics::record_http_request("GET", "/health", status_code.as_u16(), duration);

    (status_code, Json(ApiResponse::success(health_status)))
}

/// 检查数据存储状态
async fn check_data_storage() -> CheckResult {
    let start = Instant::now();

    // 尝试检查配置文件是否可访问
    match tokio::fs::metadata("data/data.toml").await {
        Ok(_) => CheckResult::ok(start.elapsed().as_millis() as u64),
        Err(e) => CheckResult::unhealthy(
            format!("Failed to access data storage: {}", e),
            start.elapsed().as_millis() as u64,
        ),
    }
}

/// 检查系统资源
async fn check_system_resources() -> CheckResult {
    let start = Instant::now();

    // 检查内存使用
    #[cfg(target_os = "linux")]
    {
        match std::fs::read_to_string("/proc/self/status") {
            Ok(status_content) => {
                // 解析 VmRSS（实际内存占用）
                for line in status_content.lines() {
                    if line.starts_with("VmRSS:") {
                        // 如果内存占用超过 1GB，标记为不健康
                        if let Some(size_str) = line.split_whitespace().nth(1)
                            && let Ok(size_kb) = size_str.parse::<u64>()
                            && size_kb > 1024 * 1024
                        {
                            return CheckResult::unhealthy(
                                format!("High memory usage: {} KB", size_kb),
                                start.elapsed().as_millis() as u64,
                            );
                        }
                    }
                }
                CheckResult::ok(start.elapsed().as_millis() as u64)
            }
            Err(e) => CheckResult::unhealthy(
                format!("Failed to check system resources: {}", e),
                start.elapsed().as_millis() as u64,
            ),
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        CheckResult::ok(start.elapsed().as_millis() as u64)
    }
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
