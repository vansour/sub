use axum::http::header;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use prometheus::Encoder;
use prometheus::TextEncoder;

/// 获取 Prometheus 格式的指标
pub async fn metrics() -> impl IntoResponse {
    let registry = crate::METRICS_REGISTRY.lock();
    let encoder = TextEncoder::new();
    let mut buffer = Vec::new();

    match encoder.encode(&registry.gather(), &mut buffer) {
        Ok(_) => {
            let text = String::from_utf8_lossy(&buffer).to_string();
            (
                StatusCode::OK,
                [(
                    header::CONTENT_TYPE,
                    "text/plain; version=0.0.4; charset=utf-8",
                )],
                text,
            )
                .into_response()
        }
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to encode metrics",
        )
            .into_response(),
    }
}
