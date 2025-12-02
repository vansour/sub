use actix_web::Error;
use actix_web::body::BoxBody;
use actix_web::dev::{ServiceRequest, ServiceResponse};
use actix_web::http::header::{HeaderName, HeaderValue, USER_AGENT};
use actix_web::middleware::Next;
use std::env;
use std::sync::Once;
use std::time::Instant;
use tracing::{error, info, warn};
use tracing_subscriber::fmt::format::FmtSpan;
use uuid::Uuid;

/// Initialize logging for the application.
///
/// Supports `RUST_LOG` for filtering and `LOG_JSON` for formatting.
/// Uses `std::sync::Once` to ensure it is initialized only once, preventing panics in tests.
pub fn init_logging() {
    static INIT: Once = Once::new();

    INIT.call_once(|| {
        // 1. Route logs from `log` crate (used by dependencies like actix-web) to `tracing`
        let _ = tracing_log::LogTracer::init();

        // 2. Parse environment variables with better defaults
        // Default to info, but keep our app (sub) at debug if needed
        let filter = env::var("RUST_LOG").unwrap_or_else(|_| "info,sub=debug".into());

        // Robust boolean parsing for LOG_JSON
        let use_json = env::var("LOG_JSON")
            .map(|v| matches!(v.to_lowercase().as_str(), "1" | "true" | "yes" | "on"))
            .unwrap_or(false);

        let subscriber_builder = tracing_subscriber::fmt()
            .with_env_filter(filter)
            // We will log the event manually at the end of the request, so disable auto span events
            .with_span_events(FmtSpan::NONE)
            .with_target(false) // Hide the verbose module path (e.g. "sub::log")
            .with_file(true) // Include file name for easier debugging
            .with_line_number(true);

        // 3. Initialize subscriber based on format
        // We use try_init() instead of init() to ignore errors if a subscriber is already set
        if use_json {
            let _ = subscriber_builder
                .json()
                .flatten_event(true) // Flatten fields into the root JSON object for easier parsing
                .try_init();
        } else {
            let _ = subscriber_builder
                .compact() // Compact format is cleaner for local development
                .try_init();
        }
    });
}

/// Middleware: traces HTTP requests with structured logging.
///
/// - Injects `x-request-id` if missing for distributed tracing.
/// - Logs duration, status, method, and path.
/// - Uses semantic log levels: ERROR for 5xx, WARN for 4xx, INFO for others.
pub async fn trace_requests(
    req: ServiceRequest,
    next: Next<BoxBody>,
) -> Result<ServiceResponse<BoxBody>, Error> {
    // 1. Extract request info
    let request_id = req
        .headers()
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .unwrap_or_else(|| Uuid::new_v4().to_string());

    let http_method = req.method().to_string();
    let http_path = req.path().to_string();
    // Keep query string for debugging, but be careful with PII in production
    let http_query = req.query_string().to_string();

    let client_ip = req
        .connection_info()
        .realip_remote_addr()
        .unwrap_or("unknown")
        .to_string();

    let user_agent = req
        .headers()
        .get(USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("-")
        .to_string();

    // 2. Create a span for this request context
    // We use standard OpenTelemetry semantic conventions for field names where possible
    let span = tracing::info_span!(
        "http_request",
        "x-request-id" = %request_id,
        "http.method" = %http_method,
        "http.path" = %http_path,
        "client.ip" = %client_ip
    );

    let _enter = span.enter();
    let start_time = Instant::now();

    // 3. Execute the actual handler
    let mut res = next.call(req).await?;

    // 4. Post-processing
    let duration = start_time.elapsed();
    let status = res.status();
    let status_code = status.as_u16();

    // Inject request ID into response headers so client can correlate logs
    res.headers_mut().insert(
        HeaderName::from_static("x-request-id"),
        HeaderValue::from_str(&request_id).unwrap(),
    );

    // 5. Structured logging with dynamic severity
    match status_code {
        500..=599 => {
            error!(
                "http.status_code" = status_code,
                "http.duration_ms" = duration.as_millis(),
                "http.user_agent" = %user_agent,
                "http.query" = %http_query,
                "request failed (server error)"
            );
        }
        400..=499 => {
            warn!(
                "http.status_code" = status_code,
                "http.duration_ms" = duration.as_millis(),
                "request failed (client error)"
            );
        }
        _ => {
            info!(
                "http.status_code" = status_code,
                "http.duration_ms" = duration.as_millis(),
                "request completed"
            );
        }
    }

    Ok(res)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_init_logging() {
        // Just ensure it doesn't panic on initialization
        let _ = std::panic::catch_unwind(|| {
            init_logging();
        });
        // Calling it a second time should be fine now due to Once
        init_logging();
    }
}
