use actix_web::Error;
use actix_web::body::BoxBody;
use actix_web::dev::{ServiceRequest, ServiceResponse};
use actix_web::http::header::{HeaderName, HeaderValue};
use actix_web::middleware::Next;
use std::env;

/// Initialize logging for the application.
pub fn init_logging() {
    // Route log crate messages to tracing
    let _ = tracing_log::LogTracer::init();

    let filter = env::var("RUST_LOG").unwrap_or_else(|_| "info".into());
    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(filter));

    let json = match env::var("LOG_JSON") {
        Ok(v) => matches!(v.as_str(), "1" | "true" | "yes" | "on"),
        Err(_) => false,
    };

    if json {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(env_filter)
            .with_span_events(tracing_subscriber::fmt::format::FmtSpan::NONE)
            .json()
            .try_init();
    } else {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(env_filter)
            .with_span_events(tracing_subscriber::fmt::format::FmtSpan::NONE)
            .pretty()
            .try_init();
    }
}

/// Middleware which creates a tracing span for each incoming request and adds structured fields.
///
/// Injects `x-request-id` header into the response if one isn't present, and logs status/latency.
pub async fn trace_requests(
    req: ServiceRequest,
    next: Next<BoxBody>,
) -> Result<ServiceResponse<BoxBody>, Error> {
    // gather fields (encapsulated in a block so any borrows from `req` end before `next.call(req)`)
    let (method, path, client_ip, user_agent, request_id) = {
        let method = req.method().to_string();
        let path = req.path().to_string();
        let client_ip = req
            .connection_info()
            .realip_remote_addr()
            .unwrap_or("unknown")
            .to_string();
        let user_agent = req
            .headers()
            .get("user-agent")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        let request_id = req
            .headers()
            .get("x-request-id")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string())
            .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
        (method, path, client_ip, user_agent, request_id)
    };

    let span = tracing::info_span!("http.request", method = %method, path = %path, client_ip = %client_ip, user_agent = %user_agent, request_id = %request_id);
    let _enter = span.enter();
    let start = std::time::Instant::now();
    let mut res: ServiceResponse<BoxBody> = next.call(req).await?;
    let status = res.status();
    let elapsed_ms = start.elapsed().as_millis();

    tracing::info!(status = status.as_u16(), elapsed_ms, "request complete");

    // Ensure response contains x-request-id for tracing correlation
    let headers = res.response_mut().headers_mut();
    if headers.get("x-request-id").is_none()
        && let Ok(v) = HeaderValue::from_str(&request_id)
    {
        headers.insert(HeaderName::from_static("x-request-id"), v);
    }
    Ok(res)
}

#[cfg(test)]
mod tests {
    #[test]
    fn smoke() {
        crate::log::init_logging();
    }
}
