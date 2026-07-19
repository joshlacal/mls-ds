use axum::{extract::Request, middleware::Next, response::Response};

pub async fn log_headers_middleware(request: Request, next: Next) -> Response {
    // Keep request logging minimal in production; avoid leaking header names/values
    let method = request.method().clone();
    // Authentication tickets and cursors are carried in query parameters on
    // WebSocket upgrades. Log only the routing path so credentials cannot be
    // copied into debug logs.
    let path = request.uri().path().to_string();

    let headers = request.headers();
    let has_authorization = headers.contains_key("authorization");
    let has_atproto_proxy = headers.contains_key("atproto-proxy");
    let content_type = headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("none");

    // Use debug level and avoid enumerating header names
    tracing::debug!(
        method = %method,
        path = %path,
        has_authorization = has_authorization,
        has_atproto_proxy = has_atproto_proxy,
        content_type = content_type,
        "Incoming HTTP request"
    );

    next.run(request).await
}

#[cfg(test)]
mod tests {
    #[test]
    fn request_logging_never_records_query_credentials() {
        let source = include_str!("logging.rs");
        let unsafe_clone = ["request.uri()", ".clone()"].concat();

        assert!(!source.contains(&unsafe_clone));
        assert!(source.contains("request.uri().path()"));
    }
}
