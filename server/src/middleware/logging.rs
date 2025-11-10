use axum::{extract::Request, middleware::Next, response::Response};

pub async fn log_headers_middleware(request: Request, next: Next) -> Response {
    // Keep request logging minimal in production; avoid leaking header names/values
    let method = request.method().clone();
    let uri = request.uri().clone();

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
        uri = %uri,
        has_authorization = has_authorization,
        has_atproto_proxy = has_atproto_proxy,
        content_type = content_type,
        "Incoming HTTP request"
    );

    next.run(request).await
}
