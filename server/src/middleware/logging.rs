use axum::{
    extract::Request,
    middleware::Next,
    response::Response,
};

pub async fn log_headers_middleware(request: Request, next: Next) -> Response {
    let headers = request.headers();
    let method = request.method().clone();
    let uri = request.uri().clone();

    let header_names: Vec<&str> = headers.keys().map(|k| k.as_str()).collect();

    let has_authorization = headers.contains_key("authorization");
    let has_atproto_proxy = headers.contains_key("atproto-proxy");
    let content_type = headers.get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("none");

    tracing::info!(
        method = %method,
        uri = %uri,
        header_count = header_names.len(),
        headers = ?header_names,
        has_authorization = has_authorization,
        has_atproto_proxy = has_atproto_proxy,
        content_type = content_type,
        "Incoming HTTP request with headers"
    );

    next.run(request).await
}
