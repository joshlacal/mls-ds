use axum::{
    extract::Request,
    http::{header, HeaderValue},
    middleware::Next,
    response::Response,
};

/// Ensures every outgoing response carries a `Content-Type` header.
///
/// Handlers that return bare `StatusCode::X` produce empty-body responses with
/// no `Content-Type`, which breaks clients that validate the header up-front
/// (e.g. Petrel's generated XRPC layer used to throw `NetworkError.invalidContentType`
/// before checking the status). This middleware is defensive: it only fills in
/// the header when missing, and never touches the body — so it composes cleanly
/// with idempotency caching, structured error responses, and any handler that
/// intentionally sets a non-JSON content type.
pub async fn response_content_type_middleware(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;

    if !response.headers().contains_key(header::CONTENT_TYPE) {
        response.headers_mut().insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
    }

    response
}
