use axum::{
    body::Bytes,
    extract::{OriginalUri, State},
    http::{HeaderMap, Method, StatusCode},
    response::IntoResponse,
};

#[derive(Clone)]
pub struct ProxyState {
    pub client: reqwest::Client,
    pub base: String,
}

pub async fn proxy(
    OriginalUri(orig): OriginalUri,
    State(state): State<ProxyState>,
    method: Method,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    let path_and_query = orig
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or(orig.path());
    let dest = format!("{}{}", state.base.trim_end_matches('/'), path_and_query);

    let mut req = state
        .client
        .request(
            reqwest::Method::from_bytes(method.as_str().as_bytes()).unwrap_or(reqwest::Method::GET),
            &dest,
        )
        .body(body);

    // Forward minimal safe headers
    if let Some(auth) = headers.get(axum::http::header::AUTHORIZATION) {
        if let Ok(s) = auth.to_str() {
            req = req.header(reqwest::header::AUTHORIZATION, s);
        }
    }
    if let Some(ct) = headers.get(axum::http::header::CONTENT_TYPE) {
        if let Ok(s) = ct.to_str() {
            req = req.header(reqwest::header::CONTENT_TYPE, s);
        }
    }

    let res = match req.send().await {
        Ok(r) => r,
        Err(e) => {
            let body = axum::Json(serde_json::json!({
                "error": "ProxyError",
                "message": format!("failed to contact upstream: {}", e),
            }));
            return (StatusCode::BAD_GATEWAY, body).into_response();
        }
    };

    let status = StatusCode::from_u16(res.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
    let bytes = match res.bytes().await {
        Ok(b) => b,
        Err(e) => {
            let body = axum::Json(serde_json::json!({
                "error": "ProxyError",
                "message": format!("failed to read upstream body: {}", e),
            }));
            return (StatusCode::BAD_GATEWAY, body).into_response();
        }
    };

    (status, bytes).into_response()
}
