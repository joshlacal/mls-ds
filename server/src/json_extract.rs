//! Helpers for deserializing request DTOs from JSON bodies and query strings,
//! mapping decode failures to `400 Bad Request`.

use axum::http::StatusCode;
use serde::de::DeserializeOwned;

pub fn from_json_body<T: DeserializeOwned>(json: &str) -> Result<T, StatusCode> {
    serde_json::from_str(json).map_err(|e| {
        tracing::warn!("Failed to deserialize JSON body: {}", e);
        StatusCode::BAD_REQUEST
    })
}

pub fn from_query_string<T: DeserializeOwned>(query: &str) -> Result<T, StatusCode> {
    serde_html_form::from_str(query).map_err(|e| {
        tracing::warn!("Failed to deserialize query parameters: {}", e);
        StatusCode::BAD_REQUEST
    })
}
