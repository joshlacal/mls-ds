//! Helpers for deserializing jacquard types from JSON/query strings.
//!
//! Jacquard types have lifetime-parameterized `Deserialize` implementations
//! and don't implement `DeserializeOwned`. These helpers deserialize from
//! owned strings, producing `'static` values via `IntoStatic`.

use axum::http::StatusCode;
use jacquard_common::IntoStatic;

/// Deserialize a jacquard type from a JSON string body, converting to 'static.
pub fn from_json_body<'a, T>(json: &'a str) -> Result<T::Output, StatusCode>
where
    T: serde::Deserialize<'a> + IntoStatic,
    T::Output: 'static,
{
    let value: T = serde_json::from_str(json).map_err(|e| {
        tracing::warn!("Failed to deserialize JSON body: {}", e);
        StatusCode::BAD_REQUEST
    })?;
    Ok(value.into_static())
}

/// Deserialize a jacquard type from a URL query string, converting to 'static.
pub fn from_query_string<'a, T>(query: &'a str) -> Result<T::Output, StatusCode>
where
    T: serde::Deserialize<'a> + IntoStatic,
    T::Output: 'static,
{
    let value: T = serde_html_form::from_str(query).map_err(|e| {
        tracing::warn!("Failed to deserialize query parameters: {}", e);
        StatusCode::BAD_REQUEST
    })?;
    Ok(value.into_static())
}
