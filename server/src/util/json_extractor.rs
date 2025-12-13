use axum::{
    async_trait,
    body::Bytes,
    extract::{FromRequest, Request},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use tracing::error;

/// Custom JSON extractor that logs deserialization errors
pub struct LoggedJson<T>(pub T);

#[async_trait]
impl<T, S> FromRequest<S> for LoggedJson<T>
where
    T: serde::de::DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = Response;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        // First extract raw bytes
        let bytes = match Bytes::from_request(req, state).await {
            Ok(b) => b,
            Err(e) => {
                error!("Failed to read request body: {}", e);
                return Err(
                    (StatusCode::BAD_REQUEST, "Failed to read request body").into_response()
                );
            }
        };

        // Log the raw body for debugging
        if let Ok(body_str) = std::str::from_utf8(&bytes) {
            error!("📥 [LoggedJson] Received request body: {}", body_str);
        }

        // Try to deserialize
        match serde_json::from_slice::<T>(&bytes) {
            Ok(value) => Ok(LoggedJson(value)),
            Err(e) => {
                error!("❌ [LoggedJson] JSON deserialization error: {}", e);
                let error_msg = format!("Invalid JSON data: {}", e);
                Err((StatusCode::UNPROCESSABLE_ENTITY, error_msg).into_response())
            }
        }
    }
}
