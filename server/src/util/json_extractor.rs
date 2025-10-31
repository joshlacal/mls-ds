use axum::{
    async_trait,
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
        use axum::extract::rejection::JsonRejection;
        use axum::Json;
        
        match Json::<T>::from_request(req, state).await {
            Ok(Json(value)) => Ok(LoggedJson(value)),
            Err(rejection) => {
                let error_msg = match &rejection {
                    JsonRejection::JsonDataError(e) => {
                        error!("JSON deserialization error: {}", e);
                        format!("Invalid JSON data: {}", e)
                    }
                    JsonRejection::JsonSyntaxError(e) => {
                        error!("JSON syntax error: {}", e);
                        format!("Invalid JSON syntax: {}", e)
                    }
                    JsonRejection::MissingJsonContentType(e) => {
                        error!("Missing Content-Type header: {}", e);
                        format!("Missing Content-Type: {}", e)
                    }
                    _ => {
                        error!("JSON extraction failed: {}", rejection);
                        format!("Request validation failed: {}", rejection)
                    }
                };
                
                Err((StatusCode::UNPROCESSABLE_ENTITY, error_msg).into_response())
            }
        }
    }
}
