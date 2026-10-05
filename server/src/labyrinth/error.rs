//! The one failure type of the Labyrinth endpoints and its wire form.
//!
//! Every failure is an atproto XRPC error body `{"error", "message"}` with the
//! status and error name the `blue.catbird.labyrinth.*` lexicons declare (plus
//! the design's common errors, docs/MLSDS_BACKEND.md §2). Storage failures are
//! logged here and cross the wire as a bare `InternalServerError`.

use axum::{
    http::{header, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;

/// A failed Labyrinth request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LabyrinthError {
    status: StatusCode,
    name: &'static str,
    message: String,
    retry_after_secs: Option<u64>,
}

pub type LabyrinthResult<T> = Result<T, LabyrinthError>;

impl LabyrinthError {
    pub fn new(status: StatusCode, name: &'static str, message: impl Into<String>) -> Self {
        Self {
            status,
            name,
            message: message.into(),
            retry_after_secs: None,
        }
    }

    pub fn status(&self) -> StatusCode {
        self.status
    }

    pub fn name(&self) -> &'static str {
        self.name
    }

    pub fn message(&self) -> &str {
        &self.message
    }

    pub fn with_retry_after(mut self, secs: u64) -> Self {
        self.retry_after_secs = Some(secs);
        self
    }

    pub fn invalid(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "InvalidRequest", message)
    }

    /// A `400` with a specific lexicon error name.
    pub fn invalid_named(name: &'static str, message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, name, message)
    }

    pub fn not_authorized(message: impl Into<String>) -> Self {
        Self::new(StatusCode::UNAUTHORIZED, "NotAuthorized", message)
    }

    pub fn device_revoked() -> Self {
        Self::new(
            StatusCode::UNAUTHORIZED,
            "DeviceRevoked",
            "the calling chat device is not current",
        )
    }

    pub fn already_exists() -> Self {
        Self::new(
            StatusCode::CONFLICT,
            "RecordAlreadyExists",
            "a record with this key already exists",
        )
    }

    pub fn not_found(name: &'static str) -> Self {
        Self::new(StatusCode::NOT_FOUND, name, "not found")
    }

    pub fn forbidden(name: &'static str, message: impl Into<String>) -> Self {
        Self::new(StatusCode::FORBIDDEN, name, message)
    }

    pub fn quota(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "QuotaExceeded", message)
    }

    /// Federation relay to a remote sequencer DS is not built yet (design §3
    /// "Federation", Y3); a typed refusal instead of a silent local write.
    pub fn relay_not_implemented() -> Self {
        Self::new(
            StatusCode::NOT_IMPLEMENTED,
            "MethodNotImplemented",
            "this conversation is sequenced by another DS; the labyrinthRelay \
             server-to-server procedure is not implemented",
        )
    }

    pub fn internal() -> Self {
        Self::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalServerError",
            "internal error",
        )
    }
}

impl std::fmt::Display for LabyrinthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} ({}): {}", self.name, self.status, self.message)
    }
}

impl std::error::Error for LabyrinthError {}

impl IntoResponse for LabyrinthError {
    fn into_response(self) -> Response {
        let mut response = (
            self.status,
            Json(json!({ "error": self.name, "message": self.message })),
        )
            .into_response();
        if let Some(secs) = self.retry_after_secs {
            if let Ok(value) = HeaderValue::from_str(&secs.to_string()) {
                response.headers_mut().insert(header::RETRY_AFTER, value);
            }
        }
        response
    }
}

/// Database failures. A quota CHECK (`*_quota`) is the caller's
/// `QuotaExceeded`; everything else is logged and redacted.
impl From<sqlx::Error> for LabyrinthError {
    fn from(error: sqlx::Error) -> Self {
        if let Some(constraint) = violated_constraint(&error, "23514") {
            if constraint.ends_with("_quota") {
                return Self::quota(format!("quota exceeded ({constraint})"));
            }
        }
        tracing::error!(?error, "labyrinth storage failure");
        Self::internal()
    }
}

/// The constraint named by a database error with SQLSTATE `code`.
pub(crate) fn violated_constraint<'a>(error: &'a sqlx::Error, code: &str) -> Option<&'a str> {
    match error {
        sqlx::Error::Database(db) if db.code().as_deref() == Some(code) => db.constraint(),
        _ => None,
    }
}

/// True for a unique violation (`23505`), optionally of one named constraint.
pub(crate) fn is_unique_violation(error: &sqlx::Error) -> bool {
    matches!(error, sqlx::Error::Database(db) if db.code().as_deref() == Some("23505"))
}
