/// IntoResponse implementations for Lexicon-generated error types
/// This allows handlers to return structured JSON error responses
use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};

/// Wrapper for createConvo errors that can be either structured or generic HTTP
pub enum CreateConvoError {
    Structured(crate::generated::blue::catbird::mls::create_convo::Error),
    Generic(StatusCode),
}

impl IntoResponse for CreateConvoError {
    fn into_response(self) -> Response {
        match self {
            Self::Structured(err) => {
                let status = match &err {
                    crate::generated::blue::catbird::mls::create_convo::Error::InvalidCipherSuite(_) => StatusCode::BAD_REQUEST,
                    crate::generated::blue::catbird::mls::create_convo::Error::KeyPackageNotFound(_) => StatusCode::CONFLICT,
                    crate::generated::blue::catbird::mls::create_convo::Error::TooManyMembers(_) => StatusCode::BAD_REQUEST,
                    crate::generated::blue::catbird::mls::create_convo::Error::MutualBlockDetected(_) => StatusCode::FORBIDDEN,
                };
                (status, Json(err)).into_response()
            }
            Self::Generic(status) => status.into_response(),
        }
    }
}

impl From<StatusCode> for CreateConvoError {
    fn from(status: StatusCode) -> Self {
        Self::Generic(status)
    }
}

impl From<crate::generated::blue::catbird::mls::create_convo::Error> for CreateConvoError {
    fn from(err: crate::generated::blue::catbird::mls::create_convo::Error) -> Self {
        Self::Structured(err)
    }
}

/// Wrapper for addMembers errors that can be either structured or generic HTTP
pub enum AddMembersError {
    Structured(crate::generated::blue::catbird::mls::add_members::Error),
    Generic(StatusCode),
}

impl IntoResponse for AddMembersError {
    fn into_response(self) -> Response {
        match self {
            Self::Structured(err) => {
                let status = match &err {
                    crate::generated::blue::catbird::mls::add_members::Error::ConvoNotFound(_) => StatusCode::NOT_FOUND,
                    crate::generated::blue::catbird::mls::add_members::Error::NotMember(_) => StatusCode::FORBIDDEN,
                    crate::generated::blue::catbird::mls::add_members::Error::KeyPackageNotFound(_) => StatusCode::CONFLICT,
                    crate::generated::blue::catbird::mls::add_members::Error::AlreadyMember(_) => StatusCode::CONFLICT,
                    crate::generated::blue::catbird::mls::add_members::Error::TooManyMembers(_) => StatusCode::BAD_REQUEST,
                    crate::generated::blue::catbird::mls::add_members::Error::BlockedByMember(_) => StatusCode::FORBIDDEN,
                };
                (status, Json(err)).into_response()
            }
            Self::Generic(status) => status.into_response(),
        }
    }
}

impl From<StatusCode> for AddMembersError {
    fn from(status: StatusCode) -> Self {
        Self::Generic(status)
    }
}

impl From<crate::generated::blue::catbird::mls::add_members::Error> for AddMembersError {
    fn from(err: crate::generated::blue::catbird::mls::add_members::Error) -> Self {
        Self::Structured(err)
    }
}
