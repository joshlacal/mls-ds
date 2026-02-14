/// IntoResponse implementations for Lexicon-generated error types
/// This allows handlers to return structured JSON error responses
use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};

use crate::generated::blue_catbird::mls::{
    add_members::AddMembersError as LexAddMembersError,
    create_convo::CreateConvoError as LexCreateConvoError,
    get_group_info::GetGroupInfoError as LexGetGroupInfoError,
    update_group_info::UpdateGroupInfoError as LexUpdateGroupInfoError,
};

/// Wrapper for createConvo errors that can be either structured or generic HTTP
pub enum CreateConvoError {
    Structured(LexCreateConvoError),
    Generic(StatusCode),
}

impl IntoResponse for CreateConvoError {
    fn into_response(self) -> Response {
        match self {
            Self::Structured(err) => {
                let status = match &err {
                    LexCreateConvoError::InvalidCipherSuite(_) => StatusCode::BAD_REQUEST,
                    LexCreateConvoError::KeyPackageNotFound(_) => StatusCode::CONFLICT,
                    LexCreateConvoError::TooManyMembers(_) => StatusCode::BAD_REQUEST,
                    LexCreateConvoError::MutualBlockDetected(_) => StatusCode::FORBIDDEN,
                    _ => StatusCode::INTERNAL_SERVER_ERROR,
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

impl From<LexCreateConvoError> for CreateConvoError {
    fn from(err: LexCreateConvoError) -> Self {
        Self::Structured(err)
    }
}

/// Wrapper for addMembers errors that can be either structured or generic HTTP
pub enum AddMembersError {
    Structured(LexAddMembersError),
    Generic(StatusCode),
}

impl IntoResponse for AddMembersError {
    fn into_response(self) -> Response {
        match self {
            Self::Structured(err) => {
                let status = match &err {
                    LexAddMembersError::ConvoNotFound(_) => StatusCode::NOT_FOUND,
                    LexAddMembersError::NotMember(_) => StatusCode::FORBIDDEN,
                    LexAddMembersError::KeyPackageNotFound(_) => StatusCode::CONFLICT,
                    LexAddMembersError::AlreadyMember(_) => StatusCode::CONFLICT,
                    LexAddMembersError::TooManyMembers(_) => StatusCode::BAD_REQUEST,
                    LexAddMembersError::BlockedByMember(_) => StatusCode::FORBIDDEN,
                    _ => StatusCode::INTERNAL_SERVER_ERROR,
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

impl From<LexAddMembersError> for AddMembersError {
    fn from(err: LexAddMembersError) -> Self {
        Self::Structured(err)
    }
}

/// Wrapper for getGroupInfo errors
pub enum GetGroupInfoError {
    Structured(LexGetGroupInfoError),
    Generic(StatusCode),
}

impl IntoResponse for GetGroupInfoError {
    fn into_response(self) -> Response {
        match self {
            Self::Structured(err) => {
                let status = match &err {
                    LexGetGroupInfoError::GroupInfoUnavailable(_) => StatusCode::NOT_FOUND,
                    LexGetGroupInfoError::NotFound(_) => StatusCode::NOT_FOUND,
                    LexGetGroupInfoError::Unauthorized(_) => StatusCode::FORBIDDEN,
                    _ => StatusCode::INTERNAL_SERVER_ERROR,
                };
                (status, Json(err)).into_response()
            }
            Self::Generic(status) => status.into_response(),
        }
    }
}

impl From<StatusCode> for GetGroupInfoError {
    fn from(status: StatusCode) -> Self {
        Self::Generic(status)
    }
}

impl From<LexGetGroupInfoError> for GetGroupInfoError {
    fn from(err: LexGetGroupInfoError) -> Self {
        Self::Structured(err)
    }
}

/// Wrapper for updateGroupInfo errors
pub enum UpdateGroupInfoError {
    Structured(LexUpdateGroupInfoError),
    Generic(StatusCode),
}

impl IntoResponse for UpdateGroupInfoError {
    fn into_response(self) -> Response {
        match self {
            Self::Structured(err) => {
                let status = match &err {
                    LexUpdateGroupInfoError::Unauthorized(_) => StatusCode::FORBIDDEN,
                    LexUpdateGroupInfoError::InvalidGroupInfo(_) => StatusCode::BAD_REQUEST,
                    _ => StatusCode::INTERNAL_SERVER_ERROR,
                };
                (status, Json(err)).into_response()
            }
            Self::Generic(status) => status.into_response(),
        }
    }
}

impl From<StatusCode> for UpdateGroupInfoError {
    fn from(status: StatusCode) -> Self {
        Self::Generic(status)
    }
}

impl From<LexUpdateGroupInfoError> for UpdateGroupInfoError {
    fn from(err: LexUpdateGroupInfoError) -> Self {
        Self::Structured(err)
    }
}
