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

/// Wrapper for getGroupInfo errors
pub enum GetGroupInfoError {
    Structured(crate::generated::blue::catbird::mls::get_group_info::Error),
    Generic(StatusCode),
}

impl IntoResponse for GetGroupInfoError {
    fn into_response(self) -> Response {
        match self {
            Self::Structured(err) => {
                let status = match &err {
                    crate::generated::blue::catbird::mls::get_group_info::Error::GroupInfoUnavailable(_) => StatusCode::NOT_FOUND,
                    crate::generated::blue::catbird::mls::get_group_info::Error::NotFound(_) => StatusCode::NOT_FOUND,
                    crate::generated::blue::catbird::mls::get_group_info::Error::Unauthorized(_) => StatusCode::FORBIDDEN,
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

impl From<crate::generated::blue::catbird::mls::get_group_info::Error> for GetGroupInfoError {
    fn from(err: crate::generated::blue::catbird::mls::get_group_info::Error) -> Self {
        Self::Structured(err)
    }
}

/// Wrapper for updateGroupInfo errors
pub enum UpdateGroupInfoError {
    Structured(crate::generated::blue::catbird::mls::update_group_info::Error),
    Generic(StatusCode),
}

impl IntoResponse for UpdateGroupInfoError {
    fn into_response(self) -> Response {
        match self {
            Self::Structured(err) => {
                let status = match &err {
                    crate::generated::blue::catbird::mls::update_group_info::Error::Unauthorized(_) => StatusCode::FORBIDDEN,
                    crate::generated::blue::catbird::mls::update_group_info::Error::InvalidGroupInfo(_) => StatusCode::BAD_REQUEST,
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

impl From<crate::generated::blue::catbird::mls::update_group_info::Error> for UpdateGroupInfoError {
    fn from(err: crate::generated::blue::catbird::mls::update_group_info::Error) -> Self {
        Self::Structured(err)
    }
}
