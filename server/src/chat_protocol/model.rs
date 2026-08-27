//! Shared error for the clean-chat cryptographic primitive layer.

use thiserror::Error;

#[derive(Clone, Debug, Error, Eq, PartialEq)]
#[error("invalid clean-chat authentication input: {0}")]
pub struct AuthPrimitiveError(pub(crate) &'static str);

impl AuthPrimitiveError {
    pub(crate) const fn invalid(reason: &'static str) -> Self {
        Self(reason)
    }
}
