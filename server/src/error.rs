///! Shared error types for MLS server handlers

use std::fmt;

#[derive(Debug)]
pub enum Error {
    DatabaseError(String),
    ValidationError(String),
    NotFound(String),
    Unauthorized(String),
    PolicyViolation(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::DatabaseError(msg) => write!(f, "Database error: {}", msg),
            Error::ValidationError(msg) => write!(f, "Validation error: {}", msg),
            Error::NotFound(msg) => write!(f, "Not found: {}", msg),
            Error::Unauthorized(msg) => write!(f, "Unauthorized: {}", msg),
            Error::PolicyViolation(msg) => write!(f, "Policy violation: {}", msg),
        }
    }
}

impl std::error::Error for Error {}
