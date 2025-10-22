use std::ffi::CString;
use std::os::raw::c_char;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum MLSError {
    #[error("Null pointer provided: {0}")]
    NullPointer(&'static str),
    
    #[error("Invalid UTF-8 string: {0}")]
    InvalidUtf8(#[from] std::str::Utf8Error),
    
    #[error("Invalid data length: expected {expected}, got {actual}")]
    InvalidLength { expected: usize, actual: usize },
    
    #[error("OpenMLS error: {0}")]
    OpenMLS(String),
    
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    
    #[error("TLS codec error: {0}")]
    TlsCodec(String),
    
    #[error("Invalid context handle")]
    InvalidContext,
    
    #[error("Group not found: {0}")]
    GroupNotFound(String),
    
    #[error("Thread safety error: {0}")]
    ThreadSafety(String),
    
    #[error("Memory allocation failed")]
    MemoryAllocation,
    
    #[error("Internal error: {0}")]
    Internal(String),
}

impl MLSError {
    pub fn to_c_string(&self) -> *mut c_char {
        let error_msg = self.to_string();
        match CString::new(error_msg) {
            Ok(c_str) => c_str.into_raw(),
            Err(_) => {
                let fallback = CString::new("Failed to create error message").unwrap();
                fallback.into_raw()
            }
        }
    }
}

pub type Result<T> = std::result::Result<T, MLSError>;
