// MLS FFI Layer - C-compatible interface
// This provides a working foundation with core functionality
// Full OpenMLS integration to be completed based on final API requirements

use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::ptr;
use std::slice;
use std::sync::{Arc, Mutex};
use std::collections::HashMap;

use crate::error::{MLSError, Result};
use crate::mls_context::MLSContext;

// Global context storage with thread-safe access
static CONTEXTS: Mutex<Option<HashMap<usize, Arc<MLSContext>>>> = Mutex::new(None);
static NEXT_CONTEXT_ID: Mutex<usize> = Mutex::new(1);

/// FFI-safe result type
/// Contains success status, error message, and data buffer
#[repr(C)]
pub struct MLSResult {
    pub success: bool,
    pub error_message: *mut c_char,
    pub data: *mut u8,
    pub data_len: usize,
}

impl MLSResult {
    /// Create a successful result with data
    pub fn ok(data: Vec<u8>) -> Self {
        let len = data.len();
        let ptr = if len > 0 {
            Box::into_raw(data.into_boxed_slice()) as *mut u8
        } else {
            ptr::null_mut()
        };
        Self {
            success: true,
            error_message: ptr::null_mut(),
            data: ptr,
            data_len: len,
        }
    }

    /// Create an error result
    pub fn err(error: MLSError) -> Self {
        Self {
            success: false,
            error_message: error.to_c_string(),
            data: ptr::null_mut(),
            data_len: 0,
        }
    }
}

/// Initialize the MLS FFI library
/// Returns a context handle (non-zero on success, 0 on failure)
#[no_mangle]
pub extern "C" fn mls_init() -> usize {
    let mut contexts_guard = match CONTEXTS.lock() {
        Ok(guard) => guard,
        Err(_) => return 0,
    };
    
    let contexts = contexts_guard.get_or_insert_with(HashMap::new);
    
    let mut next_id_guard = match NEXT_CONTEXT_ID.lock() {
        Ok(guard) => guard,
        Err(_) => return 0,
    };
    
    let context_id = *next_id_guard;
    *next_id_guard += 1;
    
    let context = Arc::new(MLSContext::new());
    contexts.insert(context_id, context);
    
    context_id
}

/// Free an MLS context and all associated resources
#[no_mangle]
pub extern "C" fn mls_free_context(context_id: usize) {
    if let Ok(mut contexts_guard) = CONTEXTS.lock() {
        if let Some(contexts) = contexts_guard.as_mut() {
            contexts.remove(&context_id);
        }
    }
}

// Helper functions

fn get_context(context_id: usize) -> Result<Arc<MLSContext>> {
    let contexts_guard = CONTEXTS.lock()
        .map_err(|_| MLSError::ThreadSafety("Failed to acquire lock".to_string()))?;
    
    let contexts = contexts_guard.as_ref()
        .ok_or(MLSError::InvalidContext)?;
    
    contexts.get(&context_id)
        .cloned()
        .ok_or(MLSError::InvalidContext)
}

fn safe_slice<'a>(ptr: *const u8, len: usize, name: &'static str) -> Result<&'a [u8]> {
    if ptr.is_null() {
        return Err(MLSError::NullPointer(name));
    }
    if len == 0 {
        return Ok(&[]);
    }
    unsafe { Ok(slice::from_raw_parts(ptr, len)) }
}

/// Create a new MLS group
/// Parameters:
///   - context_id: MLS context handle
///   - identity_bytes: User identity (email, username, etc.)
///   - identity_len: Length of identity bytes
/// Returns: MLSResult containing group ID on success
#[no_mangle]
pub extern "C" fn mls_create_group(
    context_id: usize,
    identity_bytes: *const u8,
    identity_len: usize,
) -> MLSResult {
    let result: Result<Vec<u8>> = (|| {
        let _context = get_context(context_id)?;
        let identity = safe_slice(identity_bytes, identity_len, "identity")?;
        
        // TODO: Implement full MLS group creation using OpenMLS
        // For now, return a deterministic group ID
        let group_id = format!("group_{}", hex::encode(&identity[..std::cmp::min(identity.len(), 16)]));
        Ok(group_id.into_bytes())
    })();
    
    match result {
        Ok(data) => MLSResult::ok(data),
        Err(e) => MLSResult::err(e),
    }
}

/// Add members to an existing MLS group
/// Parameters:
///   - context_id: MLS context handle
///   - group_id: Group identifier
///   - group_id_len: Length of group ID
///   - key_packages_bytes: Serialized key packages of members to add
///   - key_packages_len: Length of key packages data
/// Returns: MLSResult containing commit and welcome messages
#[no_mangle]
pub extern "C" fn mls_add_members(
    context_id: usize,
    group_id: *const u8,
    group_id_len: usize,
    key_packages_bytes: *const u8,
    key_packages_len: usize,
) -> MLSResult {
    let result: Result<Vec<u8>> = (|| {
        let _context = get_context(context_id)?;
        let _gid = safe_slice(group_id, group_id_len, "group_id")?;
        let _kp_bytes = safe_slice(key_packages_bytes, key_packages_len, "key_packages")?;
        
        // TODO: Implement member addition with OpenMLS
        // Return format: JSON with {commit: "hex", welcome: "hex"}
        Err(MLSError::Internal("Full implementation pending - requires OpenMLS API integration".to_string()))
    })();
    
    match result {
        Ok(data) => MLSResult::ok(data),
        Err(e) => MLSResult::err(e),
    }
}

/// Encrypt a message for the group
/// Parameters:
///   - context_id: MLS context handle
///   - group_id: Group identifier
///   - group_id_len: Length of group ID
///   - plaintext: Message to encrypt
///   - plaintext_len: Length of plaintext
/// Returns: MLSResult containing encrypted message
#[no_mangle]
pub extern "C" fn mls_encrypt_message(
    context_id: usize,
    group_id: *const u8,
    group_id_len: usize,
    plaintext: *const u8,
    plaintext_len: usize,
) -> MLSResult {
    let result: Result<Vec<u8>> = (|| {
        let _context = get_context(context_id)?;
        let _gid = safe_slice(group_id, group_id_len, "group_id")?;
        let _pt = safe_slice(plaintext, plaintext_len, "plaintext")?;
        
        // TODO: Implement message encryption with OpenMLS
        Err(MLSError::Internal("Full implementation pending - requires OpenMLS API integration".to_string()))
    })();
    
    match result {
        Ok(data) => MLSResult::ok(data),
        Err(e) => MLSResult::err(e),
    }
}

/// Decrypt a message from the group
/// Parameters:
///   - context_id: MLS context handle
///   - group_id: Group identifier
///   - group_id_len: Length of group ID
///   - ciphertext: Encrypted message
///   - ciphertext_len: Length of ciphertext
/// Returns: MLSResult containing decrypted message
#[no_mangle]
pub extern "C" fn mls_decrypt_message(
    context_id: usize,
    group_id: *const u8,
    group_id_len: usize,
    ciphertext: *const u8,
    ciphertext_len: usize,
) -> MLSResult {
    let result: Result<Vec<u8>> = (|| {
        let _context = get_context(context_id)?;
        let _gid = safe_slice(group_id, group_id_len, "group_id")?;
        let _ct = safe_slice(ciphertext, ciphertext_len, "ciphertext")?;
        
        // TODO: Implement message decryption with OpenMLS
        Err(MLSError::Internal("Full implementation pending - requires OpenMLS API integration".to_string()))
    })();
    
    match result {
        Ok(data) => MLSResult::ok(data),
        Err(e) => MLSResult::err(e),
    }
}

/// Create a key package for joining groups
/// Parameters:
///   - context_id: MLS context handle
///   - identity_bytes: User identity
///   - identity_len: Length of identity
/// Returns: MLSResult containing serialized key package
#[no_mangle]
pub extern "C" fn mls_create_key_package(
    context_id: usize,
    identity_bytes: *const u8,
    identity_len: usize,
) -> MLSResult {
    let result: Result<Vec<u8>> = (|| {
        let _context = get_context(context_id)?;
        let identity = safe_slice(identity_bytes, identity_len, "identity")?;
        
        // TODO: Implement key package creation with OpenMLS
        // For now, return a deterministic key package ID
        let kp_id = format!("keypackage_{}", hex::encode(&identity[..std::cmp::min(identity.len(), 16)]));
        Ok(kp_id.into_bytes())
    })();
    
    match result {
        Ok(data) => MLSResult::ok(data),
        Err(e) => MLSResult::err(e),
    }
}

/// Process a Welcome message to join a group
/// Parameters:
///   - context_id: MLS context handle
///   - welcome_bytes: Serialized Welcome message
///   - welcome_len: Length of Welcome message
///   - identity_bytes: User identity  
///   - identity_len: Length of identity
/// Returns: MLSResult containing group ID
#[no_mangle]
pub extern "C" fn mls_process_welcome(
    context_id: usize,
    welcome_bytes: *const u8,
    welcome_len: usize,
    identity_bytes: *const u8,
    identity_len: usize,
) -> MLSResult {
    let result: Result<Vec<u8>> = (|| {
        let _context = get_context(context_id)?;
        let _welcome_data = safe_slice(welcome_bytes, welcome_len, "welcome")?;
        let _identity = safe_slice(identity_bytes, identity_len, "identity")?;
        
        // TODO: Implement Welcome processing with OpenMLS
        Err(MLSError::Internal("Full implementation pending - requires OpenMLS API integration".to_string()))
    })();
    
    match result {
        Ok(data) => MLSResult::ok(data),
        Err(e) => MLSResult::err(e),
    }
}

/// Export a secret from the group's key schedule
/// Parameters:
///   - context_id: MLS context handle
///   - group_id: Group identifier
///   - group_id_len: Length of group ID
///   - label: Label for the exported secret (null-terminated string)
///   - context_bytes: Context data for secret derivation
///   - context_len: Length of context data
///   - key_length: Desired length of exported secret
/// Returns: MLSResult containing exported secret
#[no_mangle]
pub extern "C" fn mls_export_secret(
    context_id: usize,
    group_id: *const u8,
    group_id_len: usize,
    label: *const c_char,
    context_bytes: *const u8,
    context_len: usize,
    key_length: usize,
) -> MLSResult {
    let result: Result<Vec<u8>> = (|| {
        let _context = get_context(context_id)?;
        let _gid = safe_slice(group_id, group_id_len, "group_id")?;
        let _context_data = safe_slice(context_bytes, context_len, "context")?;
        
        if label.is_null() {
            return Err(MLSError::NullPointer("label"));
        }
        
        let _label_str = unsafe {
            CStr::from_ptr(label)
                .to_str()
                .map_err(|e| MLSError::InvalidUtf8(e))?
        };
        
        // TODO: Implement secret export with OpenMLS
        // For now, return zeros (DO NOT use in production!)
        Ok(vec![0u8; key_length])
    })();
    
    match result {
        Ok(data) => MLSResult::ok(data),
        Err(e) => MLSResult::err(e),
    }
}

/// Get the current epoch of the group
/// Parameters:
///   - context_id: MLS context handle
///   - group_id: Group identifier
///   - group_id_len: Length of group ID
/// Returns: Epoch number (0 on error)
#[no_mangle]
pub extern "C" fn mls_get_epoch(
    context_id: usize,
    group_id: *const u8,
    group_id_len: usize,
) -> u64 {
    let result: Result<u64> = (|| {
        let _context = get_context(context_id)?;
        let _gid = safe_slice(group_id, group_id_len, "group_id")?;
        
        // TODO: Implement epoch retrieval with OpenMLS
        Ok(0)
    })();
    
    result.unwrap_or(0)
}

/// Free a result object and its associated memory
#[no_mangle]
pub extern "C" fn mls_free_result(result: MLSResult) {
    unsafe {
        if !result.error_message.is_null() {
            let _ = CString::from_raw(result.error_message);
        }
        if !result.data.is_null() && result.data_len > 0 {
            let _ = Vec::from_raw_parts(result.data, result.data_len, result.data_len);
        }
    }
}

/// Get the last error message (for debugging)
#[no_mangle]
pub extern "C" fn mls_get_last_error() -> *mut c_char {
    let msg = CString::new("Use MLSResult.error_message for error details").unwrap();
    msg.into_raw()
}

/// Free an error message string
#[no_mangle]
pub extern "C" fn mls_free_string(s: *mut c_char) {
    if !s.is_null() {
        unsafe {
            let _ = CString::from_raw(s);
        }
    }
}
