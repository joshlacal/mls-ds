#![allow(dead_code)]

use std::ffi::{CStr, CString};
use std::os::raw::c_char;

/// FFI-safe result type
#[repr(C)]
pub struct MLSResult {
    pub success: bool,
    pub error_message: *mut c_char,
    pub data: *mut u8,
    pub data_len: usize,
}

impl MLSResult {
    pub fn ok(data: Vec<u8>) -> Self {
        let len = data.len();
        let ptr = Box::into_raw(data.into_boxed_slice()) as *mut u8;
        Self {
            success: true,
            error_message: std::ptr::null_mut(),
            data: ptr,
            data_len: len,
        }
    }

    pub fn err(msg: &str) -> Self {
        let c_msg = CString::new(msg).unwrap();
        Self {
            success: false,
            error_message: c_msg.into_raw(),
            data: std::ptr::null_mut(),
            data_len: 0,
        }
    }
}

/// Create a new MLS group
/// Returns serialized group state
#[no_mangle]
pub extern "C" fn mls_create_group(
    identity_bytes: *const u8,
    identity_len: usize,
) -> MLSResult {
    if identity_bytes.is_null() {
        return MLSResult::err("Null identity pointer");
    }

    // TODO: Implement actual OpenMLS group creation
    // For now, return placeholder
    let placeholder = b"GROUP_STATE_PLACEHOLDER".to_vec();
    MLSResult::ok(placeholder)
}

/// Join a group using a Welcome message
#[no_mangle]
pub extern "C" fn mls_join_group(
    welcome_bytes: *const u8,
    welcome_len: usize,
) -> MLSResult {
    if welcome_bytes.is_null() {
        return MLSResult::err("Null welcome pointer");
    }

    // TODO: Implement OpenMLS Welcome processing
    let placeholder = b"JOINED_GROUP_STATE".to_vec();
    MLSResult::ok(placeholder)
}

/// Add a member to the group
/// Returns (Commit, Welcome) tuple serialized
#[no_mangle]
pub extern "C" fn mls_add_member(
    group_state: *const u8,
    group_state_len: usize,
    key_package: *const u8,
    key_package_len: usize,
) -> MLSResult {
    if group_state.is_null() || key_package.is_null() {
        return MLSResult::err("Null pointer");
    }

    // TODO: Implement OpenMLS add + commit
    let placeholder = b"COMMIT_AND_WELCOME".to_vec();
    MLSResult::ok(placeholder)
}

/// Encrypt a message for the group
#[no_mangle]
pub extern "C" fn mls_encrypt_message(
    group_state: *const u8,
    group_state_len: usize,
    plaintext: *const u8,
    plaintext_len: usize,
) -> MLSResult {
    if group_state.is_null() || plaintext.is_null() {
        return MLSResult::err("Null pointer");
    }

    // TODO: Implement OpenMLS create_message
    let placeholder = b"CIPHERTEXT".to_vec();
    MLSResult::ok(placeholder)
}

/// Decrypt a message from the group
#[no_mangle]
pub extern "C" fn mls_decrypt_message(
    group_state: *const u8,
    group_state_len: usize,
    ciphertext: *const u8,
    ciphertext_len: usize,
) -> MLSResult {
    if group_state.is_null() || ciphertext.is_null() {
        return MLSResult::err("Null pointer");
    }

    // TODO: Implement OpenMLS process_message
    let placeholder = b"PLAINTEXT".to_vec();
    MLSResult::ok(placeholder)
}

/// Free a result object
#[no_mangle]
pub extern "C" fn mls_free_result(result: MLSResult) {
    unsafe {
        if !result.error_message.is_null() {
            let _ = CString::from_raw(result.error_message);
        }
        if !result.data.is_null() {
            let _ = Vec::from_raw_parts(result.data, result.data_len, result.data_len);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ffi_result() {
        let result = MLSResult::ok(vec![1, 2, 3]);
        assert!(result.success);
        assert_eq!(result.data_len, 3);
    }
}
