#[cfg(test)]
mod ffi_tests {
    use super::super::*;

    #[test]
    fn test_mls_init() {
        let context_id = mls_init();
        assert_ne!(context_id, 0, "Context ID should not be zero");
        mls_free_context(context_id);
    }

    #[test]
    fn test_create_group() {
        let context_id = mls_init();
        assert_ne!(context_id, 0);

        let identity = b"alice@example.com";
        let result = mls_create_group(
            context_id,
            identity.as_ptr(),
            identity.len(),
        );

        assert!(result.success, "Group creation should succeed");
        assert!(!result.data.is_null());
        assert!(result.data_len > 0);

        mls_free_result(result);
        mls_free_context(context_id);
    }

    #[test]
    fn test_create_key_package() {
        let context_id = mls_init();
        assert_ne!(context_id, 0);

        let identity = b"bob@example.com";
        let result = mls_create_key_package(
            context_id,
            identity.as_ptr(),
            identity.len(),
        );

        assert!(result.success, "Key package creation should succeed");
        assert!(!result.data.is_null());
        assert!(result.data_len > 0);

        mls_free_result(result);
        mls_free_context(context_id);
    }

    #[test]
    fn test_get_epoch() {
        let context_id = mls_init();
        assert_ne!(context_id, 0);

        let identity = b"alice@example.com";
        let create_result = mls_create_group(
            context_id,
            identity.as_ptr(),
            identity.len(),
        );

        assert!(create_result.success);
        
        let group_id = unsafe {
            std::slice::from_raw_parts(create_result.data, create_result.data_len)
        };

        let epoch = mls_get_epoch(
            context_id,
            group_id.as_ptr(),
            group_id.len(),
        );

        assert_eq!(epoch, 0, "Initial epoch should be 0");

        mls_free_result(create_result);
        mls_free_context(context_id);
    }

    #[test]
    fn test_export_secret() {
        let context_id = mls_init();
        assert_ne!(context_id, 0);

        let identity = b"alice@example.com";
        let create_result = mls_create_group(
            context_id,
            identity.as_ptr(),
            identity.len(),
        );

        assert!(create_result.success);
        
        let group_id = unsafe {
            std::slice::from_raw_parts(create_result.data, create_result.data_len)
        };

        let label = std::ffi::CString::new("test-export").unwrap();
        let context_data = b"test-context";
        let key_length = 32;

        let export_result = mls_export_secret(
            context_id,
            group_id.as_ptr(),
            group_id.len(),
            label.as_ptr(),
            context_data.as_ptr(),
            context_data.len(),
            key_length,
        );

        assert!(export_result.success, "Secret export should succeed");
        assert_eq!(export_result.data_len, key_length, "Exported secret should have requested length");

        mls_free_result(create_result);
        mls_free_result(export_result);
        mls_free_context(context_id);
    }

    #[test]
    fn test_null_pointer_handling() {
        let context_id = mls_init();
        assert_ne!(context_id, 0);

        let result = mls_create_group(
            context_id,
            std::ptr::null(),
            0,
        );

        assert!(!result.success, "Should fail with null pointer");
        assert!(!result.error_message.is_null(), "Should have error message");

        mls_free_result(result);
        mls_free_context(context_id);
    }

    #[test]
    fn test_invalid_context() {
        let invalid_context_id = 999999;
        let identity = b"test@example.com";
        
        let result = mls_create_group(
            invalid_context_id,
            identity.as_ptr(),
            identity.len(),
        );

        assert!(!result.success, "Should fail with invalid context");
        mls_free_result(result);
    }

    #[test]
    fn test_multiple_contexts() {
        let context1 = mls_init();
        let context2 = mls_init();
        
        assert_ne!(context1, 0);
        assert_ne!(context2, 0);
        assert_ne!(context1, context2, "Context IDs should be unique");

        mls_free_context(context1);
        mls_free_context(context2);
    }
}
