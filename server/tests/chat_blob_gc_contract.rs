//! Structural guardrails for the clean-chat blob expiry/object-GC boundary.
//!
//! The database/S3 fixture is intentionally ignored unless operators provide a
//! seeded Postgres and S3-compatible endpoint. These checks keep the safety
//! ordering reviewable in ordinary CI: a physical delete must precede the
//! terminal database update, and the worker must validate the deterministic
//! CID rather than accepting an arbitrary stored key.

#[test]
fn gc_deletes_exact_cid_before_marking_the_row_reclaimed() {
    let source = include_str!("../src/handlers/chat/expiry_worker.rs");
    let lock = source
        .find("FOR UPDATE SKIP LOCKED")
        .expect("GC must lock pending rows before touching their objects");
    let delete = source
        .find("deleter.delete_exact(&object_store_key)")
        .expect("GC must delete through the object-store abstraction");
    let update = source
        .find("UPDATE chat.blobs")
        .expect("GC must mark the row reclaimed after object deletion");
    assert!(lock < delete && delete < update);
    assert!(source.contains("object_store_key_matches"));
    assert!(source.contains("object_gc_status = 'pending'"));
    assert!(source.contains("S3 DELETE is idempotent"));
}

#[test]
fn prepare_binds_signed_prior_to_the_explicit_conversation() {
    let source = include_str!("../src/handlers/chat/blob_routes.rs");
    assert!(source.contains("projection.prior_conversation_id()"));
    assert!(source.contains("ChatProtocolErrorCode::InvalidRequest"));
}
