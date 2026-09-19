//! Evidence harness for encrypted first-message requests.
//!
//! The complete acceptance scenario is intentionally not marked ignored and
//! not represented as a TODO pass. Until T02-T06 install production request
//! interfaces, this target proves the guarded baseline and real independent
//! crypto stores; the strict evidence manifest records the first-contact
//! scenario as blocked and therefore cannot validate as release evidence.

#[path = "support/encrypted_requests.rs"]
mod encrypted_requests;

use encrypted_requests::{
    connect_guarded_request_database, reviewed_baseline, validate_request_test_database_url,
    RequestRig, REQUEST_TEST_DATABASE_URL,
};

#[test]
fn database_url_gate_accepts_only_the_exact_local_target() {
    assert!(validate_request_test_database_url(None).is_err());
    assert!(
        validate_request_test_database_url(Some("postgresql://127.0.0.1:5432/postgres")).is_err()
    );
    assert_eq!(
        validate_request_test_database_url(Some(REQUEST_TEST_DATABASE_URL)).unwrap(),
        "catbird_direct_requests_test_20260919"
    );
}

#[test]
fn reviewed_baseline_has_exactly_fourteen_ordered_entries() {
    let baseline = reviewed_baseline();
    assert_eq!(baseline.len(), 14);
    assert!(baseline
        .windows(2)
        .all(|pair| pair[0].version < pair[1].version));
}

#[tokio::test]
async fn guarded_database_is_local_owned_and_contains_reviewed_baseline() -> anyhow::Result<()> {
    let authority = connect_guarded_request_database(1).await?;
    assert_eq!(authority.database, "catbird_direct_requests_test_20260919");
    assert_eq!(authority.user, authority.owner);
    assert_eq!(authority.server_address, "127.0.0.1");
    assert_eq!(authority.baseline_migrations, 14);
    Ok(())
}

#[tokio::test]
async fn enrollment_uses_independent_real_mls_stores() -> anyhow::Result<()> {
    let server_binary = std::env::current_exe()?;
    let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/alice_did.json");
    std::env::set_var("REQUEST_SERVER_BINARY", server_binary);
    std::env::set_var("REQUEST_AUTH_FIXTURE", fixture);
    let mut rig = RequestRig::local().await?;
    rig.enroll("alice", 2).await?;
    rig.enroll("bob", 1).await?;
    assert_eq!(rig.independent_device_count("alice")?, 2);
    assert_eq!(rig.independent_device_count("bob")?, 1);
    Ok(())
}

#[tokio::test]
async fn unavailable_request_handlers_fail_closed_instead_of_passing() -> anyhow::Result<()> {
    let server_binary = std::env::current_exe()?;
    let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/alice_did.json");
    std::env::set_var("REQUEST_SERVER_BINARY", server_binary);
    std::env::set_var("REQUEST_AUTH_FIXTURE", fixture);
    let mut rig = RequestRig::local().await?;
    rig.enroll("alice", 1).await?;
    rig.enroll("bob", 1).await?;
    let error = rig
        .start_request("alice", "bob", "Hello, Bob")
        .await
        .unwrap_err();
    assert!(error.to_string().contains("T02/T03/T04"));
    Ok(())
}
