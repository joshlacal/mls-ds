//! Binary entry point for federation test fixture.
//!
//! Exists only in test environments behind `test-support`.
//! Accepts a single JSON file path containing a `RemotePrefixBootstrapSelector`.

#[tokio::main]
async fn main() {
    if let Err(err) = catbird_server::chat_protocol::test_support::run_federation_fixture().await {
        eprintln!("federation_fixture: {err}");
        std::process::exit(1);
    }
}
