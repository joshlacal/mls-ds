#[cfg(feature = "test-support")]
#[path = "../chat_protocol/test_support.rs"]
mod test_support;

#[cfg(feature = "test-support")]
#[tokio::main]
async fn main() {
    if let Err(error) = test_support::run_federation_fixture().await {
        eprintln!("federation_fixture error: {error}");
        std::process::exit(1);
    }
}

#[cfg(not(feature = "test-support"))]
fn main() {
    eprintln!("federation_fixture binary requires the 'test-support' feature");
    std::process::exit(1);
}
