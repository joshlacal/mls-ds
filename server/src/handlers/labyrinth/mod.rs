//! HTTP layer of the clean-slate Labyrinth directory (`blue.catbird.labyrinth.*`).
//!
//! Only the 6 zero-content directory and account-lifecycle endpoints remain on `mls-ds`:
//! - Procedures (3): `publishEpochHead`, `purgeMailbox`, `deleteAccountData`
//! - Queries (3): `getEpochHead`, `getChatDeviceKeys`, `getMemberDevices`

mod directory;
mod params;
mod retention;

pub(crate) use directory::read_federated_directory;
use std::sync::Arc;

use axum::{
    extract::{DefaultBodyLimit, FromRef},
    http::{header::CONTENT_TYPE, HeaderValue},
    response::{IntoResponse, Response},
    routing::{get, post},
    Router,
};

use crate::handlers::chat::ChatRuntime;
use crate::labyrinth::error::LabyrinthResult;
use crate::storage::DbPool;

/// NSID prefix of every Labyrinth endpoint.
pub const NSID_PREFIX: &str = "blue.catbird.labyrinth.";

const KIB: usize = 1024;
const LIMIT_DEFAULT: usize = 64 * KIB;

/// Active procedures and their body limits.
pub const PROCEDURES: &[(&str, usize)] = &[
    ("publishEpochHead", LIMIT_DEFAULT),
    ("purgeMailbox", LIMIT_DEFAULT),
    ("deleteAccountData", LIMIT_DEFAULT),
];

/// Active queries.
pub const QUERIES: &[&str] = &["getEpochHead", "getChatDeviceKeys", "getMemberDevices"];

fn path(name: &str) -> String {
    format!("/xrpc/{NSID_PREFIX}{name}")
}

/// A `200 OK` JSON response with the exact bytes (also the replay bytes).
fn json_ok(bytes: Vec<u8>) -> Response {
    let mut response = Response::new(axum::body::Body::from(bytes));
    response
        .headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    response
}

fn respond(result: LabyrinthResult<Vec<u8>>) -> Response {
    match result {
        Ok(bytes) => json_ok(bytes),
        Err(error) => error.into_response(),
    }
}

/// Build the `blue.catbird.labyrinth.*` router.
pub fn labyrinth_router<S>() -> Router<S>
where
    S: Clone + Send + Sync + 'static,
    DbPool: FromRef<S>,
    Arc<ChatRuntime>: FromRef<S>,
{
    Router::new()
        .route(
            &path("publishEpochHead"),
            post(directory::publish_epoch_head),
        )
        .route(&path("purgeMailbox"), post(retention::purge_mailbox))
        .route(
            &path("deleteAccountData"),
            post(retention::delete_account_data),
        )
        .route(&path("getEpochHead"), get(directory::get_epoch_head))
        .route(
            &path("getChatDeviceKeys"),
            get(directory::get_chat_device_keys),
        )
        .route(
            &path("getMemberDevices"),
            get(directory::get_member_devices),
        )
        .layer(DefaultBodyLimit::max(LIMIT_DEFAULT))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_lexicon_endpoint_is_registered_exactly_once() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../lexicon/blue/catbird/labyrinth");
        let mut lexicon = std::collections::BTreeSet::new();
        for entry in std::fs::read_dir(dir).expect("labyrinth lexicon dir") {
            let path = entry.expect("entry").path();
            let doc: serde_json::Value =
                serde_json::from_slice(&std::fs::read(&path).expect("read")).expect("json");
            let kind = doc["defs"]["main"]["type"].as_str().unwrap_or_default();
            if kind == "query" || kind == "procedure" {
                let id = doc["id"].as_str().expect("id");
                lexicon.insert((
                    id.trim_start_matches(NSID_PREFIX).to_owned(),
                    kind.to_owned(),
                ));
            }
        }
        let mut served = std::collections::BTreeSet::new();
        for (name, _) in PROCEDURES {
            assert!(served.insert(((*name).to_owned(), "procedure".to_owned())));
        }
        for name in QUERIES {
            assert!(served.insert(((*name).to_owned(), "query".to_owned())));
        }
        assert_eq!(served, lexicon);
        assert_eq!(served.len(), 6);
    }
}
