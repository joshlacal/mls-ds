//! HTTP layer of the Labyrinth backend (`blue.catbird.labyrinth.*`, design
//! labyrinth `docs/MLSDS_BACKEND.md` §2–§3; domain code in
//! `crate::labyrinth`).
//!
//! All 27 XRPC endpoints of the lexicons are registered by
//! [`labyrinth_router`]. Every one requires the clean-chat cutover gate and a
//! standard service-auth JWT whose `lxm` is the endpoint NSID; queries name
//! the calling device with `actorDeviceId`, procedures with a signed
//! `labyrinthWriteBody` (see `crate::labyrinth::auth`). `main.rs` merges the
//! router only when `LABYRINTH_ENABLED` is set.
//!
//! Federation: thread writes to a conversation sequenced by another DS
//! return a typed `501 MethodNotImplemented`; the `labyrinthRelay`
//! server-to-server procedure of design §3 is not built.

mod directory;
mod mailbox;
mod orf;
mod params;
mod thread;

use std::sync::Arc;

use axum::{
    extract::{DefaultBodyLimit, FromRef},
    http::{header::CONTENT_TYPE, HeaderValue},
    response::{IntoResponse, Response},
    routing::{get, post},
    Router,
};

use crate::blob_store::BlobStore;
use crate::handlers::chat::ChatRuntime;
use crate::labyrinth::error::LabyrinthResult;
use crate::storage::DbPool;

/// NSID prefix of every Labyrinth endpoint.
pub const NSID_PREFIX: &str = "blue.catbird.labyrinth.";

const KIB: usize = 1024;
/// Body limits (design §4 "Size limits").
const LIMIT_RECORD_STREAM: usize = 1024 * KIB;
const LIMIT_CREATE_EPOCH: usize = 512 * KIB;
const LIMIT_DEFAULT: usize = 64 * KIB;

/// The procedures, with their body limits.
pub const PROCEDURES: &[(&str, usize)] = &[
    ("createDevice", LIMIT_DEFAULT),
    ("markDeviceRevoked", LIMIT_DEFAULT),
    ("createEpoch", LIMIT_CREATE_EPOCH),
    ("createEpochMember", LIMIT_DEFAULT),
    ("createVirtualDevice", LIMIT_DEFAULT),
    ("appendOwnerBatch", LIMIT_RECORD_STREAM),
    ("createMek", LIMIT_RECORD_STREAM),
    ("appendBatch", LIMIT_RECORD_STREAM),
    ("publishEpochHead", LIMIT_DEFAULT),
    ("registerOrfState", LIMIT_DEFAULT),
    ("deleteOrfState", LIMIT_DEFAULT),
    ("putAttachmentRef", LIMIT_DEFAULT),
];

/// The queries.
pub const QUERIES: &[&str] = &[
    "getDevice",
    "listDevices",
    "getEpoch",
    "listEpochs",
    "listEpochMembers",
    "getVirtualDevice",
    "listVirtualDevices",
    "listOwnerBatches",
    "findMeks",
    "listBatches",
    "getEpochHead",
    "getChatDeviceKeys",
    "getMemberDevices",
    "getAttachmentRef",
    "getAttachmentBlob",
];

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

/// Build the `blue.catbird.labyrinth.*` router. Generic over the
/// application state like `chat_router`.
pub fn labyrinth_router<S>() -> Router<S>
where
    S: Clone + Send + Sync + 'static,
    DbPool: FromRef<S>,
    Arc<ChatRuntime>: FromRef<S>,
    BlobStore: FromRef<S>,
{
    let limit = |name: &str| {
        PROCEDURES
            .iter()
            .find(|(n, _)| *n == name)
            .map(|(_, l)| *l)
            .expect("registered procedure")
    };
    Router::new()
        .route(&path("createDevice"), post(mailbox::create_device))
        .route(
            &path("markDeviceRevoked"),
            post(mailbox::mark_device_revoked),
        )
        .route(&path("getDevice"), get(mailbox::get_device))
        .route(&path("listDevices"), get(mailbox::list_devices))
        .route(
            &path("createEpoch"),
            post(mailbox::create_epoch).layer(DefaultBodyLimit::max(limit("createEpoch"))),
        )
        .route(&path("getEpoch"), get(mailbox::get_epoch))
        .route(&path("listEpochs"), get(mailbox::list_epochs))
        .route(
            &path("createEpochMember"),
            post(mailbox::create_epoch_member),
        )
        .route(&path("listEpochMembers"), get(mailbox::list_epoch_members))
        .route(
            &path("createVirtualDevice"),
            post(mailbox::create_virtual_device),
        )
        .route(&path("getVirtualDevice"), get(mailbox::get_virtual_device))
        .route(
            &path("listVirtualDevices"),
            get(mailbox::list_virtual_devices),
        )
        .route(
            &path("appendOwnerBatch"),
            post(mailbox::append_owner_batch)
                .layer(DefaultBodyLimit::max(limit("appendOwnerBatch"))),
        )
        .route(&path("listOwnerBatches"), get(mailbox::list_owner_batches))
        .route(
            &path("createMek"),
            post(thread::create_mek).layer(DefaultBodyLimit::max(limit("createMek"))),
        )
        .route(&path("findMeks"), get(thread::find_meks))
        .route(
            &path("appendBatch"),
            post(thread::append_batch).layer(DefaultBodyLimit::max(limit("appendBatch"))),
        )
        .route(&path("listBatches"), get(thread::list_batches))
        .route(
            &path("publishEpochHead"),
            post(directory::publish_epoch_head),
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
        .route(&path("registerOrfState"), post(orf::register_orf_state))
        .route(&path("deleteOrfState"), post(orf::delete_orf_state))
        .route(&path("putAttachmentRef"), post(orf::put_attachment_ref))
        .route(&path("getAttachmentRef"), get(orf::get_attachment_ref))
        .route(&path("getAttachmentBlob"), get(orf::get_attachment_blob))
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
        assert_eq!(served.len(), 27);
    }
}
