//! Public synthetic interop fixtures, emitted by the actual private server
//! encoder. Mount only as a child of handlers::chat::subscribe_events in the
//! non-shipping proof copy. All values below are fabricated and unminted.
#![cfg(all(test, feature = "test-support"))]

use catbird_atproto::generated::blue_catbird::chat::SubscriptionMessage;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::path::Path;

const OUTPUT: &str = "/tmp/mlsv2-canonical-wire-interop-20260905";

fn preserve_identical(path: &Path, bytes: &[u8]) {
    if path.exists() {
        assert!(
            std::fs::read(path).unwrap() == bytes,
            "public fixture already exists with different bytes: {}",
            path.display()
        );
    } else {
        std::fs::write(path, bytes).unwrap();
    }
}

#[test]
fn actual_server_encoder_writes_public_interop_fixtures() {
    let directory = Path::new(OUTPUT);
    std::fs::create_dir_all(directory).unwrap();
    let examples: [(&str, &str, Value); 2] = [
        (
            "envelope",
            "blue.catbird.chat.defs#eventEnvelope",
            json!({
                "$type":"blue.catbird.chat.defs#eventEnvelope",
                "createdAt":"2026-09-05T19:36:21.676Z",
                "cursor":"synthetic-current-cursor",
                "previousCursor":"synthetic-previous-cursor",
                "payload":{
                    "$type":"blue.catbird.chat.defs#messageAvailableEvent",
                    "conversationId":"11111111-1111-4111-8111-111111111111",
                    "seq":4
                }
            }),
        ),
        (
            "typing",
            "blue.catbird.chat.defs#typingEvent",
            json!({
                "$type":"blue.catbird.chat.defs#typingEvent",
                "typingId":"33333333-3333-4333-8333-333333333333",
                "conversationId":"11111111-1111-4111-8111-111111111111",
                "actorDid":"did:plc:aaaaaaaaaaaaaaaaaaaaaaaa",
                "actorDeviceId":"22222222-2222-4222-8222-222222222222",
                "isTyping":true,
                "expiresAt":"2026-09-05T19:36:29.676Z"
            }),
        ),
    ];
    let mut files = Vec::new();
    for (name, message_type, expected) in examples {
        let message: SubscriptionMessage = serde_json::from_value(expected.clone())
            .expect("valid synthetic generated subscription DTO");
        let binary = super::encode_subscription_frame(&message)
            .expect("actual server encodes the generated inner DTO");
        let legacy_json = serde_json::to_vec(&message).unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&legacy_json).unwrap(),
            expected
        );
        // A cursor decoder consumes exactly the two concatenated CBOR maps.
        let mut input = std::io::Cursor::new(binary.as_slice());
        let header: Value = serde_ipld_dagcbor::de::from_reader_once(&mut input).unwrap();
        let body: Value = serde_ipld_dagcbor::de::from_reader_once(&mut input).unwrap();
        assert_eq!(input.position() as usize, binary.len());
        assert_eq!(header, json!({"op":1,"t":message_type}));
        assert!(body.is_object() && body.get("$type").is_none());
        let mut reconstructed = body;
        reconstructed["$type"] = json!(message_type);
        assert_eq!(reconstructed, expected);
        for (extension, bytes) in [("cbor", binary), ("json", legacy_json)] {
            let filename = format!("{name}.{extension}");
            preserve_identical(&directory.join(&filename), &bytes);
            files.push(json!({"file":filename,"length":bytes.len(),
                "sha256":hex::encode(Sha256::digest(&bytes))}));
        }
    }
    let metadata = json!({
        "classification":"public synthetic; no production data; cursors are not minted capabilities",
        "producer":"actual handlers::chat::subscribe_events::encode_subscription_frame",
        "binaryFrame":"two consecutive DAG-CBOR maps, full external t reference, no outer body $type",
        "jsonFrame":"same generated DTO serialized by the former Text frame producer",
        "conversationId":"11111111-1111-4111-8111-111111111111",
        "createdAt":"2026-09-05T19:36:21.676Z",
        "expiresAt":"2026-09-05T19:36:29.676Z",
        "previousCursor":"synthetic-previous-cursor",
        "cursor":"synthetic-current-cursor",
        "files":files
    });
    preserve_identical(
        &directory.join("metadata.json"),
        &serde_json::to_vec_pretty(&metadata).unwrap(),
    );
}
