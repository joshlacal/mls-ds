//! Contract guard for the isolated MLS protocol v2 lexicon corpus.
//!
//! The server copy is deliberately a byte-for-byte mirror of the canonical
//! PetrelCatbird overlay.  This test keeps namespace drift and accidental v1
//! coupling from becoming a later code-generation problem.

use serde_json::Value;
use std::{
    fs,
    path::{Path, PathBuf},
};

const ENDPOINTS: &[(&str, &str, &[&str])] = &[
    (
        "registerDevice",
        "procedure",
        &[
            "deviceId",
            "deviceName",
            "signaturePublicKey",
            "capabilities",
            "keyPackages",
            "idempotencyKey",
        ],
    ),
    ("getConversations", "query", &[]),
    ("getConversationState", "query", &["conversationId"]),
    ("submitTransition", "procedure", &["envelope"]),
    (
        "sendMessage",
        "procedure",
        &[
            "conversationId",
            "generation",
            "epoch",
            "confirmationTag",
            "messageId",
            "ciphertext",
            "idempotencyKey",
        ],
    ),
    ("getMessages", "query", &["conversationId"]),
    ("getPendingWelcomes", "query", &["deviceId"]),
    (
        "acknowledgeWelcome",
        "procedure",
        &["welcomeId", "conversationId", "generation", "stateVersion"],
    ),
    (
        "requestReset",
        "procedure",
        &[
            "conversationId",
            "generation",
            "stateVersion",
            "epoch",
            "confirmationTag",
            "reason",
            "idempotencyKey",
            "signature",
        ],
    ),
    (
        "authorizeAndBootstrapReset",
        "procedure",
        &["resetRequestId", "envelope"],
    ),
    ("getSubscriptionTicket", "procedure", &["eventCursor"]),
    ("subscribeEvents", "subscription", &[]),
];

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("mls-ds workspace root must exist")
}

fn canonical_root() -> PathBuf {
    workspace_root().join("../PetrelCatbird/lexicons/blue/catbird/mlsChatV2")
}

fn mirror_root() -> PathBuf {
    workspace_root().join("lexicon/blue/catbird/mlsChatV2")
}

fn lexicon(root: &Path, name: &str) -> Value {
    let path = root.join(format!("blue.catbird.mlsChatV2.{name}.json"));
    let source = fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("must read {}: {error}", path.display()));
    serde_json::from_str(&source)
        .unwrap_or_else(|error| panic!("must parse {}: {error}", path.display()))
}

fn required(definition: &Value) -> Vec<&str> {
    definition["required"]
        .as_array()
        .expect("schema must declare required fields")
        .iter()
        .map(|value| value.as_str().expect("required item must be a string"))
        .collect()
}

#[test]
fn mls_v2_namespace_and_required_contract_are_complete() {
    let canonical = canonical_root();
    let defs = lexicon(&canonical, "defs");

    assert_eq!(defs["id"], "blue.catbird.mlsChatV2.defs");
    for definition in [
        "conversationCoordinates",
        "signedTransitionEnvelope",
        "deviceCapability",
        "keyPackageReservation",
        "welcomeView",
        "typedError",
        "eventEnvelope",
    ] {
        assert!(
            defs["defs"].get(definition).is_some(),
            "defs must contain {definition}"
        );
    }
    for field in [
        "conversationId",
        "generation",
        "stateVersion",
        "groupId",
        "epoch",
        "confirmationTag",
        "lifecycle",
    ] {
        assert!(
            required(&defs["defs"]["conversationCoordinates"]).contains(&field),
            "coordinates must require {field}"
        );
    }
    for field in [
        "transitionId",
        "idempotencyKey",
        "actorDeviceId",
        "actorDid",
        "keyId",
        "transitionKind",
        "prior",
        "next",
        "payload",
        "payloadHash",
        "signature",
        "signedAt",
    ] {
        assert!(
            required(&defs["defs"]["signedTransitionEnvelope"]).contains(&field),
            "signed transition envelope must require {field}"
        );
    }
    assert_eq!(
        defs["defs"]["lifecycle"]["knownValues"],
        serde_json::json!(["active", "resetRequested", "superseded", "closed"]),
        "the lifecycle state machine must be explicit and closed"
    );

    for (name, kind, required_fields) in ENDPOINTS {
        let document = lexicon(&canonical, name);
        assert_eq!(document["id"], format!("blue.catbird.mlsChatV2.{name}"));
        let main = &document["defs"]["main"];
        assert_eq!(main["type"], *kind, "{name} must retain its endpoint kind");

        if !required_fields.is_empty() {
            let schema = if *kind == "query" {
                &main["parameters"]
            } else {
                &main["input"]["schema"]
            };
            let actual = required(schema);
            for field in *required_fields {
                assert!(actual.contains(field), "{name} must require {field}");
            }
        }
    }
}

#[test]
fn server_v2_lexicons_exactly_mirror_the_canonical_overlay_without_v1_references() {
    let canonical = canonical_root();
    let mirror = mirror_root();

    for name in std::iter::once("defs").chain(ENDPOINTS.iter().map(|(name, _, _)| *name)) {
        let filename = format!("blue.catbird.mlsChatV2.{name}.json");
        let canonical_source = fs::read_to_string(canonical.join(&filename))
            .unwrap_or_else(|error| panic!("canonical {filename} must exist: {error}"));
        let mirror_source = fs::read_to_string(mirror.join(&filename))
            .unwrap_or_else(|error| panic!("server mirror {filename} must exist: {error}"));
        assert_eq!(
            mirror_source, canonical_source,
            "server mirror drifted for {filename}"
        );
        assert!(
            !canonical_source.contains("blue.catbird.mlsChat."),
            "{filename} must not reference or reuse a v1 lexicon"
        );
    }
}
