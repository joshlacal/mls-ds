//! A fresh request's cryptographic context cannot be relabelled as a legacy
//! upgrade or rebound to a crossed-request winner. Database upgrade races are
//! a separate required publication-facade qualification.
use base64::{engine::general_purpose::STANDARD, Engine};
use catbird_server::chat_protocol::{direct_request_transcript as transcript, wire};
use serde_json::{json, Value};
#[test]
fn fresh_ciphertext_cannot_be_rebound_to_a_legacy_prior_or_other_conversation() {
    let root =
        std::env::var("T02_CORPUS_DIR").expect("explicit retained real client corpus required");
    let root = std::path::Path::new(&root).join("leaves-2");
    let read = |name: &str| std::fs::read(root.join(name)).unwrap();
    let original: Value = serde_json::from_slice(&read("context.json")).unwrap();
    let next: Value = serde_json::from_slice(&read("coordinates.json")).unwrap();
    let commit = wire::validate_public_commit(&read("add.mls"), 1_048_576).unwrap();
    let app = wire::validate_private_application(&read("application.mls"), 98304).unwrap();
    let original_hash =
        transcript::direct_request_context_hash(&serde_json::to_vec(&original).unwrap()).unwrap();
    assert_eq!(
        commit.aad(),
        transcript::direct_request_commit_aad(&original_hash).unwrap()
    );
    let mut legacy = original.clone();
    let mut prior = next.clone();
    prior["epoch"] = json!(0);
    prior["stateVersion"] = json!(0);
    prior["groupId"] = json!(STANDARD.encode([8u8; 32]));
    legacy["origin"] = json!({"$type":"blue.catbird.chat.defs#legacyPendingDirectOrigin","exactPrior":prior,"originalInvitationProvenance":{"invitationTransitionId":"77777777-7777-4777-8777-777777777777","invitedByDid":original["actorDid"],"invitedByDeviceId":original["actorDeviceId"]}});
    let hash =
        transcript::direct_request_context_hash(&serde_json::to_vec(&legacy).unwrap()).unwrap();
    assert_ne!(hash, original_hash);
    assert_ne!(
        commit.aad(),
        transcript::direct_request_commit_aad(&hash).unwrap()
    );
    assert_ne!(
        app.aad(),
        transcript::direct_request_application_aad(
            &hash,
            &read("coordinates.json"),
            original["firstMessageId"].as_str().unwrap()
        )
        .unwrap()
    );
    let mut other = original.clone();
    other["conversationId"] = json!("88888888-8888-4888-8888-888888888888");
    let hash =
        transcript::direct_request_context_hash(&serde_json::to_vec(&other).unwrap()).unwrap();
    assert_ne!(
        app.aad(),
        transcript::direct_request_application_aad(
            &hash,
            &read("coordinates.json"),
            original["firstMessageId"].as_str().unwrap()
        )
        .unwrap()
    );
}
