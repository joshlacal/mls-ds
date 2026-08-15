//! Wire-JSON bodies for the eleven signed-mutation kinds that carry no control
//! entry and so never appeared in the control-fingerprint corpus.
//!
//! These are inputs, not answers. Every derived value — canonical projection,
//! transcript, request digest, signature — is produced by the server's own
//! `chat_protocol::transcript` code in the harness that includes this file. A
//! body here that the live contract rejects fails the run rather than being
//! quietly encoded, which is the point: the shapes are pinned by the same
//! closed-lexicon projection production uses.

use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

pub const ACTOR_DID: &str = "did:plc:alicefixtureaaaaaaaaaaaa";
pub const ACTOR_DEVICE_ID: &str = "70707070-7070-4070-b070-707070707070";
pub const CONVERSATION_ID: &str = "11111111-1111-4111-9111-111111111111";
pub const SIGNED_AT: &str = "2026-07-22T14:05:09.123Z";

/// A 43-character base64url thumbprint, shaped like a real DPoP JKT.
fn dpop_jkt(label: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(label))
}

fn artifact(bytes: &[u8]) -> (String, String) {
    (
        STANDARD.encode(bytes),
        STANDARD.encode(Sha256::digest(bytes)),
    )
}

fn key_package(fill: u8, reference: u8) -> Value {
    let bytes = [fill; 64];
    let (encoded, sha256) = artifact(&bytes);
    json!({
        "framing": "mlsMessage",
        "contentType": "keyPackage",
        "bytes": encoded,
        "sha256": sha256,
        "keyPackageRef": STANDARD.encode([reference; 32])
    })
}

/// Two artifacts, strictly ascending by `keyPackageRef` — the ordering the
/// server enforces on enrollment and replenishment.
fn key_packages() -> Value {
    json!([key_package(0x41, 0x31), key_package(0x42, 0x32)])
}

fn capability() -> Value {
    json!({
        "protocolVersion": "1",
        "mlsVersion": "1.0",
        "cipherSuite": "MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519",
        "credentialType": "basic",
        "addByValue": "supported",
        "updatePath": "supported",
        "removeByValue": "supported",
        "ratchetTreeGroupInfo": "supported",
        "externalPubGroupInfo": "presentButExternalCommitsForbidden",
        "applicationFrameProfile": "dagCborApplication1",
        "controlProfile": "publicGroup1",
        "attachmentProfile": "aes256GcmBlob1",
        "metadataProfile": "exporterAes256Gcm1",
        "typingProfile": "signedClearEphemeral1"
    })
}

pub fn coordinates() -> Value {
    json!({
        "conversationId": CONVERSATION_ID,
        "generation": 1,
        "stateVersion": 2,
        "groupId": STANDARD.encode([0x22_u8; 32]),
        "epoch": 1,
        "groupContextHash": STANDARD.encode([0x23_u8; 32]),
        "confirmationTag": STANDARD.encode([0x24_u8; 32]),
        "lifecycle": "active"
    })
}

/// The same coordinates as they appear inside MLS AAD, where the conversation
/// id is raw identifier bytes rather than a UUID string.
fn aad_prior() -> Value {
    let mut prior = coordinates();
    prior["conversationId"] = json!(STANDARD.encode(uuid_bytes(CONVERSATION_ID)));
    prior
}

fn uuid_bytes(value: &str) -> [u8; 16] {
    *uuid::Uuid::parse_str(value)
        .expect("fixture identifiers are canonical UUIDs")
        .as_bytes()
}

fn device_enrollment(key_id: &str, public_key: &[u8; 32]) -> Value {
    json!({
        "$type": "blue.catbird.chat.defs#deviceEnrollmentBody",
        "signatureDomain": "CATBIRD-CHAT-DEVICE-ENROLL\u{0}",
        "actorDid": ACTOR_DID,
        "deviceId": ACTOR_DEVICE_ID,
        "deviceName": "Alice's fixture device",
        "keyId": key_id,
        "signaturePublicKey": STANDARD.encode(public_key),
        "dpopJkt": dpop_jkt(b"catbird-chat-vector-dpop-enroll"),
        "expectedAuthGeneration": 0,
        "capability": capability(),
        "keyPackages": key_packages(),
        "idempotencyKey": "00000000-0000-4000-8000-000000000011",
        "signedAt": SIGNED_AT
    })
}

/// The eleven bodies, each paired with its body name and the top-level field
/// the harness mutates to prove the signature covers it.
pub fn bodies(key_id: &str, public_key: &[u8; 32]) -> Vec<(&'static str, &'static str, Value)> {
    vec![
        (
            "deviceEnrollmentBody",
            "deviceId",
            device_enrollment(key_id, public_key),
        ),
        (
            "keyPackageReplenishmentBody",
            "idempotencyKey",
            key_package_replenishment(key_id, public_key),
        ),
        (
            // Not `newDpopJkt`: a 43-character base64url thumbprint encodes 256
            // bits, so its final character carries only four significant bits
            // and most substitutions are not decodable at all. The server
            // rejects them before a transcript exists, which would prove
            // nothing about signature coverage.
            "deviceAuthenticationRebindBody",
            "idempotencyKey",
            device_authentication_rebind(key_id),
        ),
        (
            "deviceRevocationBody",
            "targetDeviceId",
            device_revocation(key_id),
        ),
        (
            "blobUploadPreparationBody",
            "blobId",
            blob_upload_preparation(key_id),
        ),
        ("applicationSendBody", "messageId", application_send(key_id)),
        ("typingBody", "typingId", typing(key_id)),
        (
            "leafRecoveryRequestBody",
            "recoveryRequestId",
            leaf_recovery_request(key_id),
        ),
        (
            "leafRecoveryCancellationBody",
            "recoveryRequestId",
            leaf_recovery_cancellation(key_id),
        ),
        (
            "welcomeAcknowledgementBody",
            "welcomeId",
            welcome_acknowledgement(key_id),
        ),
        (
            "welcomeRejectionBody",
            "welcomeId",
            welcome_rejection(key_id),
        ),
    ]
}

fn key_package_replenishment(key_id: &str, public_key: &[u8; 32]) -> Value {
    json!({
        "$type": "blue.catbird.chat.defs#keyPackageReplenishmentBody",
        "signatureDomain": "CATBIRD-CHAT-DEVICE-REPLENISH\u{0}",
        "actorDid": ACTOR_DID,
        "actorDeviceId": ACTOR_DEVICE_ID,
        "keyId": key_id,
        "authGeneration": 1,
        "dpopJkt": dpop_jkt(b"catbird-chat-vector-dpop-replenish"),
        "signaturePublicKey": STANDARD.encode(public_key),
        "keyPackages": key_packages(),
        "idempotencyKey": "00000000-0000-4000-8000-000000000012",
        "signedAt": SIGNED_AT
    })
}

fn device_authentication_rebind(key_id: &str) -> Value {
    json!({
        "$type": "blue.catbird.chat.defs#deviceAuthenticationRebindBody",
        "signatureDomain": "CATBIRD-CHAT-DEVICE-REBIND\u{0}",
        "actorDid": ACTOR_DID,
        "actorDeviceId": ACTOR_DEVICE_ID,
        "keyId": key_id,
        "expectedAuthGeneration": 1,
        "currentDpopJkt": dpop_jkt(b"catbird-chat-vector-dpop-current"),
        "newDpopJkt": dpop_jkt(b"catbird-chat-vector-dpop-new"),
        "idempotencyKey": "00000000-0000-4000-8000-000000000013",
        "signedAt": SIGNED_AT
    })
}

fn device_revocation(key_id: &str) -> Value {
    json!({
        "$type": "blue.catbird.chat.defs#deviceRevocationBody",
        "signatureDomain": "CATBIRD-CHAT-DEVICE-REVOKE\u{0}",
        "actorDid": ACTOR_DID,
        "actorDeviceId": ACTOR_DEVICE_ID,
        "keyId": key_id,
        "authGeneration": 1,
        "targetDeviceId": "71717171-7171-4171-b171-717171717171",
        "targetAuthGeneration": 1,
        "idempotencyKey": "00000000-0000-4000-8000-000000000014",
        "signedAt": SIGNED_AT
    })
}

fn blob_upload_preparation(key_id: &str) -> Value {
    json!({
        "$type": "blue.catbird.chat.defs#blobUploadPreparationBody",
        "signatureDomain": "CATBIRD-CHAT-BLOB-PREPARE\u{0}",
        "blobId": "018f3f6a-7b2c-4d91-8a5e-0f123456789a",
        "conversationId": CONVERSATION_ID,
        "actorDid": ACTOR_DID,
        "actorDeviceId": ACTOR_DEVICE_ID,
        "keyId": key_id,
        "authGeneration": 1,
        "prior": coordinates(),
        "ciphertextSha256": STANDARD.encode(Sha256::digest(b"catbird-chat-vector-blob")),
        "ciphertextSize": 4096,
        "purpose": "attachment",
        "idempotencyKey": "00000000-0000-4000-8000-000000000015",
        "signedAt": SIGNED_AT
    })
}

fn application_send(key_id: &str) -> Value {
    let message = [0x31_u8; 8];
    let (encoded, sha256) = artifact(&message);
    let message_id = "51515151-5151-4151-9151-515151515151";
    json!({
        "$type": "blue.catbird.chat.defs#applicationSendBody",
        "signatureDomain": "CATBIRD-CHAT-MESSAGE\u{0}",
        "messageId": message_id,
        "actorDid": ACTOR_DID,
        "actorDeviceId": ACTOR_DEVICE_ID,
        "keyId": key_id,
        "authGeneration": 1,
        "prior": coordinates(),
        "aad": {
            "protocolVersion": "1",
            "conversationId": STANDARD.encode(uuid_bytes(CONVERSATION_ID)),
            "generation": 1,
            "messageId": STANDARD.encode(uuid_bytes(message_id)),
            "prior": aad_prior()
        },
        "applicationMessage": {
            "framing": "mlsMessage",
            "contentType": "privateMessageApplication",
            "bytes": encoded,
            "sha256": sha256
        },
        "blobBindings": [],
        "signedAt": SIGNED_AT
    })
}

fn typing(key_id: &str) -> Value {
    json!({
        "$type": "blue.catbird.chat.defs#typingBody",
        "signatureDomain": "CATBIRD-CHAT-TYPING\u{0}",
        "typingId": "00000000-0000-4000-8000-000000000016",
        "actorDid": ACTOR_DID,
        "actorDeviceId": ACTOR_DEVICE_ID,
        "keyId": key_id,
        "authGeneration": 1,
        "coordinates": coordinates(),
        "isTyping": true,
        "signedAt": SIGNED_AT
    })
}

fn leaf_recovery_request(key_id: &str) -> Value {
    json!({
        "$type": "blue.catbird.chat.defs#leafRecoveryRequestBody",
        "signatureDomain": "CATBIRD-CHAT-LEAF-RECOVERY-REQUEST\u{0}",
        "recoveryRequestId": "00000000-0000-4000-8000-000000000017",
        "actorDid": ACTOR_DID,
        "actorDeviceId": ACTOR_DEVICE_ID,
        "keyId": key_id,
        "authGeneration": 1,
        "prior": coordinates(),
        "recoveryKind": "replace",
        "idempotencyKey": "00000000-0000-4000-8000-000000000018",
        "signedAt": SIGNED_AT
    })
}

fn leaf_recovery_cancellation(key_id: &str) -> Value {
    json!({
        "$type": "blue.catbird.chat.defs#leafRecoveryCancellationBody",
        "signatureDomain": "CATBIRD-CHAT-LEAF-RECOVERY-CANCEL\u{0}",
        "recoveryRequestId": "00000000-0000-4000-8000-000000000017",
        "actorDid": ACTOR_DID,
        "actorDeviceId": ACTOR_DEVICE_ID,
        "keyId": key_id,
        "authGeneration": 1,
        "idempotencyKey": "00000000-0000-4000-8000-000000000019",
        "signedAt": SIGNED_AT
    })
}

fn welcome_acknowledgement(key_id: &str) -> Value {
    json!({
        "$type": "blue.catbird.chat.defs#welcomeAcknowledgementBody",
        "signatureDomain": "CATBIRD-CHAT-WELCOME-ACK\u{0}",
        "welcomeId": "00000000-0000-4000-8000-00000000001a",
        "transitionSeq": 7,
        "coordinates": coordinates(),
        "actorDid": ACTOR_DID,
        "actorDeviceId": ACTOR_DEVICE_ID,
        "keyId": key_id,
        "authGeneration": 1,
        "idempotencyKey": "00000000-0000-4000-8000-00000000001b",
        "signedAt": SIGNED_AT
    })
}

fn welcome_rejection(key_id: &str) -> Value {
    json!({
        "$type": "blue.catbird.chat.defs#welcomeRejectionBody",
        "signatureDomain": "CATBIRD-CHAT-WELCOME-REJECT\u{0}",
        "welcomeId": "00000000-0000-4000-8000-00000000001a",
        "transitionSeq": 7,
        "coordinates": coordinates(),
        "reason": "noMatchingKeyPackage",
        "actorDid": ACTOR_DID,
        "actorDeviceId": ACTOR_DEVICE_ID,
        "keyId": key_id,
        "authGeneration": 1,
        "idempotencyKey": "00000000-0000-4000-8000-00000000001c",
        "signedAt": SIGNED_AT
    })
}
