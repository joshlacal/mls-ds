//! Decoding of DS-to-DS request bodies that rejects unknown top-level fields.
//!
//! The Petrel-generated XRPC `Input` types decode "strictly" only in the sense
//! that a malformed optional field is an error. Like the lexicon rules they
//! follow, they still accept and silently drop unknown fields, and an `Input`
//! keeps no `extra_data`. The federation endpoints are stricter than that: a
//! peer that sends a field this server does not know is speaking a protocol
//! version this server does not implement, so the request is refused with
//! `400 InvalidEnvelope` instead of being acted on with the field ignored.
//! This module restores that check, which the Jacquard types made possible
//! through their `extra_data` map.

use serde::de::DeserializeOwned;

use crate::federation::FederationError;

/// Top-level input properties of `blue.catbird.mlsDS.deliverMessage`.
pub const DELIVER_MESSAGE_INPUT_FIELDS: &[&str] = &[
    "header",
    "entryBytes",
    "signedRequestBytes",
    "recipientDid",
    "entryLocator",
];

/// Top-level input properties of `blue.catbird.mlsDS.deliverWelcome`.
pub const DELIVER_WELCOME_INPUT_FIELDS: &[&str] = &[
    "header",
    "recipientDid",
    "recipientDeviceId",
    "welcomeId",
    "recoveryRequestId",
    "keyPackageRef",
    "welcomeBytes",
    "welcomeSha256",
    "entryBytes",
    "signedRequestBytes",
    "entryLocator",
    "coordinates",
    "publicSnapshotSha256",
    "treeSummarySha256",
];

/// Top-level input properties of `blue.catbird.mlsDS.submitCommit`.
pub const SUBMIT_COMMIT_INPUT_FIELDS: &[&str] = &["header", "signedRequestBytes"];

/// Decodes a DS request body into its generated `Input` type, then refuses it
/// if the top-level object carries a field outside `allowed`.
///
/// `request` names the request in error text (for example `DeliverMessage`).
/// A body that does not decode is a JSON error, as before; a body that decodes
/// but carries an unknown top-level field is `InvalidEnvelope` with the reason
/// `unknown fields in <request> request`.
pub fn decode_ds_input<T: DeserializeOwned>(
    body: &str,
    request: &str,
    allowed: &[&str],
) -> Result<T, FederationError> {
    let invalid_body = |e: serde_json::Error| {
        FederationError::Json(serde_json::Error::io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("Invalid {request} body: {e}"),
        )))
    };
    let msg: T = serde_json::from_str(body).map_err(invalid_body)?;

    let raw: serde_json::Value = serde_json::from_str(body).map_err(invalid_body)?;
    let has_unknown = raw
        .as_object()
        .is_some_and(|fields| fields.keys().any(|key| !allowed.contains(&key.as_str())));
    if has_unknown {
        return Err(FederationError::InvalidEnvelope {
            reason: format!("unknown fields in {request} request"),
        });
    }
    Ok(msg)
}

#[cfg(test)]
mod tests {
    use axum::response::IntoResponse;
    use serde_json::{json, Value};

    use super::*;
    use crate::blue_catbird::mls_ds::{
        deliver_message::Input as DeliverMessage, deliver_welcome::Input as DeliverWelcome,
        submit_commit::Input as SubmitCommit,
    };

    const UUID_A: &str = "0b8f6a52-6d0e-4c3b-9b1a-2f4c5d6e7f80";
    const UUID_B: &str = "1c9f6a52-6d0e-4c3b-9b1a-2f4c5d6e7f81";
    const UUID_C: &str = "2d9f6a52-6d0e-4c3b-9b1a-2f4c5d6e7f82";
    const UUID_D: &str = "3e9f6a52-6d0e-4c3b-9b1a-2f4c5d6e7f83";

    fn bytes32(fill: u8) -> Value {
        use base64::Engine as _;
        json!({ "$bytes": base64::engine::general_purpose::STANDARD_NO_PAD.encode([fill; 32]) })
    }

    fn header() -> Value {
        json!({
            "protocolVersion": "1",
            "deliveryId": UUID_A,
            "conversationId": UUID_B,
            "senderDsDid": "did:web:ds-a.example.com",
            "receiverDsDid": "did:web:ds-b.example.com",
            "sequencerDid": "did:web:ds-a.example.com",
            "sequencerTerm": 1,
            "receivedAt": "2026-11-27T12:00:00.000Z",
            "payloadSha256": bytes32(1),
        })
    }

    fn locator() -> Value {
        json!({
            "entryId": UUID_C,
            "seq": 1,
            "acceptedPayloadSha256": bytes32(2),
            "outerEntryFingerprint": bytes32(3),
        })
    }

    fn deliver_message_body() -> Value {
        json!({
            "header": header(),
            "entryBytes": bytes32(4),
            "signedRequestBytes": bytes32(5),
            "recipientDid": "did:plc:ragtjsm2j2vknwk6zpkrhgah",
            "entryLocator": locator(),
        })
    }

    fn deliver_welcome_body() -> Value {
        json!({
            "header": header(),
            "recipientDid": "did:plc:ragtjsm2j2vknwk6zpkrhgah",
            "recipientDeviceId": UUID_D,
            "welcomeId": UUID_A,
            "recoveryRequestId": UUID_C,
            "keyPackageRef": bytes32(6),
            "welcomeBytes": bytes32(7),
            "welcomeSha256": bytes32(8),
            "entryBytes": bytes32(9),
            "signedRequestBytes": bytes32(10),
            "entryLocator": locator(),
            "coordinates": {
                "conversationId": UUID_B,
                "generation": 0,
                "stateVersion": 1,
                "groupId": bytes32(11),
                "epoch": 1,
                "groupContextHash": bytes32(12),
                "confirmationTag": bytes32(13),
                "lifecycle": "active",
            },
            "publicSnapshotSha256": bytes32(14),
            "treeSummarySha256": bytes32(15),
        })
    }

    fn submit_commit_body() -> Value {
        json!({ "header": header(), "signedRequestBytes": bytes32(16) })
    }

    fn with_extra_field(mut body: Value) -> String {
        body["futureField"] = json!(true);
        body.to_string()
    }

    fn assert_unknown_field_rejected(err: FederationError, request: &str) {
        match &err {
            FederationError::InvalidEnvelope { reason } => {
                assert_eq!(reason, &format!("unknown fields in {request} request"));
            }
            other => panic!("expected InvalidEnvelope, got {other:?}"),
        }
        assert_eq!(
            err.into_response().status(),
            axum::http::StatusCode::BAD_REQUEST
        );
    }

    #[test]
    fn deliver_message_accepts_valid_body_and_rejects_unknown_top_level_field() {
        let valid = deliver_message_body().to_string();
        decode_ds_input::<DeliverMessage>(&valid, "DeliverMessage", DELIVER_MESSAGE_INPUT_FIELDS)
            .expect("valid deliverMessage body decodes");

        let err = decode_ds_input::<DeliverMessage>(
            &with_extra_field(deliver_message_body()),
            "DeliverMessage",
            DELIVER_MESSAGE_INPUT_FIELDS,
        )
        .expect_err("unknown top-level field must be refused");
        assert_unknown_field_rejected(err, "DeliverMessage");
    }

    #[test]
    fn deliver_welcome_accepts_valid_body_and_rejects_unknown_top_level_field() {
        let valid = deliver_welcome_body().to_string();
        decode_ds_input::<DeliverWelcome>(&valid, "DeliverWelcome", DELIVER_WELCOME_INPUT_FIELDS)
            .expect("valid deliverWelcome body decodes");

        let err = decode_ds_input::<DeliverWelcome>(
            &with_extra_field(deliver_welcome_body()),
            "DeliverWelcome",
            DELIVER_WELCOME_INPUT_FIELDS,
        )
        .expect_err("unknown top-level field must be refused");
        assert_unknown_field_rejected(err, "DeliverWelcome");
    }

    #[test]
    fn submit_commit_accepts_valid_body_and_rejects_unknown_top_level_field() {
        let valid = submit_commit_body().to_string();
        decode_ds_input::<SubmitCommit>(&valid, "SubmitCommit", SUBMIT_COMMIT_INPUT_FIELDS)
            .expect("valid submitCommit body decodes");

        let err = decode_ds_input::<SubmitCommit>(
            &with_extra_field(submit_commit_body()),
            "SubmitCommit",
            SUBMIT_COMMIT_INPUT_FIELDS,
        )
        .expect_err("unknown top-level field must be refused");
        assert_unknown_field_rejected(err, "SubmitCommit");
    }

    /// The field lists must track the lexicons, or a valid peer request that
    /// uses a newly added property would be refused.
    #[test]
    fn field_lists_match_lexicon_input_properties() {
        let cases: [(&str, &[&str]); 3] = [
            (
                include_str!(
                    "../../../../lexicon/blue/catbird/mlsDS/blue.catbird.mlsDS.deliverMessage.json"
                ),
                DELIVER_MESSAGE_INPUT_FIELDS,
            ),
            (
                include_str!(
                    "../../../../lexicon/blue/catbird/mlsDS/blue.catbird.mlsDS.deliverWelcome.json"
                ),
                DELIVER_WELCOME_INPUT_FIELDS,
            ),
            (
                include_str!(
                    "../../../../lexicon/blue/catbird/mlsDS/blue.catbird.mlsDS.submitCommit.json"
                ),
                SUBMIT_COMMIT_INPUT_FIELDS,
            ),
        ];
        for (lexicon, fields) in cases {
            let doc: Value = serde_json::from_str(lexicon).unwrap();
            let mut declared: Vec<&str> = doc["defs"]["main"]["input"]["schema"]["properties"]
                .as_object()
                .unwrap()
                .keys()
                .map(String::as_str)
                .collect();
            let mut listed = fields.to_vec();
            declared.sort_unstable();
            listed.sort_unstable();
            assert_eq!(declared, listed, "lexicon {}", doc["id"]);
        }
    }
}
