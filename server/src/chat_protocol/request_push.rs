//! Immutable identity of a publication's direct-request push event.
//!
//! The digest binds the event to its request, conversation, pair, and exact
//! recipient devices; `chat.direct_request_push_payload_digest` recomputes it
//! in SQL. Wakes themselves go out through the D2 Push Gateway
//! (`workers::request_push`).

use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::validation::BareDid;

pub(crate) const REQUEST_PUSH_AUTHORITY: &str = "did:web:chat.catbird.blue";
pub(crate) const REQUEST_PUSH_EVENT_TRANSCRIPT_DOMAIN: &[u8] =
    b"CATBIRD-DIRECT-REQUEST-PUSH-EVENT\0";

#[derive(Debug, thiserror::Error)]
pub(crate) enum RequestPushWireError {
    #[error("invalid request push wire value")]
    Invalid,
}

fn len_prefixed(output: &mut Vec<u8>, value: &str) -> Result<(), RequestPushWireError> {
    let length = u32::try_from(value.len()).map_err(|_| RequestPushWireError::Invalid)?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value.as_bytes());
    Ok(())
}

pub(crate) fn request_push_event_payload_digest(
    event_id: Uuid,
    request_id: Uuid,
    conversation_id: Uuid,
    first_message_id: Uuid,
    sender_did: &str,
    recipient_did: &str,
    recipient_device_ids: &[Uuid],
) -> Result<[u8; 32], RequestPushWireError> {
    BareDid::parse(sender_did).map_err(|_| RequestPushWireError::Invalid)?;
    BareDid::parse(recipient_did).map_err(|_| RequestPushWireError::Invalid)?;
    if sender_did == recipient_did
        || !(1..=20).contains(&recipient_device_ids.len())
        || recipient_device_ids
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
    {
        return Err(RequestPushWireError::Invalid);
    }
    let mut output = REQUEST_PUSH_EVENT_TRANSCRIPT_DOMAIN.to_vec();
    for value in [
        REQUEST_PUSH_AUTHORITY.to_owned(),
        event_id.to_string(),
        request_id.to_string(),
        conversation_id.to_string(),
        first_message_id.to_string(),
        sender_did.to_owned(),
        recipient_did.to_owned(),
    ] {
        len_prefixed(&mut output, &value)?;
    }
    output.extend_from_slice(
        &u32::try_from(recipient_device_ids.len())
            .map_err(|_| RequestPushWireError::Invalid)?
            .to_be_bytes(),
    );
    for device in recipient_device_ids {
        len_prefixed(&mut output, &device.to_string())?;
    }
    Ok(Sha256::digest(output).into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn immutable_event_digest_is_ordered_and_binds_every_coordinate() {
        let event = Uuid::parse_str("00000000-0000-4000-8000-000000000001").unwrap();
        let request = Uuid::parse_str("00000000-0000-4000-8000-000000000002").unwrap();
        let conversation = Uuid::parse_str("00000000-0000-4000-8000-000000000003").unwrap();
        let first = Uuid::parse_str("00000000-0000-4000-8000-000000000004").unwrap();
        let devices = [
            Uuid::parse_str("00000000-0000-4000-8000-000000000005").unwrap(),
            Uuid::parse_str("00000000-0000-4000-8000-000000000006").unwrap(),
        ];
        let digest = request_push_event_payload_digest(
            event,
            request,
            conversation,
            first,
            "did:web:alice.example.org",
            "did:web:bob.example.org",
            &devices,
        )
        .unwrap();
        assert_ne!(digest, [0; 32]);
        assert_ne!(
            digest,
            request_push_event_payload_digest(
                event,
                request,
                conversation,
                first,
                "did:web:alice.example.org",
                "did:web:carol.example.org",
                &devices,
            )
            .unwrap()
        );
        assert!(request_push_event_payload_digest(
            event,
            request,
            conversation,
            first,
            "did:web:alice.example.org",
            "did:web:bob.example.org",
            &[devices[1], devices[0]],
        )
        .is_err());
    }
}
