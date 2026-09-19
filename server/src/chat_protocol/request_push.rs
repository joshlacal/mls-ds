//! Strict internal wire contract for generic encrypted-request push metadata.
//! These bodies contain identifiers and digests only; no MLS artifact or
//! plaintext is accepted by either shape.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::{DateTime, SecondsFormat, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::validation::{
    decode_canonical_base64url, BareDid, CanonicalTimestamp, CanonicalUuidV4, KeyThumbprint,
    MAX_SAFE_INTEGER,
};

pub(crate) const REQUEST_PUSH_AUTHORITY: &str = "did:web:chat.catbird.blue";
pub(crate) const REQUEST_PUSH_EVENT_DOMAIN: &[u8] = b"CATBIRD-DIRECT-REQUEST-PUSH\0";
pub(crate) const REQUEST_PUSH_EVENT_TRANSCRIPT_DOMAIN: &[u8] =
    b"CATBIRD-DIRECT-REQUEST-PUSH-EVENT\0";
pub(crate) const REQUEST_PUSH_ELIGIBILITY_DOMAIN: &[u8] =
    b"CATBIRD-DIRECT-REQUEST-PUSH-ELIGIBILITY\0";
pub(crate) const MAX_INTERNAL_BODY_BYTES: usize = 32 * 1024;

#[derive(Debug, thiserror::Error)]
pub(crate) enum RequestPushWireError {
    #[error("invalid request push wire value")]
    Invalid,
    #[error("request push wire body is too large")]
    TooLarge,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct SignedInternalEnvelope {
    pub body: String,
    pub signature: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct RequestPushEventBody {
    pub protocol_version: u8,
    pub authority_did: String,
    pub key_id: String,
    pub event_id: String,
    pub request_id: String,
    pub conversation_id: String,
    pub first_message_id: String,
    pub sender_did: String,
    pub recipient_did: String,
    pub recipient_device_ids: Vec<String>,
    pub payload_digest: String,
    pub issued_at: String,
    pub expires_at: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct RequestPushEligibilityRequest {
    pub event_id: String,
    pub request_id: String,
    pub recipient_did: String,
    pub device_id: String,
    pub provider: String,
    pub registration_id: String,
    pub token_generation: i64,
    pub binding_digest: String,
    pub target_key_id: String,
    pub device_auth_generation: i64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct RequestPushEligibilityBody {
    pub protocol_version: u8,
    pub authority_did: String,
    pub key_id: String,
    pub event_id: String,
    pub request_id: String,
    pub recipient_did: String,
    pub device_id: String,
    pub provider: String,
    pub registration_id: String,
    pub token_generation: i64,
    pub binding_digest: String,
    pub target_key_id: String,
    pub device_auth_generation: i64,
    pub conversation_id: String,
    pub first_message_id: String,
    pub sender_did: String,
    pub eligible: bool,
    pub checked_at: String,
    pub expires_at: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct RequestPushEventAck {
    pub event_id: String,
    pub payload_digest: String,
    pub accepted: bool,
}

fn uuid(value: &str) -> Result<Uuid, RequestPushWireError> {
    CanonicalUuidV4::parse(value).map_err(|_| RequestPushWireError::Invalid)?;
    Uuid::parse_str(value).map_err(|_| RequestPushWireError::Invalid)
}

fn digest(value: &str) -> Result<[u8; 32], RequestPushWireError> {
    decode_canonical_base64url(value)
        .map_err(|_| RequestPushWireError::Invalid)?
        .try_into()
        .map_err(|_| RequestPushWireError::Invalid)
}

fn generation(value: i64) -> Result<i64, RequestPushWireError> {
    if (1..=MAX_SAFE_INTEGER).contains(&value) {
        Ok(value)
    } else {
        Err(RequestPushWireError::Invalid)
    }
}

fn timestamp(value: &str) -> Result<DateTime<Utc>, RequestPushWireError> {
    CanonicalTimestamp::parse(value)
        .map_err(|_| RequestPushWireError::Invalid)
        .map(|value| value.datetime())
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

impl RequestPushEventBody {
    pub(crate) fn validate(&self, now: DateTime<Utc>) -> Result<(), RequestPushWireError> {
        if self.protocol_version != 1
            || self.authority_did != REQUEST_PUSH_AUTHORITY
            || !self
                .key_id
                .starts_with("did:web:chat.catbird.blue#chat-request-receipt-")
        {
            return Err(RequestPushWireError::Invalid);
        }
        let event = uuid(&self.event_id)?;
        let request = uuid(&self.request_id)?;
        let conversation = uuid(&self.conversation_id)?;
        let first = uuid(&self.first_message_id)?;
        BareDid::parse(&self.sender_did).map_err(|_| RequestPushWireError::Invalid)?;
        BareDid::parse(&self.recipient_did).map_err(|_| RequestPushWireError::Invalid)?;
        let devices = self
            .recipient_device_ids
            .iter()
            .map(|value| uuid(value))
            .collect::<Result<Vec<_>, _>>()?;
        if devices.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(RequestPushWireError::Invalid);
        }
        let payload = digest(&self.payload_digest)?;
        if payload
            != request_push_event_payload_digest(
                event,
                request,
                conversation,
                first,
                &self.sender_did,
                &self.recipient_did,
                &devices,
            )?
        {
            return Err(RequestPushWireError::Invalid);
        }
        let issued = timestamp(&self.issued_at)?;
        let expires = timestamp(&self.expires_at)?;
        if issued > now + chrono::Duration::seconds(5)
            || expires <= now
            || expires <= issued
            || expires > issued + chrono::Duration::seconds(60)
        {
            return Err(RequestPushWireError::Invalid);
        }
        Ok(())
    }
}

impl RequestPushEligibilityRequest {
    pub(crate) fn validate(&self) -> Result<(), RequestPushWireError> {
        uuid(&self.event_id)?;
        uuid(&self.request_id)?;
        BareDid::parse(&self.recipient_did).map_err(|_| RequestPushWireError::Invalid)?;
        uuid(&self.device_id)?;
        uuid(&self.registration_id)?;
        if !matches!(self.provider.as_str(), "apns" | "fcm") {
            return Err(RequestPushWireError::Invalid);
        }
        generation(self.token_generation)?;
        digest(&self.binding_digest)?;
        KeyThumbprint::parse(&self.target_key_id).map_err(|_| RequestPushWireError::Invalid)?;
        generation(self.device_auth_generation)?;
        Ok(())
    }
}

impl RequestPushEligibilityBody {
    pub(crate) fn validate(&self, now: DateTime<Utc>) -> Result<(), RequestPushWireError> {
        if self.protocol_version != 1
            || self.authority_did != REQUEST_PUSH_AUTHORITY
            || !self
                .key_id
                .starts_with("did:web:chat.catbird.blue#chat-request-receipt-")
        {
            return Err(RequestPushWireError::Invalid);
        }
        self.as_request().validate()?;
        uuid(&self.conversation_id)?;
        uuid(&self.first_message_id)?;
        BareDid::parse(&self.sender_did).map_err(|_| RequestPushWireError::Invalid)?;
        let checked = timestamp(&self.checked_at)?;
        let expires = timestamp(&self.expires_at)?;
        if checked > now + chrono::Duration::seconds(1)
            || expires <= now
            || expires <= checked
            || expires > checked + chrono::Duration::seconds(5)
        {
            return Err(RequestPushWireError::Invalid);
        }
        Ok(())
    }

    pub(crate) fn as_request(&self) -> RequestPushEligibilityRequest {
        RequestPushEligibilityRequest {
            event_id: self.event_id.clone(),
            request_id: self.request_id.clone(),
            recipient_did: self.recipient_did.clone(),
            device_id: self.device_id.clone(),
            provider: self.provider.clone(),
            registration_id: self.registration_id.clone(),
            token_generation: self.token_generation,
            binding_digest: self.binding_digest.clone(),
            target_key_id: self.target_key_id.clone(),
            device_auth_generation: self.device_auth_generation,
        }
    }
}

pub(crate) fn canonical_time(value: DateTime<Utc>) -> String {
    value.to_rfc3339_opts(SecondsFormat::Millis, true)
}

pub(crate) fn envelope_signing_bytes(
    domain: &[u8],
    body: &[u8],
) -> Result<Vec<u8>, RequestPushWireError> {
    if body.is_empty() || body.len() > MAX_INTERNAL_BODY_BYTES {
        return Err(if body.len() > MAX_INTERNAL_BODY_BYTES {
            RequestPushWireError::TooLarge
        } else {
            RequestPushWireError::Invalid
        });
    }
    let mut bytes = Vec::with_capacity(domain.len() + body.len());
    bytes.extend_from_slice(domain);
    bytes.extend_from_slice(body);
    Ok(bytes)
}

pub(crate) fn encode_digest(value: [u8; 32]) -> String {
    URL_SAFE_NO_PAD.encode(value)
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

    #[test]
    fn eligibility_rejects_unknown_fields_and_noncanonical_coordinates() {
        let good = serde_json::json!({
            "eventId":"00000000-0000-4000-8000-000000000001",
            "requestId":"00000000-0000-4000-8000-000000000002",
            "recipientDid":"did:web:bob.example.org",
            "deviceId":"00000000-0000-4000-8000-000000000003",
            "provider":"apns",
            "registrationId":"00000000-0000-4000-8000-000000000004",
            "tokenGeneration":1,
            "bindingDigest":URL_SAFE_NO_PAD.encode([7;32]),
            "targetKeyId":URL_SAFE_NO_PAD.encode([8;32]),
            "deviceAuthGeneration":1
        });
        let parsed: RequestPushEligibilityRequest = serde_json::from_value(good.clone()).unwrap();
        parsed.validate().unwrap();
        let mut unknown = good;
        unknown["token"] = serde_json::json!("forbidden");
        assert!(serde_json::from_value::<RequestPushEligibilityRequest>(unknown).is_err());
    }
}
