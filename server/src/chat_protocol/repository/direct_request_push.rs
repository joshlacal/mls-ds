//! Current, transaction-bound authority for one request-push attempt.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};
use sqlx::{Postgres, Row, Transaction};
use uuid::Uuid;

use super::super::{
    relationship_policy::{PublicTransport, RelationshipAuthority},
    request_push::RequestPushEligibilityRequest,
};

#[derive(Debug, thiserror::Error)]
pub(crate) enum RequestPushEligibilityError {
    #[error("invalid eligibility request")]
    Invalid,
    #[error("request push event not found")]
    NotFound,
    #[error("relationship authority unavailable")]
    PolicyUnavailable,
    #[error("request push storage failed")]
    Database(#[from] sqlx::Error),
    #[error("request push authority invariant failed")]
    Invariant,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RequestPushEligibilityDecision {
    pub conversation_id: Uuid,
    pub first_message_id: Uuid,
    pub sender_did: String,
    pub eligible: bool,
    pub checked_at: DateTime<Utc>,
}

async fn device_binding_is_current(
    tx: &mut Transaction<'_, Postgres>,
    recipient_did: &str,
    requested_device: Uuid,
    requested_registration: Uuid,
    requested_binding: &[u8],
    request: &RequestPushEligibilityRequest,
) -> Result<bool, sqlx::Error> {
    let device = sqlx::query(
        "SELECT status,auth_generation FROM chat.devices \
          WHERE user_did=$1 AND device_id=$2 FOR UPDATE",
    )
    .bind(recipient_did)
    .bind(requested_device)
    .fetch_optional(&mut **tx)
    .await?;
    let (device_status, stored_auth_generation) = device
        .map(|row| {
            (
                row.get::<String, _>("status"),
                row.get::<i64, _>("auth_generation"),
            )
        })
        .unwrap_or_default();

    let current_key: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM chat.device_keys \
          WHERE user_did=$1 AND device_id=$2 AND key_id=$3 AND revoked_at IS NULL \
            AND enrollment_auth_generation <= $4)",
    )
    .bind(recipient_did)
    .bind(requested_device)
    .bind(&request.target_key_id)
    .bind(request.device_auth_generation)
    .fetch_one(&mut **tx)
    .await?;

    let binding = sqlx::query(
        "SELECT registration_id,token_generation,binding_digest,key_id,auth_generation,enabled \
           FROM chat.request_push_bindings \
          WHERE user_did=$1 AND device_id=$2 AND provider=$3 FOR UPDATE",
    )
    .bind(recipient_did)
    .bind(requested_device)
    .bind(&request.provider)
    .fetch_optional(&mut **tx)
    .await?;
    let binding_matches = binding.is_some_and(|row| {
        row.get::<Uuid, _>("registration_id") == requested_registration
            && row.get::<i64, _>("token_generation") == request.token_generation
            && row.get::<Vec<u8>, _>("binding_digest") == requested_binding
            && row.get::<String, _>("key_id") == request.target_key_id
            && row.get::<i64, _>("auth_generation") == request.device_auth_generation
            && row.get::<bool, _>("enabled")
    });

    Ok(device_status == "active"
        && stored_auth_generation == request.device_auth_generation
        && current_key
        && binding_matches)
}

/// Private witness minted only after the request, conversation, consent,
/// selected device, current device key and exact push binding were checked in
/// one transaction. Relationship collection consumes these exact digests.
pub(super) struct LockedDirectRequestPushEligibility {
    transaction_id: String,
    sender_did: String,
    recipient_did: String,
    authenticated_actor_digest: [u8; 32],
    durable_read_set_digest: [u8; 32],
}

impl LockedDirectRequestPushEligibility {
    pub(super) fn parts(&self) -> (&str, &str, &str, [u8; 32], [u8; 32]) {
        (
            &self.transaction_id,
            &self.sender_did,
            &self.recipient_did,
            self.authenticated_actor_digest,
            self.durable_read_set_digest,
        )
    }
}

pub(crate) async fn evaluate_eligibility<T: PublicTransport>(
    tx: &mut Transaction<'_, Postgres>,
    request: &RequestPushEligibilityRequest,
    authenticated_credential_digest: [u8; 32],
    authority: &RelationshipAuthority<T>,
    now: DateTime<Utc>,
) -> Result<RequestPushEligibilityDecision, RequestPushEligibilityError> {
    request
        .validate()
        .map_err(|_| RequestPushEligibilityError::Invalid)?;
    if authenticated_credential_digest == [0; 32] {
        return Err(RequestPushEligibilityError::Invariant);
    }
    let request_id =
        Uuid::parse_str(&request.request_id).map_err(|_| RequestPushEligibilityError::Invalid)?;
    let requested_event =
        Uuid::parse_str(&request.event_id).map_err(|_| RequestPushEligibilityError::Invalid)?;
    let requested_device =
        Uuid::parse_str(&request.device_id).map_err(|_| RequestPushEligibilityError::Invalid)?;
    let requested_registration = Uuid::parse_str(&request.registration_id)
        .map_err(|_| RequestPushEligibilityError::Invalid)?;
    let requested_binding = URL_SAFE_NO_PAD
        .decode(&request.binding_digest)
        .map_err(|_| RequestPushEligibilityError::Invalid)?;

    // The immutable mapping is selected by request ID so a changed event ID or
    // recipient can receive a signed negative decision without becoming lookup
    // authority for a different request.
    let mapping = sqlx::query(
        "SELECT e.event_id,e.conversation_id,e.first_message_id,e.sender_did,e.recipient_did,\
                p.import_until,p.publication_digest \
           FROM chat.direct_request_push_events e \
           JOIN chat.direct_request_publications p USING(request_id) \
          WHERE e.request_id=$1",
    )
    .bind(request_id)
    .fetch_optional(&mut **tx)
    .await?
    .ok_or(RequestPushEligibilityError::NotFound)?;
    let event_id: Uuid = mapping.get("event_id");
    let conversation_id: Uuid = mapping.get("conversation_id");
    let first_message_id: Uuid = mapping.get("first_message_id");
    let sender_did: String = mapping.get("sender_did");
    let recipient_did: String = mapping.get("recipient_did");
    let import_until: DateTime<Utc> = mapping.get("import_until");
    let publication_digest: Vec<u8> = mapping.get("publication_digest");

    let mut eligible = event_id == requested_event && recipient_did == request.recipient_did;

    // Conversation is the established first mutable authority lock.
    let conversation = sqlx::query(
        "SELECT lifecycle,protocol_version,current_generation,current_state_version \
           FROM chat.conversations WHERE conversation_id=$1 FOR UPDATE",
    )
    .bind(conversation_id)
    .fetch_optional(&mut **tx)
    .await?;
    let Some(conversation) = conversation else {
        return Err(RequestPushEligibilityError::Invariant);
    };
    let lifecycle: String = conversation.get("lifecycle");
    let protocol_version: String = conversation.get("protocol_version");
    let current_generation: i64 = conversation.get("current_generation");
    let current_state_version: i64 = conversation.get("current_state_version");
    eligible &= lifecycle == "active" && protocol_version == "2" && import_until > now;

    let consent: Option<String> = sqlx::query_scalar(
        "SELECT consent FROM chat.direct_request_lifecycle WHERE request_id=$1 FOR UPDATE",
    )
    .bind(request_id)
    .fetch_optional(&mut **tx)
    .await?
    .flatten();
    eligible &= consent.is_none();

    let pending: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM chat.participants \
          WHERE conversation_id=$1 AND user_did=$2 AND current_membership AND status='pending')",
    )
    .bind(conversation_id)
    .bind(&recipient_did)
    .fetch_one(&mut **tx)
    .await?;
    eligible &= pending;

    let selected_import_until: Option<DateTime<Utc>> = sqlx::query_scalar(
        "SELECT d.import_until FROM chat.direct_request_push_event_recipients r \
          JOIN chat.direct_request_device_deliveries d \
            ON (d.request_id,d.owner_did,d.owner_device_id) \
             =(r.request_id,r.recipient_did,r.recipient_device_id) \
          WHERE r.event_id=$1 AND r.request_id=$2 AND r.recipient_did=$3 \
            AND r.recipient_device_id=$4",
    )
    .bind(event_id)
    .bind(request_id)
    .bind(&recipient_did)
    .bind(requested_device)
    .fetch_optional(&mut **tx)
    .await?;
    eligible &= selected_import_until.is_some_and(|deadline| deadline > now);

    let active_leaf: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM chat.member_devices \
          WHERE conversation_id=$1 AND generation=$2 AND user_did=$3 AND device_id=$4 \
            AND active AND removed_at IS NULL)",
    )
    .bind(conversation_id)
    .bind(current_generation)
    .bind(&recipient_did)
    .bind(requested_device)
    .fetch_one(&mut **tx)
    .await?;
    eligible &= active_leaf;

    eligible &= device_binding_is_current(
        tx,
        &recipient_did,
        requested_device,
        requested_registration,
        &requested_binding,
        request,
    )
    .await?;

    if eligible {
        let transaction_id: String = sqlx::query_scalar("SELECT txid_current()::text")
            .fetch_one(&mut **tx)
            .await?;
        let mut read_set = Sha256::new();
        read_set.update(b"CATBIRD-DIRECT-REQUEST-PUSH-ELIGIBILITY-READ-SET\0");
        for bytes in [
            request_id.as_bytes().as_slice(),
            event_id.as_bytes().as_slice(),
            conversation_id.as_bytes().as_slice(),
            requested_device.as_bytes().as_slice(),
            publication_digest.as_slice(),
            request.binding_digest.as_bytes(),
            request.target_key_id.as_bytes(),
        ] {
            read_set.update((bytes.len() as u64).to_be_bytes());
            read_set.update(bytes);
        }
        read_set.update(current_generation.to_be_bytes());
        read_set.update(current_state_version.to_be_bytes());
        read_set.update(request.token_generation.to_be_bytes());
        read_set.update(request.device_auth_generation.to_be_bytes());
        let witness = LockedDirectRequestPushEligibility {
            transaction_id,
            sender_did: sender_did.clone(),
            recipient_did: recipient_did.clone(),
            authenticated_actor_digest: authenticated_credential_digest,
            durable_read_set_digest: read_set.finalize().into(),
        };
        eligible = super::relationship::verify_direct_request_push_policy(tx, &witness, authority)
            .await
            .map_err(|_| RequestPushEligibilityError::PolicyUnavailable)?;
    }

    // The initial `now` is only an early rejection bound. Database locks and
    // the live relationship fetch can wait, so the final signed authority must
    // be bound to a database clock sampled after both. Crossing either retained
    // import deadline while waiting produces a signed negative, never a fresh
    // positive stamped after stale validation.
    let checked_at: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(&mut **tx)
        .await?;
    eligible &= import_until > checked_at
        && selected_import_until.is_some_and(|deadline| deadline > checked_at);

    Ok(RequestPushEligibilityDecision {
        conversation_id,
        first_message_id,
        sender_did,
        eligible,
        checked_at,
    })
}

#[cfg(test)]
#[path = "../../../tests/common/chat_protocol.rs"]
mod chat_protocol;

#[cfg(test)]
#[path = "../../../tests/common/direct_request_database.rs"]
mod direct_request_database;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chat_protocol::{
        dpop::repository_test_evidence,
        repository::{auth, prelude, push_binding},
        transcript::{decode_canonical_signed_mutation, decode_rebind_bootstrap},
    };
    use catbird_atproto::{
        blue_catbird::chat::{PushRegistrationBody, SignedPushRegistration},
        push_registration,
    };
    use ed25519_dalek::{Signer, SigningKey};
    use serde_json::json;

    fn signed_push_registration(
        body: PushRegistrationBody,
        key: &SigningKey,
    ) -> SignedPushRegistration {
        let signature = key.sign(&push_registration::transcript(&body).unwrap());
        SignedPushRegistration {
            body,
            signature: signature.to_bytes().to_vec().into(),
            extra_data: None,
        }
    }

    fn signed_rebind(
        did: &str,
        device: Uuid,
        key_id: &str,
        old_jkt: &str,
        new_jkt: &str,
        operation: Uuid,
        signed_at: &str,
        key: &SigningKey,
    ) -> Vec<u8> {
        let body = json!({
            "$type": "blue.catbird.chat.defs#deviceAuthenticationRebindBody",
            "signatureDomain": "CATBIRD-CHAT-DEVICE-REBIND\0",
            "actorDid": did,
            "actorDeviceId": device,
            "keyId": key_id,
            "expectedAuthGeneration": 1,
            "currentDpopJkt": old_jkt,
            "newDpopJkt": new_jkt,
            "idempotencyKey": operation,
            "signedAt": signed_at,
        });
        let placeholder = serde_json::to_vec(&json!({
            "body": body.clone(),
            "signature": base64::engine::general_purpose::STANDARD.encode([0_u8; 64]),
        }))
        .unwrap();
        let canonical = decode_canonical_signed_mutation(&placeholder).unwrap();
        let signature = key.sign(canonical.transcript_bytes());
        serde_json::to_vec(&json!({
            "body": body,
            "signature": base64::engine::general_purpose::STANDARD.encode(signature.to_bytes()),
        }))
        .unwrap()
    }

    #[tokio::test]
    async fn same_key_rebind_rejects_old_binding_and_accepts_fresh_binding() {
        let pool = direct_request_database::setup().await;
        let did = "did:plc:ewvi7nxzyoun6zhxrhs64oiz";
        let device = Uuid::new_v4();
        let registration = Uuid::new_v4();
        let key = SigningKey::from_bytes(&[55; 32]);
        let public = key.verifying_key().to_bytes();
        let key_id = URL_SAFE_NO_PAD.encode(Sha256::digest(public));
        let old_jkt = URL_SAFE_NO_PAD.encode(Sha256::digest(b"old test DPoP key"));
        let new_jkt = URL_SAFE_NO_PAD.encode(Sha256::digest(b"new test DPoP key"));
        let now = Utc::now();
        let signed_at = now.to_rfc3339_opts(chrono::SecondsFormat::Millis, true);

        let mut setup = pool.begin().await.unwrap();
        sqlx::query(
            "INSERT INTO chat.principals(user_did,created_at) VALUES($1,$2) ON CONFLICT DO NOTHING",
        )
        .bind(did)
        .bind(now)
        .execute(&mut *setup)
        .await
        .unwrap();
        sqlx::query("INSERT INTO chat.devices(user_did,device_id,device_name,status,dpop_jkt,auth_generation,capabilities,created_at,updated_at) VALUES($1,$2,'rebind push fixture','active',$3,1,chat.protocol_capabilities(),$4,$4)")
            .bind(did).bind(device).bind(&old_jkt).bind(now).execute(&mut *setup).await.unwrap();
        sqlx::query("INSERT INTO chat.device_keys(user_did,device_id,key_id,signing_public_key,enrollment_auth_generation,created_at) VALUES($1,$2,$3,$4,1,$5)")
            .bind(did).bind(device).bind(&key_id).bind(public.as_slice()).bind(now).execute(&mut *setup).await.unwrap();

        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../../catbird-atproto/tests/fixtures/push-registration.json"
        ))
        .unwrap();
        let mut old_body: PushRegistrationBody =
            serde_json::from_value(fixture["body"].clone()).unwrap();
        old_body.actor_did = did.parse().unwrap();
        old_body.actor_device_id = device.to_string().into();
        old_body.key_id = key_id.clone().into();
        old_body.registration_id = registration.to_string().into();
        old_body.auth_generation = 1;
        old_body.token_generation = 1;
        old_body.enabled = true;
        old_body.token_sha256 = Sha256::digest(b"old-token").to_vec().into();
        old_body.signed_at = signed_at.parse().unwrap();
        setup.commit().await.unwrap();
        let (_, old_ack) = push_binding::register(
            &pool,
            did,
            signed_push_registration(old_body.clone(), &key),
            Some("old-token"),
        )
        .await
        .unwrap();

        let mut old_request = RequestPushEligibilityRequest {
            event_id: Uuid::new_v4().to_string(),
            request_id: Uuid::new_v4().to_string(),
            recipient_did: did.to_owned(),
            device_id: device.to_string(),
            provider: old_body.provider.to_string(),
            registration_id: registration.to_string(),
            token_generation: 1,
            binding_digest: URL_SAFE_NO_PAD.encode(old_ack.binding_digest.as_ref()),
            target_key_id: key_id.clone(),
            device_auth_generation: 1,
        };
        let mut check = pool.begin().await.unwrap();
        assert!(device_binding_is_current(
            &mut check,
            did,
            device,
            registration,
            old_ack.binding_digest.as_ref(),
            &old_request,
        )
        .await
        .unwrap());
        check.rollback().await.unwrap();

        let operation = Uuid::new_v4();
        let raw = signed_rebind(
            did, device, &key_id, &old_jkt, &new_jkt, operation, &signed_at, &key,
        );
        let bootstrap = decode_rebind_bootstrap(&raw).unwrap();
        let proof_jti: [u8; 12] = Uuid::new_v4().as_bytes()[..12].try_into().unwrap();
        let admission = auth::authorize_rebind_operation_only(
            &pool,
            repository_test_evidence::rebind_with_replay(
                bootstrap,
                Uuid::new_v4(),
                proof_jti,
                &signed_at,
            ),
        )
        .await
        .unwrap();
        let mut rebind = pool.begin().await.unwrap();
        let prelude::PreparedRebindOperation::First(prepared) =
            prelude::prepare_rebind_operation(&mut rebind, admission)
                .await
                .unwrap()
        else {
            panic!("fresh rebind replayed")
        };
        {
            let authority = prepared.effect_authority();
            prelude::persist_rebind_bootstrap_effects(&mut rebind, &authority)
                .await
                .unwrap();
        }
        prelude::complete_rebind_bootstrap_operation(
            &mut rebind,
            prepared.into_completion_guard(),
            200,
            br#"{"authGeneration":2}"#,
            None,
        )
        .await
        .unwrap();
        rebind.commit().await.unwrap();

        let generations: (i64, i64) = sqlx::query_as(
            "SELECT d.auth_generation,k.enrollment_auth_generation FROM chat.devices d JOIN chat.device_keys k USING(user_did,device_id) WHERE d.user_did=$1 AND d.device_id=$2 AND k.key_id=$3",
        )
        .bind(did)
        .bind(device)
        .bind(&key_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(generations, (2, 1));

        let mut stale = pool.begin().await.unwrap();
        assert!(!device_binding_is_current(
            &mut stale,
            did,
            device,
            registration,
            old_ack.binding_digest.as_ref(),
            &old_request,
        )
        .await
        .unwrap());
        stale.rollback().await.unwrap();

        let mut fresh_body = old_body;
        fresh_body.auth_generation = 2;
        fresh_body.token_generation = 2;
        fresh_body.token_sha256 = Sha256::digest(b"fresh-token").to_vec().into();
        fresh_body.signed_at = signed_at.parse().unwrap();
        let (_, fresh_ack) = push_binding::register(
            &pool,
            did,
            signed_push_registration(fresh_body, &key),
            Some("fresh-token"),
        )
        .await
        .unwrap();

        old_request.token_generation = 2;
        old_request.binding_digest = URL_SAFE_NO_PAD.encode(fresh_ack.binding_digest.as_ref());
        old_request.device_auth_generation = 2;
        let mut fresh = pool.begin().await.unwrap();
        assert!(device_binding_is_current(
            &mut fresh,
            did,
            device,
            registration,
            fresh_ack.binding_digest.as_ref(),
            &old_request,
        )
        .await
        .unwrap());
        fresh.rollback().await.unwrap();
    }
}
