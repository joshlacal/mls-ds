//! Account consent remains independent from MLS leaf membership. Every ordinary
//! conversation mutation passes this gate before claiming first execution.
use super::prelude::PreludeError;
use crate::chat_protocol::{
    dpop::VerifiedChatDeviceRequest,
    transcript::{
        CanonicalValueRef, ClosedObjectRef, SignedMutationKind, VerifiedMutationProjection,
    },
};
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

#[path = "direct_request_permissions.rs"]
mod permissions;
use permissions::allowed_while_pending;

fn conversation_id(body: &ClosedObjectRef<'_>) -> Option<Uuid> {
    if let Some(CanonicalValueRef::Uuid(id)) = body.get("conversationId") {
        return Some(Uuid::from_bytes(*id.as_bytes()));
    }
    for key in [
        "prior",
        "coordinate",
        "coordinates",
        "boundCoordinate",
        "context",
    ] {
        if let Some(CanonicalValueRef::Object(nested)) = body.get(key) {
            if let Some(id) = conversation_id(&nested) {
                return Some(id);
            }
        }
    }
    None
}

pub(crate) async fn enforce_ordinary_mutation(
    tx: &mut Transaction<'_, Postgres>,
    authority: &VerifiedChatDeviceRequest,
) -> Result<(), PreludeError> {
    let Some(mutation) = authority.mutation() else {
        return Ok(());
    };
    use VerifiedMutationProjection::*;
    let body = match mutation.projection() {
        DirectRequestPublication(_) | DirectRequestAcceptance(_) => {
            return Err(PreludeError::DirectRequestConsentRequired)
        }
        DeviceEnrollment(p) => p.body(),
        KeyPackageReplenishment(p) => p.body(),
        DeviceAuthenticationRebind(p) => p.body(),
        DeviceRevocation(p) => p.body(),
        BlobUploadPreparation(p) => p.body(),
        BlobDeletion(p) => p.body(),
        Creation(p) => p.body(),
        CommitTransition(p) => p.body(),
        PolicyTransition(p) => p.body(),
        ParticipantAcceptance(p) => p.body(),
        ApplicationSend(p) => p.body(),
        Typing(p) => p.body(),
        MetadataTransition(p) => p.body(),
        ResetRequest(p) => p.body(),
        ResetActivation(p) => p.body(),
        LeafRecoveryRequest(p) => p.body(),
        LeafRecoveryCancellation(p) => p.body(),
        LeafRecoveryFulfillment(p) => p.body(),
        ConversationClose(p) => p.body(),
        LeaveRequest(p) => p.body(),
        ZeroLeafLeave(p) => p.body(),
        LeaveCancellation(p) => p.body(),
        LeaveCommitFulfillment(p) => p.body(),
        WelcomeAcknowledgement(p) => p.body(),
        WelcomeRejection(p) => p.body(),
    };
    let id = match conversation_id(&body) {
        Some(id) => Some(id),
        None if mutation.kind() == SignedMutationKind::BlobDeletion => match body.get("blobId") {
            Some(CanonicalValueRef::Uuid(id)) => {
                sqlx::query_scalar("SELECT conversation_id FROM chat.blob_bindings WHERE blob_id=$1")
                    .bind(Uuid::from_bytes(*id.as_bytes()))
                    .fetch_optional(&mut **tx)
                    .await?
            }
            _ => return Err(PreludeError::DirectRequestConsentRequired),
        },
        None if mutation.kind() == SignedMutationKind::LeafRecoveryCancellation => {
            match body.get("recoveryRequestId") {
                Some(CanonicalValueRef::Uuid(id)) => sqlx::query_scalar("SELECT conversation_id FROM chat.leaf_recovery_requests WHERE recovery_request_id=$1")
                    .bind(Uuid::from_bytes(*id.as_bytes())).fetch_optional(&mut **tx).await?,
                _ => return Err(PreludeError::DirectRequestConsentRequired),
            }
        }
        None => None,
    };
    let Some(id) = id else {
        return Ok(());
    };
    // Canonical principal locks are already held. Lock the conversation head
    // before looking at consent so acceptance/close cannot race this decision.
    let protocol: Option<String> = sqlx::query_scalar(
        "SELECT protocol_version FROM chat.conversations WHERE conversation_id=$1 FOR UPDATE",
    )
    .bind(id)
    .fetch_optional(&mut **tx)
    .await?;
    if protocol.as_deref() != Some("2") {
        return Ok(());
    }
    let consent: Option<String> = sqlx::query_scalar("SELECT COALESCE(l.consent,'pending') FROM chat.direct_request_publications p LEFT JOIN chat.direct_request_lifecycle l USING(request_id) WHERE p.conversation_id=$1 ORDER BY p.generation DESC LIMIT 1")
        .bind(id).fetch_optional(&mut **tx).await?;
    match consent.as_deref() {
        Some("accepted") => Ok(()),
        Some("pending") if allowed_while_pending(mutation.kind()) => Ok(()),
        _ => Err(PreludeError::DirectRequestConsentRequired),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn pending_creator_and_recipient_cannot_bypass_first_message_limit() {
        use SignedMutationKind::*;
        for kind in [
            ApplicationSend,
            Typing,
            BlobUploadPreparation,
            BlobDeletion,
            CommitTransition,
            PolicyTransition,
            ParticipantAcceptance,
            MetadataTransition,
            ResetRequest,
            ResetActivation,
            LeafRecoveryRequest,
            LeafRecoveryFulfillment,
        ] {
            assert!(!allowed_while_pending(kind), "{kind:?}");
        }
        for kind in [ConversationClose, WelcomeAcknowledgement, WelcomeRejection] {
            assert!(allowed_while_pending(kind), "{kind:?}");
        }
    }
}

/// Reconstruct the v2 request view only from retained signed publication and
/// signed acceptance proof. Neither current membership nor a device leaf can
/// upgrade account consent.
pub(crate) async fn load_request_projection(
    tx: &mut Transaction<'_, Postgres>,
    conversation_id: Uuid,
    requester_did: &str,
) -> Result<
    Option<(
        crate::chat_protocol::direct_request_transcript::VerifiedDirectRequest,
        catbird_atproto::generated::blue_catbird::chat::DirectRequestState,
    )>,
    super::inventory::InventoryRepositoryError,
> {
    use super::inventory::InventoryRepositoryError as E;
    use crate::chat_protocol::direct_request_transcript::{
        verify_direct_request_acceptance_proof, verify_signed_request, DirectRequestKind,
    };
    use serde_json::{json, Value};
    use sqlx::Row;
    let protocol: Option<String> = sqlx::query_scalar(
        "SELECT protocol_version FROM chat.conversations WHERE conversation_id=$1",
    )
    .bind(conversation_id)
    .fetch_optional(&mut **tx)
    .await?;
    if protocol.as_deref() != Some("2") {
        return Ok(None);
    }
    let row = sqlx::query("SELECT p.signed_publication,p.request_id,p.recipient_did,k.signing_public_key,l.consent,l.acceptance_proof FROM chat.direct_request_publications p JOIN chat.device_keys k ON k.user_did=p.actor_did AND k.device_id=p.actor_device_id AND k.key_id=p.actor_key_id LEFT JOIN chat.direct_request_lifecycle l USING(request_id) WHERE p.conversation_id=$1 ORDER BY p.generation DESC LIMIT 1")
        .bind(conversation_id).fetch_optional(&mut **tx).await?.ok_or(E::InvalidMaterialization)?;
    let signed: Option<Vec<u8>> = row.try_get("signed_publication")?;
    let Some(signed) = signed else {
        return Ok(None);
    };
    let key: Vec<u8> = row.try_get("signing_public_key")?;
    let publication = verify_signed_request(DirectRequestKind::Publish, &signed, &key)
        .map_err(|_| E::InvalidMaterialization)?;
    let body = publication.body();
    if body["conversationId"].as_str() != Some(conversation_id.to_string().as_str())
        || body["requestId"].as_str()
            != Some(row.try_get::<Uuid, _>("request_id")?.to_string().as_str())
    {
        return Err(E::InvalidMaterialization);
    }
    let recipient: String = row.try_get("recipient_did")?;
    let consent: Option<String> = row.try_get("consent")?;
    let proof: Option<Vec<u8>> = row.try_get("acceptance_proof")?;
    let acceptance_proof = match proof {
        Some(bytes) => {
            let proof: Value =
                serde_json::from_slice(&bytes).map_err(|_| E::InvalidMaterialization)?;
            let device = Uuid::parse_str(
                proof["entry"]["signedRequest"]["body"]["actorDeviceId"]
                    .as_str()
                    .ok_or(E::InvalidMaterialization)?,
            )
            .map_err(|_| E::InvalidMaterialization)?;
            let key_id = proof["entry"]["signedRequest"]["body"]["keyId"]
                .as_str()
                .ok_or(E::InvalidMaterialization)?;
            let recipient_key: Vec<u8> = sqlx::query_scalar("SELECT signing_public_key FROM chat.device_keys WHERE user_did=$1 AND device_id=$2 AND key_id=$3")
                .bind(&recipient).bind(device).bind(key_id).fetch_one(&mut **tx).await?;
            let authority_key: Vec<u8> = sqlx::query_scalar("SELECT public_key FROM chat.direct_request_receipt_keys WHERE key_id=$1")
                .bind(proof["receipt"]["body"]["keyId"].as_str().ok_or(E::InvalidMaterialization)?)
                .fetch_one(&mut **tx).await?;
            let verified =
                verify_direct_request_acceptance_proof(&bytes, &authority_key, &recipient_key)
                    .map_err(|_| E::InvalidMaterialization)?;
            if verified["entry"]["signedRequest"]["body"]["actorDid"] != recipient
                || verified["receipt"]["body"]["requestId"] != body["requestId"]
            {
                return Err(E::InvalidMaterialization);
            }
            Some(verified)
        }
        None => None,
    };
    let consent = match consent.as_deref() {
        None if requester_did == recipient => "incomingPending",
        None => "outgoingPending",
        Some("accepted") if acceptance_proof.is_some() => "accepted",
        Some("closed") => "closed",
        // Server-driven 30-day expiry is terminal like close. The wire
        // directRequestState.consent knownValues have no "expired" arm, so it
        // projects as "closed"; the signed publishedExpiry receipt (outcome
        // query) carries the distinction.
        Some("expired") => "closed",
        _ => return Err(E::InvalidMaterialization),
    };
    let mut value = json!({"requestId":body["requestId"],"senderDid":body["actorDid"],"recipientDid":body["recipientDid"],"firstMessageId":body["firstMessageId"],"contextHash":body["contextHash"],"preparationDigest":body["preparationDigest"],"importUntil":body["importUntil"],"consent":consent});
    if let Some(proof) = acceptance_proof {
        value["acceptanceProof"] = proof;
    }
    let view = crate::chat_protocol::transcript::decode_direct_request_generated_view(
        &serde_json::to_vec(&value).map_err(|_| E::InvalidMaterialization)?,
        "directRequestState",
        false,
    )
    .map_err(|_| E::InvalidMaterialization)?;
    Ok(Some((publication, view)))
}

pub(crate) async fn pending_request_welcomes(
    tx: &mut Transaction<'_, Postgres>,
    user_did: &str,
    device_id: Uuid,
) -> Result<Vec<(Uuid, Vec<u8>, Option<Uuid>)>, super::inventory::InventoryRepositoryError> {
    use super::inventory::InventoryRepositoryError as E;
    use base64::{engine::general_purpose::STANDARD, Engine};
    use serde_json::{json, Value};
    use sqlx::Row;
    let rows=sqlx::query("SELECT p.request_id,p.conversation_id,p.request_entry,p.signed_publication,p.full_welcome,p.full_welcome_sha256,d.provenance FROM chat.direct_request_device_deliveries d JOIN chat.direct_request_publications p USING(request_id) JOIN chat.conversations c ON c.conversation_id=p.conversation_id LEFT JOIN chat.direct_request_welcome_outcomes o ON o.request_id=d.request_id AND o.recipient_did=d.owner_did AND o.recipient_device_id=d.owner_device_id WHERE d.owner_did=$1 AND d.owner_device_id=$2 AND d.import_until>transaction_timestamp() AND o.request_id IS NULL AND c.lifecycle='active' AND c.current_generation=p.generation ORDER BY p.request_id")
        .bind(user_did).bind(device_id).fetch_all(&mut **tx).await?;
    let mut items = Vec::with_capacity(rows.len());
    for row in rows {
        let request_id: Uuid = row.try_get("request_id")?;
        let entry: Value = serde_json::from_slice(&row.try_get::<Vec<u8>, _>("request_entry")?)
            .map_err(|_| E::InvalidMaterialization)?;
        let publication: Value =
            serde_json::from_slice(&row.try_get::<Vec<u8>, _>("signed_publication")?)
                .map_err(|_| E::InvalidMaterialization)?;
        let provenance: Value = serde_json::from_slice(&row.try_get::<Vec<u8>, _>("provenance")?)
            .map_err(|_| E::InvalidMaterialization)?;
        let view = json!({"$type":"blue.catbird.chat.defs#directRequestWelcomeView","welcomeId":request_id,"conversationId":row.try_get::<Uuid,_>("conversation_id")?,"transitionSeq":entry["seq"],"coordinates":publication["body"]["next"],"status":"pending","opaqueWelcome":STANDARD.encode(row.try_get::<Vec<u8>,_>("full_welcome")?),"sha256":STANDARD.encode(row.try_get::<Vec<u8>,_>("full_welcome_sha256")?),"recipientDid":user_did,"recipientDeviceId":device_id,"provenance":provenance});
        let typed:catbird_atproto::generated::blue_catbird::chat::get_pending_welcomes::GetPendingWelcomesOutputItemsItem=crate::chat_protocol::transcript::decode_direct_request_generated_view(&serde_json::to_vec(&view).map_err(|_|E::InvalidMaterialization)?, "directRequestWelcomeView", true).map_err(|_|E::InvalidMaterialization)?;
        items.push((
            request_id,
            serde_json::to_vec(
                &crate::chat_protocol::transcript::direct_request_generated_view_wire(
                    &typed,
                    "directRequestWelcomeView",
                    true,
                )
                .map_err(|_| E::InvalidMaterialization)?,
            )
            .map_err(|_| E::InvalidMaterialization)?,
            None,
        ));
    }
    let inbox_rows = sqlx::query(
        "SELECT delivery_id, request_id, conversation_id, request_entry, signed_publication, full_welcome, full_welcome_sha256, provenance \
         FROM chat.direct_request_transport_inbox \
         WHERE recipient_did = $1 AND recipient_device_id = $2 \
           AND status = 'pending' \
           AND import_until > transaction_timestamp() \
         ORDER BY request_id"
    )
    .bind(user_did).bind(device_id).fetch_all(&mut **tx).await?;
    for row in inbox_rows {
        let request_id: Uuid = row.try_get("request_id")?;
        let entry: Value = serde_json::from_slice(&row.try_get::<Vec<u8>, _>("request_entry")?)
            .map_err(|_| E::InvalidMaterialization)?;
        let publication: Value =
            serde_json::from_slice(&row.try_get::<Vec<u8>, _>("signed_publication")?)
                .map_err(|_| E::InvalidMaterialization)?;
        let provenance: Value = serde_json::from_slice(&row.try_get::<Vec<u8>, _>("provenance")?)
            .map_err(|_| E::InvalidMaterialization)?;
        let view = json!({"$type":"blue.catbird.chat.defs#directRequestWelcomeView","welcomeId":request_id,"conversationId":row.try_get::<Uuid,_>("conversation_id")?,"transitionSeq":entry["seq"],"coordinates":publication["body"]["next"],"status":"pending","opaqueWelcome":STANDARD.encode(row.try_get::<Vec<u8>,_>("full_welcome")?),"sha256":STANDARD.encode(row.try_get::<Vec<u8>,_>("full_welcome_sha256")?),"recipientDid":user_did,"recipientDeviceId":device_id,"provenance":provenance});
        let typed:catbird_atproto::generated::blue_catbird::chat::get_pending_welcomes::GetPendingWelcomesOutputItemsItem=crate::chat_protocol::transcript::decode_direct_request_generated_view(&serde_json::to_vec(&view).map_err(|_|E::InvalidMaterialization)?, "directRequestWelcomeView", true).map_err(|_|E::InvalidMaterialization)?;
        items.push((
            request_id,
            serde_json::to_vec(
                &crate::chat_protocol::transcript::direct_request_generated_view_wire(
                    &typed,
                    "directRequestWelcomeView",
                    true,
                )
                .map_err(|_| E::InvalidMaterialization)?,
            )
            .map_err(|_| E::InvalidMaterialization)?,
            Some(row.try_get("delivery_id")?),
        ));
    }
    Ok(items)
}
