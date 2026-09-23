//! C12: cancel versus delayed prepare/publish, on the shipping router and the
//! shared guarded database.
//!
//! Every request is staged through the real keys/prepare RPCs and a real
//! SQLCipher sender (`support/staged_direct_request.rs`). Races are ordered by
//! holding the production per-request operation lock in a separate session
//! (`support/c12_c13.rs::OperationBarrier`) and queueing the racing RPCs behind
//! it; PostgreSQL grants the waiters in arrival order when it is released.
//! Every receipt is verified against the fixture's receipt authority. Each
//! test releases what it prepares (cancel) or publishes (signed close).
//! The preparation-timeout race needs a lease to expire and runs in
//! `encrypted_request_c13_expiry.rs` under the shared faketime clock.
#![allow(dead_code, unused_imports)]
#[path = "support/encrypted_requests.rs"]
mod encrypted_requests;
#[path = "support/staged_direct_request.rs"]
mod staged_direct_request;
#[path = "support/c12_c13.rs"]
mod c12_c13;

use anyhow::Context as _;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use c12_c13::*;
use catbird_mls::chat_v2::transcript::direct_request::DirectRequestKind;
use encrypted_requests::canonical_now;
use serde_json::json;
use staged_direct_request::stage_request;
use uuid::Uuid;

const OK: reqwest::StatusCode = reqwest::StatusCode::OK;

#[tokio::test(flavor = "multi_thread")]
async fn c12_unknown_to_cancelled_tombstone_blocks_late_prepare_and_publish() -> anyhow::Result<()> {
    let s = stage_request("c12-tombstone").await?;
    let (b, b_conversation, b_first) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
    // The delayed prepare is signed now but delivered only after the cancel.
    let prepare_b = sign_direct(
        &s,
        DirectRequestKind::Prepare,
        json!({
            "$type":"blue.catbird.chat.defs#directRequestPreparationBody",
            "signatureDomain":"CATBIRD-DIRECT-REQUEST-PREPARE\0","protocolVersion":"2",
            "actorDid":s.alice.did,"actorDeviceId":s.alice.device_id.to_string(),
            "keyId":alice_key_id(&s),"authGeneration":1,"requestId":b.to_string(),
            "firstMessageId":b_first.to_string(),"conversationId":b_conversation.to_string(),
            "recipientDid":s.bob.did,"origin":{"$type":"blue.catbird.chat.defs#freshDirectOrigin"},
            "profile":"encryptedIntroduction1","idempotencyKey":b.to_string(),
            "signedAt":canonical_now()
        }),
    )?;
    let prepare_b_digest = request_digest(DirectRequestKind::Prepare, &prepare_b, &s.alice_public)?;

    let (status, unknown) = outcome(&s, b).await?;
    assert_eq!(status, OK, "{unknown}");
    assert_eq!(unknown["outcome"]["$type"], "blue.catbird.chat.defs#directRequestUnknownOutcome");
    assert_eq!(db_query(&format!("SELECT count(*) FROM chat.direct_request_attempts WHERE request_id='{b}'"))?, "0");

    // Unknown -> cancelled tombstone, minted by the real cancel RPC.
    let (status, cancelled) = post(&s, CANCEL_NSID, &signed_cancel(&s, b, &prepare_b_digest)?).await?;
    assert_eq!(status, OK, "{cancelled}");
    let receipt = verified_receipt(&s, &cancelled)?;
    assert_eq!(receipt["$type"], "blue.catbird.chat.defs#directRequestCancelledReceipt");
    assert_eq!(receipt["requestId"], b.to_string());
    assert_eq!(receipt["requestKind"], "cancel");
    assert_eq!(receipt["preparationRequestDigest"], STANDARD.encode(prepare_b_digest));
    let tombstone = ("cancelled".to_owned(), Some(untyped_outcome(&cancelled)?));
    assert_eq!(stored_terminal(b)?, tombstone, "tombstone is the durable receipt");

    // Late prepare of the same request returns the tombstone, reserves nothing.
    let (status, late_prepare) = post(&s, PREPARE_NSID, &prepare_b).await?;
    assert_eq!(status, OK, "{late_prepare}");
    assert_eq!(late_prepare["outcome"], cancelled["outcome"], "late prepare returns the tombstone");

    // Late publish for the same request identity returns the tombstone too.
    let mut body = s.publication["body"].clone();
    body["requestId"] = json!(b.to_string());
    body["conversationId"] = json!(b_conversation.to_string());
    body["firstMessageId"] = json!(b_first.to_string());
    body["preparationRequestDigest"] = json!(STANDARD.encode(prepare_b_digest));
    body["idempotencyKey"] = json!(b.to_string());
    body["signedAt"] = json!(canonical_now());
    let late_publish = sign_direct(&s, DirectRequestKind::Publish, body)?;
    let (status, late_published) = post(&s, PUBLISH_NSID, &late_publish).await?;
    assert_eq!(status, OK, "{late_published}");
    assert_eq!(late_published["outcome"], cancelled["outcome"], "late publish returns the tombstone");

    assert_eq!(stored_terminal(b)?, tombstone, "tombstone unchanged by late prepare/publish");
    assert_eq!(
        db_query(&format!(
            "SELECT (SELECT count(*) FROM chat.direct_request_selected_devices WHERE request_id='{b}')||'|'||\
                    (SELECT count(*) FROM chat.direct_request_publications WHERE request_id='{b}')||'|'||\
                    (SELECT count(*) FROM chat.conversations WHERE conversation_id='{b_conversation}')"
        ))?,
        "0|0|0",
        "no reservation, publication or conversation for the tombstoned request"
    );

    // Release the staged request A through the real cancel RPC.
    let (status, released) =
        post(&s, CANCEL_NSID, &signed_cancel(&s, s.request_id, &s.preparation_request_digest)?).await?;
    assert_eq!(status, OK, "{released}");
    assert_eq!(verified_receipt(&s, &released)?["$type"], "blue.catbird.chat.defs#directRequestCancelledReceipt");
    assert_eq!(stored_terminal(s.request_id)?.0, "cancelled");
    println!("C12 tombstone request {b}: cancel/late-prepare/late-publish share one cancelled receipt");
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn c12_barrier_cancel_first_blocks_delayed_publish() -> anyhow::Result<()> {
    let s = stage_request("c12-cancel-first").await?;
    let barrier = OperationBarrier::hold(s.request_id)?;
    let cancel = spawn_post(&s, CANCEL_NSID, signed_cancel(&s, s.request_id, &s.preparation_request_digest)?);
    barrier.wait_for_waiters(1).await?;
    let publish = spawn_post(&s, PUBLISH_NSID, s.publication.clone());
    let queued = barrier.wait_for_waiters(2).await?;
    assert_eq!(stored_terminal(s.request_id)?, ("prepared".to_owned(), None), "barrier holds both");
    println!("C12 cancel-first: {queued} RPC sessions queued behind the operation lock");
    barrier.release()?;

    let (cancel_status, cancelled) = cancel.await??;
    let (publish_status, published) = publish.await??;
    assert_eq!(cancel_status, OK, "{cancelled}");
    assert_eq!(publish_status, OK, "{published}");
    let receipt = verified_receipt(&s, &cancelled)?;
    assert_eq!(receipt["$type"], "blue.catbird.chat.defs#directRequestCancelledReceipt");
    assert_eq!(receipt["requestId"], s.request_id.to_string());
    assert_eq!(published["outcome"], cancelled["outcome"], "delayed publish returns the cancel");
    assert_eq!(stored_terminal(s.request_id)?, ("cancelled".to_owned(), Some(untyped_outcome(&cancelled)?)));
    assert_eq!(
        db_query(&format!(
            "SELECT (SELECT count(*) FROM chat.direct_request_publications WHERE request_id='{r}')||'|'||\
                    (SELECT count(*) FROM chat.conversations WHERE conversation_id='{c}')",
            r = s.request_id,
            c = s.conversation_id
        ))?,
        "0|0",
        "delayed publish wrote nothing"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn c12_barrier_publish_first_cancel_returns_committed_identity_and_withdrawal_is_signed_close(
) -> anyhow::Result<()> {
    let s = stage_request("c12-publish-first").await?;
    let barrier = OperationBarrier::hold(s.request_id)?;
    let publish = spawn_post(&s, PUBLISH_NSID, s.publication.clone());
    barrier.wait_for_waiters(1).await?;
    let cancel = spawn_post(&s, CANCEL_NSID, signed_cancel(&s, s.request_id, &s.preparation_request_digest)?);
    let queued = barrier.wait_for_waiters(2).await?;
    println!("C12 publish-first: {queued} RPC sessions queued behind the operation lock");
    barrier.release()?;

    let (publish_status, published) = publish.await??;
    let (cancel_status, cancelled) = cancel.await??;
    assert_eq!(publish_status, OK, "{published}");
    assert_eq!(cancel_status, OK, "{cancelled}");
    s.verified_published_receipt(&published["outcome"])?;
    assert_eq!(cancelled["outcome"], published["outcome"], "cancel after publish returns the committed identity");
    assert_eq!(stored_terminal(s.request_id)?, ("published".to_owned(), Some(untyped_outcome(&published)?)));
    assert_eq!(
        db_query(&format!("SELECT count(*) FROM chat.direct_request_publications WHERE request_id='{}'", s.request_id))?,
        "1"
    );

    // Withdrawal is the real signed closeConversation, not cancel.
    let (status, closed, transition_id) = close_published(&s).await?;
    assert_eq!(status, OK, "signed close: {closed}");
    assert!(closed["result"]["tombstone"].is_object(), "close returns the tombstone: {closed}");
    let (r, c) = (s.request_id, s.conversation_id);
    let after = db_query(&format!(
        "SELECT (SELECT lifecycle FROM chat.conversations WHERE conversation_id='{c}')||'|'||\
                (SELECT kind FROM chat.transitions WHERE transition_id='{transition_id}' AND conversation_id='{c}')||'|'||\
                (SELECT consent FROM chat.direct_request_lifecycle WHERE request_id='{r}')||'|'||\
                (SELECT (closed_at IS NOT NULL)::text FROM chat.direct_request_lifecycle WHERE request_id='{r}')||'|'||\
                (SELECT reason FROM chat.direct_request_pending_releases WHERE request_id='{r}')||'|'||\
                (SELECT status FROM chat.direct_request_attempts WHERE request_id='{r}')"
    ))?;
    println!("C12 after signed close lifecycle|transition|consent|closed|release|attempt = {after}");
    assert_eq!(after, "superseded|closeConversation|closed|true|closed|published");

    // Cancel after the withdrawal still only reports the committed publication.
    let (status, late_cancel) =
        post(&s, CANCEL_NSID, &signed_cancel(&s, s.request_id, &s.preparation_request_digest)?).await?;
    assert_eq!(status, OK, "{late_cancel}");
    assert_eq!(late_cancel["outcome"], published["outcome"]);
    Ok(())
}
