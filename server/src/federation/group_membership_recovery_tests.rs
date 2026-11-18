//! Signed recovery-package exports from an active member's group mirror.

use super::*;
use crate::{
    chat_protocol::{
        test_support::seed_remote_clean_slate_application_fixture,
        wire::{validate_key_package, KeyPackageValidationPolicy, MAX_KEY_PACKAGE_WIRE_BYTES},
    },
    common::executor_seed::genuine_terminal_fixture::{
        build_genuine_invitee_key_package, AcceptanceInvitee,
    },
};
use tower_util::ServiceExt as _;

const FETCH: &str = "blue.catbird.mlsDS.fetchKeyPackage";

async fn fetch(c: &Closing, party: &Party, id: Uuid, signed: &Value) -> (StatusCode, Value) {
    let body = serde_json::to_vec(&json!({
        "conversationId": c.cid, "userDid": party.did, "deviceId": party.device,
        "keyId": party.key_id, "recoveryRequestId": id, "signedRequest": signed,
    }))
    .unwrap();
    let request = axum::http::Request::post(format!("/xrpc/{FETCH}"))
        .header("content-type", "application/json")
        .header(S2S_CALLER_DID_HEADER, SEQ_DS)
        .header(S2S_TARGET_DID_HEADER, HOME_DS)
        .header(
            S2S_MAC_HEADER,
            compute_s2s_mac(HMAC.as_bytes(), SEQ_DS, HOME_DS, FETCH, &body),
        )
        .body(axum::body::Body::from(body))
        .unwrap();
    let response = scope_sim_ds(
        c.home_hooks.clone(),
        group_relay_router(c.home.clone()).oneshot(request),
    )
    .await
    .unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .unwrap();
    (status, serde_json::from_slice(&bytes).unwrap())
}

async fn inventory(pool: &DbPool, party: &Party, usage: &str) -> Vec<u8> {
    let now = current_utc();
    let owner = AcceptanceInvitee {
        did: party.did.clone(),
        device_id: party.device,
        key_id: party.key_id.clone(),
        signing_key: party.signing_key(),
        participant_period_id: Uuid::new_v4(),
    };
    let (reference, wrapper, start, end) = build_genuine_invitee_key_package(
        &owner,
        now,
        now - chrono::Duration::hours(1),
        now + chrono::Duration::days(1),
    );
    let validated = validate_key_package(
        &wrapper,
        KeyPackageValidationPolicy {
            expected_basic_credential: format!("{}#{}", party.did, party.device).as_bytes(),
            expected_signature_key: &party.signing_key().verifying_key().to_bytes(),
            now_unix_seconds: now.timestamp().try_into().unwrap(),
            max_bytes: MAX_KEY_PACKAGE_WIRE_BYTES,
        },
    )
    .unwrap();
    sqlx::query(
        "INSERT INTO chat.key_packages(key_package_ref,wrapper_bytes,wrapper_sha256,init_key, \
         owner_did,owner_device_id,owner_key_id,owner_auth_generation,not_before,not_after, \
         status,created_at,usage_scope) VALUES($1,$2,$3,$4,$5,$6,$7,1,$8,$9,'available',$10,$11)",
    )
    .bind(reference.as_slice())
    .bind(&wrapper)
    .bind(Sha256::digest(&wrapper).to_vec())
    .bind(validated.init_key())
    .bind(&party.did)
    .bind(party.device)
    .bind(&party.key_id)
    .bind(start)
    .bind(end)
    .bind(now)
    .bind(usage)
    .execute(pool)
    .await
    .unwrap();
    wrapper
}

async fn mirror_fixture() -> (Closing, Party) {
    let (dbs, seq, home) = databases().await;
    let mirror = seed_remote_clean_slate_application_fixture(&home, HOME_DS, SEQ_DS, None)
        .await
        .unwrap();
    let requester_seed = [0x6b; 32];
    let public = ed25519_dalek::SigningKey::from_bytes(&requester_seed)
        .verifying_key()
        .to_bytes();
    let requester_device = Uuid::new_v4();
    let key_id = seed_actor_at(
        &home,
        &mirror.recipient_did,
        requester_device,
        &public,
        clock_now(&home).await,
    )
    .await;
    let requester = Party {
        did: mirror.recipient_did.clone(),
        device: requester_device,
        key_id,
        seed: requester_seed,
    };
    let existing_device = Party {
        did: mirror.recipient_did.clone(),
        device: mirror.recipient_device_id,
        key_id: mirror.recipient_key_id,
        seed: mirror.recipient_ed25519_seed,
    };
    let admin = Party {
        did: mirror.sender_did,
        device: mirror.sender_device_id,
        key_id: mirror.sender_key_id,
        seed: mirror.sender_ed25519_seed,
    };
    let c = Closing::new(
        dbs,
        seq,
        home,
        mirror.conversation_id,
        admin,
        requester,
        mirror.signed_request["body"]["prior"].clone(),
    )
    .await;
    publish_device(&c.network, &c.peer.did, &public);
    (c, existing_device)
}

async fn transfer_count(pool: &DbPool, id: Uuid) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM chat.group_key_package_exports WHERE recovery_request_id=$1",
    )
    .bind(id)
    .fetch_one(pool)
    .await
    .unwrap()
}

async fn set_membership(c: &Closing, status: &str, evidence_seq: i64) {
    sqlx::query(
        "INSERT INTO chat.remote_group_memberships
            (conversation_id,user_did,sequencer_did,status,evidence_seq,evidence_entry_id,updated_at)
         VALUES($1,$2,$3,$4,$5,$6,$7)
         ON CONFLICT(conversation_id,user_did) DO UPDATE SET status=EXCLUDED.status,
             evidence_seq=EXCLUDED.evidence_seq,evidence_entry_id=EXCLUDED.evidence_entry_id,
             updated_at=EXCLUDED.updated_at",
    )
    .bind(c.cid)
    .bind(&c.peer.did)
    .bind(SEQ_DS)
    .bind(status)
    .bind(evidence_seq)
    .bind(Uuid::new_v4())
    .bind(current_utc())
    .execute(&c.home_pool)
    .await
    .unwrap();
}

#[tokio::test]
async fn active_group_member_add_exports_only_its_live_recovery_package() {
    let (c, existing_device) = mirror_fixture().await;
    scope_ds_clock(c.clock.clone(), async {
        let (id, signed) = c.peer.recovery_request(&c.prior, "add");
        inventory(&c.home_pool, &existing_device, "recovery").await;
        inventory(&c.home_pool, &c.peer, "direct-request").await;
        let (unavailable, error) = fetch(&c, &c.peer, id, &signed).await;
        assert!(!unavailable.is_success(), "{error}");
        assert_eq!(error["error"], "KeyPackageUnavailable");
        assert!(error.get("package").is_none());

        let wrapper = inventory(&c.home_pool, &c.peer, "recovery").await;
        let (status, answer) = fetch(&c, &c.peer, id, &signed).await;
        assert_eq!(status, StatusCode::OK, "{answer}");
        assert_eq!(answer["package"]["device"]["userDid"], c.peer.did);
        assert_eq!(
            answer["package"]["device"]["deviceId"],
            c.peer.device.to_string()
        );
        assert_eq!(answer["package"]["device"]["keyId"], c.peer.key_id);
        assert_eq!(answer["package"]["device"]["authGeneration"], 1);
        assert_eq!(answer["package"]["wrapper"], json!(wrapper));
        assert_eq!(fetch(&c, &c.peer, id, &signed).await, (status, answer));

        let expires_at: chrono::DateTime<chrono::Utc> =
            sqlx::query_scalar("SELECT not_after FROM chat.key_packages WHERE wrapper_sha256=$1")
                .bind(Sha256::digest(&wrapper).to_vec())
                .fetch_one(&c.home_pool)
                .await
                .unwrap();
        c.clock.set_utc(expires_at);
        let (later, later_signed) = c.peer.recovery_request(&c.prior, "add");
        let (expired, error) = fetch(&c, &c.peer, later, &later_signed).await;
        assert!(!expired.is_success(), "{error}");
        assert_eq!(error["error"], "KeyPackageUnavailable");
        assert!(error.get("package").is_none());
        assert_eq!(transfer_count(&c.home_pool, later).await, 0);

        inventory(&c.home_pool, &c.peer, "recovery").await;
        set_membership(&c, "removed", 20).await;
        let (removed_id, removed_request) = c.peer.recovery_request(&c.prior, "add");
        let (status, error) = fetch(&c, &c.peer, removed_id, &removed_request).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{error}");
        assert!(error.get("package").is_none());
        assert_eq!(transfer_count(&c.home_pool, removed_id).await, 0);
    })
    .await;
}

#[tokio::test]
async fn recovery_on_a_graphless_home_uses_the_indexed_membership() {
    let (mut c, _) = mirror_fixture().await;
    c.cid = Uuid::new_v4();
    c.prior["conversationId"] = json!(c.cid);
    scope_ds_clock(c.clock.clone(), async {
        let has_graph: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM chat.conversations WHERE conversation_id=$1)",
        )
        .bind(c.cid)
        .fetch_one(&c.home_pool)
        .await
        .unwrap();
        assert!(!has_graph);
        let wrapper = inventory(&c.home_pool, &c.peer, "recovery").await;
        set_membership(&c, "pending", 1).await;
        let (pending_id, signed) = c.peer.recovery_request(&c.prior, "add");
        let (status, reply) = fetch(&c, &c.peer, pending_id, &signed).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{reply}");
        assert!(reply.get("package").is_none());
        assert_eq!(transfer_count(&c.home_pool, pending_id).await, 0);

        set_membership(&c, "active", 2).await;
        let (active_id, signed) = c.peer.recovery_request(&c.prior, "add");
        let (first, replay) = tokio::join!(
            fetch(&c, &c.peer, active_id, &signed),
            fetch(&c, &c.peer, active_id, &signed),
        );
        assert_eq!(first, replay);
        let (status, reply) = first;
        assert_eq!(status, StatusCode::OK, "{reply}");
        assert_eq!(reply["package"]["wrapper"], json!(wrapper));
        assert_eq!(transfer_count(&c.home_pool, active_id).await, 1);
    })
    .await;
}

#[test]
fn recovery_export_rechecks_authority_and_time_after_the_package_lock() {
    let source = include_str!("group_membership.rs");
    let export = source
        .split_once("async fn export_package(")
        .unwrap()
        .1
        .split_once("async fn require_live_export_authority(")
        .unwrap()
        .0;
    let after_lock = export.split_once("FOR UPDATE OF kp").unwrap().1;
    let after_authority = after_lock
        .split_once("require_live_export_authority(&mut tx")
        .unwrap()
        .1;
    let after_clock = after_authority
        .split_once("let now = crate::sim_hooks::current_utc();")
        .unwrap()
        .1;
    let after_expiry = after_clock.split_once("if now >= not_after").unwrap().1;
    assert!(after_expiry.contains("claim_recovery_transfer("));
}
