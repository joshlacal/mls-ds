//! Comprehensive 2-DS + ATProto Spaces Federation & Clean-Slate Cutover Integration Suite
//! (`Spec §7` `G3`, `G4`, `G6`, `Gate 10`, `I1`–`I16`, `D1`–`D4`, `C33`, `1A`, `3A`).
//!
//! Boots TWO independent `clean_slate_federation_fixture` OS server processes over two freshly
//! migrated PostgreSQL 16 databases:
//! - `ds-a` (`did:web:ds-a.federation.catbird.blue`)
//! - `ds-b` (`did:plc:dsbfederationlocal24char`)
//!
//! Plus loopback `Swan`-profile Spaces PDS, `bluesky-social/atproto#5187` reference Spaces PDS,
//! non-Spaces legacy PDS (`501 Not Implemented` for `I15`), and `nest`-profile Push Gateway (`D2`).

#![cfg(feature = "labyrinth")]

#[allow(dead_code)]
#[path = "../../e2e-tests/tests/support/native_spaces.rs"]
mod native_spaces;

use std::{
    collections::BTreeSet,
    sync::{atomic::Ordering, Arc, Mutex},
    time::{Duration, Instant},
};

use aes_gcm::{
    aead::{Aead as _, KeyInit as _},
    Aes256Gcm, Nonce as AesNonce,
};
use anyhow::{Context, Result};
use axum::{
    body::Bytes as AxumBytes,
    http::{header::CONTENT_TYPE, HeaderMap, StatusCode},
    routing::post,
    Json, Router,
};
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine as _,
};
use bird_daemon::bot::{BotLlmResponder, FederatedBirdBot, FederatedBotConfig};
use catbird_mls::{
    client::{
        account_did_hash_hex, chat_wire::StoredArchivedReceipt, CatbirdMlsClient,
        CatbirdMlsClientConfig, PlatformKeyStore, REQUIRED_LABYRINTH_OAUTH_SCOPES,
    },
    groups::{
        lifecycle::MemberRole,
        metadata_v1::{
            maybe_rehost_avatar_on_setter_leave, validate_metadata_snapshot_size,
            SpaceAvatarPointer,
        },
    },
    metadata::GroupMetadataV1,
    push::{process_push_notification, PushKeystore, PushWakePayload},
    MLSError,
};
use chrono::{SecondsFormat, Utc};
use ed25519_dalek::{Signature as Ed25519Signature, Signer as _, SigningKey as Ed25519SigningKey};
use hmac::{Hmac, Mac};
use labyrinth::{
    device::DeviceSecrets, epoch::open_genesis, records::defs::EpochPublicDef,
    sign::TransportSigner,
};
use labyrinth_protocol::receipt::{
    compute_archive_commitment, verify_sequencer_receipt_sec1, SignedSequencerReceipt,
};
use native_spaces::{
    assert_authority_notified, delegation, did_key, mint_es256_service_jwt, p256_public_jwk,
    CleanSlateDsProcess, DidDirectory, MemoryKeyStore, SpacesPds,
};
use p256::{
    ecdsa::{signature::Verifier as _, Signature as P256Signature, SigningKey as P256SigningKey},
    SecretKey as P256Secret,
};
use petrel_spaces::{
    encapsulate_p256, format_accept_signature, sign_credential_request, verify_commit_mac,
    MacProfile, SigningKeyPair,
};
use serde::Serialize;
use serde_json::{json, Value};
use sha2::{Digest as _, Sha256};
use tokio_postgres::Client as PgClient;
use uuid::Uuid;

type HmacSha256 = Hmac<Sha256>;

const S2S_SECRET: &[u8] = b"clean-slate-federation-s2s-secret-32b!";
const DS_A_DID: &str = "did:web:ds-a.federation.catbird.blue";
const DS_B_DID: &str = "did:plc:dsbfederationlocal24char";
const PUSH_GATEWAY_SIGNATURE_DOMAIN: &[u8] = b"CATBIRD-CHAT-PUSH-GATEWAY\0";

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct PushGatewayTranscriptPayload<'a> {
    app_id: &'a str,
    auth_generation: i64,
    device_id: String,
    enabled: bool,
    gateway_url: &'a str,
    key_id: &'a str,
    push_key: &'a str,
    signed_at: &'a str,
}

#[allow(clippy::too_many_arguments)]
fn build_push_gateway_transcript(
    device_id: &Uuid,
    key_id: &str,
    auth_generation: i64,
    gateway_url: &str,
    app_id: &str,
    push_key: &str,
    enabled: bool,
    signed_at: &str,
) -> Result<Vec<u8>> {
    let payload = PushGatewayTranscriptPayload {
        app_id,
        auth_generation,
        device_id: device_id.to_string(),
        enabled,
        gateway_url,
        key_id,
        push_key,
        signed_at,
    };
    let cbor = serde_ipld_dagcbor::to_vec(&payload)?;
    let mut out = Vec::with_capacity(PUSH_GATEWAY_SIGNATURE_DOMAIN.len() + cbor.len());
    out.extend_from_slice(PUSH_GATEWAY_SIGNATURE_DOMAIN);
    out.extend_from_slice(&cbor);
    Ok(out)
}

fn compute_s2s_mac(caller_did: &str, target_did: &str, lxm: &str, body: &[u8]) -> String {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(S2S_SECRET).expect("hmac");
    mac.update(b"CATBIRD-S2S-GROUP-RELAY\0");
    mac.update(caller_did.as_bytes());
    mac.update(&[0]);
    mac.update(target_did.as_bytes());
    mac.update(&[0]);
    mac.update(lxm.as_bytes());
    mac.update(&[0]);
    mac.update(body);
    URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
}

// ============================================================================
// Loopback Push Gateway (`nest` profile — `D2`, `I12`)
// ============================================================================

#[derive(Clone, Debug)]
struct CapturedPushWake {
    auth_header: String,
    raw_body: Vec<u8>,
    body: Value,
}

struct LoopbackPushGateway {
    canonical_https_url: String,
    loopback_http_url: String,
    wakes: Arc<Mutex<Vec<CapturedPushWake>>>,
}

impl LoopbackPushGateway {
    async fn start() -> Self {
        Self::start_with_host("nest-push.federation.catbird.blue").await
    }

    async fn start_with_host(host: &str) -> Self {
        let wakes: Arc<Mutex<Vec<CapturedPushWake>>> = Arc::new(Mutex::new(Vec::new()));
        let wakes_clone = wakes.clone();
        let app = Router::new().route(
            "/xrpc/blue.catbird.push.deliver",
            post(move |headers: HeaderMap, raw_body: AxumBytes| {
                let wakes = wakes_clone.clone();
                async move {
                    let auth_header = headers
                        .get(axum::http::header::AUTHORIZATION)
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or_default()
                        .to_string();
                    let body: Value =
                        serde_json::from_slice(&raw_body).expect("valid JSON push wake body");
                    wakes.lock().unwrap().push(CapturedPushWake {
                        auth_header,
                        raw_body: raw_body.to_vec(),
                        body,
                    });
                    (
                        StatusCode::OK,
                        Json(json!({
                            "results": [{
                                "pushKey": "pk",
                                "status": "delivered"
                            }]
                        })),
                    )
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        Self {
            canonical_https_url: format!("https://{host}/xrpc/blue.catbird.push.deliver"),
            loopback_http_url: format!("http://{addr}/xrpc/blue.catbird.push.deliver"),
            wakes,
        }
    }
}

struct Ed25519TransportSigner {
    sk: Ed25519SigningKey,
}

impl TransportSigner for Ed25519TransportSigner {
    fn transport_public_key(&self) -> [u8; 32] {
        self.sk.verifying_key().to_bytes()
    }

    fn sign_transport(&self, message: &[u8]) -> [u8; 64] {
        self.sk.sign(message).to_bytes()
    }
}

struct DeterministicBirdResponder;

#[async_trait::async_trait]
impl BotLlmResponder for DeterministicBirdResponder {
    async fn generate_reply(&self, sender_did: &str, text: &str) -> anyhow::Result<String> {
        Ok(format!(
            "chirp! federated reply to {sender_did} ({} bytes)",
            text.len()
        ))
    }
}

/// `(entries, sends of message_id, next_entry_seq)` of a conversation `pool`'s DS sequences:
/// everything an accepted application send changes.
async fn send_footprint(
    pool: &PgClient,
    conversation_id: &Uuid,
    message_id: &Uuid,
) -> Result<(i64, i64, i64)> {
    let row = pool
        .query_one(
            "SELECT (SELECT COUNT(*) FROM chat.entries WHERE conversation_id = $1), \
                    (SELECT COUNT(*) FROM chat.message_sends \
                      WHERE conversation_id = $1 AND message_id = $2), \
                    (SELECT next_entry_seq FROM chat.conversations WHERE conversation_id = $1)",
            &[conversation_id, message_id],
        )
        .await?;
    Ok((row.get(0), row.get(1), row.get(2)))
}

async fn count_ds_operational_rows(pool: &PgClient) -> Result<i64> {
    let tables = [
        "chat.conversations",
        "chat.entries",
        "chat.transitions",
        "chat.conversation_spaces",
        "chat.space_credential_jtis",
        "chat.space_delegation_jtis",
        "chat.conversation_space_writers",
        "labyrinth.epoch_heads",
        "labyrinth.operations",
    ];
    let mut total = 0_i64;
    for tbl in tables {
        let row = pool
            .query_one(&format!("SELECT COUNT(*) FROM {tbl}"), &[])
            .await?;
        let n: i64 = row.get(0);
        total += n;
    }
    Ok(total)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn federation_spaces_full_cutover_end_to_end() -> Result<()> {
    // ========================================================================
    // Boot Topology: 2 Real `clean_slate_federation_fixture` Processes +
    // `Swan` PDS + `atproto#5187` Reference PDS + Legacy Non-Spaces PDS + Push Gateway
    // ========================================================================
    let mut ds_a = CleanSlateDsProcess::spawn(DS_A_DID, S2S_SECRET).await?;
    let ds_b = CleanSlateDsProcess::spawn(DS_B_DID, S2S_SECRET).await?;

    // Every identity's DID document, as PLC / did:web would serve it to each PDS's resolveDid.
    let directory = DidDirectory::new();
    directory.publish(&ds_a.service_did, ds_a.did_document.clone());
    directory.publish(&ds_b.service_did, ds_b.did_document.clone());

    let swan_pds = SpacesPds::start(
        "did:web:swan.federation.catbird.blue",
        true,
        directory.clone(),
    )
    .await;
    let ref_pds = SpacesPds::start(
        "did:web:spaces-ref.federation.catbird.blue",
        true,
        directory.clone(),
    )
    .await;
    let legacy_pds = SpacesPds::start(
        "did:web:legacy.federation.catbird.blue",
        false,
        directory.clone(),
    )
    .await;
    let push_gw = LoopbackPushGateway::start().await;

    let admin_http = reqwest::Client::new();

    // Verify `ds-a` (`did:web`) serves `/.well-known/did.json` with `#atproto_mls` + `#mls-receipt-1`
    let did_doc_resp: Value = admin_http
        .get(format!("{}/.well-known/did.json", ds_a.base_url))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    assert_eq!(did_doc_resp["id"], DS_A_DID);
    assert!(
        did_doc_resp["verificationMethod"]
            .as_array()
            .unwrap()
            .iter()
            .any(|vm| vm["id"] == format!("{DS_A_DID}#mls-receipt-1")),
        "ds-a DID document must advertise #mls-receipt-1"
    );
    assert!(
        ds_b.did_document["verificationMethod"]
            .as_array()
            .unwrap()
            .iter()
            .any(|vm| vm["id"] == format!("{DS_B_DID}#mls-receipt-1")),
        "ds-b (did:plc) DID document must advertise #mls-receipt-1"
    );

    // Register cross-DS & Push Gateway overrides on both servers
    for ds in [&ds_a, &ds_b] {
        admin_http
            .post(format!(
                "{}/_test/clean-slate/register-push-override",
                ds.base_url
            ))
            .json(&json!({
                "canonicalHttpsUrl": push_gw.canonical_https_url,
                "loopbackHttpUrl": push_gw.loopback_http_url,
            }))
            .send()
            .await?
            .error_for_status()?;
        ds.register_ds(&admin_http, &ds_a).await?;
        ds.register_ds(&admin_http, &ds_b).await?;
    }

    // ========================================================================
    // Scenario 1: Federated Enrollment (`did:web` + `did:plc`), `I15` Spaces Gate,
    // Personal Mailbox Space, and `publishEpochHead` -> `getEpochHead` Witness Chain
    // ========================================================================
    let temp_root = tempfile::tempdir()?;
    let scopes: Vec<String> = REQUIRED_LABYRINTH_OAUTH_SCOPES
        .iter()
        .map(|s| (*s).to_string())
        .collect();

    // Negative `I15` check: account on `legacy_pds` (non-Spaces PDS) is cleanly blocked with zero KP upload
    let legacy_transport = Arc::new(legacy_pds.client_transport(&ds_a.base_url));
    let carol_legacy_client = CatbirdMlsClient::open(
        CatbirdMlsClientConfig {
            storage_root: temp_root
                .path()
                .join("carol-legacy")
                .to_string_lossy()
                .into(),
            account_did: "did:plc:carollegacynonspaces24ch".into(),
            device_id: Uuid::new_v4().to_string(),
            home_ds_did: DS_A_DID.into(),
            home_ds_endpoint: ds_a.base_url.clone(),
            pds_endpoint: legacy_pds.base_url.clone(),
        },
        Arc::new(MemoryKeyStore::new()),
        legacy_transport,
        None,
    )?;
    let legacy_elig = carol_legacy_client.check_spaces_eligibility(&scopes)?;
    assert!(
        !legacy_elig.eligible,
        "I15: legacy PDS without Spaces MUST block MLS eligibility"
    );
    assert!(
        carol_legacy_client.enroll_device(&scopes).is_err(),
        "I15: enroll_device MUST fail closed on non-Spaces PDS"
    );

    // Seed an active conversation on `ds-b` (`did:plc`) with Alice homed on `ds-a` (`did:web`),
    // Bob homed on `ds-b` (`did:plc`), and Eve on `ref_pds` (`atproto#5187`)
    let archive_commitment = [0x7A_u8; 32];
    let eve_did = "did:plc:eveatprotospacesref24chr";
    let seed_response = admin_http
        .post(format!(
            "{}/_test/clean-slate/seed-group-fixture",
            ds_b.base_url
        ))
        .json(&json!({
            "direct": false,
            "recipientServiceDid": DS_A_DID,
            "archiveCommitmentHex": hex::encode(archive_commitment),
            "extraMembers": []
        }))
        .send()
        .await?;
    let seed_status = seed_response.status();
    let seed_body = seed_response.bytes().await?;
    assert_eq!(
        seed_status,
        reqwest::StatusCode::OK,
        "seed-group-fixture: {}",
        String::from_utf8_lossy(&seed_body)
    );
    let seeded_b: Value = serde_json::from_slice(&seed_body)?;

    let convo_id = Uuid::parse_str(seeded_b["conversationId"].as_str().unwrap())?;
    let space_uri = seeded_b["spaceUri"].as_str().unwrap().to_string();
    assert_eq!(
        space_uri,
        format!("at:space/{DS_B_DID}/blue.catbird.labyrinth.conversation/{convo_id}-0"),
        "Conversation Space URI must be rooted at sequencing DS (ds-b did:plc)"
    );

    // Note: in `seed_clean_slate_application_fixture`:
    // - `senderDid` (requester) is conversation admin
    // - `recipientDid` (fulfiller) is homed on `recipientServiceDid` (`DS_A_DID`)
    let bob_admin_did = seeded_b["senderDid"].as_str().unwrap().to_string();
    let bob_device_id = Uuid::parse_str(seeded_b["senderDeviceId"].as_str().unwrap())?;
    let bob_key_id = seeded_b["senderKeyId"].as_str().unwrap().to_string();
    let bob_ed_seed: [u8; 32] = STANDARD
        .decode(seeded_b["senderEd25519SeedB64"].as_str().unwrap())?
        .try_into()
        .unwrap();
    let bob_ed_sk = Ed25519SigningKey::from_bytes(&bob_ed_seed);
    let seeded_message_id = Uuid::parse_str(seeded_b["messageId"].as_str().unwrap())?;
    let seeded_send = &seeded_b["signedRequest"]["body"];
    assert_eq!(seeded_send["messageId"], seeded_message_id.to_string());
    assert_eq!(seeded_send["actorDid"], bob_admin_did);
    assert_eq!(seeded_send["actorDeviceId"], bob_device_id.to_string());
    assert_eq!(seeded_send["keyId"], bob_key_id);
    let seeded_aad = &seeded_send["aad"];
    assert_eq!(
        seeded_aad["conversationId"],
        STANDARD.encode(convo_id.as_bytes())
    );
    assert_eq!(
        seeded_aad["messageId"],
        STANDARD.encode(seeded_message_id.as_bytes())
    );
    assert_eq!(
        seeded_aad["archiveCommitment"],
        STANDARD.encode(archive_commitment)
    );
    assert_eq!(
        seeded_aad["prior"]["conversationId"],
        STANDARD.encode(convo_id.as_bytes())
    );
    for field in [
        "generation",
        "stateVersion",
        "groupId",
        "epoch",
        "groupContextHash",
        "confirmationTag",
        "lifecycle",
    ] {
        assert_eq!(
            seeded_aad["prior"][field], seeded_send["prior"][field],
            "seeded application AAD prior {field}"
        );
    }
    let seeded_attestation = &seeded_aad["originalSenderAttestation"];
    assert_eq!(seeded_attestation["senderDid"], bob_admin_did);
    assert_eq!(
        seeded_attestation["senderDeviceId"],
        bob_device_id.to_string()
    );
    let seeded_attestation_key = STANDARD.decode(
        seeded_attestation["senderTransportPubkey"]
            .as_str()
            .unwrap(),
    )?;
    assert_eq!(
        seeded_attestation_key.as_slice(),
        bob_ed_sk.verifying_key().to_bytes().as_slice()
    );
    let seeded_attestation_signature: [u8; 64] = STANDARD
        .decode(seeded_attestation["signature"].as_str().unwrap())?
        .try_into()
        .unwrap();
    let seeded_attestation_transcript =
        labyrinth_protocol::transcripts::original_sender_archive_transcript(
            &convo_id.to_string(),
            &seeded_message_id.to_string(),
            &archive_commitment,
        );
    bob_ed_sk
        .verifying_key()
        .verify_strict(
            &seeded_attestation_transcript,
            &Ed25519Signature::from_bytes(&seeded_attestation_signature),
        )
        .expect("seeded originalSenderAttestation must verify over exact coordinates");

    let alice_remote_did = seeded_b["recipientDid"].as_str().unwrap().to_string();
    let alice_device_id = Uuid::parse_str(seeded_b["recipientDeviceId"].as_str().unwrap())?;
    let alice_key_id = seeded_b["recipientKeyId"].as_str().unwrap().to_string();
    let alice_ed_seed: [u8; 32] = STANDARD
        .decode(seeded_b["recipientEd25519SeedB64"].as_str().unwrap())?
        .try_into()
        .unwrap();
    let alice_ed_sk = Ed25519SigningKey::from_bytes(&alice_ed_seed);

    // Dedicated real-SDK DIDs for live federated C33 + group SDK round-trips (no synthetic fixture rows!)
    let alice_sdk_did = "did:plc:alicesdkfederated24chars".to_string();
    let alice_sdk_device_id = Uuid::new_v4();
    let alice_sdk_p256 = P256SigningKey::random(&mut rand::rngs::OsRng);

    let bob_sdk_did = "did:plc:bobsdkfederatedaa24chars".to_string();
    let bob_sdk_device_id = Uuid::new_v4();
    let bob_sdk_p256 = P256SigningKey::random(&mut rand::rngs::OsRng);

    // `#atproto` keys + PDS homes (OAuth sessions) for the fixture and real-SDK accounts
    let alice_p256 = P256SigningKey::random(&mut rand::rngs::OsRng);
    let bob_p256 = P256SigningKey::random(&mut rand::rngs::OsRng);
    let eve_p256 = P256SigningKey::random(&mut rand::rngs::OsRng);
    let alice_kem_did_key =
        swan_pds.add_account(&alice_remote_did, alice_p256.clone(), "alice-pds-oauth");
    let bob_kem_did_key = swan_pds.add_account(&bob_admin_did, bob_p256.clone(), "bob-pds-oauth");
    let eve_kem_did_key = ref_pds.add_account(eve_did, eve_p256.clone(), "eve-pds-oauth");
    swan_pds.add_account(
        &alice_sdk_did,
        alice_sdk_p256.clone(),
        "alice-sdk-pds-oauth",
    );
    swan_pds.add_account(&bob_sdk_did, bob_sdk_p256.clone(), "bob-sdk-pds-oauth");

    for ds in [&ds_a, &ds_b] {
        for (did, sk, pds_url) in [
            (alice_remote_did.as_str(), &alice_p256, &swan_pds.base_url),
            (bob_admin_did.as_str(), &bob_p256, &swan_pds.base_url),
            (eve_did, &eve_p256, &ref_pds.base_url),
            (alice_sdk_did.as_str(), &alice_sdk_p256, &swan_pds.base_url),
            (bob_sdk_did.as_str(), &bob_sdk_p256, &swan_pds.base_url),
        ] {
            ds.register_did(&admin_http, did, sk.verifying_key(), pds_url)
                .await?;
        }
    }

    // Replicate Alice's active chat device + device_key on her home `ds-a` (`D1` / `D2` / `3A`)
    let alice_pub_slice = alice_ed_sk.verifying_key().to_bytes();
    let alice_pub_bytes: &[u8] = alice_pub_slice.as_slice();
    {
        let tx = ds_a.pool.transaction().await?;
        tx.execute(
            "INSERT INTO chat.principals (user_did, created_at) \
             VALUES ($1, clock_timestamp()) ON CONFLICT DO NOTHING",
            &[&alice_remote_did],
        )
        .await?;
        tx.execute(
            "INSERT INTO chat.devices ( \
                 user_did, device_id, device_name, status, dpop_jkt, auth_generation, capabilities, created_at, updated_at \
             ) VALUES ($1, $2, 'alice-home-fixture', 'active', $3, 1, chat.protocol_capabilities(), clock_timestamp(), clock_timestamp()) \
             ON CONFLICT DO NOTHING",
            &[&alice_remote_did, &alice_device_id, &alice_key_id],
        )
        .await?;
        tx.execute(
            "INSERT INTO chat.device_keys ( \
                 user_did, device_id, key_id, signing_public_key, enrollment_auth_generation, created_at \
             ) VALUES ($1, $2, $3, $4, 1, clock_timestamp()) \
             ON CONFLICT DO NOTHING",
            &[&alice_remote_did, &alice_device_id, &alice_key_id, &alice_pub_bytes],
        )
        .await?;
        tx.commit().await?;
    }

    // Alice's D1-firewalled transport ONLY permits her home `ds-a` and her own `swan_pds`!
    let alice_firewall = Arc::new(swan_pds.client_transport(&ds_a.base_url));
    alice_firewall.set_account(
        &alice_sdk_did,
        alice_sdk_p256.clone(),
        DS_A_DID,
        &swan_pds.base_url,
        "alice-sdk-pds-oauth",
    );

    // Enroll Alice's `CatbirdMlsClient` (`MLS_256_XWING` + `D4` default-on Labyrinth) on `ds-a` + `swan_pds`
    let alice_keystore = Arc::new(MemoryKeyStore::new());
    let alice_sdk = {
        let storage_root = temp_root.path().join("alice-sdk").to_string_lossy().into();
        let did = alice_sdk_did.clone();
        let dev_id = alice_sdk_device_id.to_string();
        let ds_url = ds_a.base_url.clone();
        let pds_url = swan_pds.base_url.clone();
        let ks = alice_keystore.clone();
        let fw = alice_firewall.clone();
        tokio::task::spawn_blocking(move || {
            CatbirdMlsClient::open(
                CatbirdMlsClientConfig {
                    storage_root,
                    account_did: did,
                    device_id: dev_id,
                    home_ds_did: DS_A_DID.into(),
                    home_ds_endpoint: ds_url,
                    pds_endpoint: pds_url,
                },
                ks,
                fw,
                None,
            )
        })
        .await??
    };
    let alice_enroll = {
        let sdk = alice_sdk.clone();
        let sc = scopes.clone();
        tokio::task::spawn_blocking(move || sdk.enroll_device(&sc)).await??
    };
    assert!(
        alice_enroll
            .direct_request_kp_bytes
            .windows(2)
            .any(|w| w == [0x00, 0x4d]),
        "I16: enrolled KeyPackage must carry MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519 (0x004D)"
    );
    assert!(
        alice_enroll.labyrinth_backup_enabled,
        "D4: Labyrinth must be default-on"
    );
    assert_eq!(
        alice_enroll.mailbox_space_uri,
        format!("at:space/{alice_sdk_did}/blue.catbird.labyrinth.mailbox/self")
    );

    // Publish real signed `EpochPublic` (epoch 0) for Alice to `ds-a`'s `publishEpochHead` and verify via `getEpochHead` (`Gate 6`, `L-F01`)
    let alice_lab_secrets = DeviceSecrets::generate()?;
    let alice_transport_signer = Ed25519TransportSigner {
        sk: alice_ed_sk.clone(),
    };
    let (_pending_ep0, new_ep0) = open_genesis(
        &alice_remote_did,
        &alice_lab_secrets,
        &alice_transport_signer,
    )?;
    let ep0_def = EpochPublicDef::from_public(&new_ep0.record.public);
    let publish_body_bytes = serde_json::to_vec(&json!({ "epoch": ep0_def }))?;
    let publish_sha = hex::encode(Sha256::digest(&publish_body_bytes));
    let op_id = hex::encode(Uuid::new_v4().as_bytes());
    let write_body_bytes = serde_json::to_vec(&json!({
        "operationId": op_id,
        "actorDeviceId": alice_device_id.to_string(),
        "endpointNsid": "blue.catbird.labyrinth.publishEpochHead",
        "payloadSha256": publish_sha,
        "signedAt": Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
    }))?;
    let write_sig: Ed25519Signature =
        alice_ed_sk.sign(&[b"CATBIRD-LABYRINTH-WRITE\0".as_slice(), &write_body_bytes].concat());
    let alice_pub_jwt = mint_es256_service_jwt(
        &alice_p256,
        &alice_remote_did,
        &format!("{DS_A_DID}#atproto_mls"),
        "blue.catbird.labyrinth.publishEpochHead",
    );
    let pub_resp = admin_http
        .post(format!(
            "{}/xrpc/blue.catbird.labyrinth.publishEpochHead",
            ds_a.base_url
        ))
        .header("authorization", format!("Bearer {alice_pub_jwt}"))
        .header(CONTENT_TYPE, "application/json")
        .header(
            "catbird-labyrinth-write",
            URL_SAFE_NO_PAD.encode(&write_body_bytes),
        )
        .header(
            "catbird-labyrinth-write-signature",
            URL_SAFE_NO_PAD.encode(write_sig.to_bytes()),
        )
        .body(publish_body_bytes)
        .send()
        .await?;
    assert_eq!(
        pub_resp.status(),
        reqwest::StatusCode::OK,
        "publishEpochHead must succeed"
    );

    // Query `getEpochHead` with device-signed read header (`Gate 6` + `L-F01` `chain` + `floorSeq`)
    #[derive(serde::Serialize)]
    #[serde(rename_all = "camelCase")]
    struct ReadClaim<'a> {
        v: u8,
        nsid: &'a str,
        query: &'a str,
        did: &'a str,
        device_id: String,
        issued_at: i64,
    }
    let raw_query = format!(
        "actorDeviceId={}&did={}&epochNumber=0",
        alice_device_id,
        urlencoding::encode(&alice_remote_did)
    );
    let mut query_pairs: Vec<(String, String)> = url::form_urlencoded::parse(raw_query.as_bytes())
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();
    query_pairs.sort();
    let canon_query = query_pairs
        .iter()
        .map(|(k, v)| format!("{}={}", urlencoding::encode(k), urlencoding::encode(v)))
        .collect::<Vec<_>>()
        .join("&");
    let read_claim_bytes = serde_json::to_vec(&ReadClaim {
        v: 1,
        nsid: "blue.catbird.labyrinth.getEpochHead",
        query: &canon_query,
        did: &alice_remote_did,
        device_id: alice_device_id.to_string(),
        issued_at: Utc::now().timestamp_millis(),
    })?;
    let read_sig: Ed25519Signature =
        alice_ed_sk.sign(&[b"CATBIRD-LABYRINTH-READ\0".as_slice(), &read_claim_bytes].concat());
    let alice_get_head_jwt = mint_es256_service_jwt(
        &alice_p256,
        &alice_remote_did,
        &format!("{DS_A_DID}#atproto_mls"),
        "blue.catbird.labyrinth.getEpochHead",
    );
    // DS-A serves Alice's epoch head only from her authoritative home, resolved
    // from her public chat declaration (an unresolvable home fails closed with
    // RelayUnavailable); her PDS publishes one naming DS-A, as an enrolled
    // account's does.
    swan_pds.put_record(
        &alice_remote_did,
        "blue.catbird.chat.declaration",
        "self",
        json!({
            "$type": "blue.catbird.chat.declaration",
            "allowIncoming": "all",
            "deliveryService": DS_A_DID,
            "protocolVersion": "1",
            "createdAt": Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
        }),
    );
    let (head_status, _, head_bytes) = alice_firewall
        .get_with_headers(
            &format!(
                "{}/xrpc/blue.catbird.labyrinth.getEpochHead?{raw_query}",
                ds_a.base_url
            ),
            &[
                ("authorization", format!("Bearer {alice_get_head_jwt}")),
                (
                    "catbird-labyrinth-read",
                    URL_SAFE_NO_PAD.encode(&read_claim_bytes),
                ),
                (
                    "catbird-labyrinth-read-signature",
                    URL_SAFE_NO_PAD.encode(read_sig.to_bytes()),
                ),
            ],
        )
        .await?;
    assert_eq!(head_status, 200);
    let head_json: Value = serde_json::from_slice(&head_bytes)?;
    assert_eq!(head_json["epoch"]["epochNumber"], 0);
    assert_eq!(head_json["floorSeq"], 0);
    assert_eq!(
        head_json["chain"].as_array().unwrap().len(),
        1,
        "L-F01: getEpochHead must return contiguous verified chain"
    );

    // ========================================================================
    // Scenario 2: `C33` Direct Request Lifecycle, Pending Space Exclusion,
    // 30-Day Expiry Release, and Real-SDK Bidirectional Federated DM + Labyrinth Flush
    // ========================================================================
    let c33_res: Value = admin_http
        .post(format!(
            "{}/_test/clean-slate/c33-expire-and-recheck",
            ds_a.base_url
        ))
        .json(&json!({}))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    assert_eq!(
        c33_res["pendingActiveWriters"], 0,
        "C33: pending target MUST NOT appear as an active writer before acceptance"
    );
    assert!(c33_res["sweptCount"].as_u64().unwrap() >= 1);
    assert_eq!(c33_res["conversationLifecycle"], "superseded");
    assert_eq!(c33_res["consent"], "expired");
    assert_eq!(
        c33_res["reRequestConflict"], false,
        "C33: pair-owner fence MUST release after 30-day expiry so clean re-request succeeds"
    );

    // Step 1: Real-SDK federated enrollment (`alice_sdk` on `ds-a` `did:web` + `bob_sdk` on `ds-b` `did:plc`)
    let bob_firewall = Arc::new(swan_pds.client_transport(&ds_b.base_url));
    bob_firewall.set_account(
        &bob_sdk_did,
        bob_sdk_p256.clone(),
        DS_B_DID,
        &swan_pds.base_url,
        "bob-sdk-pds-oauth",
    );
    let bob_keystore = Arc::new(MemoryKeyStore::new());
    let bob_storage_root = temp_root.path().join("bob-sdk");
    let bob_sdk = {
        let storage_root = bob_storage_root.to_string_lossy().into();
        let did = bob_sdk_did.clone();
        let dev_id = bob_sdk_device_id.to_string();
        let ds_url = ds_b.base_url.clone();
        let pds_url = swan_pds.base_url.clone();
        let ks = bob_keystore.clone();
        let fw = bob_firewall.clone();
        tokio::task::spawn_blocking(move || {
            CatbirdMlsClient::open(
                CatbirdMlsClientConfig {
                    storage_root,
                    account_did: did,
                    device_id: dev_id,
                    home_ds_did: DS_B_DID.into(),
                    home_ds_endpoint: ds_url,
                    pds_endpoint: pds_url,
                },
                ks,
                fw,
                None,
            )
        })
        .await??
    };
    let bob_enroll = {
        let sdk = bob_sdk.clone();
        let sc = scopes.clone();
        tokio::task::spawn_blocking(move || sdk.enroll_device(&sc)).await??
    };
    assert!(bob_enroll.labyrinth_backup_enabled);

    // Assert live PostgreSQL `chat.devices` + PDS `blue.catbird.chat.device` records exist for BOTH SDK clients (`ADR-009` / `I4`)
    let alice_dev_rows: i64 = ds_a
        .pool
        .query_one(
            "SELECT COUNT(*) FROM chat.devices WHERE user_did = $1 AND device_id = $2 AND status = 'active'",
            &[&alice_sdk_did, &alice_sdk_device_id],
        )
        .await?
        .get(0);
    assert_eq!(
        alice_dev_rows, 1,
        "alice_sdk.enroll_device must register active device on ds-a"
    );
    let bob_dev_rows: i64 = ds_b
        .pool
        .query_one(
            "SELECT COUNT(*) FROM chat.devices WHERE user_did = $1 AND device_id = $2 AND status = 'active'",
            &[&bob_sdk_did, &bob_sdk_device_id],
        )
        .await?
        .get(0);
    assert_eq!(
        bob_dev_rows, 1,
        "bob_sdk.enroll_device must register active device on ds-b"
    );
    for (did, device_id) in [
        (&alice_sdk_did, alice_sdk_device_id),
        (&bob_sdk_did, bob_sdk_device_id),
    ] {
        assert!(
            swan_pds
                .record(did, "blue.catbird.chat.device", &device_id.to_string())
                .is_some(),
            "I4/ADR-009: {did} enroll_device must publish blue.catbird.chat.device record on PDS"
        );
    }

    // Step 2: `alice_sdk` initiates a federated `C33` Direct Request to `bob_sdk_did` across `ds-a` -> `ds-b`
    let requested_convo_uuid = Uuid::new_v4().to_string();
    let alice_dm_convo = {
        let sdk = alice_sdk.clone();
        let cid = requested_convo_uuid.clone();
        let peer = bob_sdk_did.clone();
        tokio::task::spawn_blocking(move || {
            sdk.create_group(
                &cid,
                DS_A_DID,
                vec![peer],
                None,
                Some("Hey Bob, federated C33 request!".into()),
            )
        })
        .await??
    };
    let fed_convo_id = alice_dm_convo.conversation_id.clone();
    assert_eq!(
        {
            let sdk = alice_sdk.clone();
            tokio::task::spawn_blocking(move || sdk.flush_labyrinth_queue()).await??
        },
        0,
        "C33: sender MUST NOT flush opening message to Conversation Space while direct request is pending"
    );

    // Step 3: `bob_sdk.sync()` on `ds-b` discovers pending Welcome + C33 request, verifies Alice's `I4` PDS device key,
    // decrypts the opening message, acknowledges Welcome, and accepts the request across `ds-b` -> `ds-a` (`seq = 2`)
    let bob_synced = {
        let sdk = bob_sdk.clone();
        tokio::task::spawn_blocking(move || sdk.sync()).await??
    };
    assert!(
        bob_synced >= 1,
        "bob_sdk.sync() must discover relayed federated C33 Welcome/request on ds-b"
    );
    let bob_pending_reqs = {
        let sdk = bob_sdk.clone();
        tokio::task::spawn_blocking(move || sdk.list_requests(Some("pending"))).await??
    };
    assert_eq!(
        bob_pending_reqs.len(),
        1,
        "bob_sdk must list 1 pending federated C33 direct request"
    );
    let bob_req_id = bob_pending_reqs[0].request_id.clone();
    let bob_convos = {
        let sdk = bob_sdk.clone();
        tokio::task::spawn_blocking(move || sdk.list_conversations(None, 50)).await??
    };
    let bob_dm_convo = bob_convos
        .iter()
        .find(|c| c.conversation_id == fed_convo_id)
        .expect("bob_sdk must hold identical federated conversation_id after Welcome import");
    assert_eq!(
        bob_dm_convo.group_id, alice_dm_convo.group_id,
        "MLS group_id must match bit-for-bit across alice_sdk (ds-a) and bob_sdk (ds-b)"
    );
    let bob_initial_msgs = {
        let sdk = bob_sdk.clone();
        let cid = fed_convo_id.clone();
        tokio::task::spawn_blocking(move || sdk.list_messages(&cid, None, 50)).await??
    };
    assert!(
        bob_initial_msgs
            .iter()
            .any(|m| m.plaintext_json.contains("Hey Bob, federated C33 request!")),
        "bob_sdk must decrypt Alice's C33 opening message over MLS_256_XWING Welcome"
    );

    {
        let sdk = bob_sdk.clone();
        let rid = bob_req_id.clone();
        tokio::task::spawn_blocking(move || sdk.accept_direct_request(&rid)).await??;
    }
    assert_eq!(
        {
            let sdk = bob_sdk.clone();
            tokio::task::spawn_blocking(move || sdk.list_requests(Some("accepted")))
                .await??
                .len()
        },
        1,
        "bob_sdk must transition request to accepted"
    );
    {
        let sdk = alice_sdk.clone();
        tokio::task::spawn_blocking(move || sdk.sync()).await??;
    }

    // Step 4: Register Bob's Push Gateway on `ds-b`, send live federated `MLS_256_XWING` messages in BOTH directions
    // (`alice_sdk` -> `ds-a` -> `ds-b` -> `D2` push wake -> `process_push_notification` + `bob_sdk.sync()`,
    //  then `bob_sdk` -> `ds-b` -> `ds-a` -> `alice_sdk.sync()`), verifying ES256 `I13` receipts!
    let bob_push_gw =
        LoopbackPushGateway::start_with_host("nest-push-b.federation.catbird.blue").await;
    admin_http
        .post(format!(
            "{}/_test/clean-slate/register-push-override",
            ds_b.base_url
        ))
        .json(&json!({
            "canonicalHttpsUrl": bob_push_gw.canonical_https_url,
            "loopbackHttpUrl": bob_push_gw.loopback_http_url,
        }))
        .send()
        .await?
        .error_for_status()?;
    let bob_pg_reg = {
        let sdk = bob_sdk.clone();
        let gw_url = bob_push_gw.canonical_https_url.clone();
        tokio::task::spawn_blocking(move || {
            sdk.build_signed_push_gateway_registration(
                &gw_url,
                "blue.catbird.ios",
                "opaque-push-key-bob-sdk-0001",
                true,
            )
        })
        .await??
    };
    let bob_pg_jwt = mint_es256_service_jwt(
        &bob_sdk_p256,
        &bob_sdk_did,
        &format!("{DS_B_DID}#atproto_mls"),
        "blue.catbird.chat.registerPushGateway",
    );
    admin_http
        .post(format!(
            "{}/xrpc/blue.catbird.chat.registerPushGateway",
            ds_b.base_url
        ))
        .header("authorization", format!("Bearer {bob_pg_jwt}"))
        .header(CONTENT_TYPE, "application/json")
        .body(bob_pg_reg.request_json)
        .send()
        .await?
        .error_for_status()?;

    let alice_msg_id = Uuid::new_v4().to_string();
    let alice_dm_msg = {
        let sdk = alice_sdk.clone();
        let cid = fed_convo_id.clone();
        let mid = alice_msg_id.clone();
        tokio::task::spawn_blocking(move || sdk.send_message(&cid, &mid, "Hello after C33 accept!"))
            .await??
    };
    assert!(alice_dm_msg
        .plaintext_json
        .contains("Hello after C33 accept!"));
    assert_eq!(
        alice_dm_msg.seq, 3,
        "Alice's post-accept message must be sequenced at seq = 3"
    );

    let captured_bob_wake = {
        let wakes = bob_push_gw.wakes.lock().unwrap();
        assert_eq!(
            wakes.len(),
            1,
            "D2: home ds-b must dispatch exactly 1 push wake to Bob's registered Push Gateway upon inbound federated delivery"
        );
        wakes[0].clone()
    };
    {
        let bearer = captured_bob_wake
            .auth_header
            .strip_prefix("Bearer ")
            .expect("D2: Bearer wake JWT required");
        let parts: Vec<&str> = bearer.split('.').collect();
        assert_eq!(parts.len(), 3);
        let signing_input = format!("{}.{}", parts[0], parts[1]);
        let sig_bytes = URL_SAFE_NO_PAD.decode(parts[2])?;
        let sig = P256Signature::from_slice(&sig_bytes)?;
        ds_b.signing_key
            .verifying_key()
            .verify(signing_input.as_bytes(), &sig)
            .expect("D2: ds-b push wake JWT must verify under ds-b's ES256 #atproto key");
    }
    let inline_ct_val = &captured_bob_wake.body["payload"]["ciphertext"];
    let inline_ct_b64 = inline_ct_val
        .get("$bytes")
        .and_then(Value::as_str)
        .or_else(|| inline_ct_val.as_str())
        .expect("I12: <=2200B federated push wake must include inline ciphertext");
    let inline_ct_bytes = STANDARD
        .decode(inline_ct_b64)
        .or_else(|_| URL_SAFE_NO_PAD.decode(inline_ct_b64))?;
    let wake_seq = captured_bob_wake.body["payload"]["seq"]
        .as_i64()
        .unwrap_or(3);
    let push_preview = {
        let root = bob_storage_root.clone();
        let did_hash = bob_sdk.account_did_hash().to_string();
        let ks: Arc<dyn PushKeystore> = bob_keystore.clone();
        let wake = PushWakePayload {
            kind: "applicationMessage".to_string(),
            conversation_id: fed_convo_id.clone(),
            generation: 0,
            entry_seq: wake_seq,
            message_id: alice_msg_id.clone(),
            recipient_account_hash: did_hash.clone(),
            fetch_required: false,
            sender_did: Some(alice_sdk_did.clone()),
            inline_ciphertext: Some(inline_ct_bytes),
        };
        tokio::task::spawn_blocking(move || {
            process_push_notification(&root, &did_hash, ks, None, &wake)
        })
        .await??
    };
    assert!(
        !push_preview.fallback_generic && push_preview.body.contains("Hello after C33 accept!"),
        "G1/D2: process_push_notification must decrypt inline federated push ciphertext without Tokio or generic fallback"
    );
    {
        let sdk = bob_sdk.clone();
        tokio::task::spawn_blocking(move || -> Result<(), MLSError> {
            sdk.handle_darwin_push_wakeup()?;
            sdk.sync()?;
            Ok(())
        })
        .await??;
    }
    let bob_msgs_after_push = {
        let sdk = bob_sdk.clone();
        let cid = fed_convo_id.clone();
        tokio::task::spawn_blocking(move || sdk.list_messages(&cid, None, 50)).await??
    };
    assert!(
        bob_msgs_after_push
            .iter()
            .any(|m| m.seq == 3 && m.plaintext_json.contains("Hello after C33 accept!")),
        "bob_sdk must surface Alice's seq=3 decrypted message after push wake + sync without double-decrypting"
    );

    let bob_reply_id = Uuid::new_v4().to_string();
    let bob_dm_msg = {
        let sdk = bob_sdk.clone();
        let cid = fed_convo_id.clone();
        let mid = bob_reply_id.clone();
        tokio::task::spawn_blocking(move || sdk.send_message(&cid, &mid, "Hi Alice from ds-b!"))
            .await??
    };
    assert!(bob_dm_msg.plaintext_json.contains("Hi Alice from ds-b!"));
    assert_eq!(
        bob_dm_msg.seq, 4,
        "Bob's cross-DS reply relayed ds-b -> ds-a must be sequenced at seq = 4 with ES256 I13 receipt"
    );

    {
        let sdk = alice_sdk.clone();
        tokio::task::spawn_blocking(move || sdk.sync()).await??;
    }
    let alice_msgs_after_reply = {
        let sdk = alice_sdk.clone();
        let cid = fed_convo_id.clone();
        tokio::task::spawn_blocking(move || sdk.list_messages(&cid, None, 50)).await??
    };
    assert!(
        alice_msgs_after_reply
            .iter()
            .any(|m| m.seq == 4 && m.plaintext_json.contains("Hi Alice from ds-b!")),
        "alice_sdk.sync() on ds-a must decrypt Bob's federated reply from ds-b at seq = 4"
    );

    // Step 5: Receipt-verified Labyrinth Conversation Space archival on `swan_pds` (`I13`, `D1` firewall == 0 blocked)
    let alice_flushed = {
        let sdk = alice_sdk.clone();
        tokio::task::spawn_blocking(move || sdk.flush_labyrinth_queue()).await??
    };
    let bob_flushed = {
        let sdk = bob_sdk.clone();
        tokio::task::spawn_blocking(move || sdk.flush_labyrinth_queue()).await??
    };
    assert!(
        alice_flushed >= 2,
        "alice_sdk.flush_labyrinth_queue() must commit C33 opening + post-accept messages to Conversation Space"
    );
    assert!(
        bob_flushed >= 1,
        "bob_sdk.flush_labyrinth_queue() must commit receipt-verified reply batch to Conversation Space"
    );
    let pair_coord_did = std::cmp::min(DS_A_DID, DS_B_DID);
    let fed_space_uri =
        format!("at:space/{pair_coord_did}/blue.catbird.labyrinth.conversation/{fed_convo_id}-0");
    use labyrinth::records::nsid;
    for (did, mailbox) in [
        (&alice_sdk_did, &alice_enroll.mailbox_space_uri),
        (&bob_sdk_did, &bob_enroll.mailbox_space_uri),
    ] {
        assert!(
            !swan_pds
                .space_records(&fed_space_uri, did, nsid::BATCH)
                .is_empty(),
            "swan_pds must hold {did}'s Conversation Space batch writes"
        );
        // ds-b, the pair coordinator, is the Space authority.
        assert_authority_notified(&ds_b, &swan_pds, &fed_space_uri, did).await?;
        // The default-on archive enrolled this device in the account's personal mailbox Space.
        assert!(
            !swan_pds
                .space_records(mailbox, did, nsid::DEVICE)
                .is_empty(),
            "{did}'s personal mailbox Space must hold its Labyrinth device"
        );
    }
    assert_eq!(
        alice_firewall.blocked_attempts.load(Ordering::SeqCst),
        0,
        "D1: alice_sdk MUST NEVER contact peer ds-b directly"
    );
    assert_eq!(
        bob_firewall.blocked_attempts.load(Ordering::SeqCst),
        0,
        "D1: bob_sdk MUST NEVER contact peer ds-a directly"
    );

    // ========================================================================
    // Scenario 3: `D1` Cross-Server Group Relay (`relayGroupMutation` / `deliverGroupEntry`),
    // `I13` ES256 Receipt Verification (`did:plc`), `D2` Push Gateway Inline vs Fetch-Required,
    // `409` Epoch Conflict, and `D3` Admin-Only Removal
    // ========================================================================
    // Alice registers her Push Gateway ONLY on her home `ds-a` (`D2`: `ds-b` has 0 push bindings for Alice)
    let pg_signed_at = Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true);
    let pg_push_key = "opaque-push-key-alice-device-0001";
    let pg_transcript = build_push_gateway_transcript(
        &alice_device_id,
        &alice_key_id,
        1,
        &push_gw.canonical_https_url,
        "blue.catbird.ios",
        pg_push_key,
        true,
        &pg_signed_at,
    )?;
    let pg_sig: Ed25519Signature = alice_ed_sk.sign(&pg_transcript);
    let alice_pg_jwt = mint_es256_service_jwt(
        &alice_p256,
        &alice_remote_did,
        &format!("{DS_A_DID}#atproto_mls"),
        "blue.catbird.chat.registerPushGateway",
    );
    let (pg_status, _, _) = alice_firewall
        .post_json_with_headers(
            &format!(
                "{}/xrpc/blue.catbird.chat.registerPushGateway",
                ds_a.base_url
            ),
            &[("authorization", format!("Bearer {alice_pg_jwt}"))],
            &json!({
                "deviceId": alice_device_id.to_string(),
                "gatewayUrl": push_gw.canonical_https_url,
                "appId": "blue.catbird.ios",
                "pushKey": pg_push_key,
                "enabled": true,
                "keyId": alice_key_id,
                "authGeneration": 1,
                "signedAt": pg_signed_at,
                "signature": { "$bytes": STANDARD.encode(pg_sig.to_bytes()) },
            }),
        )
        .await?;
    assert_eq!(
        pg_status, 200,
        "D2: registerPushGateway on home ds-a must return 200"
    );

    let alice_bindings_on_ds_b: i64 = ds_b
        .pool
        .query_one(
            "SELECT COUNT(*) FROM chat.push_gateway_bindings WHERE user_did = $1",
            &[&alice_remote_did],
        )
        .await?
        .get(0);
    assert_eq!(
        alice_bindings_on_ds_b, 0,
        "D2: sequencing ds-b MUST hold zero push gateway bindings for remote member Alice"
    );

    // The sequencer accepts a relayed mutation only from the actor's own home: `ds-a` relaying
    // `ds-b`-local Bob's genuine seeded send is refused, and the conversation is untouched.
    let footprint_before = send_footprint(&ds_b.pool, &convo_id, &seeded_message_id).await?;
    let bob_relay_bytes = serde_json::to_vec(&json!({
        "conversationId": convo_id,
        "endpoint": "blue.catbird.chat.sendMessage",
        "actorDid": bob_admin_did,
        "actorDeviceId": bob_device_id,
        "signedRequest": seeded_b["signedRequest"],
    }))?;
    let bob_relay_mac = compute_s2s_mac(
        DS_A_DID,
        DS_B_DID,
        "blue.catbird.mlsDS.relayGroupMutation",
        &bob_relay_bytes,
    );
    let bob_relay_resp = admin_http
        .post(format!(
            "{}/xrpc/blue.catbird.mlsDS.relayGroupMutation",
            ds_b.base_url
        ))
        .header(CONTENT_TYPE, "application/json")
        .header("x-catbird-s2s-caller-did", DS_A_DID)
        .header("x-catbird-s2s-target-did", DS_B_DID)
        .header("x-catbird-s2s-mac", bob_relay_mac)
        .body(bob_relay_bytes)
        .send()
        .await?;
    assert_eq!(
        bob_relay_resp.status(),
        reqwest::StatusCode::FORBIDDEN,
        "D1: ds-a must not relay a mutation for ds-b-local Bob"
    );
    let bob_refusal: Value = bob_relay_resp.json().await?;
    assert_eq!(bob_refusal["error"], "NotAuthorized", "{bob_refusal}");
    assert_eq!(
        bob_refusal["message"], "caller is not the participant's home DS",
        "{bob_refusal}"
    );
    assert_eq!(
        send_footprint(&ds_b.pool, &convo_id, &seeded_message_id).await?,
        footprint_before,
        "D1: a refused relay must sequence nothing and record no send"
    );

    // Relay a member's signed group application message over S2S `relayGroupMutation` from the
    // member's home DS to the sequencer `ds-b` (`did:plc`). A sequencer accepts a relayed
    // mutation only from the actor's own home (`group_relay_security_tests::
    // group_application_relay_checks_home_leaf_device_key_and_pruned_replay`): `ds-a` relays
    // for Alice, whom it homes, never for `ds-b`-local Bob. The seeded send (its prior
    // coordinates, AAD and opaque ciphertext) is re-signed as Alice's leaf device.
    let mut alice_send_body = seeded_b["signedRequest"]["body"].clone();
    alice_send_body["actorDid"] = json!(alice_remote_did);
    alice_send_body["actorDeviceId"] = json!(alice_device_id);
    alice_send_body["keyId"] = json!(alice_key_id);
    let attestation_transcript =
        labyrinth_protocol::transcripts::original_sender_archive_transcript(
            &convo_id.to_string(),
            &seeded_message_id.to_string(),
            &archive_commitment,
        );
    let alice_attestation_signature = alice_ed_sk.sign(&attestation_transcript);
    alice_ed_sk
        .verifying_key()
        .verify_strict(&attestation_transcript, &alice_attestation_signature)
        .expect("Alice's originalSenderAttestation must verify before relay");
    let alice_original_sender_attestation = json!({
        "senderDid": alice_remote_did,
        "senderDeviceId": alice_device_id,
        "senderTransportPubkey": STANDARD.encode(alice_ed_sk.verifying_key().to_bytes()),
        "signature": STANDARD.encode(alice_attestation_signature.to_bytes()),
    });
    alice_send_body["aad"]["originalSenderAttestation"] = alice_original_sender_attestation.clone();
    let alice_signed_send: Value = admin_http
        .post(format!("{}/_test/clean-slate/sign-mutation", ds_b.base_url))
        .json(&json!({
            "body": alice_send_body,
            "ed25519SeedB64": STANDARD.encode(alice_ed_sk.to_bytes()),
        }))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let relay_req = json!({
        "conversationId": convo_id,
        "endpoint": "blue.catbird.chat.sendMessage",
        "actorDid": alice_remote_did,
        "actorDeviceId": alice_device_id,
        "signedRequest": alice_signed_send,
    });
    let relay_req_bytes = serde_json::to_vec(&relay_req)?;
    let relay_mac = compute_s2s_mac(
        DS_A_DID,
        DS_B_DID,
        "blue.catbird.mlsDS.relayGroupMutation",
        &relay_req_bytes,
    );
    let relay_resp = admin_http
        .post(format!(
            "{}/xrpc/blue.catbird.mlsDS.relayGroupMutation",
            ds_b.base_url
        ))
        .header(CONTENT_TYPE, "application/json")
        .header("x-catbird-s2s-caller-did", DS_A_DID)
        .header("x-catbird-s2s-target-did", DS_B_DID)
        .header("x-catbird-s2s-mac", relay_mac)
        .body(relay_req_bytes)
        .send()
        .await?;
    let relay_status = relay_resp.status();
    let relay_body = relay_resp.bytes().await?;
    assert_eq!(
        relay_status,
        reqwest::StatusCode::OK,
        "relayGroupMutation: {}",
        String::from_utf8_lossy(&relay_body)
    );
    let relay_out: Value = serde_json::from_slice(&relay_body)?;
    let sequenced_entry = relay_out["entry"].clone();
    let sequenced_seq = sequenced_entry["seq"].as_i64().unwrap();
    assert!(sequenced_seq >= 2);

    // Verify `I13` ES256 `sequencerReceipt` under `ds-b`'s (`did:plc`) `#mls-receipt-1` key!
    let mut rcpt_wire = sequenced_entry["sequencerReceipt"].clone();
    assert_eq!(rcpt_wire["conversationId"], convo_id.to_string());
    assert_eq!(
        rcpt_wire["generation"],
        alice_signed_send["body"]["prior"]["generation"]
    );
    assert_eq!(
        rcpt_wire["groupId"],
        alice_signed_send["body"]["prior"]["groupId"]
    );
    assert_eq!(
        rcpt_wire["epoch"],
        alice_signed_send["body"]["prior"]["epoch"]
    );
    assert_eq!(rcpt_wire["entryId"], sequenced_entry["entryId"]);
    assert_eq!(rcpt_wire["seq"], sequenced_entry["seq"]);
    assert_eq!(rcpt_wire["senderDid"], alice_remote_did);
    assert_eq!(rcpt_wire["senderDeviceId"], alice_device_id.to_string());
    assert_eq!(
        rcpt_wire["archiveCommitment"],
        STANDARD.encode(archive_commitment)
    );
    assert!(
        rcpt_wire.get("originalSenderAttestation").is_none(),
        "chat sequencerReceipt is the ES256 half of the Labyrinth archived receipt"
    );
    rcpt_wire["originalSenderAttestation"] = alice_original_sender_attestation.clone();
    assert_eq!(rcpt_wire["sequencerDid"], DS_B_DID);
    assert_eq!(rcpt_wire["kid"], format!("{DS_B_DID}#mls-receipt-1"));
    for bytes_field in ["groupId", "archiveCommitment", "signature"] {
        if let Some(b64) = rcpt_wire[bytes_field].as_str().map(str::to_owned) {
            rcpt_wire[bytes_field] = json!({ "$bytes": b64.trim_end_matches('=') });
        }
    }
    for bytes_field in ["senderTransportPubkey", "signature"] {
        if let Some(b64) = rcpt_wire["originalSenderAttestation"][bytes_field]
            .as_str()
            .map(str::to_owned)
        {
            rcpt_wire["originalSenderAttestation"][bytes_field] =
                json!({ "$bytes": b64.trim_end_matches('=') });
        }
    }
    let rcpt_def: labyrinth::records::defs::SequencerReceiptDef =
        serde_json::from_value(rcpt_wire)?;
    let archived_rcpt = rcpt_def.to_archived()?;
    assert_eq!(
        archived_rcpt.signed.payload.archive_commitment, archive_commitment,
        "I13: federated sequencerReceipt MUST sign the sender's AAD archiveCommitment"
    );
    let signed_rcpt = SignedSequencerReceipt {
        payload: archived_rcpt.signed.payload,
        key_id: archived_rcpt.signed.key_id,
        signature: archived_rcpt.signed.signature,
    };
    let ds_b_rcpt_uncompressed = ds_b
        .receipt_key
        .verifying_key()
        .to_encoded_point(false)
        .as_bytes()
        .to_vec();
    verify_sequencer_receipt_sec1(&ds_b_rcpt_uncompressed, DS_B_DID, &signed_rcpt)
        .expect("I13: ES256 sequencerReceipt from did:plc ds-b MUST verify");

    // Stale-epoch conflict (`409 StaleCoordinates`) on `relayGroupMutation`
    let mut stale_signed_req = alice_signed_send.clone();
    stale_signed_req["body"]["messageId"] = json!(Uuid::new_v4());
    stale_signed_req["body"]["prior"]["epoch"] = json!(999);
    let stale_body_val = stale_signed_req["body"].clone();
    let stale_wrapped: Value = admin_http
        .post(format!("{}/_test/clean-slate/sign-mutation", ds_b.base_url))
        .json(&json!({
            "body": stale_body_val,
            "ed25519SeedB64": STANDARD.encode(alice_ed_sk.to_bytes()),
        }))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let stale_relay = json!({
        "conversationId": convo_id,
        "endpoint": "blue.catbird.chat.sendMessage",
        "actorDid": alice_remote_did,
        "actorDeviceId": alice_device_id,
        "signedRequest": stale_wrapped,
    });
    let stale_bytes = serde_json::to_vec(&stale_relay)?;
    let stale_mac = compute_s2s_mac(
        DS_A_DID,
        DS_B_DID,
        "blue.catbird.mlsDS.relayGroupMutation",
        &stale_bytes,
    );
    let stale_resp = admin_http
        .post(format!(
            "{}/xrpc/blue.catbird.mlsDS.relayGroupMutation",
            ds_b.base_url
        ))
        .header(CONTENT_TYPE, "application/json")
        .header("x-catbird-s2s-caller-did", DS_A_DID)
        .header("x-catbird-s2s-target-did", DS_B_DID)
        .header("x-catbird-s2s-mac", stale_mac)
        .body(stale_bytes)
        .send()
        .await?;
    assert_eq!(
        stale_resp.status(),
        reqwest::StatusCode::CONFLICT,
        "stale epoch relayed mutation must return 409 StaleCoordinates"
    );

    // A live federated group that `ds-b` sequences, with a member homed on `ds-a`. Bob's device
    // creates it; `ds-b` delivers the membership entries that provision `ds-a`'s mirror, Alice's
    // device joins through her home, and her send reaches the sequencer only through `ds-a`'s
    // relay, then every member.
    let relay_group_cid = Uuid::new_v4().to_string();
    let relay_group = {
        let sdk = bob_sdk.clone();
        let cid = relay_group_cid.clone();
        let peer = alice_sdk_did.clone();
        tokio::task::spawn_blocking(move || {
            sdk.create_group(
                &cid,
                DS_B_DID,
                vec![peer],
                Some("Federated Relay Group".into()),
                None,
            )
        })
        .await??
    };
    assert_eq!(relay_group.sequencer_did, DS_B_DID);
    // Alice accepts, Bob fulfils her leaf recovery, Alice joins from the Welcome. `ds-b` delivers
    // each of its local commits to `ds-a` after committing, so rounds repeat until her device holds
    // the group.
    let join_deadline = Instant::now() + Duration::from_secs(30);
    loop {
        for sdk in [&alice_sdk, &bob_sdk, &alice_sdk] {
            let sdk = sdk.clone();
            tokio::task::spawn_blocking(move || sdk.sync()).await??;
        }
        let (sdk, cid) = (alice_sdk.clone(), relay_group_cid.clone());
        if tokio::task::spawn_blocking(move || sdk.list_members(&cid))
            .await?
            .is_ok()
        {
            break;
        }
        assert!(
            Instant::now() < join_deadline,
            "D1: Alice's device must join the ds-b-sequenced group through her home ds-a"
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    for sdk in [&alice_sdk, &bob_sdk] {
        let (sdk, cid) = (sdk.clone(), relay_group_cid.clone());
        let members: BTreeSet<String> = tokio::task::spawn_blocking(move || sdk.list_members(&cid))
            .await??
            .into_iter()
            .collect();
        assert_eq!(
            members,
            BTreeSet::from([alice_sdk_did.clone(), bob_sdk_did.clone()]),
            "D1: both homes' members must hold the ds-b-sequenced group"
        );
    }
    let relayed_id = Uuid::new_v4().to_string();
    let relayed = {
        let (sdk, cid, mid) = (
            alice_sdk.clone(),
            relay_group_cid.clone(),
            relayed_id.clone(),
        );
        tokio::task::spawn_blocking(move || sdk.send_message(&cid, &mid, "Relayed by my home ds-a"))
            .await??
    };
    // `I13`: the receipt Alice's device holds for the relayed send is `ds-b`'s ES256 receipt over
    // the archive commitment of the exact frame she sent.
    let queued = {
        let (sdk, cid) = (alice_sdk.clone(), relay_group_cid.clone());
        tokio::task::spawn_blocking(move || sdk.list_pending_labyrinth_queue(Some(&cid), 10))
            .await??
    };
    let queued_send = queued
        .iter()
        .find(|q| q.message_id == relayed_id)
        .expect("alice's relayed send must be queued for her archive");
    let stored_rcpt: StoredArchivedReceipt = serde_json::from_str(
        queued_send
            .sequencer_receipt_json
            .as_deref()
            .expect("I13: the relayed send must carry ds-b's sequencer receipt"),
    )?;
    assert_eq!(stored_rcpt.sequencer_did, DS_B_DID);
    assert_eq!(stored_rcpt.seq, relayed.seq as u64);
    let frame_nonce: [u8; 32] = STANDARD
        .decode(queued_send.frame_nonce_b64.as_deref().expect("frame nonce"))?
        .try_into()
        .expect("32-byte frame nonce");
    let relayed_rcpt = stored_rcpt.to_labyrinth_archived()?;
    assert_eq!(
        relayed_rcpt.signed.payload.archive_commitment,
        compute_archive_commitment(&frame_nonce, queued_send.labyrinth_frame_json.as_bytes()),
        "I13: ds-b's receipt must sign the archive commitment of Alice's relayed frame"
    );
    verify_sequencer_receipt_sec1(
        &ds_b_rcpt_uncompressed,
        DS_B_DID,
        &SignedSequencerReceipt {
            payload: relayed_rcpt.signed.payload,
            key_id: relayed_rcpt.signed.key_id,
            signature: relayed_rcpt.signed.signature,
        },
    )
    .expect("I13: ds-b's receipt for the relayed send must verify");
    {
        let sdk = bob_sdk.clone();
        tokio::task::spawn_blocking(move || sdk.sync()).await??;
    }
    let bob_group_msgs = {
        let (sdk, cid) = (bob_sdk.clone(), relay_group_cid.clone());
        tokio::task::spawn_blocking(move || sdk.list_messages(&cid, None, 50)).await??
    };
    assert!(
        bob_group_msgs.iter().any(|m| m.message_id == relayed_id
            && m.sender_did == alice_sdk_did
            && m.seq == relayed.seq
            && m.plaintext_json.contains("Relayed by my home ds-a")),
        "D1: ds-b-local Bob must receive Alice's relayed send at its sequenced seq: {bob_group_msgs:?}"
    );

    // `D2`: Alice's device registers its Push Gateway only at her home `ds-a`. `ds-b` delivers
    // Bob's sends to `ds-a`, which wakes her gateway: inline ciphertext up to 2,200 B,
    // fetch-required above.
    let alice_sdk_pg = {
        let (sdk, gw_url) = (alice_sdk.clone(), push_gw.canonical_https_url.clone());
        tokio::task::spawn_blocking(move || {
            sdk.build_signed_push_gateway_registration(
                &gw_url,
                "blue.catbird.ios",
                "opaque-push-key-alice-sdk-0001",
                true,
            )
        })
        .await??
    };
    let alice_sdk_pg_jwt = mint_es256_service_jwt(
        &alice_sdk_p256,
        &alice_sdk_did,
        &format!("{DS_A_DID}#atproto_mls"),
        "blue.catbird.chat.registerPushGateway",
    );
    admin_http
        .post(format!(
            "{}/xrpc/blue.catbird.chat.registerPushGateway",
            ds_a.base_url
        ))
        .header("authorization", format!("Bearer {alice_sdk_pg_jwt}"))
        .header(CONTENT_TYPE, "application/json")
        .body(alice_sdk_pg.request_json)
        .send()
        .await?
        .error_for_status()?;
    let alice_sdk_bindings_on_ds_b: i64 = ds_b
        .pool
        .query_one(
            "SELECT COUNT(*) FROM chat.push_gateway_bindings WHERE user_did = $1",
            &[&alice_sdk_did],
        )
        .await?
        .get(0);
    assert_eq!(
        alice_sdk_bindings_on_ds_b, 0,
        "D2: sequencing ds-b MUST hold zero push gateway bindings for remote member Alice"
    );
    assert!(
        push_gw.wakes.lock().unwrap().is_empty(),
        "D2: no wake may precede Bob's sends"
    );
    for (wake_count, text) in [
        (1, "Hi Alice, from ds-b".to_string()),
        (2, "x".repeat(3000)),
    ] {
        let (sdk, cid, mid) = (
            bob_sdk.clone(),
            relay_group_cid.clone(),
            Uuid::new_v4().to_string(),
        );
        tokio::task::spawn_blocking(move || sdk.send_message(&cid, &mid, &text)).await??;
        // `ds-b` delivers to remote homes after its commit; wait for this send's wake.
        let deadline = Instant::now() + Duration::from_secs(20);
        while push_gw.wakes.lock().unwrap().len() < wake_count {
            assert!(
                Instant::now() < deadline,
                "D2: home ds-a must wake Alice's gateway for Bob's send #{wake_count}"
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    {
        let wakes = push_gw.wakes.lock().unwrap();
        assert_eq!(
            wakes.len(),
            2,
            "D2: home ds-a must dispatch both push wakes"
        );
        let ds_a_vk = *ds_a.signing_key.verifying_key();
        assert_eq!(wakes[0].body["payload"]["wakeKind"], "applicationMessage");
        assert!(
            wakes[0].body["payload"]["ciphertext"].is_object()
                || wakes[0].body["payload"]["ciphertext"].is_string(),
            "I12: <=2200B wake MUST embed inline ciphertext"
        );
        assert_eq!(wakes[1].body["payload"]["wakeKind"], "applicationMessage");
        assert!(
            wakes[1].body["payload"].get("ciphertext").is_none()
                || wakes[1].body["payload"]["ciphertext"].is_null(),
            "I12: >2200B wake MUST omit inline ciphertext (fetch-required)"
        );
        for w in wakes.iter() {
            let bearer = w
                .auth_header
                .strip_prefix("Bearer ")
                .expect("D2: Bearer wake JWT required");
            let parts: Vec<&str> = bearer.split('.').collect();
            assert_eq!(parts.len(), 3, "D2: compact wake JWT must have 3 segments");
            let hdr: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[0])?)?;
            let claims: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1])?)?;
            let sig = P256Signature::from_slice(&URL_SAFE_NO_PAD.decode(parts[2])?)?;
            ds_a_vk
                .verify(format!("{}.{}", parts[0], parts[1]).as_bytes(), &sig)
                .expect("D2: ds-a #atproto ES256 signature on wake JWT must verify");
            assert_eq!(hdr["alg"], "ES256");
            assert_eq!(hdr["typ"], "atproto-push-wake+jwt");
            assert_eq!(hdr["kid"], "#atproto");
            assert_eq!(claims["iss"], DS_A_DID);
            assert_eq!(claims["aud"], "did:web:nest-push.federation.catbird.blue");
            assert_eq!(claims["lxm"], "blue.catbird.push.deliver");
            assert_eq!(claims["htm"], "POST");
            assert_eq!(claims["htu"], push_gw.canonical_https_url);
            assert_eq!(
                claims["body_sha256"].as_str().unwrap(),
                hex::encode(Sha256::digest(&w.raw_body)),
                "D2: WakeJwtClaims.body_sha256 must bind exact wire JSON bytes"
            );
            let raw = serde_json::to_string(&w.body)?;
            assert!(
                !raw.contains(&bob_sdk_did),
                "D2: zero sender DID in push wake"
            );
            assert!(
                !raw.contains("senderHandle"),
                "D2: zero sender handle in push wake"
            );
            assert!(
                !raw.contains("groupName") && !raw.contains("Federated Relay Group"),
                "D2: zero group title in push wake"
            );
        }
    }

    admin_http
        .post(format!(
            "{}/_test/clean-slate/add-zero-leaf-member",
            ds_b.base_url
        ))
        .json(&json!({
            "conversationId": convo_id,
            "adminDid": bob_admin_did,
            "memberDid": eve_did,
        }))
        .send()
        .await?
        .error_for_status()?;

    // `D3` / `M-F01` admin-only removal: non-admin Alice (`role = 'member'`) MUST be rejected with 403!
    let non_admin_kick = admin_http
        .post(format!("{}/_test/clean-slate/remove-member", ds_b.base_url))
        .json(&json!({
            "conversationId": convo_id,
            "actorDid": alice_remote_did,
            "targetDid": eve_did,
        }))
        .send()
        .await?;
    assert_eq!(
        non_admin_kick.status(),
        reqwest::StatusCode::FORBIDDEN,
        "D3/M-F01: non-admin member removal MUST be rejected with 403 Forbidden"
    );

    // ========================================================================
    // Scenario 5 & Scenario 6: `.staged` -> `.space` Media Privacy, `3A` Stateless
    // Home-`mls-ds` Space Relays (`relaySpaceCredential` & `relaySpaceRead`),
    // HPKE-authenticated commit headers, and `Gate 10` Immediate Removed-Member Eviction
    // ========================================================================
    // Upload encrypted media to both `swan_pds` (Bob's avatar) and `ref_pds` (Eve's attachment)
    let avatar_sym_key = [0x42_u8; 32];
    let avatar_cipher = Aes256Gcm::new_from_slice(&avatar_sym_key)
        .unwrap()
        .encrypt(
            AesNonce::from_slice(&[0x11_u8; 12]),
            b"group-avatar-png-bytes".as_ref(),
        )
        .expect("encrypt avatar");
    let avatar_sha256: [u8; 32] = Sha256::digest(&avatar_cipher).into();

    let bob_upload: Value = admin_http
        .post(format!(
            "{}/xrpc/com.atproto.repo.uploadBlob",
            swan_pds.base_url
        ))
        .header("authorization", "Bearer bob-pds-oauth")
        .header(CONTENT_TYPE, "application/octet-stream")
        .body(avatar_cipher.clone())
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let bob_avatar_cid = bob_upload["blob"]["ref"]["$link"]
        .as_str()
        .unwrap()
        .to_string();

    // Gate 10: `.staged` blob MUST return 404 on public `com.atproto.sync.getBlob` BEFORE promotion
    let staged_public_resp = admin_http
        .get(format!(
            "{}/xrpc/com.atproto.sync.getBlob?did={}&cid={}",
            swan_pds.base_url,
            urlencoding::encode(&bob_admin_did),
            urlencoding::encode(&bob_avatar_cid)
        ))
        .send()
        .await?;
    assert_eq!(staged_public_resp.status(), reqwest::StatusCode::NOT_FOUND);

    // Promote Bob's avatar into Conversation Space on `swan_pds`: the PDS commits it only after
    // `ds-b`, the Space authority, accepts its service-authenticated `notifyRepoUpdate`.
    admin_http
        .post(format!(
            "{}/xrpc/com.atproto.space.applyWrites",
            swan_pds.base_url
        ))
        .header("authorization", "Bearer bob-pds-oauth")
        .json(&json!({
            "space": space_uri,
            "repo": bob_admin_did,
            "writes": [{
                "$type": "com.atproto.space.applyWrites#create",
                "collection": "blue.catbird.labyrinth.msg",
                "rkey": "avatar-op-1",
                "value": {
                    "$type": "blue.catbird.labyrinth.msg",
                    "avatar": bob_upload["blob"],
                }
            }]
        }))
        .send()
        .await?
        .error_for_status()?;
    assert_authority_notified(&ds_b, &swan_pds, &space_uri, &bob_admin_did).await?;

    // Gate 10: `.space` blob MUST STILL return 404 on public `com.atproto.sync.getBlob` AFTER promotion
    let promoted_public_resp = admin_http
        .get(format!(
            "{}/xrpc/com.atproto.sync.getBlob?did={}&cid={}",
            swan_pds.base_url,
            urlencoding::encode(&bob_admin_did),
            urlencoding::encode(&bob_avatar_cid)
        ))
        .send()
        .await?;
    assert_eq!(
        promoted_public_resp.status(),
        reqwest::StatusCode::NOT_FOUND
    );

    // Eve uploads + promotes an attachment on `ref_pds` (`bluesky-social/atproto#5187`), which notifies `ds-b`
    let eve_media_cipher = vec![0xEE_u8; 512];
    let eve_upload: Value = admin_http
        .post(format!(
            "{}/xrpc/com.atproto.repo.uploadBlob",
            ref_pds.base_url
        ))
        .header("authorization", "Bearer eve-pds-oauth")
        .header(CONTENT_TYPE, "application/octet-stream")
        .body(eve_media_cipher.clone())
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let eve_blob_cid = eve_upload["blob"]["ref"]["$link"]
        .as_str()
        .unwrap()
        .to_string();
    admin_http
        .post(format!(
            "{}/xrpc/com.atproto.space.applyWrites",
            ref_pds.base_url
        ))
        .header("authorization", "Bearer eve-pds-oauth")
        .json(&json!({
            "space": space_uri,
            "repo": eve_did,
            "writes": [{
                "$type": "com.atproto.space.applyWrites#create",
                "collection": "blue.catbird.labyrinth.msg",
                "rkey": "eve-msg-1",
                "value": {
                    "$type": "blue.catbird.labyrinth.msg",
                    "attachment": eve_upload["blob"],
                }
            }]
        }))
        .send()
        .await?
        .error_for_status()?;
    assert_authority_notified(&ds_b, &ref_pds, &space_uri, eve_did).await?;

    // Unauthenticated & outsider reads MUST be rejected (401 & 403)
    let unauth_blob = admin_http
        .get(format!(
            "{}/xrpc/com.atproto.space.getBlob?space={}&repo={}&cid={}",
            ref_pds.base_url,
            urlencoding::encode(&space_uri),
            urlencoding::encode(eve_did),
            urlencoding::encode(&eve_blob_cid)
        ))
        .send()
        .await?;
    assert_eq!(unauth_blob.status(), reqwest::StatusCode::UNAUTHORIZED);

    let outsider_did = "did:plc:outsidernonmember24chars";
    let outsider_p256 = P256SigningKey::random(&mut rand::rngs::OsRng);
    admin_http
        .post(format!("{}/_test/clean-slate/register-did", ds_b.base_url))
        .json(&json!({
            "did": outsider_did,
            "p256Jwk": p256_public_jwk(outsider_p256.verifying_key()),
            "endpointUrl": swan_pds.base_url,
        }))
        .send()
        .await?
        .error_for_status()?;
    let outsider_eph = P256Secret::random(&mut rand::rngs::OsRng);
    let outsider_cnf = did_key(&outsider_eph.public_key());
    let now = Utc::now().timestamp();
    let outsider_del = delegation(
        &outsider_p256,
        &outsider_did,
        &space_uri,
        &Uuid::new_v4().to_string(),
        now as u64,
    );
    let outsider_cred_resp = admin_http
        .post(format!(
            "{}/xrpc/com.atproto.space.authorizeSpaceSync",
            ds_b.base_url
        ))
        .json(&json!({
            "space": space_uri,
            "credentialKey": outsider_cnf,
            "delegationToken": outsider_del,
        }))
        .send()
        .await?;
    assert_eq!(
        outsider_cred_resp.status(),
        reqwest::StatusCode::FORBIDDEN,
        "non-member delegation token MUST be rejected with 403 Forbidden"
    );

    // Mint Eve's active 10-minute Space credential on BOTH `swan_pds` and `ref_pds` use-cases
    let eve_eph = P256Secret::random(&mut rand::rngs::OsRng);
    let eve_proof_key = SigningKeyPair::from_p256_bytes(&eve_eph.to_bytes())?;
    let eve_cnf = did_key(&eve_eph.public_key());
    let now = Utc::now().timestamp();
    let eve_del = delegation(
        &eve_p256,
        &eve_did,
        &space_uri,
        &Uuid::new_v4().to_string(),
        now as u64,
    );
    let eve_cred_json: Value = admin_http
        .post(format!(
            "{}/xrpc/com.atproto.space.authorizeSpaceSync",
            ds_b.base_url
        ))
        .json(&json!({
            "space": space_uri,
            "credentialKey": eve_cnf,
            "delegationToken": eve_del,
            "notify": ref_pds.notify_registration(&space_uri),
        }))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let eve_cred = eve_cred_json["credential"].as_str().unwrap().to_string();

    // Verify Eve CAN read both `swan_pds` and `ref_pds` BEFORE removal: each presentation names
    // the writer whose repo it reads (`Atproto-Space-Audience`).
    for (pds_url, writer, cid) in [
        (
            &swan_pds.base_url,
            bob_admin_did.as_str(),
            bob_avatar_cid.as_str(),
        ),
        (&ref_pds.base_url, eve_did, eve_blob_cid.as_str()),
    ] {
        let signed_hdrs = sign_credential_request(
            &eve_cred,
            &eve_proof_key,
            writer,
            Utc::now().timestamp(),
            Some(&Uuid::new_v4().to_string()),
        )?;
        let pre_resp = admin_http
            .get(format!(
                "{pds_url}/xrpc/com.atproto.space.getBlob?space={}&repo={}&cid={}",
                urlencoding::encode(&space_uri),
                urlencoding::encode(writer),
                urlencoding::encode(cid),
            ))
            .header("authorization", &signed_hdrs.authorization)
            .header(
                "atproto-space-audience",
                &signed_hdrs.atproto_space_audience,
            )
            .header("signature-input", &signed_hdrs.signature_input)
            .header("signature", &signed_hdrs.signature)
            .send()
            .await?;
        assert_eq!(pre_resp.status(), reqwest::StatusCode::OK);
    }

    // `3A` Stateless Home-`mls-ds` Relays (`relaySpaceCredential` & `relaySpaceRead`) for Alice via `ds-a`!
    // Snapshot row counts on `ds-a` BEFORE `relaySpaceCredential` + `relaySpaceRead`
    let ds_a_rows_before_relay = count_ds_operational_rows(&ds_a.pool).await?;

    let alice_eph = P256Secret::random(&mut rand::rngs::OsRng);
    let alice_proof_key = SigningKeyPair::from_p256_bytes(&alice_eph.to_bytes())?;
    let alice_cnf = did_key(&alice_eph.public_key());
    let now = Utc::now().timestamp();
    let alice_del = delegation(
        &alice_p256,
        &alice_remote_did,
        &space_uri,
        &Uuid::new_v4().to_string(),
        now as u64,
    );
    let alice_relay_cred_jwt = mint_es256_service_jwt(
        &alice_p256,
        &alice_remote_did,
        &format!("{DS_A_DID}#atproto_mls"),
        "blue.catbird.chat.relaySpaceCredential",
    );
    let (rc_status, _, rc_bytes) = alice_firewall
        .post_json_with_headers(
            &format!(
                "{}/xrpc/blue.catbird.chat.relaySpaceCredential",
                ds_a.base_url
            ),
            &[("authorization", format!("Bearer {alice_relay_cred_jwt}"))],
            &json!({
                "actorDeviceId": alice_device_id.to_string(),
                "authorityDid": DS_B_DID,
                "space": space_uri,
                "delegationToken": alice_del,
                "cnfKey": alice_cnf,
                "notify": swan_pds.notify_registration(&space_uri),
            }),
        )
        .await?;
    assert_eq!(
        rc_status, 200,
        "3A: relaySpaceCredential through ds-a to did:plc ds-b must succeed"
    );
    let rc_json: Value = serde_json::from_slice(&rc_bytes)?;
    let alice_cred = rc_json["credential"].as_str().unwrap().to_string();

    // Negative `3A` NSID allowlist check: `com.atproto.space.putRecord` -> `400 InvalidNsid`
    let bad_nsid_jwt = mint_es256_service_jwt(
        &alice_p256,
        &alice_remote_did,
        &format!("{DS_A_DID}#atproto_mls"),
        "blue.catbird.chat.relaySpaceRead",
    );
    let (bad_nsid_status, _, bad_nsid_body) = alice_firewall
        .post_json_with_headers(
            &format!("{}/xrpc/blue.catbird.chat.relaySpaceRead", ds_a.base_url),
            &[("authorization", format!("Bearer {bad_nsid_jwt}"))],
            &json!({
                "actorDeviceId": alice_device_id.to_string(),
                "targetDid": eve_did,
                "nsid": "com.atproto.space.putRecord",
                "credential": alice_cred,
                "spaceAudience": eve_did,
                "signatureInput": "sig1=()",
                "signature": "sig1=:AA==:",
            }),
        )
        .await?;
    assert_eq!(bad_nsid_status, 400);
    assert!(String::from_utf8_lossy(&bad_nsid_body).contains("InvalidNsid"));

    // Negative `3A` SSRF checks: `did:web:169.254.169.254` and `did:web:10.0.0.1` -> `400 InvalidTargetEndpoint`
    for ssrf_did in ["did:web:169.254.169.254", "did:web:10.0.0.1"] {
        let ssrf_jwt = mint_es256_service_jwt(
            &alice_p256,
            &alice_remote_did,
            &format!("{DS_A_DID}#atproto_mls"),
            "blue.catbird.chat.relaySpaceRead",
        );
        let (ssrf_status, _, ssrf_body) = alice_firewall
            .post_json_with_headers(
                &format!("{}/xrpc/blue.catbird.chat.relaySpaceRead", ds_a.base_url),
                &[("authorization", format!("Bearer {ssrf_jwt}"))],
                &json!({
                    "actorDeviceId": alice_device_id.to_string(),
                    "targetDid": ssrf_did,
                    "nsid": "com.atproto.space.getSpace",
                    "query": format!("space={}", urlencoding::encode(&space_uri)),
                    "credential": alice_cred,
                    "spaceAudience": ssrf_did,
                    "signatureInput": "sig1=()",
                    "signature": "sig1=:AA==:",
                }),
            )
            .await?;
        assert_eq!(ssrf_status, 400);
        assert!(
            String::from_utf8_lossy(&ssrf_body).contains("InvalidTargetEndpoint"),
            "3A/M-F06: SSRF target {ssrf_did} must be blocked with InvalidTargetEndpoint"
        );
    }

    // Gate 10: Admin Bob removes Eve (`200 OK`) -> `ds-b` revokes Eve's credential & fans out
    // `notifyCredentialsRevoked` to BOTH `swan_pds` and `ref_pds`!
    let kick_eve_resp: Value = admin_http
        .post(format!("{}/_test/clean-slate/remove-member", ds_b.base_url))
        .json(&json!({
            "conversationId": convo_id,
            "actorDid": bob_admin_did,
            "targetDid": eve_did,
        }))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    assert_eq!(kick_eve_resp["removed"], true);
    assert!(
        kick_eve_resp["notifiedWriterHosts"].as_u64().unwrap() >= 2,
        "Gate 10: notifyCredentialsRevoked must fan out to both Swan and atproto#5187 PDS hosts"
    );

    // Gate 10: Eve's unexpired 10-minute credential MUST NOW IMMEDIATELY FAIL with `401 CredentialRevoked`
    // on `ds-b` (`listWriters`), `swan_pds` (`getBlob` & `listRepoOps`), AND `ref_pds` (`getBlob` & `listRepoOps`),
    // AND re-minting via `authorizeSpaceSync` MUST return `403 Forbidden`!
    let eve_ds_b_pop = sign_credential_request(
        &eve_cred,
        &eve_proof_key,
        DS_B_DID,
        Utc::now().timestamp(),
        Some(&Uuid::new_v4().to_string()),
    )?;
    let evicted_list_writers = admin_http
        .get(format!(
            "{}/xrpc/com.atproto.space.listWriters?space={}",
            ds_b.base_url,
            urlencoding::encode(&space_uri),
        ))
        .header("authorization", &eve_ds_b_pop.authorization)
        .header(
            "atproto-space-audience",
            &eve_ds_b_pop.atproto_space_audience,
        )
        .header("signature-input", &eve_ds_b_pop.signature_input)
        .header("signature", &eve_ds_b_pop.signature)
        .send()
        .await?;
    assert_eq!(
        evicted_list_writers.status(),
        reqwest::StatusCode::UNAUTHORIZED,
        "Gate 10: removed member Eve's cached credential must fail with 401 on ds-b listWriters"
    );

    let now = Utc::now().timestamp();
    let eve_remint_del = delegation(
        &eve_p256,
        &eve_did,
        &space_uri,
        &Uuid::new_v4().to_string(),
        now as u64,
    );
    let eve_remint_resp = admin_http
        .post(format!(
            "{}/xrpc/com.atproto.space.authorizeSpaceSync",
            ds_b.base_url
        ))
        .json(&json!({
            "space": space_uri,
            "credentialKey": eve_cnf,
            "delegationToken": eve_remint_del,
        }))
        .send()
        .await?;
    assert_eq!(
        eve_remint_resp.status(),
        reqwest::StatusCode::FORBIDDEN,
        "Gate 10: removed member Eve re-minting authorizeSpaceSync MUST fail with 403 Forbidden"
    );

    for (pds_url, writer, cid) in [
        (
            &swan_pds.base_url,
            bob_admin_did.as_str(),
            bob_avatar_cid.as_str(),
        ),
        (&ref_pds.base_url, eve_did, eve_blob_cid.as_str()),
    ] {
        let h1 = sign_credential_request(
            &eve_cred,
            &eve_proof_key,
            writer,
            Utc::now().timestamp(),
            Some(&Uuid::new_v4().to_string()),
        )?;
        let evicted_blob = admin_http
            .get(format!(
                "{pds_url}/xrpc/com.atproto.space.getBlob?space={}&repo={}&cid={}",
                urlencoding::encode(&space_uri),
                urlencoding::encode(writer),
                urlencoding::encode(cid),
            ))
            .header("authorization", &h1.authorization)
            .header("atproto-space-audience", &h1.atproto_space_audience)
            .header("signature-input", &h1.signature_input)
            .header("signature", &h1.signature)
            .send()
            .await?;
        assert_eq!(
            evicted_blob.status(),
            reqwest::StatusCode::UNAUTHORIZED,
            "Gate 10: removed member Eve's cached credential must fail with 401 on {pds_url} ({writer})"
        );

        let h2 = sign_credential_request(
            &eve_cred,
            &eve_proof_key,
            writer,
            Utc::now().timestamp(),
            Some(&Uuid::new_v4().to_string()),
        )?;
        let evicted_ops = admin_http
            .get(format!(
                "{pds_url}/xrpc/com.atproto.space.listRepoOps?space={}&repo={}",
                urlencoding::encode(&space_uri),
                urlencoding::encode(writer),
            ))
            .header("authorization", &h2.authorization)
            .header("atproto-space-audience", &h2.atproto_space_audience)
            .header("signature-input", &h2.signature_input)
            .header("signature", &h2.signature)
            .send()
            .await?;
        assert_eq!(evicted_ops.status(), reqwest::StatusCode::UNAUTHORIZED);
    }

    // Remaining member Alice reads `listWriters` on `ds-b` AND Eve's historical repo ops + blob on `ref_pds`
    // EXCLUSIVELY through her home `ds-a`'s stateless `relaySpaceRead` (`3A` + `D1` firewall)!
    let list_writers_pop = sign_credential_request(
        &alice_cred,
        &alice_proof_key,
        DS_B_DID,
        Utc::now().timestamp(),
        Some(&Uuid::new_v4().to_string()),
    )?;
    let lr_jwt = mint_es256_service_jwt(
        &alice_p256,
        &alice_remote_did,
        &format!("{DS_A_DID}#atproto_mls"),
        "blue.catbird.chat.relaySpaceRead",
    );
    let (lr_status, _, lr_bytes) = alice_firewall
        .post_json_with_headers(
            &format!("{}/xrpc/blue.catbird.chat.relaySpaceRead", ds_a.base_url),
            &[("authorization", format!("Bearer {lr_jwt}"))],
            &json!({
                "actorDeviceId": alice_device_id.to_string(),
                "targetDid": DS_B_DID,
                "nsid": "com.atproto.space.listWriters",
                "query": format!("space={}", urlencoding::encode(&space_uri)),
                "credential": alice_cred,
                "spaceAudience": DS_B_DID,
                "signatureInput": list_writers_pop.signature_input,
                "signature": list_writers_pop.signature,
            }),
        )
        .await?;
    assert_eq!(lr_status, 200);
    let lr_json: Value = serde_json::from_slice(&lr_bytes)?;
    let repo_dids: Vec<&str> = lr_json["repos"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| {
            r["repo"]
                .as_str()
                .expect("listWriters entry has a repo DID")
        })
        .collect();
    assert!(
        repo_dids.contains(&eve_did),
        "Historical writer Eve MUST remain listed in listWriters after removal"
    );

    // Alice reads Eve's `listRepoOps` on `ref_pds` via `ds-a` `relaySpaceRead` with HPKE `Accept-Signature`
    // and cryptographically verifies the signed commitment + CORS `Access-Control-Expose-Headers`!
    let encap_eve = encapsulate_p256(&eve_kem_did_key)?;
    let accept_signature = format_accept_signature(MacProfile::Commit, &encap_eve.key_share)?;
    let ops_pop = sign_credential_request(
        &alice_cred,
        &alice_proof_key,
        eve_did,
        Utc::now().timestamp(),
        Some(&Uuid::new_v4().to_string()),
    )?;
    let ops_jwt = mint_es256_service_jwt(
        &alice_p256,
        &alice_remote_did,
        &format!("{DS_A_DID}#atproto_mls"),
        "blue.catbird.chat.relaySpaceRead",
    );
    let (ops_status, ops_hdrs, ops_bytes) = alice_firewall
        .post_json_with_headers(
            &format!("{}/xrpc/blue.catbird.chat.relaySpaceRead", ds_a.base_url),
            &[("authorization", format!("Bearer {ops_jwt}"))],
            &json!({
                "actorDeviceId": alice_device_id.to_string(),
                "targetDid": eve_did,
                "nsid": "com.atproto.space.listRepoOps",
                "query": format!(
                    "space={}&repo={}",
                    urlencoding::encode(&space_uri),
                    urlencoding::encode(eve_did)
                ),
                "credential": alice_cred,
                "spaceAudience": eve_did,
                "acceptSignature": accept_signature,
                "signatureInput": ops_pop.signature_input,
                "signature": ops_pop.signature,
            }),
        )
        .await?;
    assert_eq!(ops_status, 200);
    let exposed_hdr = ops_hdrs
        .get("access-control-expose-headers")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    for name in ["atproto-space-commit", "signature-input", "signature"] {
        assert!(
            exposed_hdr
                .split(',')
                .any(|header| header.trim().eq_ignore_ascii_case(name)),
            "relay must expose {name}"
        );
    }
    let header = |name: &'static str| {
        ops_hdrs
            .get(name)
            .and_then(|v| v.to_str().ok())
            .expect("relay must forward MAC evidence")
    };
    let verified = verify_commit_mac(
        &encap_eve.shared_secret,
        header("atproto-space-commit"),
        header("signature-input"),
        header("signature"),
    )?;
    assert_eq!(verified.keyid, encap_eve.key_share);
    let ops_json: Value = serde_json::from_slice(&ops_bytes)?;
    let commit_rev = ops_json["commit"]["rev"].as_str().unwrap();
    let commit_data: [u8; 32] = STANDARD
        .decode(ops_json["commit"]["data"]["$bytes"].as_str().unwrap())?
        .try_into()
        .unwrap();
    assert_eq!(verified.space.as_str(), space_uri);
    assert_eq!(verified.repo.as_str(), eve_did);
    assert_eq!(verified.rev.as_str(), commit_rev);
    assert_eq!(verified.data, commit_data);

    // Verify `3A` statelessness: ZERO operational rows added on `ds-a` across `relaySpaceCredential` & `relaySpaceRead`!
    let ds_a_rows_after_relay = count_ds_operational_rows(&ds_a.pool).await?;
    assert_eq!(
        ds_a_rows_before_relay, ds_a_rows_after_relay,
        "3A: relaySpaceCredential and relaySpaceRead MUST write zero operational rows on home mls-ds"
    );
    assert_eq!(
        alice_firewall.blocked_attempts.load(Ordering::SeqCst),
        0,
        "D1: Alice made zero direct connections to ds-b or ref_pds"
    );
    let _ = (&alice_kem_did_key, &bob_kem_did_key, &bob_key_id);

    // ========================================================================
    // Scenario 4: `1A` `GroupMetadataV1` (`<= 16 KiB` Cap, `> 16 KiB` -> `413`),
    // Space-Backed Avatar Pointer, and Automatic Admin Avatar Re-Host on Leave
    // ========================================================================
    let meta_v1 = GroupMetadataV1 {
        extra: Default::default(),
        version: 1,
        title: "Clean-Slate Federated Group".into(),
        description: String::new(),
        avatar_blob_locator: None,
        avatar_content_type: Some("image/png".into()),
        space_avatar: Some(SpaceAvatarPointer {
            setter_did: bob_admin_did.clone(),
            space_blob_cid: bob_avatar_cid.clone(),
            sym_key: avatar_sym_key.to_vec(),
            sha256: avatar_sha256.to_vec(),
            mime_type: Some("image/png".into()),
        }),
    };
    let meta_plain = serde_json::to_vec(&meta_v1)?;
    let meta_key = [0x55_u8; 32];
    let meta_cipher = Aes256Gcm::new_from_slice(&meta_key)
        .unwrap()
        .encrypt(AesNonce::from_slice(&[0x22_u8; 12]), meta_plain.as_slice())
        .unwrap();
    validate_metadata_snapshot_size(&meta_cipher)?;

    let set_meta_res: Value = admin_http
        .post(format!(
            "{}/_test/clean-slate/set-group-metadata",
            ds_b.base_url
        ))
        .json(&json!({
            "conversationId": convo_id,
            "epoch": 0,
            "ciphertextB64": STANDARD.encode(&meta_cipher),
            "actorDid": bob_admin_did,
            "actorDeviceId": bob_device_id,
        }))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    assert_eq!(set_meta_res["stored"], true);
    let mv_initial = set_meta_res["metadataVersion"].as_u64().unwrap();

    // Oversized `> 16 KiB` (`16_385` B) snapshot MUST fail with `413 Payload Too Large` and DB constraint proof
    let oversized_bytes = vec![0xCC_u8; 16_385];
    assert!(validate_metadata_snapshot_size(&oversized_bytes).is_err());
    let oversized_resp = admin_http
        .post(format!(
            "{}/_test/clean-slate/set-group-metadata",
            ds_b.base_url
        ))
        .json(&json!({
            "conversationId": convo_id,
            "epoch": 0,
            "ciphertextB64": STANDARD.encode(&oversized_bytes),
            "actorDid": bob_admin_did,
            "actorDeviceId": bob_device_id,
        }))
        .send()
        .await?;
    assert_eq!(
        oversized_resp.status(),
        reqwest::StatusCode::PAYLOAD_TOO_LARGE
    );
    let oversized_json: Value = oversized_resp.json().await?;
    assert_eq!(oversized_json["rejectedByDbConstraint"], true);

    // Promote Alice to co-admin before Bob voluntarily leaves, then Bob voluntarily leaves
    admin_http
        .post(format!("{}/_test/clean-slate/promote-admin", ds_b.base_url))
        .json(&json!({
            "conversationId": convo_id,
            "actorDid": bob_admin_did,
            "targetDid": alice_remote_did,
        }))
        .send()
        .await?
        .error_for_status()?;

    let leave_res: Value = admin_http
        .post(format!(
            "{}/_test/clean-slate/voluntary-leave",
            ds_b.base_url
        ))
        .json(&json!({
            "conversationId": convo_id,
            "actorDid": bob_admin_did,
        }))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    assert_eq!(leave_res["left"], true);

    // Active admin Alice automatically re-hosts Bob's Space avatar into Alice's own `.space` repo (`maybe_rehost_avatar_on_setter_leave`)!
    let rehosted = maybe_rehost_avatar_on_setter_leave(
        &meta_v1,
        mv_initial,
        &bob_admin_did,
        &alice_remote_did,
        MemberRole::Admin,
        |setter_did, cid| {
            let swan_url = swan_pds.base_url.clone();
            let sp = space_uri.clone();
            let cred = alice_cred.clone();
            let eph_bytes = alice_eph.to_bytes();
            let http = admin_http.clone();
            async move {
                let proof_key = SigningKeyPair::from_p256_bytes(&eph_bytes)
                    .map_err(|e| MLSError::Internal(e.to_string()))?;
                let pop = sign_credential_request(
                    &cred,
                    &proof_key,
                    &setter_did,
                    Utc::now().timestamp(),
                    Some(&Uuid::new_v4().to_string()),
                )
                .map_err(|e| MLSError::Internal(e.to_string()))?;
                let bytes = http
                    .get(format!(
                        "{swan_url}/xrpc/com.atproto.space.getBlob?space={}&repo={}&cid={}",
                        urlencoding::encode(&sp),
                        urlencoding::encode(&setter_did),
                        urlencoding::encode(&cid),
                    ))
                    .header("authorization", &pop.authorization)
                    .header("atproto-space-audience", &pop.atproto_space_audience)
                    .header("signature-input", &pop.signature_input)
                    .header("signature", &pop.signature)
                    .send()
                    .await
                    .map_err(|e| MLSError::Internal(e.to_string()))?
                    .error_for_status()
                    .map_err(|e| MLSError::Internal(e.to_string()))?
                    .bytes()
                    .await
                    .map_err(|e| MLSError::Internal(e.to_string()))?
                    .to_vec();
                Ok(bytes)
            }
        },
        |new_owner_did, ct_bytes, mime| {
            let swan_url = swan_pds.base_url.clone();
            let sp = space_uri.clone();
            let http = admin_http.clone();
            async move {
                let up: Value = http
                    .post(format!("{swan_url}/xrpc/com.atproto.repo.uploadBlob"))
                    .header("authorization", "Bearer alice-pds-oauth")
                    .header(
                        CONTENT_TYPE,
                        mime.as_deref().unwrap_or("application/octet-stream"),
                    )
                    .body(ct_bytes)
                    .send()
                    .await
                    .map_err(|e| MLSError::Internal(e.to_string()))?
                    .error_for_status()
                    .map_err(|e| MLSError::Internal(e.to_string()))?
                    .json()
                    .await
                    .map_err(|e| MLSError::Internal(e.to_string()))?;
                let cid = up["blob"]["ref"]["$link"]
                    .as_str()
                    .unwrap_or_default()
                    .to_string();
                http.post(format!("{swan_url}/xrpc/com.atproto.space.applyWrites"))
                    .header("authorization", "Bearer alice-pds-oauth")
                    .json(&json!({
                        "space": sp,
                        "repo": new_owner_did,
                        "writes": [{
                            "$type": "com.atproto.space.applyWrites#create",
                            "collection": "blue.catbird.labyrinth.msg",
                            "rkey": "rehosted-avatar-1",
                            "value": { "avatar": up["blob"] }
                        }]
                    }))
                    .send()
                    .await
                    .map_err(|e| MLSError::Internal(e.to_string()))?
                    .error_for_status()
                    .map_err(|e| MLSError::Internal(e.to_string()))?;
                Ok(cid)
            }
        },
    )
    .await?
    .expect("1A: active admin Alice must re-host departing setter Bob's Space avatar");

    assert_eq!(rehosted.next_metadata_version, mv_initial + 1);
    assert_eq!(
        rehosted.metadata.space_avatar.as_ref().unwrap().setter_did,
        alice_remote_did
    );

    let rehosted_cipher = Aes256Gcm::new_from_slice(&meta_key)
        .unwrap()
        .encrypt(
            AesNonce::from_slice(&[0x33_u8; 12]),
            serde_json::to_vec(&rehosted.metadata)?.as_slice(),
        )
        .unwrap();
    let set_meta_rehosted: Value = admin_http
        .post(format!(
            "{}/_test/clean-slate/set-group-metadata",
            ds_b.base_url
        ))
        .json(&json!({
            "conversationId": convo_id,
            "epoch": 0,
            "ciphertextB64": STANDARD.encode(&rehosted_cipher),
            "actorDid": alice_remote_did,
            "actorDeviceId": alice_device_id,
        }))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    assert_eq!(
        set_meta_rehosted["metadataVersion"].as_u64(),
        Some(mv_initial + 1)
    );

    // ========================================================================
    // Scenario 7: `BIRDaemon` `nest`-Free Federated Group & C33 Participation (`G3`)
    // ========================================================================
    assert!(
        std::env::var("BIRD_NEST_BASE_URL").is_err(),
        "G3: BIRD_NEST_BASE_URL must be completely unset"
    );
    let bird_did = "did:plc:birdaemonfederated24chrs";
    let bird_p256 = P256SigningKey::random(&mut rand::rngs::OsRng);
    swan_pds.add_account(bird_did, bird_p256.clone(), "bird-pds-oauth");
    for ds in [&ds_a, &ds_b] {
        ds.register_did(
            &admin_http,
            bird_did,
            bird_p256.verifying_key(),
            &swan_pds.base_url,
        )
        .await?;
    }

    let bird_bot = FederatedBirdBot::open_and_enroll_with_pds_token_for_test(
        FederatedBotConfig {
            storage_root: temp_root.path().join("bird-bot"),
            bot_did: bird_did.to_string(),
            bot_handle: "bird.catbird.blue".to_string(),
            device_id: Uuid::new_v4().to_string(),
            home_ds_did: DS_B_DID.to_string(),
            home_ds_endpoint: ds_b.base_url.clone(),
            pds_endpoint: swan_pds.base_url.clone(),
            pds_supports_spaces: true,
            granted_oauth_scopes: scopes.clone(),
            accept_chat_requests: true,
            reply_to_all_messages: false,
            max_reply_characters: 500,
        },
        Arc::new(DeterministicBirdResponder),
        Some("bird-pds-oauth".into()),
    )?;
    assert!(bird_bot
        .enrollment_receipt()
        .direct_request_kp_bytes
        .windows(2)
        .any(|w| w == [0x00, 0x4d]));
    assert!(bird_bot.enrollment_receipt().labyrinth_backup_enabled);
    // Start the bot before sending the live mention. Its first successful sync
    // records a watermark so it never replies to a backlog of old messages.
    assert!(bird_bot.sync_and_reply().await?.is_empty());
    assert_eq!(
        bird_bot.conversation_watermark("__cold_start_complete__")?,
        Some(1)
    );

    // 7a. Live federated group creation on `ds-b` with cross-DS participants (`alice_sdk_did` on `ds-a`, `bob_sdk_did` on `ds-b`)
    let bird_group_id = Uuid::new_v4().to_string();
    let bird_group_row = bird_bot.create_group(
        &bird_group_id,
        vec![alice_sdk_did.clone(), bob_sdk_did.clone()],
        Some("Federated Bird Group".into()),
    )?;
    assert_eq!(
        bird_group_row.title.as_deref(),
        Some("Federated Bird Group")
    );
    let bird_group_uuid = Uuid::parse_str(&bird_group_row.conversation_id)?;
    let bird_group_db_count: i64 = ds_b
        .pool
        .query_one(
            "SELECT COUNT(*) FROM chat.conversations WHERE conversation_id = $1",
            &[&bird_group_uuid],
        )
        .await?
        .get(0);
    assert_eq!(
        bird_group_db_count, 1,
        "G3: FederatedBirdBot.create_group must sequence live conversation on ds-b"
    );

    // 7b. Live federated C33 DM from `alice_sdk` (`ds-a`) -> `bird_bot` (`ds-b`) -> `sync_and_reply()` -> `alice_sdk.sync()`
    let bird_dm_requested_id = Uuid::new_v4().to_string();
    let bird_dm_convo = {
        let sdk = alice_sdk.clone();
        let cid = bird_dm_requested_id.clone();
        let peer = bird_did.to_string();
        tokio::task::spawn_blocking(move || {
            sdk.create_group(
                &cid,
                DS_A_DID,
                vec![peer],
                None,
                Some("Hey @bird.catbird.blue status check over federated DS!".into()),
            )
        })
        .await??
    };
    let bird_replies = bird_bot.sync_and_reply().await?;
    assert_eq!(
        bird_replies.len(),
        1,
        "G3: FederatedBirdBot.sync_and_reply must accept federated C33 request and reply to @bird.catbird.blue mention"
    );
    assert!(bird_replies[0]
        .plaintext_json
        .contains("chirp! federated reply"));
    assert!(bird_bot.flush_labyrinth_queue()? >= 1);

    // Verify `alice_sdk` on `ds-a` receives and decrypts `bird_bot`'s federated reply!
    {
        let sdk = alice_sdk.clone();
        tokio::task::spawn_blocking(move || sdk.sync()).await??;
    }
    let alice_bird_msgs = {
        let sdk = alice_sdk.clone();
        let cid = bird_dm_convo.conversation_id.clone();
        tokio::task::spawn_blocking(move || sdk.list_messages(&cid, None, 20)).await??
    };
    assert!(
        alice_bird_msgs
            .iter()
            .any(|m| m.plaintext_json.contains("chirp! federated reply")),
        "G3: alice_sdk on ds-a must decrypt FederatedBirdBot's live MLS_256_XWING reply from ds-b"
    );

    // ========================================================================
    // Scenario 8: `G6` & `I14` Zero-Content Retention & PostgreSQL Schema Audit
    // Across BOTH `ds-a` and `ds-b`
    // ========================================================================
    // Seed a dedicated conversation on `ds-a`, sequence an application send, ACK from both leaf
    // devices via `acknowledgeEntries`, and prove `accepted_payload_bytes IS NULL` while `1..N`
    // seq contiguity and control entries remain intact!
    let prune_seed: Value = admin_http
        .post(format!(
            "{}/_test/clean-slate/seed-group-fixture",
            ds_a.base_url
        ))
        .json(&json!({
            "direct": false,
            "recipientServiceDid": DS_A_DID,
            "archiveCommitmentHex": hex::encode([0x5A_u8; 32]),
            "extraMembers": []
        }))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let prune_cid = Uuid::parse_str(prune_seed["conversationId"].as_str().unwrap())?;
    let p_sender_did = prune_seed["senderDid"].as_str().unwrap().to_string();
    let p_sender_dev = Uuid::parse_str(prune_seed["senderDeviceId"].as_str().unwrap())?;
    let p_sender_kid = prune_seed["senderKeyId"].as_str().unwrap().to_string();
    let p_sender_ed = Ed25519SigningKey::from_bytes(
        &STANDARD
            .decode(prune_seed["senderEd25519SeedB64"].as_str().unwrap())?
            .try_into()
            .unwrap(),
    );
    let p_rcpt_did = prune_seed["recipientDid"].as_str().unwrap().to_string();
    let p_rcpt_dev = Uuid::parse_str(prune_seed["recipientDeviceId"].as_str().unwrap())?;
    let p_rcpt_kid = prune_seed["recipientKeyId"].as_str().unwrap().to_string();
    let p_rcpt_ed = Ed25519SigningKey::from_bytes(
        &STANDARD
            .decode(prune_seed["recipientEd25519SeedB64"].as_str().unwrap())?
            .try_into()
            .unwrap(),
    );
    let p_sender_p256 = P256SigningKey::random(&mut rand::rngs::OsRng);
    let p_rcpt_p256 = P256SigningKey::random(&mut rand::rngs::OsRng);
    for (did, sk) in [(&p_sender_did, &p_sender_p256), (&p_rcpt_did, &p_rcpt_p256)] {
        admin_http
            .post(format!("{}/_test/clean-slate/register-did", ds_a.base_url))
            .json(&json!({
                "did": did,
                "p256Jwk": p256_public_jwk(sk.verifying_key()),
                "endpointUrl": swan_pds.base_url,
            }))
            .send()
            .await?
            .error_for_status()?;
    }

    // Sequence an applicationEntry on `ds-a`. Both seeded members are homed on `ds-a`, so the
    // sender reaches the sequencer through its own home's `sendMessage`; no peer may relay a
    // mutation for an actor it does not home.
    let prune_send_jwt = mint_es256_service_jwt(
        &p_sender_p256,
        &p_sender_did,
        &format!("{DS_A_DID}#atproto_mls"),
        "blue.catbird.chat.sendMessage",
    );
    let prune_send_out: Value = admin_http
        .post(format!(
            "{}/xrpc/blue.catbird.chat.sendMessage",
            ds_a.base_url
        ))
        .header("authorization", format!("Bearer {prune_send_jwt}"))
        .header(CONTENT_TYPE, "application/json")
        .body(serde_json::to_vec(
            &json!({"signedRequest": prune_seed["signedRequest"]}),
        )?)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let app_seq = prune_send_out["entry"]["seq"].as_i64().unwrap();

    // The seeded signing devices acknowledge through the shipping endpoint.
    // Earlier live clients verified and decrypted their MLS conversations.
    {
        let ack_endpoint = format!(
            "{}/xrpc/blue.catbird.chat.acknowledgeEntries",
            ds_a.base_url
        );
        let signed_ack = async |did: &str,
                                device: Uuid,
                                key_id: &str,
                                signer: &Ed25519SigningKey,
                                pds_key: &P256SigningKey|
               -> Result<i64> {
            let ack_signed_at = Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true);
            #[derive(serde::Serialize)]
            struct AckPayload<'a> {
                #[serde(rename = "keyId")]
                key_id: &'a str,
                #[serde(rename = "upToSeq")]
                up_to_seq: i64,
                #[serde(rename = "signedAt")]
                signed_at: &'a str,
                generation: i64,
                #[serde(rename = "actorDeviceId")]
                actor_device_id: String,
                #[serde(rename = "authGeneration")]
                auth_generation: i64,
                #[serde(rename = "conversationId")]
                conversation_id: String,
            }
            let cbor = serde_ipld_dagcbor::to_vec(&AckPayload {
                key_id: key_id,
                up_to_seq: app_seq,
                signed_at: &ack_signed_at,
                generation: 0,
                actor_device_id: device.to_string(),
                auth_generation: 1,
                conversation_id: prune_cid.to_string(),
            })?;
            let ack_sig: Ed25519Signature =
                signer.sign(&[b"CATBIRD-CHAT-ACK-ENTRIES\0".as_slice(), &cbor].concat());
            let ack_jwt = mint_es256_service_jwt(
                pds_key,
                did,
                &format!("{DS_A_DID}#atproto_mls"),
                "blue.catbird.chat.acknowledgeEntries",
            );
            let response: Value = admin_http
                .post(&ack_endpoint)
                .header("authorization", format!("Bearer {ack_jwt}"))
                .header(CONTENT_TYPE, "application/json")
                .json(&json!({
                    "conversationId": prune_cid,
                    "generation": 0,
                    "actorDeviceId": device,
                    "keyId": key_id,
                    "authGeneration": 1,
                    "upToSeq": app_seq,
                    "signedAt": ack_signed_at,
                    "signature": STANDARD.encode(ack_sig.to_bytes()),
                }))
                .send()
                .await?
                .error_for_status()?
                .json()
                .await?;

            anyhow::ensure!(
                response["acknowledgedSeq"].as_i64() == Some(app_seq),
                "server did not acknowledge the entry: {response}"
            );
            response["prunedCount"]
                .as_i64()
                .context("acknowledgeEntries prunedCount")
        };
        assert_eq!(
            signed_ack(
                &p_sender_did,
                p_sender_dev,
                &p_sender_kid,
                &p_sender_ed,
                &p_sender_p256
            )
            .await?,
            0
        );
        // The recipient registers its signed push gateway through the native SDK.
        let rcpt_ks = Arc::new(MemoryKeyStore::new());
        let rcpt_hash = account_did_hash_hex(&p_rcpt_did)?;
        rcpt_ks.store_signature_keypair(
            format!("mls-signer:{rcpt_hash}"),
            p_rcpt_ed.to_bytes().to_vec(),
        )?;
        let rcpt_transport = Arc::new(swan_pds.client_transport(&ds_a.base_url));
        let rcpt_sdk = CatbirdMlsClient::open(
            CatbirdMlsClientConfig {
                storage_root: temp_root
                    .path()
                    .join("rcpt-prune-sdk")
                    .to_string_lossy()
                    .into(),
                account_did: p_rcpt_did.clone(),
                device_id: p_rcpt_dev.to_string(),
                home_ds_did: DS_A_DID.to_string(),
                home_ds_endpoint: ds_a.base_url.clone(),
                pds_endpoint: swan_pds.base_url.clone(),
            },
            rcpt_ks,
            rcpt_transport.clone(),
            None,
        )?;

        let sdk_pg_reg = rcpt_sdk.build_signed_push_gateway_registration(
            &push_gw.canonical_https_url,
            "blue.catbird.android",
            "push_key_sdk_signed_opaque_0123456789abcdef",
            true,
        )?;
        assert_eq!(sdk_pg_reg.key_id, p_rcpt_kid);
        let rcpt_pg_jwt = mint_es256_service_jwt(
            &p_rcpt_p256,
            &p_rcpt_did,
            &format!("{DS_A_DID}#atproto_mls"),
            "blue.catbird.chat.registerPushGateway",
        );
        admin_http
            .post(format!(
                "{}/xrpc/blue.catbird.chat.registerPushGateway",
                ds_a.base_url
            ))
            .header("authorization", format!("Bearer {rcpt_pg_jwt}"))
            .header(CONTENT_TYPE, "application/json")
            .body(sdk_pg_reg.request_json)
            .send()
            .await?
            .error_for_status()?;

        assert_eq!(
            signed_ack(
                &p_rcpt_did,
                p_rcpt_dev,
                &p_rcpt_kid,
                &p_rcpt_ed,
                &p_rcpt_p256
            )
            .await?,
            0
        );

        let fresh = ds_a
            .pool
            .query_one(
                "SELECT accepted_payload_bytes IS NOT NULL AND payload_pruned_at IS NULL
                    AND received_at > clock_timestamp() - INTERVAL '72 hours',
                    (SELECT COUNT(*) FROM chat.device_entry_acks
                     WHERE conversation_id = $1 AND acked_through_seq >= $2)
                 FROM chat.entries WHERE conversation_id = $1 AND seq = $2",
                &[&prune_cid, &app_seq],
            )
            .await?;
        assert!(
            fresh.get::<_, bool>(0),
            "acknowledged ciphertext must remain during the 72-hour floor"
        );

        assert_eq!(
            fresh.get::<_, i64>(1),
            2,
            "both fixture devices acknowledged the entry"
        );

        // As in the real-database pruning suite, adjust only the receipt time
        // of this disposable immutable entry, then send another ordinary ACK.
        let age = ds_a.pool.transaction().await?;
        age.batch_execute("SET LOCAL session_replication_role = replica")
            .await?;
        let aged = age
            .query_one(
                "UPDATE chat.entries SET received_at = clock_timestamp() - INTERVAL '73 hours'
                 WHERE conversation_id = $1 AND seq = $2
                 RETURNING (EXTRACT(EPOCH FROM (clock_timestamp() - received_at)) / 3600)::int",
                &[&prune_cid, &app_seq],
            )
            .await?;
        assert_eq!(aged.get::<_, i32>(0), 73);
        let mapped = age.execute(
            "UPDATE chat.message_sends send SET received_at = entry.received_at
             FROM chat.entries entry WHERE entry.conversation_id = $1 AND entry.seq = $2
             AND send.conversation_id = entry.conversation_id AND send.message_id = entry.message_id",
            &[&prune_cid, &app_seq]
        ).await?;
        assert_eq!(mapped, 1, "keep receipt and entry timestamps identical");
        age.commit().await?;
        assert_eq!(
            signed_ack(
                &p_sender_did,
                p_sender_dev,
                &p_sender_kid,
                &p_sender_ed,
                &p_sender_p256
            )
            .await?,
            1
        );
    }

    let prune_row = ds_a
        .pool
        .query_one(
            "SELECT accepted_payload_bytes IS NULL, payload_pruned_at IS NOT NULL \
               FROM chat.entries WHERE conversation_id = $1 AND seq = $2",
            &[&prune_cid, &app_seq],
        )
        .await?;
    let pruned_payload_null: bool = prune_row.get(0);
    let pruned_at_set: bool = prune_row.get(1);
    assert!(
        pruned_payload_null && pruned_at_set,
        "I14/G6: acknowledged applicationEntry ciphertext MUST be pruned after the 72-hour floor"
    );

    let seq_rows = ds_a
        .pool
        .query(
            "SELECT seq FROM chat.entries WHERE conversation_id = $1 ORDER BY seq ASC",
            &[&prune_cid],
        )
        .await?;
    let seqs: Vec<i64> = seq_rows.into_iter().map(|r| r.get(0)).collect();
    assert_eq!(
        seqs,
        (1..=app_seq).collect::<Vec<_>>(),
        "I14: entry sequence numbers 1..N must remain strictly contiguous after ciphertext pruning"
    );

    // Close & wipe `convo_id` on `ds-b`: prove active conversation refuses premature wipe,
    // `notifySpaceUpdate#spaceDeleted` fans out (`410 SpaceDeleted`), and operational rows are wiped!
    let wipe_res: Value = admin_http
        .post(format!(
            "{}/_test/clean-slate/close-and-wipe-conversation",
            ds_b.base_url
        ))
        .json(&json!({ "conversationId": convo_id }))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    assert_eq!(wipe_res["refusedWhileActive"], true);
    assert!(wipe_res["notifiedSpaceDeleted"].as_u64().unwrap() >= 2);
    assert_eq!(wipe_res["wiped"], true);

    let remaining_entries_b: i64 = ds_b
        .pool
        .query_one(
            "SELECT COUNT(*) FROM chat.entries WHERE conversation_id = $1",
            &[&convo_id],
        )
        .await?
        .get(0);
    assert_eq!(
        remaining_entries_b, 0,
        "G6/I14: chat.wipe_closed_conversation_operational_rows must wipe all operational entries"
    );

    // Verify `swan_pds` and `ref_pds` received the authority's `notifySpaceUpdate#spaceDeleted` and now return
    // `410 SpaceDeleted` to their writers (Bob on `swan_pds`, Eve on `ref_pds`)
    for (pds, token) in [(&swan_pds, "bob-pds-oauth"), (&ref_pds, "eve-pds-oauth")] {
        assert!(
            pds.space_deleted(&space_uri),
            "{} kept the deleted Space",
            pds.pds_did
        );
        let del_resp = admin_http
            .get(format!(
                "{}/xrpc/com.atproto.space.getSpace?space={}",
                pds.base_url,
                urlencoding::encode(&space_uri)
            ))
            .bearer_auth(token)
            .send()
            .await?;
        assert_eq!(del_resp.status(), reqwest::StatusCode::GONE);
    }

    // Account deletion on `ds-a`: wipes `labyrinth.epoch_heads` while preserving `labyrinth.epoch_head_floors` (`Gate 6`)
    let del_acct: Value = admin_http
        .post(format!(
            "{}/_test/clean-slate/delete-account",
            ds_a.base_url
        ))
        .json(&json!({ "did": alice_remote_did }))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    assert_eq!(del_acct["deleted"], true);
    let alice_heads_after: i64 = ds_a
        .pool
        .query_one(
            "SELECT COUNT(*) FROM labyrinth.epoch_heads WHERE did = $1",
            &[&alice_remote_did],
        )
        .await?
        .get(0);
    let alice_floors_after: i64 = ds_a
        .pool
        .query_one(
            "SELECT COUNT(*) FROM labyrinth.epoch_head_floors WHERE did = $1",
            &[&alice_remote_did],
        )
        .await?
        .get(0);
    assert_eq!(
        alice_heads_after, 0,
        "deleteAccountData must purge epoch_heads"
    );
    assert_eq!(
        alice_floors_after, 1,
        "Gate 6: deleteAccountData MUST preserve epoch_head_floors rollback floor"
    );

    // Final `G6` / `I14` PostgreSQL catalog scan across BOTH `ds-a` and `ds-b`:
    for ds in [&ds_a, &ds_b] {
        let blob_tables: i64 = ds
            .pool
            .query_one(
                "SELECT COUNT(*) FROM information_schema.tables \
                  WHERE table_schema = 'chat' AND table_name LIKE 'blob%'",
                &[],
            )
            .await?
            .get(0);
        assert_eq!(
            blob_tables, 0,
            "G6: zero chat.blob* tables on {}",
            ds.service_did
        );

        let push_token_cols: i64 = ds
            .pool
            .query_one(
                "SELECT COUNT(*) FROM information_schema.columns \
                  WHERE table_schema IN ('public', 'chat', 'labyrinth') \
                    AND column_name LIKE '%push_token%'",
                &[],
            )
            .await?
            .get(0);
        assert_eq!(
            push_token_cols, 0,
            "I12: zero raw push_token columns on {}",
            ds.service_did
        );

        let lab_rows = ds
            .pool
            .query(
                "SELECT table_name FROM information_schema.tables \
                  WHERE table_schema = 'labyrinth' ORDER BY table_name ASC",
                &[],
            )
            .await?;
        let lab_tables: Vec<String> = lab_rows.into_iter().map(|r| r.get(0)).collect();
        assert_eq!(
            lab_tables,
            [
                "account_erasure_operations",
                "epoch_head_floors",
                "epoch_heads",
                "operations",
                "recovery_share_events",
                "recovery_shares",
            ],
            "G6: labyrinth schema on {} must contain only epoch, erasure and encrypted recovery-share tables",
            ds.service_did
        );

        let pub_rows = ds
            .pool
            .query(
                "SELECT t.tablename FROM pg_tables t \
                   JOIN pg_namespace n ON n.nspname = t.schemaname \
                   JOIN pg_class c ON c.relnamespace = n.oid AND c.relname = t.tablename \
                  WHERE t.schemaname = 'public' AND NOT c.relispartition \
                  ORDER BY t.tablename ASC",
                &[],
            )
            .await?;
        let pub_tables: Vec<String> = pub_rows.into_iter().map(|r| r.get(0)).collect();
        assert_eq!(
            pub_tables,
            vec![
                "_sqlx_migrations",
                "auth_jti_nonce",
                "did_ds_mappings",
                "ds_endpoints",
                "federation_outbox",
                "federation_peer_policy_audit_log",
                "federation_peers",
                "federation_sync_state",
                "outbound_queue",
            ],
            "G6: public schema on {} must hold strictly S2S federation/nonce tables + _sqlx_migrations",
            ds.service_did
        );
    }

    let _ = &ds_a.db_url;
    Ok(())
}
