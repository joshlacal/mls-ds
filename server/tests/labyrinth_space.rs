//! Signed HTTP route tests over disposable PostgreSQL. Space ciphertext is a
//! deterministic admission fixture here, not a claim of live PDS publication.
mod common;
#[path = "common/labyrinth_harness.rs"]
mod harness;
use axum::{body::Body, http::Request};
use catbird_server::labyrinth::{repo::space, wire::records::Batch};
use ed25519_dalek::Signer;
use harness::*;
use serde_json::{json, Value};
use uuid::Uuid;

const MEK: [u8; 12] = [6; 12];

/// Upgrade a populated predecessor schema, without manufacturing an empty
/// successful migration. Seeding bypasses chat's event-ledger invariants only;
/// the migration itself runs with all ordinary immutability guards enabled.
#[tokio::test]
async fn migration_preserves_existing_ciphertext_and_backfills_mek_generation() {
    use common::fresh_db::{acquire_migration_lock, DisposableDatabase};
    use std::borrow::Cow;
    let _guard = acquire_migration_lock().await;
    let db = DisposableDatabase::mint("labyrinth_srv_").await;
    let pool = db.connect(1).await;
    let mut conn = pool.acquire().await.unwrap();
    sqlx::query("SET chat.operation_claim_activation_approved = 'handlers-and-legacy-apis-sealed'")
        .execute(&mut *conn)
        .await
        .unwrap();
    let full = sqlx::migrate!("./migrations");
    let predecessor = sqlx::migrate::Migrator {
        migrations: Cow::Owned(
            full.iter()
                .filter(|m| m.version < 20261023000001)
                .cloned()
                .collect(),
        ),
        ..sqlx::migrate::Migrator::DEFAULT
    };
    predecessor.run(&mut *conn).await.unwrap();
    let thread = Uuid::new_v4();
    let author = "did:plc:abcdefghijklmnopqrstuvwx";
    let record = batch_record(thread, [7; 32], &[(MEK, 500)]).to_string();
    sqlx::query("SET session_replication_role=replica")
        .execute(&mut *conn)
        .await
        .unwrap();
    sqlx::query("INSERT INTO chat.conversations(conversation_id,kind,lifecycle,current_generation,current_state_version,next_entry_seq,created_at) VALUES($1,'group','active',1,1,3,now())")
        .bind(thread).execute(&mut *conn).await.unwrap();
    sqlx::query("INSERT INTO chat.generations(conversation_id,generation,group_id,lifecycle,genesis_group_info_bytes,genesis_group_info_sha256,current_state_version,activated_seq,activated_at) VALUES($1,1,$2,'active',$3,digest($3,'sha256'),1,1,now())")
        .bind(thread).bind(vec![1_u8;32]).bind(vec![2_u8;16]).execute(&mut *conn).await.unwrap();
    sqlx::query("INSERT INTO labyrinth.meks(conversation_id,author_did,mek_id,sender_kind,writer_device_id,record,record_bytes,seq,chat_seq,received_at) VALUES($1,$2,$3,'transport',$4,'{}',2,1,2,now())")
        .bind(thread).bind(author).bind(MEK.as_slice()).bind(Uuid::new_v4()).execute(&mut *conn).await.unwrap();
    sqlx::query("INSERT INTO labyrinth.batches(conversation_id,author_did,rkey,mek_id,writer_device_id,min_ts,max_ts,record,record_bytes,seq,chat_seq,received_at,mek_author_did) VALUES($1,$2,'2222222222222',$3,$4,500,500,$5::jsonb,$6,2,2,now(),$2)")
        .bind(thread).bind(author).bind(MEK.as_slice()).bind(Uuid::new_v4()).bind(&record).bind(record.len() as i32).execute(&mut *conn).await.unwrap();
    sqlx::query("SET session_replication_role=origin")
        .execute(&mut *conn)
        .await
        .unwrap();
    full.run(&mut *conn).await.unwrap();
    let migrated: (String, Option<String>, Option<i64>, Value, Option<Uuid>, Option<String>) = sqlx::query_as("SELECT s.placement,s.space,m.chat_generation,b.record,b.space_generation,b.source_cid FROM labyrinth.thread_storage s JOIN labyrinth.meks m USING(conversation_id) JOIN labyrinth.batches b USING(conversation_id) WHERE s.conversation_id=$1")
        .bind(thread).fetch_one(&mut *conn).await.unwrap();
    assert_eq!(migrated.0, "mlsds");
    assert_eq!(migrated.1, None);
    assert_eq!(migrated.2, Some(1));
    assert_eq!(migrated.3, serde_json::from_str::<Value>(&record).unwrap());
    assert_eq!(migrated.4, None);
    assert_eq!(migrated.5, None);
    assert!(
        sqlx::query("UPDATE labyrinth.meks SET chat_generation=2 WHERE conversation_id=$1")
            .bind(thread)
            .execute(&mut *conn)
            .await
            .is_err()
    );
    drop(conn);
    pool.close().await;
}
async fn space_thread(env: &Env, authority: &Device, devices: &[&Device]) -> Uuid {
    let leaves: Vec<_> = devices
        .iter()
        .map(|device| Leaf {
            device,
            joined_seq: 1,
            removed_seq: None,
        })
        .collect();
    seed_conversation_with_storage(env, Uuid::new_v4(), &leaves, 3, Some(&authority.did)).await
}
async fn placement(device: &Device, thread: Uuid) -> Value {
    device
        .query("getThreadStorage", &[("threadId", thread.to_string())])
        .await
        .ok()
        .clone()
}
fn input(thread: Uuid, device: &Device, p: &Value, timestamp: u64) -> Value {
    let record = batch_record(thread, device.chat_pub(), &[(MEK, timestamp)]);
    let batch: Batch = serde_json::from_value(record.clone()).unwrap();
    let cid = space::batch_cid(&batch).unwrap();
    json!({"record":record,"generation":p["generation"],"space":p["space"],"cid":cid,"rkey":format!("{:064x}",timestamp)})
}
async fn create_mek(device: &Device, thread: Uuid, readers: &[&Device]) {
    let readers: Vec<_> = readers.iter().map(|d| d.did.as_str()).collect();
    device
        .call(
            "createMek",
            &json!({"record":transport_mek(thread, MEK, device.chat_pub(), &readers)}),
        )
        .await
        .ok();
}
async fn list(device: &Device, thread: Uuid, p: &Value) -> Reply {
    device
        .query(
            "listSpaceBatches",
            &[
                ("threadId", thread.to_string()),
                ("generation", p["generation"].as_str().unwrap().into()),
            ],
        )
        .await
}
async fn policy(env: &Env, authority: &Device, p: &Value, user: &str) -> Reply {
    let nsid = "blue.catbird.labyrinth.getSpaceMembership";
    let q = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("space", p["space"].as_str().unwrap())
        .append_pair("user", user)
        .finish();
    send(
        &env.router,
        Request::get(format!("/xrpc/{nsid}?{q}"))
            .header("authorization", format!("Bearer {}", authority.token(nsid)))
            .body(Body::empty())
            .unwrap(),
    )
    .await
}

async fn delete_space(env: &Env, authority: &Device, p: &Value, generation: &str) -> Reply {
    let nsid = "blue.catbird.labyrinth.deleteSpaceGeneration";
    send(
        &env.router,
        Request::post(format!("/xrpc/{nsid}"))
            .header("authorization", format!("Bearer {}", authority.token(nsid)))
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&json!({"space":p["space"],"generation":generation})).unwrap(),
            ))
            .unwrap(),
    )
    .await
}

#[tokio::test]
async fn space_admission_is_cid_bound_idempotent_and_metadata_only() {
    let env = Env::new().await;
    let authority = env.account().await;
    let alice = env.account().await;
    let bob = env.account().await;
    let stranger = env.account().await;
    let thread = space_thread(&env, &authority, &[&alice, &bob, &stranger]).await;
    let p = placement(&alice, thread).await;
    assert_eq!(p["placement"], "space");
    assert!(p["space"]
        .as_str()
        .unwrap()
        .ends_with(p["generation"].as_str().unwrap()));
    assert_eq!(placement(&bob, thread).await, p);
    create_mek(&alice, thread, &[&alice, &bob]).await;
    let first = input(thread, &alice, &p, 500);
    let receipt = alice.call("appendSpaceBatch", &first).await.ok().clone();
    assert_eq!(receipt["rkey"], first["rkey"]);
    assert_eq!(receipt["order"]["seq"], 2);
    assert_eq!(receipt["order"]["chatSeq"], 2);
    assert_eq!(alice.call("appendSpaceBatch", &first).await.ok(), &receipt);
    let stored: (String, i64) = sqlx::query_as("SELECT record::text, (SELECT count(*) FROM labyrinth.batches WHERE conversation_id=$1) FROM labyrinth.batches WHERE conversation_id=$1").bind(thread).fetch_one(&env.pool).await.unwrap();
    let metadata: Value = serde_json::from_str(&stored.0).unwrap();
    assert_eq!(metadata["items"][0]["signedEncMessage"]["$bytes"], "");
    assert_eq!(stored.1, 1);
    let fetched = list(&bob, thread, &p).await;
    let view = &fetched.ok()["items"][0];
    assert_eq!(view["cid"], first["cid"]);
    assert_eq!(view["author"], alice.did);
    assert_eq!(view["order"], receipt["order"]);
    assert_eq!(view["redactions"], json!([]));
    assert_eq!(view["itemCount"], 1);
    assert!(view.get("record").is_none());
    assert_eq!(list(&stranger, thread, &p).await.ok()["items"], json!([]));
    stranger
        .call("appendSpaceBatch", &input(thread, &stranger, &p, 1))
        .await
        .fails(403, "NotRecipient");
    let mut wrong = first.clone();
    wrong["generation"] = json!(Uuid::new_v4());
    alice
        .call("appendSpaceBatch", &wrong)
        .await
        .fails(400, "StorageGenerationMismatch");
    wrong = first.clone();
    wrong["cid"] = json!("bad");
    alice
        .call("appendSpaceBatch", &wrong)
        .await
        .fails(400, "InvalidRequest");
    wrong = first.clone();
    wrong["record"]["items"][0]["signedEncMessage"] = b(&[0x62; 96]);
    wrong["cid"] =
        json!(space::batch_cid(&serde_json::from_value(wrong["record"].clone()).unwrap()).unwrap());
    alice
        .call("appendSpaceBatch", &wrong)
        .await
        .fails(409, "RecordAlreadyExists");
    bob.call("appendSpaceBatch", &first)
        .await
        .fails(400, "SenderKeyMismatch");
    alice
        .call("appendBatch", &json!({"record":first["record"]}))
        .await
        .fails(400, "StorageGenerationMismatch");
    alice
        .query("listBatches", &[("threadId", thread.to_string())])
        .await
        .fails(400, "StorageGenerationMismatch");
    alice
        .query(
            "getMessages",
            &[
                ("threadId", thread.to_string()),
                ("messageIds", "msg-0-500".into()),
            ],
        )
        .await
        .fails(400, "StorageGenerationMismatch");
    // SQL itself enforces the no-ciphertext invariant, including within the
    // retention scope that normally permits record rewrites.
    let mut tx = env.pool.begin().await.unwrap();
    sqlx::query("SELECT labyrinth.open_retention_scope()")
        .execute(&mut *tx)
        .await
        .unwrap();
    assert!(
        sqlx::query("UPDATE labyrinth.batches SET record=$2::jsonb WHERE conversation_id=$1")
            .bind(thread)
            .bind(first["record"].to_string())
            .execute(&mut *tx)
            .await
            .is_err()
    );
    tx.rollback().await.unwrap();
    // Omitting the Space discriminator cannot bypass the database invariant.
    assert!(sqlx::query("INSERT INTO labyrinth.batches(conversation_id,author_did,rkey,mek_id,writer_device_id,min_ts,max_ts,record,record_bytes,seq,chat_seq,received_at,mek_author_did) SELECT conversation_id,author_did,'2222222222222',mek_id,writer_device_id,min_ts,max_ts,$2::jsonb,record_bytes,seq+1,chat_seq,received_at,mek_author_did FROM labyrinth.batches WHERE conversation_id=$1")
        .bind(thread).bind(first["record"].to_string()).execute(&env.pool).await.is_err());
}

#[tokio::test]
async fn sequencing_and_paging_use_server_order_and_current_mek_generation() {
    let env = Env::new().await;
    let authority = env.account().await;
    let alice = env.account().await;
    let thread = space_thread(&env, &authority, &[&alice]).await;
    let p = placement(&alice, thread).await;
    create_mek(&alice, thread, &[&alice]).await;
    alice
        .call("appendSpaceBatch", &input(thread, &alice, &p, 500))
        .await
        .ok();
    set_next_entry_seq(&env, thread, 9).await;
    alice
        .call("appendSpaceBatch", &input(thread, &alice, &p, 1))
        .await
        .ok();
    let result = list(&alice, thread, &p).await;
    let items = result.ok()["items"].as_array().unwrap();
    assert_eq!(items[0]["order"]["seq"], 2);
    assert_eq!(items[1]["order"]["seq"], 3);
    assert_eq!(items[1]["order"]["chatSeq"], 8);
    let page = alice
        .query(
            "listSpaceBatches",
            &[
                ("threadId", thread.to_string()),
                ("generation", p["generation"].as_str().unwrap().into()),
                ("reverse", "true".into()),
                ("limit", "1".into()),
            ],
        )
        .await;
    assert_eq!(page.ok()["items"][0]["order"]["seq"], 3);
    assert_eq!(page.json["cursor"], "3");
    // Simulate a committed successor generation through the existing fixture
    // replica bypass: an old MEK must not authorize a new-generation write.
    let mut tx = env.pool.begin().await.unwrap();
    sqlx::query("SET LOCAL session_replication_role=replica")
        .execute(&mut *tx)
        .await
        .unwrap();
    sqlx::query("UPDATE chat.conversations SET current_generation=2 WHERE conversation_id=$1")
        .bind(thread)
        .execute(&mut *tx)
        .await
        .unwrap();
    sqlx::query("UPDATE chat.member_devices SET generation=2 WHERE conversation_id=$1")
        .bind(thread)
        .execute(&mut *tx)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    alice
        .call("appendSpaceBatch", &input(thread, &alice, &p, 99))
        .await
        .fails(400, "UnknownMek");
}

#[tokio::test]
async fn tombstones_and_deleted_generation_cannot_fork_or_fall_back() {
    let env = Env::new().await;
    let authority = env.account().await;
    let alice = env.account().await;
    let thread = space_thread(&env, &authority, &[&alice]).await;
    let p = placement(&alice, thread).await;
    create_mek(&alice, thread, &[&alice]).await;
    let batch = input(thread, &alice, &p, 2);
    alice.call("appendSpaceBatch", &batch).await.ok();
    let message = "msg-0-2";
    let text = format!(
        "catbird.labyrinth.redaction:did={};message_id={message};thread_id={}",
        alice.did,
        hex::encode(thread.to_string().as_bytes())
    );
    let redaction = json!({"transportPubkey":b(&alice.chat_pub()),"sig":b(&alice.chat_key.sign(text.as_bytes()).to_bytes())});
    assert_eq!(
        alice
            .call(
                "redactMessage",
                &json!({"threadId":thread,"messageId":message,"redaction":redaction})
            )
            .await
            .ok()["redacted"],
        1
    );
    let listed = list(&alice, thread, &p).await;
    assert_eq!(listed.ok()["items"][0]["cid"], batch["cid"]);
    assert_eq!(
        listed.json["items"][0]["redactions"][0]["messageId"],
        message
    );
    assert_eq!(listed.json["items"][0]["redactions"][0]["timestamp"], 2);
    // Account deletion uses the same metadata retention and server-signed
    // tombstone path, including a second batch not already manually redacted.
    let second = input(thread, &alice, &p, 3);
    alice.call("appendSpaceBatch", &second).await.ok();
    alice.call("deleteAccountData", &json!({})).await.ok();
    let after_purge = list(&alice, thread, &p).await;
    let rows = after_purge.ok()["items"].as_array().unwrap();
    assert_eq!(rows.len(), 2);
    assert!(rows
        .iter()
        .all(|r| r["itemCount"] == 1 && r["redactions"].as_array().unwrap().len() == 1));
    assert_eq!(
        rows[1]["redactions"][0]["redaction"]["reason"],
        "accountDeleted"
    );
    let keys_before_deletion = alice
        .query(
            "findMeks",
            &[
                ("threadId", thread.to_string()),
                ("mekId", hex::encode(MEK)),
            ],
        )
        .await;
    assert_eq!(
        keys_before_deletion.ok()["items"].as_array().unwrap().len(),
        1
    );
    let generation = p["generation"].as_str().unwrap();
    delete_space(&env, &alice, &p, generation)
        .await
        .fails(403, "NotAuthorized");
    delete_space(&env, &authority, &p, &Uuid::new_v4().to_string())
        .await
        .fails(400, "StorageGenerationMismatch");
    let (deleted, retry) = tokio::join!(
        delete_space(&env, &authority, &p, generation),
        delete_space(&env, &authority, &p, generation)
    );
    assert_eq!(
        deleted.ok(),
        &json!({"space":p["space"],"generation":generation,"deleted":true})
    );
    assert_eq!(retry.ok(), deleted.ok());
    policy(&env, &authority, &p, &alice.did)
        .await
        .fails(410, "SpaceDeleted");
    let mut conn = env.pool.acquire().await.unwrap();
    let liveness = catbird_server::labyrinth::repo::liveness::sender_state(
        &mut conn, &alice.did, thread, message, &alice.did,
    )
    .await
    .unwrap_err();
    assert_eq!(liveness.name(), "SpaceDeleted");
    drop(conn);
    alice
        .query("getThreadStorage", &[("threadId", thread.to_string())])
        .await
        .fails(410, "SpaceDeleted");
    list(&alice, thread, &p).await.fails(410, "SpaceDeleted");
    alice
        .query(
            "findMeks",
            &[
                ("threadId", thread.to_string()),
                ("mekId", hex::encode(MEK)),
            ],
        )
        .await
        .fails(410, "SpaceDeleted");
    alice
        .call("appendSpaceBatch", &batch)
        .await
        .fails(410, "SpaceDeleted");
    assert!(sqlx::query(
        "UPDATE labyrinth.thread_storage SET deleted_at=NULL WHERE conversation_id=$1"
    )
    .bind(thread)
    .execute(&env.pool)
    .await
    .is_err());
    assert!(sqlx::query(
        "UPDATE labyrinth.thread_storage SET generation=$2 WHERE conversation_id=$1"
    )
    .bind(thread)
    .bind(Uuid::new_v4())
    .execute(&env.pool)
    .await
    .is_err());
}

#[tokio::test]
async fn authority_policy_checks_exact_committed_membership_without_user_device_proof() {
    let env = Env::new().await;
    let authority = env.account().await;
    let alice = env.account().await;
    let outsider = env.account().await;
    let thread = space_thread(&env, &authority, &[&alice]).await;
    let p = placement(&alice, thread).await;
    let granted = policy(&env, &authority, &p, &alice.did).await;
    assert_eq!(granted.ok()["user"], alice.did);
    assert_eq!(granted.json["space"], p["space"]);
    assert_eq!(granted.json["generation"], p["generation"]);
    assert_eq!(granted.json["chatGeneration"], 1);
    assert_eq!(granted.json["chatSeq"], 2);
    policy(&env, &outsider, &p, &alice.did)
        .await
        .fails(403, "NotAuthorized");
    policy(&env, &authority, &p, &outsider.did)
        .await
        .fails(403, "NotParticipant");
    remove_member(&env, thread, &alice, 3).await;
    policy(&env, &authority, &p, &alice.did)
        .await
        .fails(403, "NotParticipant");
}

/// MLSDS-01: the authority's policy calls were metered by its issuer DID
/// alone, so every user of the deployment shared one 200/min bucket (and a
/// burst of 10), and throttling came back as `401 NotAuthorized`. The quota
/// is per (authority, user), and throttling is `429` with `Retry-After`.
///
/// The calls go through the server's per-IP pre-auth limiter, as in the real
/// router, from one address: the authority sends every user's calls from
/// its one egress address, so a per-IP bucket the size of one user's quota
/// would still let that user throttle every other.
#[tokio::test]
async fn authority_policy_quota_is_per_user_and_throttles_with_429() {
    use catbird_server::middleware::rate_limit::{rate_limit_middleware, SpaceAuthorityQuota};
    let env = Env::new().await;
    let authority = env.account().await;
    let alice = env.account().await;
    let bob = env.account().await;
    let thread = space_thread(&env, &authority, &[&alice, &bob]).await;
    let p = placement(&alice, thread).await;
    let router = env
        .router
        .clone()
        .layer(axum::middleware::from_fn(rate_limit_middleware));
    let per_user = SpaceAuthorityQuota::from_env().per_user;
    for call in 0..per_user {
        let response = policy_from_egress(&router, &authority, &p, &alice.did).await;
        assert_eq!(response.status(), 200, "call {call}");
    }
    // The bucket refilled at per_user/60 per second during those calls, far
    // slower than they ran, so it runs dry within a bounded number more.
    let mut throttled = None;
    for _ in 0..per_user {
        let response = policy_from_egress(&router, &authority, &p, &alice.did).await;
        if response.status() != 200 {
            throttled = Some(response);
            break;
        }
    }
    let throttled = throttled.expect("the per-user quota never ran dry");
    assert_eq!(throttled.status(), 429);
    let retry_after: u64 = throttled.headers()["retry-after"]
        .to_str()
        .unwrap()
        .parse()
        .unwrap();
    assert!(retry_after >= 1);
    let bytes = axum::body::to_bytes(throttled.into_body(), usize::MAX)
        .await
        .unwrap();
    let body: Value = serde_json::from_slice(&bytes).unwrap();
    // The per-user quota, not the per-IP pre-auth limiter (`RateLimitExceeded`).
    assert_eq!(body["error"], "RateLimited", "{body}");
    // Another user of the same authority, from the same address, is not
    // throttled.
    let response = policy_from_egress(&router, &authority, &p, &bob.did).await;
    assert_eq!(response.status(), 200);
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let body: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(body["user"], bob.did);
}

/// `getSpaceMembership` through `router` from the authority's one egress
/// address.
async fn policy_from_egress(
    router: &axum::Router,
    authority: &Device,
    p: &Value,
    user: &str,
) -> axum::response::Response {
    use tower_util::ServiceExt;
    let egress = std::net::SocketAddr::from(([198, 51, 100, 7], 443));
    let nsid = "blue.catbird.labyrinth.getSpaceMembership";
    let q = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("space", p["space"].as_str().unwrap())
        .append_pair("user", user)
        .finish();
    router
        .clone()
        .oneshot(
            Request::get(format!("/xrpc/{nsid}?{q}"))
                .header("authorization", format!("Bearer {}", authority.token(nsid)))
                .extension(axum::extract::ConnectInfo(egress))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
}

// Observe real PostgreSQL lock waits instead of relying on scheduler timing.
async fn wait_for_blocker(pool: &sqlx::PgPool, blocked: i32, blocker: i32) {
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            let waiting: bool = sqlx::query_scalar("SELECT $1::int = ANY(pg_blocking_pids($2))")
                .bind(blocker)
                .bind(blocked)
                .fetch_one(pool)
                .await
                .unwrap();
            if waiting {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("policy must reach the expected PostgreSQL row lock");
}

async fn policy_transaction(
    env: &Env,
    authority: &Device,
    p: &Value,
    user: &str,
) -> (i32, tokio::task::JoinHandle<Result<Value, String>>) {
    let pool = env.pool.clone();
    let authority = authority.did.clone();
    let space_ref = p["space"].as_str().unwrap().to_owned();
    let user = user.to_owned();
    let (sender, receiver) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(async move {
        let mut tx = pool.begin().await.unwrap();
        let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(&mut *tx)
            .await
            .unwrap();
        sender.send(pid).unwrap();
        let result = space::membership(&mut tx, &authority, &space_ref, &user)
            .await
            .map(|v| serde_json::to_value(v).unwrap())
            .map_err(|e| e.name().to_owned());
        tx.rollback().await.unwrap();
        result
    });
    (receiver.await.unwrap(), task)
}

#[tokio::test]
async fn membership_locks_identity_before_head_and_revocation_fails_closed() {
    let env = Env::new().await;
    let authority = env.account().await;
    let alice = env.account().await;
    let thread = space_thread(&env, &authority, &[&alice]).await;
    let p = placement(&alice, thread).await;
    let mut revocation = env.pool.begin().await.unwrap();
    let revocation_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *revocation)
        .await
        .unwrap();
    // The real revokeDevice path takes these two identity locks before the
    // conversation head. This transaction reproduces that admission boundary;
    // fixture updates below do not claim a signed native MLS revocation.
    sqlx::query("SELECT device.device_id FROM chat.devices device JOIN chat.device_keys k ON k.user_did=device.user_did AND k.device_id=device.device_id WHERE device.user_did=$1 AND device.device_id=$2 FOR UPDATE OF device,k")
        .bind(&alice.did).bind(alice.device_id).execute(&mut *revocation).await.unwrap();
    let (policy_pid, checking) = policy_transaction(&env, &authority, &p, &alice.did).await;
    wait_for_blocker(&env.pool, policy_pid, revocation_pid).await;
    // This would fail immediately if policy held the head while waiting for
    // our identity locks: the original order formed a real two-way deadlock.
    let head = sqlx::query(
        "SELECT conversation_id FROM chat.conversations WHERE conversation_id=$1 FOR UPDATE NOWAIT",
    )
    .bind(thread)
    .execute(&mut *revocation)
    .await;
    if let Err(error) = head {
        revocation.rollback().await.unwrap();
        let _ = checking.await;
        panic!("policy held the conversation before its identity locks: {error}");
    }
    sqlx::query("SET LOCAL session_replication_role=replica")
        .execute(&mut *revocation)
        .await
        .unwrap();
    let revocation_id = Uuid::new_v4();
    sqlx::query("UPDATE chat.devices SET status='revoked', revoked_at=now(), revocation_id=$3 WHERE user_did=$1 AND device_id=$2")
        .bind(&alice.did).bind(alice.device_id).bind(revocation_id).execute(&mut *revocation).await.unwrap();
    sqlx::query("UPDATE chat.device_keys SET revoked_at=now(), revocation_id=$3 WHERE user_did=$1 AND device_id=$2")
        .bind(&alice.did).bind(alice.device_id).bind(revocation_id).execute(&mut *revocation).await.unwrap();
    revocation.commit().await.unwrap();
    let result = tokio::time::timeout(std::time::Duration::from_secs(5), checking)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(result.unwrap_err(), "NotParticipant");
}

#[tokio::test]
async fn membership_revalidates_same_leaf_after_waiting_for_head() {
    let env = Env::new().await;
    let authority = env.account().await;
    let alice = env.account().await;
    let thread = space_thread(&env, &authority, &[&alice]).await;
    let p = placement(&alice, thread).await;
    let mut removal = env.pool.begin().await.unwrap();
    let removal_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *removal)
        .await
        .unwrap();
    sqlx::query(
        "SELECT conversation_id FROM chat.conversations WHERE conversation_id=$1 FOR UPDATE",
    )
    .bind(thread)
    .execute(&mut *removal)
    .await
    .unwrap();
    let (policy_pid, checking) = policy_transaction(&env, &authority, &p, &alice.did).await;
    wait_for_blocker(&env.pool, policy_pid, removal_pid).await;
    sqlx::query("SET LOCAL session_replication_role=replica")
        .execute(&mut *removal)
        .await
        .unwrap();
    let transition = Uuid::new_v4();
    sqlx::query("UPDATE chat.member_devices SET active=false, removed_state_version=2, removed_transition_id=$3, removed_seq=3, removed_at=now() WHERE conversation_id=$1 AND user_did=$2 AND active")
        .bind(thread).bind(&alice.did).bind(transition).execute(&mut *removal).await.unwrap();
    sqlx::query("UPDATE chat.participants SET current_membership=false, removing_transition_id=$3, removing_seq=3, removed_at=now() WHERE conversation_id=$1 AND user_did=$2 AND current_membership")
        .bind(thread).bind(&alice.did).bind(transition).execute(&mut *removal).await.unwrap();
    removal.commit().await.unwrap();
    let result = tokio::time::timeout(std::time::Duration::from_secs(5), checking)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(result.unwrap_err(), "NotParticipant");
}

#[tokio::test]
async fn legacy_placement_is_explicit_and_cannot_be_rebound() {
    let env = Env::new().await;
    let alice = env.account().await;
    let thread = seed_conversation(
        &env,
        &[Leaf {
            device: &alice,
            joined_seq: 1,
            removed_seq: None,
        }],
        3,
    )
    .await;
    let p = placement(&alice, thread).await;
    assert_eq!(p["placement"], "mlsds");
    assert!(p.get("space").is_none());
    assert_eq!(placement(&alice, thread).await, p);
    assert!(sqlx::query("UPDATE labyrinth.thread_storage SET placement='space', space='at://did:web:authority.example.com/space/blue.catbird.labyrinth.conversation/' || generation::text WHERE conversation_id=$1").bind(thread).execute(&env.pool).await.is_err());
}

/// Actual DS policy route over TCP for the separate Swan issuer integration.
/// Every account, key and database here is disposable and created by Env.
/// Write a `stop` file in LABYRINTH_SPACE_POLICY_FIXTURE_DIR to shut it down.
#[tokio::test]
#[ignore = "opt-in loopback Swan issuer integration; ephemeral test keys only"]
async fn live_policy_fixture() {
    use std::{io::Write, os::unix::fs::OpenOptionsExt, path::PathBuf};
    let dir = PathBuf::from(
        std::env::var("LABYRINTH_SPACE_POLICY_FIXTURE_DIR")
            .expect("explicit fixture output directory"),
    );
    std::fs::create_dir_all(&dir).unwrap();
    let env = Env::new().await;
    let authority = env.account().await;
    let alice = env.account().await;
    let outsider = env.account().await;
    let thread = space_thread(&env, &authority, &[&alice]).await;
    let p = placement(&alice, thread).await;
    let deletable = space_thread(&env, &authority, &[&alice]).await;
    let deletable_p = placement(&alice, deletable).await;
    let deleted = space_thread(&env, &authority, &[&alice]).await;
    let deleted_p = placement(&alice, deleted).await;
    let removed = space_thread(&env, &authority, &[&alice]).await;
    let removed_p = placement(&alice, removed).await;
    remove_member(&env, removed, &alice, 3).await;
    let mut tx = env.pool.begin().await.unwrap();
    space::mark_deleted(
        &mut tx,
        deleted,
        Uuid::parse_str(deleted_p["generation"].as_str().unwrap()).unwrap(),
        env.now().await,
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    let key_path = dir.join("authority-private-key.raw");
    let mut key = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&key_path)
        .unwrap();
    key.write_all(&authority.service_auth_secret_bytes())
        .unwrap();
    key.sync_all().unwrap();
    let outsider_key_path = dir.join("outsider-private-key.raw");
    let mut outsider_key = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&outsider_key_path)
        .unwrap();
    outsider_key
        .write_all(&outsider.service_auth_secret_bytes())
        .unwrap();
    outsider_key.sync_all().unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let router = env.router.clone();
    let server = tokio::spawn(async move {
        axum::serve(listener, router)
            .with_graceful_shutdown(async {
                let _ = shutdown_rx.await;
            })
            .await
            .unwrap();
    });
    let ready = json!({"origin":origin,"audience":catbird_server::auth::expected_mls_service_ref(),"authorityDID":authority.did,"userDID":alice.did,"outsiderDID":outsider.did,"space":p["space"],"generation":p["generation"],"deletedSpace":deleted_p["space"],"removedSpace":removed_p["space"],"deletableSpace":deletable_p["space"],"authorityPrivateKeyPath":key_path,"outsiderPrivateKeyPath":outsider_key_path,"policyNSID":"blue.catbird.labyrinth.getSpaceMembership","deleteGenerationNSID":"blue.catbird.labyrinth.deleteSpaceGeneration"});
    std::fs::write(
        dir.join("ready.json"),
        serde_json::to_vec_pretty(&ready).unwrap(),
    )
    .unwrap();
    println!(
        "DS policy fixture ready: {}",
        dir.join("ready.json").display()
    );
    for tick in 0..3600 {
        if dir.join("stop").exists() {
            break;
        }
        if tick % 60 == 0 {
            // Fixture DIDs do not exist in the public PLC directory. Keep
            // their same ephemeral public keys published to the test cache
            // throughout this long-lived fixture; production auth's ordinary
            // five-minute cache expiry must not outlive our fixture setup.
            authority.cache_did_document().await;
            outsider.cache_did_document().await;
            policy(&env, &authority, &p, &alice.did).await.ok();
        }
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
    let _ = shutdown_tx.send(());
    server.await.unwrap();
}

#[test]
fn batch_cid_matches_independent_cbor_vector() {
    use catbird_server::labyrinth::wire::{bytes::Bytes, records::SealedMessage};
    use sha2::{Digest, Sha256};
    let batch = Batch {
        type_: "blue.catbird.labyrinth.batch".into(),
        thread_id: "00000000-0000-4000-8000-000000000001".into(),
        items: vec![SealedMessage {
            message_id: "msg".into(),
            timestamp: 1,
            mek_id: Bytes(vec![6; 12]),
            sender_transport_pubkey: Bytes(vec![7; 32]),
            signed_enc_message: Bytes(vec![0x61; 96]),
            redaction: None,
        }],
        created_at: "2026-10-04T12:00:00.000Z".into(),
    };
    let encoded = serde_ipld_dagcbor::to_vec(&batch).unwrap();
    assert_eq!(encoded.len(), 343);
    assert_eq!(
        hex::encode(Sha256::digest(&encoded)),
        "5150bfa291949bc062c9fcc1f49479d383cc1070aa1de93eca2f970ee6c8d8a7"
    );
    assert_eq!(
        space::batch_cid(&batch).unwrap(),
        "bafyreicrkc72femutpagfsp4yh2ji6otqpgba4fkdxut5srps4honsgyu4"
    );
    assert_eq!(
        serde_ipld_dagcbor::from_slice::<Batch>(&encoded).unwrap(),
        batch
    );
}
