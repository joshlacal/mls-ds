//! C27 quota and cancellation abuse, repository layer.
//!
//! Every attempt, reservation, cancellation, settlement and refusal below is
//! produced by the production repository functions compiled from
//! `direct_request_lock.rs` / `direct_request_store.rs`. The only direct SQL
//! writes are enrollment fixtures (principal/device/key/package/capability/
//! grant), the same fixture surface used by the reviewed preparation cases.
//! No budget, attempt, charge or conversation row is hand-written; assertions
//! read the rows the production functions produced.
//!
//! Live-router clauses (second introduction via another RPC / group note,
//! capacity refusal preserving a published Welcome) are in
//! `e2e-tests/tests/encrypted_request_c27.rs`.
#![allow(dead_code)]
pub use catbird_server::{auth, chat_protocol};
#[path = "common/chat_protocol.rs"]
pub mod chat_protocol_baseline;
mod common {
    pub use super::chat_protocol_baseline as chat_protocol;
    pub mod direct_request_database;
    // main's chat_protocol harness serializes migrations via fresh_db.
    pub mod fresh_db;
}
mod repository {
    pub mod prelude {
        include!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/chat_protocol/repository/direct_request_lock.rs"
        ));
    }
    mod direct_request_preparation {
        include!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/chat_protocol/repository/direct_request_store.rs"
        ));

        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
        use sqlx::PgPool;
        use std::sync::Arc;
        use tokio::sync::Barrier;

        type R<T> = Result<T, DirectRequestStoreError>;

        fn did() -> String {
            const A: &[u8] = b"abcdefghijklmnopqrstuvwxyz234567";
            let b = Uuid::new_v4().into_bytes();
            let s: String = (0..24).map(|i| A[(b[i % 16] as usize + i * 7) % 32] as char).collect();
            format!("did:plc:{s}")
        }

        /// Enrollment fixture: one active device with one package in `scope`
        /// (and a request grant when `grant`).
        async fn device(tx: &mut Transaction<'_, Postgres>, owner: &str, scope: &str, grant: bool) -> SelectedDevice {
            let now = Utc::now();
            let id = Uuid::new_v4();
            let signing = Sha256::digest(id.as_bytes()).to_vec();
            let key = URL_SAFE_NO_PAD.encode(Sha256::digest(&signing));
            sqlx::query("INSERT INTO chat.principals(user_did,created_at) VALUES($1,$2) ON CONFLICT DO NOTHING")
                .bind(owner).bind(now).execute(&mut **tx).await.unwrap();
            sqlx::query("INSERT INTO chat.devices(user_did,device_id,device_name,status,dpop_jkt,auth_generation,capabilities,created_at,updated_at) VALUES($1,$2,'c27','active',$3,1,chat.protocol_capabilities(),$4,$4)")
                .bind(owner).bind(id).bind(&key).bind(now).execute(&mut **tx).await.unwrap();
            sqlx::query("INSERT INTO chat.device_keys(user_did,device_id,key_id,signing_public_key,enrollment_auth_generation,created_at) VALUES($1,$2,$3,$4,1,$5)")
                .bind(owner).bind(id).bind(&key).bind(&signing).bind(now).execute(&mut **tx).await.unwrap();
            sqlx::query("INSERT INTO chat.direct_request_capabilities(owner_did,owner_device_id,owner_key_id,auth_generation,revision,enabled,protocol_version,signed_publication,publication_digest,updated_at) VALUES($1,$2,$3,1,1,TRUE,'2','c27',$4,$5)")
                .bind(owner).bind(id).bind(&key).bind(vec![1_u8; 32]).bind(now).execute(&mut **tx).await.unwrap();
            let mut d = SelectedDevice {
                owner_did: owner.into(), owner_device_id: id, owner_key_id: key, auth_generation: 1,
                grant_id: Uuid::nil(), grant_digest: vec![1; 32], capability_revision: 1,
                key_package_ref: vec![], wrapper_bytes: vec![], signed_grant: b"c27".to_vec(), expires_at: now,
            };
            package(tx, &mut d, scope, grant).await;
            d
        }

        /// Enrollment fixture: one more package for an existing device.
        async fn package(tx: &mut Transaction<'_, Postgres>, d: &mut SelectedDevice, scope: &str, grant: bool) -> Vec<u8> {
            let now = Utc::now();
            let reference = Sha256::digest(Uuid::new_v4().as_bytes()).to_vec();
            let wrapper = vec![7_u8; 40];
            let expiry = now + Duration::days(10);
            sqlx::query("INSERT INTO chat.key_packages(key_package_ref,wrapper_bytes,wrapper_sha256,init_key,owner_did,owner_device_id,owner_key_id,owner_auth_generation,not_before,not_after,status,created_at,usage_scope) VALUES($1,$2,$3,$4,$5,$6,$7,1,$8,$9,'available',$10,$11)")
                .bind(&reference).bind(&wrapper).bind(Sha256::digest(&wrapper).to_vec()).bind(Uuid::new_v4().as_bytes().as_slice())
                .bind(&d.owner_did).bind(d.owner_device_id).bind(&d.owner_key_id).bind(now - Duration::seconds(5)).bind(expiry).bind(now).bind(scope)
                .execute(&mut **tx).await.unwrap();
            if grant {
                d.grant_id = Uuid::new_v4();
                sqlx::query("INSERT INTO chat.direct_request_grants(grant_id,revision,owner_did,owner_device_id,owner_key_id,auth_generation,capability_revision,key_package_ref,purpose,protocol_version,profile,signed_grant,grant_digest,expires_at,created_at) VALUES($1,1,$2,$3,$4,1,1,$5,'direct-request-bootstrap','2','encryptedIntroduction1','c27',$6,$7,$8)")
                    .bind(d.grant_id).bind(&d.owner_did).bind(d.owner_device_id).bind(&d.owner_key_id).bind(&reference)
                    .bind(vec![1_u8; 32]).bind(expiry).bind(now).execute(&mut **tx).await.unwrap();
            }
            d.key_package_ref = reference.clone();
            reference
        }

        fn identity(actor: &SelectedDevice, recipient: &str) -> AttemptIdentity {
            AttemptIdentity {
                request_id: Uuid::new_v4(), actor_did: actor.owner_did.clone(), actor_device_id: actor.owner_device_id,
                actor_key_id: actor.owner_key_id.clone(), actor_auth_generation: 1, recipient_did: recipient.into(),
                prepare_digest: Sha256::digest(Uuid::new_v4().as_bytes()).to_vec(),
            }
        }

        /// Production lock order: operation + budget, then canonical identities.
        async fn lock(tx: &mut Transaction<'_, Postgres>, i: &AttemptIdentity) -> R<LockedAttempt> {
            let op = super::prelude::lock_direct_request_operation(tx, i.request_id).await?;
            super::prelude::lock_direct_request_identity_scope(tx, &[i.actor_did.clone(), i.recipient_did.clone()]).await?;
            load_locked_attempt(tx, i.clone(), &op).await
        }

        /// Real preparation: selection then reservation (which runs the
        /// production budget/quota check before any effect).
        async fn prepare_sized(tx: &mut Transaction<'_, Postgres>, i: &AttemptIdentity, snapshot: &[u8]) -> R<Vec<u8>> {
            let l = lock(tx, i).await?;
            let now = Utc::now();
            let selected = select_devices(tx, &l, now).await?;
            reserve_preparation(tx, &l, &selected, snapshot, &Sha256::digest(snapshot), now).await
        }
        async fn prepare(tx: &mut Transaction<'_, Postgres>, i: &AttemptIdentity) -> R<Vec<u8>> {
            prepare_sized(tx, i, b"c27-signed-preparation-snapshot").await
        }
        async fn cancel(tx: &mut Transaction<'_, Postgres>, i: &AttemptIdentity) -> R<Vec<u8>> {
            let l = lock(tx, i).await?;
            finish_terminal(tx, l, TerminalOutcome::Cancelled, format!("cancel:{}", i.request_id).as_bytes(), None, Utc::now()).await
        }

        async fn one<T: for<'r> sqlx::Decode<'r, Postgres> + sqlx::Type<Postgres> + Send + Unpin>(
            tx: &mut Transaction<'_, Postgres>, sql: &str, id: &str,
        ) -> T {
            sqlx::query_scalar(sql).bind(id).fetch_one(&mut **tx).await.unwrap()
        }
        async fn live(tx: &mut Transaction<'_, Postgres>, actor: &str) -> i64 {
            one(tx, "SELECT count(*) FROM chat.direct_request_attempts WHERE actor_did=$1 AND status='prepared'", actor).await
        }
        /// Immutable projection of every request row touching an account.
        async fn history(tx: &mut Transaction<'_, Postgres>, account: &str) -> String {
            one(tx, "SELECT jsonb_build_object(\
                'attempts',(SELECT jsonb_agg(md5(to_jsonb(a)::text) ORDER BY a.request_id) FROM chat.direct_request_attempts a WHERE a.actor_did=$1 OR a.recipient_did=$1),\
                'charges',(SELECT jsonb_agg(md5(to_jsonb(c)::text) ORDER BY c.request_id) FROM chat.direct_request_retained_charges c JOIN chat.direct_request_attempts a USING(request_id) WHERE a.actor_did=$1 OR a.recipient_did=$1),\
                'selected',(SELECT jsonb_agg(md5(to_jsonb(s)::text) ORDER BY s.key_package_ref) FROM chat.direct_request_selected_devices s JOIN chat.direct_request_attempts a USING(request_id) WHERE a.actor_did=$1 OR a.recipient_did=$1),\
                'packages',(SELECT jsonb_agg(jsonb_build_object('ref',encode(k.key_package_ref,'hex'),'status',k.status,'scope',k.usage_scope) ORDER BY k.key_package_ref) FROM chat.key_packages k WHERE k.owner_did=$1))::text", account).await
        }

        /// Dedicated loopback database for budget/quota isolation: the shared
        /// guarded database is validated first, its schema cloned, and only the
        /// migration-1 budget singleton seed is re-run. Dropped on scope exit.
        struct Isolated {
            name: String,
            pool: PgPool,
        }
        impl Drop for Isolated {
            fn drop(&mut self) {
                let status = std::process::Command::new("psql")
                    .args(["-X", "-q", "postgresql://127.0.0.1:5432/postgres", "-c", &format!("DROP DATABASE IF EXISTS {} WITH (FORCE)", self.name)])
                    .status().unwrap();
                assert!(status.success(), "drop {}", self.name);
            }
        }
        async fn isolated() -> Isolated {
            crate::common::direct_request_database::setup().await;
            let name = format!("catbird_direct_requests_c27_{}", &Uuid::new_v4().simple().to_string()[..16]);
            let admin = PgPool::connect("postgresql://127.0.0.1:5432/postgres").await.unwrap();
            sqlx::query(&format!("CREATE DATABASE {name}")).execute(&admin).await.unwrap();
            admin.close().await;
            let clone = std::process::Command::new("sh").arg("-c").arg(format!(
                "pg_dump -s postgresql://127.0.0.1:5432/catbird_direct_requests_test_20260919 | psql -X -q -v ON_ERROR_STOP=1 postgresql://127.0.0.1:5432/{name} >/dev/null"
            )).status().unwrap();
            let url = format!("postgresql://127.0.0.1:5432/{name}");
            let pool = sqlx::postgres::PgPoolOptions::new().max_connections(8).connect(&url).await.unwrap();
            let iso = Isolated { name: name.clone(), pool };
            assert!(clone.success(), "schema clone into {name}");
            let (db, host): (String, Option<String>) = sqlx::query_as("SELECT current_database(),host(inet_server_addr())").fetch_one(&iso.pool).await.unwrap();
            assert_eq!((db.as_str(), host.as_deref()), (name.as_str(), Some("127.0.0.1")));
            // Verbatim seed statement of migration 20260919000001.
            sqlx::query("INSERT INTO chat.direct_request_budget(singleton) VALUES(TRUE) ON CONFLICT DO NOTHING").execute(&iso.pool).await.unwrap();
            iso
        }

        /// All `ids` open transactions, meet at a barrier, then race the real
        /// preparation. Winners commit; losers roll back.
        async fn race(pool: &PgPool, ids: Vec<AttemptIdentity>) -> Vec<R<()>> {
            let barrier = Arc::new(Barrier::new(ids.len()));
            let tasks = ids.into_iter().map(|i| {
                let (pool, barrier) = (pool.clone(), barrier.clone());
                tokio::spawn(async move {
                    let mut tx = pool.begin().await.unwrap();
                    sqlx::query("SELECT 1").execute(&mut *tx).await.unwrap();
                    barrier.wait().await;
                    match prepare(&mut tx, &i).await {
                        Ok(_) => { tx.commit().await.unwrap(); Ok(()) }
                        Err(e) => { tx.rollback().await.unwrap(); Err(e) }
                    }
                })
            }).collect::<Vec<_>>();
            let mut out = Vec::new();
            for t in tasks { out.push(t.await.unwrap()); }
            out
        }
        fn tally(results: &[R<()>]) -> (usize, usize) {
            for r in results {
                assert!(matches!(r, Ok(()) | Err(DirectRequestStoreError::QuotaExceeded)), "unexpected race outcome {r:?}");
            }
            (results.iter().filter(|r| r.is_ok()).count(), results.iter().filter(|r| r.is_err()).count())
        }
        /// Release committed winners through the real cancellation path so the
        /// shared database keeps no live reservation from this test.
        async fn release(pool: &PgPool, actors: &[&SelectedDevice]) {
            let mut tx = pool.begin().await.unwrap();
            for a in actors {
                let rows: Vec<(Uuid, String, Vec<u8>)> = sqlx::query_as("SELECT request_id,recipient_did,prepare_digest FROM chat.direct_request_attempts WHERE actor_did=$1 AND status='prepared'")
                    .bind(&a.owner_did).fetch_all(&mut *tx).await.unwrap();
                for (request_id, recipient, digest) in rows {
                    let mut i = identity(a, &recipient);
                    i.request_id = request_id;
                    i.prepare_digest = digest;
                    cancel(&mut tx, &i).await.unwrap();
                }
            }
            tx.commit().await.unwrap();
        }

        // Clause 1: concurrent live quotas and the per-hour quota, each raced
        // by real concurrent transactions released together by a barrier.
        #[tokio::test]
        async fn c27_concurrent_and_hourly_quotas_hold_under_real_concurrent_transactions() {
            let iso = isolated().await;
            let pool = iso.pool.clone();

            // Pair limit (1 live per sender device and recipient).
            let mut tx = pool.begin().await.unwrap();
            let alice = device(&mut tx, &did(), "recovery", false).await;
            let bob_did = did();
            let mut bob = device(&mut tx, &bob_did, "direct-request", true).await;
            for _ in 0..2 { package(&mut tx, &mut bob, "direct-request", true).await; }
            tx.commit().await.unwrap();
            let (won, lost) = tally(&race(&pool, (0..3).map(|_| identity(&alice, &bob_did)).collect()).await);
            assert_eq!((won, lost), (1, 2), "same pair: exactly one live preparation");
            let mut tx = pool.begin().await.unwrap();
            assert_eq!(live(&mut tx, &alice.owner_did).await, 1);
            tx.rollback().await.unwrap();

            // Sender limit (2 live per sender) across distinct recipients.
            let mut tx = pool.begin().await.unwrap();
            let carol = device(&mut tx, &did(), "recovery", false).await;
            let mut targets = Vec::new();
            for _ in 0..3 { let t = did(); device(&mut tx, &t, "direct-request", true).await; targets.push(t); }
            tx.commit().await.unwrap();
            let (won, lost) = tally(&race(&pool, targets.iter().map(|t| identity(&carol, t)).collect()).await);
            assert_eq!((won, lost), (2, 1), "sender: exactly two live preparations");

            // Recipient limit (4 live per recipient): one committed, four race.
            let mut tx = pool.begin().await.unwrap();
            let dave_did = did();
            let mut dave = device(&mut tx, &dave_did, "direct-request", true).await;
            for _ in 0..4 { package(&mut tx, &mut dave, "direct-request", true).await; }
            let mut senders = Vec::new();
            for _ in 0..5 { senders.push(device(&mut tx, &did(), "recovery", false).await); }
            prepare(&mut tx, &identity(&senders[0], &dave_did)).await.unwrap();
            tx.commit().await.unwrap();
            let (won, lost) = tally(&race(&pool, senders[1..].iter().map(|s| identity(s, &dave_did)).collect()).await);
            assert_eq!((won, lost), (3, 1), "recipient: exactly four live preparations in total");

            // Hourly limit (20 per sender): 19 committed prepare/cancel
            // cycles, then two concurrent attempts race for the 20th slot.
            let mut tx = pool.begin().await.unwrap();
            let erin = device(&mut tx, &did(), "recovery", false).await;
            for _ in 0..19 {
                let t = did();
                device(&mut tx, &t, "direct-request", true).await;
                let i = identity(&erin, &t);
                prepare(&mut tx, &i).await.unwrap();
                cancel(&mut tx, &i).await.unwrap();
            }
            let mut last = Vec::new();
            for _ in 0..2 { let t = did(); device(&mut tx, &t, "direct-request", true).await; last.push(t); }
            tx.commit().await.unwrap();
            assert_eq!(live(&mut pool.begin().await.unwrap(), &erin.owner_did).await, 0, "cancelled cycles hold no live slot");
            let (won, lost) = tally(&race(&pool, last.iter().map(|t| identity(&erin, t)).collect()).await);
            assert_eq!((won, lost), (1, 1), "hourly: exactly one of two racers takes the 20th slot");
            let mut tx = pool.begin().await.unwrap();
            let hourly: i64 = one(&mut tx, "SELECT count(*) FROM chat.direct_request_attempts WHERE actor_did=$1 AND prepared_at IS NOT NULL", &erin.owner_did).await;
            assert_eq!(hourly, 20);
            tx.rollback().await.unwrap();

            let mut all = vec![&alice, &carol, &erin];
            all.extend(senders.iter());
            release(&pool, &all).await;
        }

        // Clause 2: cancelled attempts keep counting and are bounded.
        #[tokio::test]
        async fn c27_cancelled_attempts_count_toward_hourly_quota_and_tombstones_are_bounded() {
            let iso = isolated().await;
            let pool = iso.pool.clone();
            let mut tx = pool.begin().await.unwrap();
            let alice = device(&mut tx, &did(), "recovery", false).await;
            let snapshot = b"c27-signed-preparation-snapshot";
            for n in 0..20 {
                let t = did();
                device(&mut tx, &t, "direct-request", true).await;
                let i = identity(&alice, &t);
                prepare(&mut tx, &i).await.unwrap();
                let receipt = cancel(&mut tx, &i).await.unwrap();
                let (status, prepared, reserved): (String, bool, i64) = sqlx::query_as("SELECT status,prepared_at IS NOT NULL,reserved_bytes FROM chat.direct_request_attempts WHERE request_id=$1")
                    .bind(i.request_id).fetch_one(&mut *tx).await.unwrap();
                assert_eq!(status, "cancelled");
                assert!(prepared, "cancellation {n} must keep prepared_at");
                // Settles from the 8 MiB reservation to exactly its retained
                // artifacts: snapshot + attempt/ledger/selection rows + receipt.
                assert_eq!(reserved, snapshot.len() as i64 + 3 * 16_384 + receipt.len() as i64);
                let charged: i64 = one(&mut tx, "SELECT charged_bytes FROM chat.direct_request_retained_charges WHERE request_id=$1::uuid", &i.request_id.to_string()).await;
                assert_eq!(charged, reserved);
                assert_eq!(live(&mut tx, &alice.owner_did).await, 0);
            }
            let t = did();
            device(&mut tx, &t, "direct-request", true).await;
            let before = history(&mut tx, &alice.owner_did).await;
            assert!(matches!(prepare(&mut tx, &identity(&alice, &t)).await, Err(DirectRequestStoreError::QuotaExceeded)),
                "21st attempt in the hour must be refused although every earlier attempt was cancelled");
            assert_eq!(history(&mut tx, &alice.owner_did).await, before, "refusal must not alter prior history");

            // Unknown cancellation writes one bounded tombstone and fences the ID.
            let unknown = identity(&alice, &did());
            let tombstone = cancel(&mut tx, &unknown).await.unwrap();
            let charged: i64 = one(&mut tx, "SELECT charged_bytes FROM chat.direct_request_retained_charges WHERE request_id=$1::uuid", &unknown.request_id.to_string()).await;
            assert_eq!(charged, 2 * 16_384 + tombstone.len() as i64);
            let l = lock(&mut tx, &unknown).await.unwrap();
            let replay = reserve_preparation(&mut tx, &l, &[], b"late", &[0; 32], Utc::now()).await.unwrap();
            assert_eq!(replay, tombstone, "late preparation replays the tombstone");
            assert_eq!(cancel(&mut tx, &unknown).await.unwrap(), tombstone, "repeat cancel adds nothing");
            let rows: i64 = one(&mut tx, "SELECT count(*) FROM chat.direct_request_retained_charges WHERE request_id=$1::uuid", &unknown.request_id.to_string()).await;
            assert_eq!(rows, 1);
            tx.rollback().await.unwrap();
        }

        // Clause 3: cycling one pair through recreate/terminate is bounded.
        #[tokio::test]
        async fn c27_same_pair_recreate_cycles_are_bounded() {
            let iso = isolated().await;
            let pool = iso.pool.clone();
            let mut tx = pool.begin().await.unwrap();
            let alice = device(&mut tx, &did(), "recovery", false).await;
            let bob_did = did();
            let mut bob = device(&mut tx, &bob_did, "direct-request", true).await;
            for _ in 0..21 { package(&mut tx, &mut bob, "direct-request", true).await; }
            for n in 0..20 {
                let i = identity(&alice, &bob_did);
                prepare(&mut tx, &i).await.unwrap();
                if n == 0 {
                    assert!(matches!(prepare(&mut tx, &identity(&alice, &bob_did)).await, Err(DirectRequestStoreError::QuotaExceeded)),
                        "recreate while the previous attempt is live is refused");
                }
                cancel(&mut tx, &i).await.unwrap();
            }
            let before = history(&mut tx, &alice.owner_did).await;
            assert!(matches!(prepare(&mut tx, &identity(&alice, &bob_did)).await, Err(DirectRequestStoreError::QuotaExceeded)),
                "21st cycle within the hour is refused");
            assert_eq!(history(&mut tx, &alice.owner_did).await, before);
            let (attempts, charges, available): (i64, i64, i64) = sqlx::query_as("SELECT \
                (SELECT count(*) FROM chat.direct_request_attempts WHERE actor_did=$1 AND recipient_did=$2), \
                (SELECT count(*) FROM chat.direct_request_retained_charges c JOIN chat.direct_request_attempts a USING(request_id) WHERE a.actor_did=$1 AND a.recipient_did=$2), \
                (SELECT count(*) FROM chat.key_packages WHERE owner_did=$2 AND status='available')")
                .bind(&alice.owner_did).bind(&bob_did).fetch_one(&mut *tx).await.unwrap();
            assert_eq!((attempts, charges), (20, 20), "one immutable tombstone per completed cycle, none for refusals");
            assert_eq!(available, 2, "refused cycles consume no recipient package");
            tx.rollback().await.unwrap();
        }

        // Clause 4: request-pool depletion is bounded to the request pool.
        #[tokio::test]
        async fn c27_request_pool_depletion_is_bounded_and_never_touches_recovery_pool() {
            let iso = isolated().await;
            let pool = iso.pool.clone();
            let mut tx = pool.begin().await.unwrap();
            let bob_did = did();
            let mut bob = device(&mut tx, &bob_did, "direct-request", true).await;
            package(&mut tx, &mut bob, "direct-request", true).await;
            let mut recovery = Vec::new();
            for _ in 0..3 { recovery.push(package(&mut tx, &mut bob, "recovery", false).await); }
            let mut senders = Vec::new();
            for _ in 0..3 { senders.push(device(&mut tx, &did(), "recovery", false).await); }
            prepare(&mut tx, &identity(&senders[0], &bob_did)).await.unwrap();
            prepare(&mut tx, &identity(&senders[1], &bob_did)).await.unwrap();
            let before = history(&mut tx, &bob_did).await;
            let refused = identity(&senders[2], &bob_did);
            assert!(matches!(prepare(&mut tx, &refused).await, Err(DirectRequestStoreError::RecipientKeysUnavailable)));
            assert_eq!(history(&mut tx, &bob_did).await, before, "depletion refusal writes nothing and reserves nothing");
            let absent: i64 = one(&mut tx, "SELECT count(*) FROM chat.direct_request_attempts WHERE request_id=$1::uuid", &refused.request_id.to_string()).await;
            assert_eq!(absent, 0);
            for r in &recovery {
                let (status, scope): (String, String) = sqlx::query_as("SELECT status,usage_scope FROM chat.key_packages WHERE key_package_ref=$1")
                    .bind(r).fetch_one(&mut *tx).await.unwrap();
                assert_eq!((status.as_str(), scope.as_str()), ("available", "recovery"));
            }
            let (reserved, selected_recovery): (i64, i64) = sqlx::query_as("SELECT \
                (SELECT count(*) FROM chat.key_packages WHERE owner_did=$1 AND usage_scope='direct-request' AND status='reserved'), \
                (SELECT count(*) FROM chat.direct_request_selected_devices s JOIN chat.key_packages k USING(key_package_ref) WHERE k.owner_did=$1 AND k.usage_scope='recovery')")
                .bind(&bob_did).fetch_one(&mut *tx).await.unwrap();
            assert_eq!((reserved, selected_recovery), (2, 0));
            tx.rollback().await.unwrap();
        }

        // Clause 5 (+7 at repository level): account pending, account retained
        // and global pending byte budgets refuse new capacity without evicting
        // or rewriting any existing request history.
        #[tokio::test]
        async fn c27_retained_byte_budgets_refuse_capacity_without_eviction() {
            let iso = isolated().await;
            let pool = iso.pool.clone();

            // Account pending: live PREPARED (unpublished) reservations
            // accumulate pending bytes until a further reservation that would
            // exceed 64 MiB is refused without rewriting history.
            let mut tx = pool.begin().await.unwrap();
            let alice = device(&mut tx, &did(), "recovery", false).await;
            let bob_did = did();
            device(&mut tx, &bob_did, "direct-request", true).await;
            let first = identity(&alice, &bob_did);
            let snap_36mb = vec![0x36_u8; 36 * 1_048_576];
            prepare_sized(&mut tx, &first, &snap_36mb).await.unwrap();
            let carol_did = did();
            device(&mut tx, &carol_did, "direct-request", true).await;
            let second = identity(&alice, &carol_did);
            let snap_30mb = vec![0x30_u8; 30 * 1_048_576];
            let before = history(&mut tx, &alice.owner_did).await;
            assert!(matches!(
                prepare_sized(&mut tx, &second, &snap_30mb).await,
                Err(DirectRequestStoreError::QuotaExceeded)
            ), "36 MiB + 30 MiB exceeds 64 MiB account pending cap while sender_live=1 (< 2)");
            assert_eq!(history(&mut tx, &alice.owner_did).await, before, "refused preparation leaves history intact without eviction");
            // Cancelling the first live reservation retires its pending charge
            cancel(&mut tx, &first).await.unwrap();
            assert!(prepare_sized(&mut tx, &second, &snap_30mb).await.is_ok(), "reservation succeeds after retiring pending bytes");
            tx.rollback().await.unwrap();

            // Account retained: a published request's charge is retained against
            // the 256 MiB account limit. An over-cap settlement exceeding 256 MiB
            // is refused with no partial effect.
            let mut tx = pool.begin().await.unwrap();
            let alice = device(&mut tx, &did(), "recovery", false).await;
            let bob_did = did();
            device(&mut tx, &bob_did, "direct-request", true).await;
            let over = identity(&alice, &bob_did);
            prepare(&mut tx, &over).await.unwrap();
            let before = history(&mut tx, &alice.owner_did).await;
            let l = lock(&mut tx, &over).await.unwrap();
            assert!(matches!(
                finish_terminal_charged(&mut tx, l, TerminalOutcome::Published, b"c27-published-receipt", Some(&[9; 32]), Utc::now(), Some(270 * 1_048_576)).await,
                Err(DirectRequestStoreError::QuotaExceeded)));
            assert_eq!(history(&mut tx, &alice.owner_did).await, before, "refused settlement leaves the prepared attempt intact");

            // Separately prove retained bytes of published requests still refuse
            // new capacity without eviction (the retained budget clause).
            let l2 = lock(&mut tx, &over).await.unwrap();
            finish_terminal_charged(&mut tx, l2, TerminalOutcome::Published, b"c27-published-receipt", Some(&[9; 32]), Utc::now(), Some(250 * 1_048_576)).await.unwrap();
            let carol_did = did();
            device(&mut tx, &carol_did, "direct-request", true).await;
            let before_carol = history(&mut tx, &alice.owner_did).await;
            assert!(matches!(prepare(&mut tx, &identity(&alice, &carol_did)).await, Err(DirectRequestStoreError::QuotaExceeded)),
                "new prepare refused when published retained charge (250 MiB) + next prep exceeds 256 MiB account retained limit");
            assert_eq!(history(&mut tx, &alice.owner_did).await, before_carol, "retained refusal does not evict published request history");
            tx.rollback().await.unwrap();
            // Account retained: distinct senders each prepare (maximum 8 MB
            // snapshot, under the 8 MiB prepare-response cap) and cancel to
            // one recipient; retained artifacts accumulate with no pending
            // capacity until the 256 MiB default account limit refuses.
            let mut tx = pool.begin().await.unwrap();
            let bob_did = did();
            let mut bob = device(&mut tx, &bob_did, "direct-request", true).await;
            let snapshot = vec![0x5a_u8; 8_000_000];
            let mut retained = 0_i64;
            let mut completed = 0;
            let refusal = loop {
                assert!(completed < 40, "account retained budget never refused");
                let sender = device(&mut tx, &did(), "recovery", false).await;
                let i = identity(&sender, &bob_did);
                let before = history(&mut tx, &bob_did).await;
                match prepare_sized(&mut tx, &i, &snapshot).await {
                    Ok(_) => {}
                    Err(e) => { assert_eq!(history(&mut tx, &bob_did).await, before); break (e, retained); }
                }
                let receipt = cancel(&mut tx, &i).await.unwrap();
                retained += snapshot.len() as i64 + 3 * 16_384 + receipt.len() as i64;
                completed += 1;
                package(&mut tx, &mut bob, "direct-request", true).await;
            };
            assert!(matches!(refusal.0, DirectRequestStoreError::QuotaExceeded));
            assert!(refusal.1 <= 268_435_456 && refusal.1 + 8_388_608 > 268_435_456,
                "refused exactly when the next 8 MiB reservation would exceed 256 MiB (retained {})", refusal.1);
            let pending: i64 = one(&mut tx, "SELECT COALESCE(sum(reserved_bytes),0)::bigint FROM chat.direct_request_attempts WHERE recipient_did=$1 AND status IN('prepared','published')", &bob_did).await;
            assert_eq!(pending, 0, "the refusal was the retained budget, not pending capacity");
            let charges: i64 = one(&mut tx, "SELECT count(*) FROM chat.direct_request_retained_charges c JOIN chat.direct_request_attempts a USING(request_id) WHERE a.recipient_did=$1", &bob_did).await;
            assert_eq!(charges, completed, "every retained history row survives the refusal");
            tx.rollback().await.unwrap();

            // Global pending: one live 8 MiB reservation per fresh account pair
            // (each account stays far below its own caps) until the 1 GiB
            // global pending budget refuses. The dedicated database starts at
            // zero, so exactly 128 reservations fit.
            let mut tx = pool.begin().await.unwrap();
            let mut made = 0;
            let mut first: Option<(String, String)> = None;
            loop {
                assert!(made <= 128, "global pending budget never refused");
                let sender = device(&mut tx, &did(), "recovery", false).await;
                let t = did();
                device(&mut tx, &t, "direct-request", true).await;
                match prepare(&mut tx, &identity(&sender, &t)).await {
                    Ok(_) => {
                        if first.is_none() { first = Some((sender.owner_did.clone(), history(&mut tx, &sender.owner_did).await)); }
                        made += 1;
                    }
                    Err(e) => {
                        assert!(matches!(e, DirectRequestStoreError::QuotaExceeded), "{e:?}");
                        let pending: i64 = sqlx::query_scalar("SELECT pending_bytes FROM chat.direct_request_effective_budget WHERE singleton").fetch_one(&mut *tx).await.unwrap();
                        assert_eq!(pending, 128 * 8_388_608, "refusal exactly at the global pending cap");
                        break;
                    }
                }
            }
            assert_eq!(made, 128);
            let (who, snap) = first.unwrap();
            assert_eq!(history(&mut tx, &who).await, snap, "earliest reservation survives global refusal unchanged");
            tx.rollback().await.unwrap();
        }
    }
}
