//! A closed federation gate (emergency kill switch, or the runtime mode off)
//! pauses outbound dispatch before any claim or send. On the scoped DS clock a
//! due durable row keeps its status, retry count and due time through every
//! closed worker pass; the first pass after the gate reopens dispatches it.
//! An inline `OutboundClient` call is refused before it connects, and a row
//! already claimed when the gate closes goes back to pending unsent, its
//! attempt unconsumed.
//!
//! The kill switch and the mode override are process-global; this binary's one
//! test owns them.

mod common;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use catbird_server::{
    auth::AuthMiddleware,
    federation::{
        outbound::{OutboundClient, OutboundError},
        queue::OutboundQueue,
        resolver::{DsResolver, ValidatedRemoteDestination},
        FederationMode,
    },
    sim_hooks::{scope_ds_clock, ManualDsClock},
};
use chrono::{DateTime, Duration, Utc};

const KILL_SWITCH: &str = "FEDERATION_EMERGENCY_KILL_SWITCH";
const ROW_ID: &str = "paused-account-deletion-relay";
// Not allowlisted: once dispatch resumes, the outbound peer policy settles the
// row before any network I/O.
const PEER_DID: &str = "did:web:paused-peer.example.com";

#[tokio::test]
async fn closed_federation_gate_pauses_outbound_dispatch_until_it_reopens() {
    let db = common::fresh_db::fresh_fully_migrated_db("fed_dispatch_pause_").await;
    let pool = db.connect(2).await;
    // Whole seconds, so the stored due time compares exactly.
    let t0 = DateTime::<Utc>::from_timestamp(Utc::now().timestamp(), 0).unwrap();
    let due = t0 - Duration::seconds(1);
    sqlx::query(
        "INSERT INTO outbound_queue (id, target_ds_did, target_endpoint, method, payload, convo_id, \
         status, retry_count, max_retries, next_retry_at) \
         VALUES ($1, $2, '', 'blue.catbird.mlsDS.relayAccountDeletion', $3, 'paused-convo', \
         'pending', 0, 5, $4)",
    )
    .bind(ROW_ID)
    .bind(PEER_DID)
    .bind(b"{}".to_vec())
    .bind(due)
    .execute(&pool)
    .await
    .unwrap();
    let resolver = Arc::new(DsResolver::new(
        pool.clone(),
        reqwest::Client::new(),
        "did:web:pausing-home.example.com".into(),
        "https://pausing-home.example.com".into(),
        None,
        60,
    ));
    let queue = OutboundQueue::new(pool.clone(), AuthMiddleware::new(), resolver);
    let sign = |_target: &str, _method: &str| Ok::<String, String>(String::new());
    let row = || async {
        sqlx::query_as::<_, (String, i32, DateTime<Utc>)>(
            "SELECT status, retry_count, next_retry_at FROM outbound_queue WHERE id = $1",
        )
        .bind(ROW_ID)
        .fetch_one(&pool)
        .await
        .unwrap()
    };
    let clock = Arc::new(ManualDsClock::new(t0));

    // A loopback peer counting every request that reaches it.
    let hits = Arc::new(AtomicUsize::new(0));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let counter = hits.clone();
    tokio::spawn(async move {
        let stub = axum::Router::new().fallback(move || {
            let counter = counter.clone();
            async move {
                counter.fetch_add(1, Ordering::SeqCst);
                axum::Json(serde_json::json!({ "accepted": true }))
            }
        });
        axum::serve(listener, stub).await.unwrap();
    });
    let peer = ValidatedRemoteDestination {
        url: url::Url::parse(&format!("http://{addr}")).unwrap(),
        host: "127.0.0.1".to_owned(),
        addrs: vec![addr],
    };
    let inline_send = || async {
        OutboundClient::new(1, 1)
            .call_procedure_pinned(
                &peer,
                "blue.catbird.mlsDS.deliverMessage",
                "token",
                &serde_json::json!({}),
            )
            .await
    };

    scope_ds_clock(clock.clone(), async {
        for (closed_by, kill_switch, mode) in [
            ("kill switch", true, FederationMode::Allowlist),
            ("runtime mode off", false, FederationMode::Off),
        ] {
            if kill_switch {
                std::env::set_var(KILL_SWITCH, "1");
            } else {
                std::env::remove_var(KILL_SWITCH);
            }
            FederationMode::set_runtime_override(Some(mode));
            // Worker passes across ten minutes: past every backoff step.
            for minutes in [0, 1, 10] {
                clock.set_utc(t0 + Duration::minutes(minutes));
                let dispatched = queue
                    .process_pending_batch(&OutboundClient::new(1, 1), &sign)
                    .await
                    .unwrap();
                assert_eq!(dispatched, 0, "{closed_by} at +{minutes}m dispatched");
                assert_eq!(
                    row().await,
                    ("pending".to_owned(), 0, due),
                    "{closed_by} at +{minutes}m must leave the row untouched"
                );
            }
            let refused = inline_send().await.expect_err("closed gate sent inline");
            assert!(
                matches!(refused, OutboundError::FederationDisabled { .. })
                    && refused.is_retryable(),
                "{closed_by}: inline send must be a retryable FederationDisabled, got {refused:?}"
            );
            assert_eq!(
                hits.load(Ordering::SeqCst),
                0,
                "{closed_by}: inline send reached the peer"
            );
        }

        // A row claimed before the gate closed is handed back unsent: pending,
        // its attempt unconsumed, never dead-lettered.
        let claimed = queue.claim_due_batch(1).await.unwrap();
        assert_eq!(claimed.len(), 1);
        assert_eq!(row().await.0, "in_flight");
        queue
            .process_item(&claimed[0], &OutboundClient::new(1, 1), &sign)
            .await;
        let deferred = row().await;
        assert_eq!(
            (deferred.0.as_str(), deferred.1),
            ("pending", 0),
            "a closed gate consumed the claimed row's attempt"
        );
        assert_eq!(hits.load(Ordering::SeqCst), 0);

        std::env::remove_var(KILL_SWITCH);
        FederationMode::set_runtime_override(Some(FederationMode::Allowlist));
        clock.set_utc(deferred.2 + Duration::seconds(1));
        let dispatched = queue
            .process_pending_batch(&OutboundClient::new(1, 1), &sign)
            .await
            .unwrap();
        assert_eq!(dispatched, 1, "the reopened gate resumes dispatch");
        assert_ne!(
            row().await,
            deferred,
            "the resumed pass acted on the paused row"
        );
        inline_send().await.expect("the reopened gate sends inline");
        assert_eq!(
            hits.load(Ordering::SeqCst),
            1,
            "the peer was reachable all along"
        );
    })
    .await;
}
