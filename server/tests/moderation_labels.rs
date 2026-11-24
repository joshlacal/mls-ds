//! Operator takedowns mirrored from Ozone labels (`catbird_server::moderation`).
//!
//! Each case mints its own fully migrated disposable database.

mod common;

use catbird_server::moderation::{
    apply_label_event, is_account_restricted, labels::AccountLabelEvent,
};
use chrono::{DateTime, Duration, Utc};

const OZONE: &str = "did:plc:ozonecatbirdtest";
const SPAMMER: &str = "did:plc:spammeraccount";
const BYSTANDER: &str = "did:plc:bystanderaccount";

fn event(
    val: &str,
    cts: DateTime<Utc>,
    exp: Option<DateTime<Utc>>,
    neg: bool,
) -> AccountLabelEvent {
    AccountLabelEvent {
        src: OZONE.into(),
        did: SPAMMER.into(),
        val: val.into(),
        cts,
        exp,
        neg,
    }
}

#[tokio::test]
async fn takedown_restricts_until_a_newer_negation() {
    let db = common::fresh_db::fresh_fully_migrated_db("moderation_labels_").await;
    let pool = db.connect(2).await;
    let t0 = Utc::now() - Duration::minutes(10);

    assert!(!is_account_restricted(&pool, SPAMMER).await.unwrap());

    apply_label_event(&pool, &event("!takedown", t0, None, false))
        .await
        .unwrap();
    assert!(is_account_restricted(&pool, SPAMMER).await.unwrap());
    assert!(!is_account_restricted(&pool, BYSTANDER).await.unwrap());

    // A stale negation replayed by a full resync must not lift a newer ban.
    apply_label_event(
        &pool,
        &event("!takedown", t0 - Duration::minutes(5), None, true),
    )
    .await
    .unwrap();
    assert!(is_account_restricted(&pool, SPAMMER).await.unwrap());

    apply_label_event(
        &pool,
        &event("!takedown", t0 + Duration::minutes(1), None, true),
    )
    .await
    .unwrap();
    assert!(!is_account_restricted(&pool, SPAMMER).await.unwrap());

    // Replaying the original takedown after the reversal changes nothing.
    apply_label_event(&pool, &event("!takedown", t0, None, false))
        .await
        .unwrap();
    assert!(!is_account_restricted(&pool, SPAMMER).await.unwrap());
}

#[tokio::test]
async fn timed_suspension_lapses_at_its_expiry() {
    let db = common::fresh_db::fresh_fully_migrated_db("moderation_labels_").await;
    let pool = db.connect(2).await;
    let now = Utc::now();

    apply_label_event(
        &pool,
        &event(
            "!suspend",
            now - Duration::hours(2),
            Some(now + Duration::hours(1)),
            false,
        ),
    )
    .await
    .unwrap();
    assert!(is_account_restricted(&pool, SPAMMER).await.unwrap());

    apply_label_event(
        &pool,
        &event(
            "!suspend",
            now - Duration::hours(1),
            Some(now - Duration::minutes(1)),
            false,
        ),
    )
    .await
    .unwrap();
    assert!(!is_account_restricted(&pool, SPAMMER).await.unwrap());
}

#[tokio::test]
async fn malformed_dids_are_refused_by_the_schema() {
    let db = common::fresh_db::fresh_fully_migrated_db("moderation_labels_").await;
    let pool = db.connect(2).await;
    let mut bad = event("!takedown", Utc::now(), None, false);
    bad.did = "at://did:plc:x/app.bsky.feed.post/1".into();
    assert!(apply_label_event(&pool, &bad).await.is_err());
}
