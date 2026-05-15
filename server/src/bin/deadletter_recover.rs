use anyhow::{bail, Context, Result};
use catbird_server::db;
use serde_json::json;
use sqlx::PgPool;
use std::{env, time::Duration};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Action {
    Reset,
    Drop,
    ReissueAll,
}

impl Action {
    fn parse(value: &str) -> Result<Self> {
        match value {
            "reset" => Ok(Self::Reset),
            "drop" => Ok(Self::Drop),
            "reissue-all" => Ok(Self::ReissueAll),
            other => bail!("unsupported --action {other}; expected reset, drop, or reissue-all"),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Reset => "reset",
            Self::Drop => "drop",
            Self::ReissueAll => "reissue-all",
        }
    }
}

#[derive(Debug)]
struct Args {
    convo_id: String,
    action: Action,
    operator_did: String,
    reason: Option<String>,
    dry_run: bool,
}

impl Args {
    fn parse() -> Result<Self> {
        let mut convo_id = None;
        let mut action = None;
        let mut operator_did = env::var("OPERATOR_DID").ok();
        let mut reason = None;
        let mut dry_run = true;

        let mut iter = env::args().skip(1);
        while let Some(arg) = iter.next() {
            match arg.as_str() {
                "--convo-id" => convo_id = iter.next(),
                "--action" => {
                    action = Some(Action::parse(
                        &iter.next().context("--action requires a value")?,
                    )?)
                }
                "--operator-did" => operator_did = iter.next(),
                "--reason" => reason = iter.next(),
                "--dry-run" => dry_run = true,
                "--execute" => dry_run = false,
                "--help" | "-h" => {
                    print_help();
                    std::process::exit(0);
                }
                other => bail!("unknown argument {other}; pass --help for usage"),
            }
        }

        Ok(Self {
            convo_id: convo_id.context("--convo-id <id> is required")?,
            action: action.context("--action {reset|drop|reissue-all} is required")?,
            operator_did: operator_did.context(
                "--operator-did <did> or OPERATOR_DID is required for audit attribution",
            )?,
            reason,
            dry_run,
        })
    }
}

fn print_help() {
    println!(
        "Usage: deadletter_recover --convo-id <id> --action {{reset|drop|reissue-all}} [--operator-did <did>] [--reason <text>] [--dry-run|--execute]\n\
         Defaults to --dry-run. Use Doppler or DATABASE_URL for database access."
    );
}

#[tokio::main]
async fn main() -> Result<()> {
    dotenvy::dotenv().ok();
    let args = Args::parse()?;

    let pool = db::init_db_default()
        .await
        .context("failed to initialize database pool")?;

    let exists: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM conversations WHERE id = $1)")
            .bind(&args.convo_id)
            .fetch_one(&pool)
            .await
            .context("failed to check conversation existence")?;
    if !exists {
        bail!("conversation {} does not exist", args.convo_id);
    }

    let details = match args.action {
        Action::Reset => recover_reset(&pool, &args).await?,
        Action::Drop => recover_drop(&pool, &args).await?,
        Action::ReissueAll => recover_reissue_all(&pool, &args).await?,
    };

    let success = details
        .get("success")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);

    sqlx::query(
        r#"
        INSERT INTO dead_letter_recoveries
            (id, convo_id, operator_did, action, reason, dry_run, success, details)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        "#,
    )
    .bind(Uuid::new_v4().to_string())
    .bind(&args.convo_id)
    .bind(&args.operator_did)
    .bind(args.action.as_str())
    .bind(&args.reason)
    .bind(args.dry_run)
    .bind(success)
    .bind(&details)
    .execute(&pool)
    .await
    .context("failed to write dead_letter_recoveries audit row")?;

    println!("{}", serde_json::to_string_pretty(&details)?);
    Ok(())
}

async fn recover_reset(pool: &PgPool, args: &Args) -> Result<serde_json::Value> {
    let current: (i32, Option<String>) =
        sqlx::query_as("SELECT reset_count, group_id FROM conversations WHERE id = $1")
            .bind(&args.convo_id)
            .fetch_one(pool)
            .await
            .context("failed to read reset state")?;

    if args.dry_run {
        return Ok(json!({
            "success": true,
            "dryRun": true,
            "action": "reset",
            "convoId": args.convo_id,
            "currentResetCount": current.0,
            "currentGroupId": current.1,
            "would": "clear circuit breaker and enqueue a reset request marker for client activation"
        }));
    }

    let request_id = Uuid::new_v4().to_string();
    let reset_generation = current.0.saturating_add(1);
    let new_group_id = format!("deadletter-reset-{}-{}", args.convo_id, request_id);

    let mut tx = pool.begin().await.context("failed to begin reset tx")?;
    sqlx::query(
        r#"
        UPDATE conversations
        SET reset_count = $2,
            auto_reset_disabled_at = NULL,
            consecutive_reset_count = 0,
            needs_rejoin = true,
            rejoin_requested_at = NOW(),
            rejoin_reason = COALESCE($3, 'deadletter_recover reset'),
            updated_at = NOW()
        WHERE id = $1
        "#,
    )
    .bind(&args.convo_id)
    .bind(reset_generation)
    .bind(&args.reason)
    .execute(&mut *tx)
    .await
    .context("failed to update conversation reset marker")?;

    sqlx::query(
        r#"
        INSERT INTO event_stream (id, convo_id, event_type, payload, emitted_at)
        VALUES ($1, $2, 'groupResetEvent', $3, NOW())
        "#,
    )
    .bind(&request_id)
    .bind(&args.convo_id)
    .bind(json!({
        "$type": "blue.catbird.mlsChat.subscribeEvents#groupResetEvent",
        "cursor": request_id,
        "convoId": args.convo_id,
        "newGroupId": new_group_id,
        "resetGeneration": reset_generation,
        "resetBy": args.operator_did,
        "cipherSuite": "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519",
        "reason": args.reason.as_deref().unwrap_or("deadletter_recover reset")
    }))
    .execute(&mut *tx)
    .await
    .context("failed to insert reset event marker")?;

    tx.commit().await.context("failed to commit reset tx")?;

    Ok(json!({
        "success": true,
        "dryRun": false,
        "action": "reset",
        "convoId": args.convo_id,
        "resetGeneration": reset_generation,
        "requestEventId": request_id,
        "newGroupId": new_group_id
    }))
}

async fn recover_drop(pool: &PgPool, args: &Args) -> Result<serde_json::Value> {
    if args.dry_run {
        let counts: (i64, i64) = sqlx::query_as(
            r#"
            SELECT
                (SELECT COUNT(*) FROM reissue_requests WHERE convo_id = $1),
                (SELECT COUNT(*) FROM welcome_messages WHERE convo_id = $1 AND consumed = false)
            "#,
        )
        .bind(&args.convo_id)
        .fetch_one(pool)
        .await
        .context("failed to count droppable recovery rows")?;
        return Ok(json!({
            "success": true,
            "dryRun": true,
            "action": "drop",
            "convoId": args.convo_id,
            "wouldDeleteReissueRequests": counts.0,
            "wouldConsumePendingWelcomes": counts.1
        }));
    }

    let mut tx = pool.begin().await.context("failed to begin drop tx")?;
    let reissue_deleted = sqlx::query("DELETE FROM reissue_requests WHERE convo_id = $1")
        .bind(&args.convo_id)
        .execute(&mut *tx)
        .await
        .context("failed to delete reissue requests")?
        .rows_affected();
    let welcomes_consumed = sqlx::query(
        r#"
        UPDATE welcome_messages
        SET consumed = true,
            consumed_at = NOW(),
            error_reason = COALESCE(error_reason, 'deadletter_recover drop')
        WHERE convo_id = $1
          AND consumed = false
        "#,
    )
    .bind(&args.convo_id)
    .execute(&mut *tx)
    .await
    .context("failed to consume pending welcomes")?
    .rows_affected();
    tx.commit().await.context("failed to commit drop tx")?;

    Ok(json!({
        "success": true,
        "dryRun": false,
        "action": "drop",
        "convoId": args.convo_id,
        "reissueRequestsDeleted": reissue_deleted,
        "pendingWelcomesConsumed": welcomes_consumed
    }))
}

async fn recover_reissue_all(pool: &PgPool, args: &Args) -> Result<serde_json::Value> {
    let recipients: Vec<String> = sqlx::query_scalar(
        r#"
        SELECT member_did
        FROM members
        WHERE convo_id = $1
          AND left_at IS NULL
          AND member_did <> $2
        ORDER BY member_did
        "#,
    )
    .bind(&args.convo_id)
    .bind(&args.operator_did)
    .fetch_all(pool)
    .await
    .context("failed to list active members")?;

    if args.dry_run {
        return Ok(json!({
            "success": true,
            "dryRun": true,
            "action": "reissue-all",
            "convoId": args.convo_id,
            "wouldRequestRecipients": recipients
        }));
    }

    let requested_at = chrono::Utc::now();
    let mut tx = pool
        .begin()
        .await
        .context("failed to begin reissue-all tx")?;
    for recipient in &recipients {
        sqlx::query(
            r#"
            INSERT INTO reissue_requests
                (id, convo_id, recipient_device_did, requested_at, attempts, last_attempt_at)
            VALUES ($1, $2, $3, $4, 1, $4)
            "#,
        )
        .bind(Uuid::new_v4().to_string())
        .bind(&args.convo_id)
        .bind(recipient)
        .bind(requested_at)
        .execute(&mut *tx)
        .await
        .context("failed to insert reissue request")?;
    }
    tx.commit()
        .await
        .context("failed to commit reissue-all tx")?;

    tokio::time::sleep(Duration::from_millis(1)).await;

    Ok(json!({
        "success": true,
        "dryRun": false,
        "action": "reissue-all",
        "convoId": args.convo_id,
        "requestedRecipients": recipients.len()
    }))
}
