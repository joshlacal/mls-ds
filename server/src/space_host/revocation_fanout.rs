//! Post-commit Space revocation (`notifyCredentialsRevoked`), Space deletion (`notifySpaceUpdate#spaceDeleted`),
//! and `notifyRepoUpdate` / `removeWriter` syncer fan-out (`M-F04`).
//!
//! CRITICAL INVARIANT (`M-F04`): Every HTTP delivery function in this module runs strictly AFTER the outer
//! PostgreSQL transaction commits so webhook HTTP calls never hold open row locks or transactions.

use std::{collections::BTreeSet, time::Duration};

use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde_json::{json, Value};
use uuid::Uuid;

use super::SpaceHostRuntime;
use crate::push_gateway::ssrf::{system_dns_resolve, validate_https_url_with_resolver};

pub(crate) fn allow_loopback_space_endpoint(url: &str) -> bool {
    cfg!(any(test, feature = "test-support"))
        && (url.starts_with("http://127.0.0.1:") || url.starts_with("http://[::1]:"))
}

pub(crate) fn build_space_webhook_client(
    full_url: &str,
    is_test_override: bool,
) -> Result<(String, reqwest::Client), String> {
    if is_test_override || allow_loopback_space_endpoint(full_url) {
        static TEST_OVERRIDE_CLIENT: std::sync::OnceLock<reqwest::Client> =
            std::sync::OnceLock::new();
        let client = TEST_OVERRIDE_CLIENT
            .get_or_init(|| {
                reqwest::Client::builder()
                    .redirect(reqwest::redirect::Policy::none())
                    .timeout(Duration::from_secs(10))
                    .build()
                    .expect("build test space notice HTTP client")
            })
            .clone();
        return Ok((full_url.to_string(), client));
    }
    let validated = validate_https_url_with_resolver(full_url, None, false, system_dns_resolve)
        .map_err(|e| format!("Space notice SSRF check failed: {e}"))?;
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(10))
        .resolve_to_addrs(&validated.host, &validated.pinned_addrs)
        .build()
        .map_err(|e| e.to_string())?;
    Ok((validated.effective_url, client))
}

async fn post_pds_space_notice(
    runtime: &SpaceHostRuntime,
    target_did_or_ref: &str,
    nsid: &str,
    body: &Value,
) -> Result<(), String> {
    let (_, ep, is_override) = runtime
        .resolve_did_entry(target_did_or_ref, false)
        .await
        .map_err(|e| e.to_string())?;
    let endpoint_base = ep.trim_end_matches('/');
    if endpoint_base.is_empty() {
        return Ok(());
    }

    let full_url = format!("{endpoint_base}/xrpc/{nsid}");
    let (effective_url, http_client) = build_space_webhook_client(&full_url, is_override)?;

    let aud = if target_did_or_ref.contains('#') {
        target_did_or_ref.to_string()
    } else {
        format!("{target_did_or_ref}#atproto_pds")
    };
    let jwt = runtime.mint_service_jwt(&aud, nsid)?;
    let resp = crate::sim_hooks::send_reqwest(
        http_client
            .post(&effective_url)
            .header(reqwest::header::AUTHORIZATION, format!("Bearer {jwt}"))
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .json(body),
    )
    .await?;

    if !resp.status().is_success() {
        return Err(format!(
            "Space notice {nsid} returned HTTP {}",
            resp.status().as_u16()
        ));
    }
    Ok(())
}

/// Deliver an unauthenticated `com.atproto.space.notifySpaceUpdate` webhook carrying the
/// subscriber's registration `token` in the JSON body (`atproto#5187` Nov-12).
pub(crate) async fn post_syncer_space_update(
    endpoint_url: &str,
    space_uri: &str,
    token: &str,
    update: Value,
) -> Result<(), String> {
    let endpoint_base = endpoint_url.trim_end_matches('/');
    if endpoint_base.is_empty() {
        return Ok(());
    }
    let full_url = format!("{endpoint_base}/xrpc/com.atproto.space.notifySpaceUpdate");
    let is_override = allow_loopback_space_endpoint(&full_url);
    let (effective_url, http_client) = build_space_webhook_client(&full_url, is_override)?;

    let payload = json!({
        "space": space_uri,
        "token": token,
        "update": update,
    });
    let resp = crate::sim_hooks::send_reqwest(
        http_client
            .post(&effective_url)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .json(&payload),
    )
    .await?;

    if !resp.status().is_success() {
        return Err(format!(
            "notifySpaceUpdate returned HTTP {}",
            resp.status().as_u16()
        ));
    }
    Ok(())
}

async fn fan_out_revoked_jtis_to_writers(
    runtime: &SpaceHostRuntime,
    space_uri: &str,
    revoked_jtis: &[String],
    writer_dids: &[String],
) -> usize {
    if revoked_jtis.is_empty() || writer_dids.is_empty() {
        return 0;
    }
    let mut delivered = 0_usize;
    for chunk in revoked_jtis.chunks(100) {
        let payload = json!({
            "space": space_uri,
            "credentials": chunk,
        });
        for writer_did in writer_dids {
            if post_pds_space_notice(
                runtime,
                writer_did,
                "com.atproto.space.notifyCredentialsRevoked",
                &payload,
            )
            .await
            .is_ok()
            {
                delivered += 1;
            }
        }
    }
    delivered
}

/// Revoke all active Space credential `jti`s for `target_did` in `(conversation_id, generation)`
/// and fan out `com.atproto.space.notifyCredentialsRevoked` to ALL writers' PDSes.
pub async fn revoke_member_space_credentials_and_fan_out(
    runtime: &SpaceHostRuntime,
    conversation_id: Uuid,
    generation: i64,
    target_did: &str,
) -> Result<usize, String> {
    let space_uri: Option<String> = sqlx::query_scalar(
        "SELECT space_uri FROM chat.conversation_spaces WHERE conversation_id = $1 AND generation = $2",
    )
    .bind(conversation_id)
    .bind(generation)
    .fetch_optional(runtime.pool())
    .await
    .map_err(|e| e.to_string())?;

    let Some(space_uri) = space_uri else {
        return Ok(0);
    };

    let now = crate::sim_hooks::current_utc();
    let mut revoked_jtis: Vec<String> = sqlx::query_scalar(
        "UPDATE chat.space_credential_jtis \
            SET revoked_at = $3 \
          WHERE space_uri = $1 \
            AND writer_did = $2 \
            AND revoked_at IS NULL \
            AND expires_at > $3 \
      RETURNING jti",
    )
    .bind(&space_uri)
    .bind(target_did)
    .bind(now)
    .fetch_all(runtime.pool())
    .await
    .map_err(|e| e.to_string())?;
    // `UPDATE .. RETURNING` has no row-order guarantee. Keep the wire payload
    // stable so retries and deterministic simulator replays send identical bytes.
    revoked_jtis.sort_unstable();

    if revoked_jtis.is_empty() {
        return Ok(0);
    }

    // Fan out to EVERY writer's PDS in this Space (so cached credentials are evicted across every writer repo host).
    let writer_dids: Vec<String> = sqlx::query_scalar(
        "SELECT writer_did FROM chat.conversation_space_writers WHERE space_uri = $1 ORDER BY writer_did ASC",
    )
    .bind(&space_uri)
    .fetch_all(runtime.pool())
    .await
    .map_err(|e| e.to_string())?;

    Ok(fan_out_revoked_jtis_to_writers(runtime, &space_uri, &revoked_jtis, &writer_dids).await)
}

/// Revoke all active Space credentials across every active conversation where `target_did` participates
/// (used post-commit after `revokeDevice`).
pub async fn revoke_user_space_credentials_across_conversations(
    runtime: &SpaceHostRuntime,
    target_did: &str,
) -> Result<usize, String> {
    let now = crate::sim_hooks::current_utc();
    let pairs: Vec<(Uuid, i64)> = sqlx::query_as(
        "SELECT cs.conversation_id, cs.generation \
           FROM chat.conversation_spaces cs \
           JOIN chat.space_credential_jtis j ON j.space_uri = cs.space_uri \
          WHERE j.writer_did = $1 \
            AND j.revoked_at IS NULL \
            AND j.expires_at > $2 \
          GROUP BY cs.conversation_id, cs.generation",
    )
    .bind(target_did)
    .bind(now)
    .fetch_all(runtime.pool())
    .await
    .map_err(|e| e.to_string())?;

    let mut total = 0_usize;
    for (conversation_id, generation) in pairs {
        total += revoke_member_space_credentials_and_fan_out(
            runtime,
            conversation_id,
            generation,
            target_did,
        )
        .await?;
    }
    Ok(total)
}

/// Revoke active Space credentials and fan out `notifyCredentialsRevoked` for any writer in
/// `(conversation_id, generation)` whose `chat.participants` membership is no longer active (`M-F04`).
pub async fn revoke_inactive_space_credentials_for_conversation(
    runtime: &SpaceHostRuntime,
    conversation_id: Uuid,
    generation: i64,
) -> Result<usize, String> {
    let now = crate::sim_hooks::current_utc();
    let inactive_writers: Vec<String> = sqlx::query_scalar(
        "SELECT DISTINCT j.writer_did \
           FROM chat.conversation_spaces cs \
           JOIN chat.space_credential_jtis j ON j.space_uri = cs.space_uri \
          WHERE cs.conversation_id = $1 \
            AND cs.generation = $2 \
            AND j.revoked_at IS NULL \
            AND j.expires_at > $3 \
            AND NOT EXISTS ( \
                SELECT 1 \
                  FROM chat.participants p \
                 WHERE p.conversation_id = $1 \
                   AND p.user_did = j.writer_did \
                   AND p.current_membership = TRUE \
                   AND p.status = 'active' \
            )",
    )
    .bind(conversation_id)
    .bind(generation)
    .bind(now)
    .fetch_all(runtime.pool())
    .await
    .map_err(|e| e.to_string())?;

    let mut total = 0_usize;
    for writer_did in &inactive_writers {
        total += revoke_member_space_credentials_and_fan_out(
            runtime,
            conversation_id,
            generation,
            writer_did,
        )
        .await?;
    }
    Ok(total)
}

#[derive(Debug, Clone)]
pub struct PreparedSpaceDeletedFanout {
    pub space_uri: String,
    pub subscribers: Vec<(String, String)>,
    pub revoked_jtis: Vec<String>,
    pub writer_dids: Vec<String>,
}

/// Capture Space deletion notification targets inside the caller's transaction
/// before `chat.wipe_closed_conversation_operational_rows` deletes the rows.
pub async fn prepare_space_deleted_fanout_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    conversation_id: Uuid,
    generation: i64,
) -> Result<Option<PreparedSpaceDeletedFanout>, String> {
    let now = crate::sim_hooks::current_utc();
    let space_uri: Option<String> = sqlx::query_scalar(
        "SELECT space_uri FROM chat.conversation_spaces \
          WHERE conversation_id = $1 AND generation = $2",
    )
    .bind(conversation_id)
    .bind(generation)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|e| e.to_string())?;
    let Some(space_uri) = space_uri else {
        return Ok(None);
    };
    let subscribers: Vec<(String, String)> = sqlx::query_as(
        "SELECT endpoint_url, token \
           FROM chat.conversation_space_subscribers \
          WHERE space_uri = $1 AND confirmed = TRUE \
          ORDER BY endpoint_url ASC, token ASC",
    )
    .bind(&space_uri)
    .fetch_all(&mut **tx)
    .await
    .map_err(|e| e.to_string())?;
    let mut revoked_jtis: Vec<String> = sqlx::query_scalar(
        "SELECT jti FROM chat.space_credential_jtis \
          WHERE space_uri = $1 AND revoked_at IS NULL AND expires_at > $2",
    )
    .bind(&space_uri)
    .bind(now)
    .fetch_all(&mut **tx)
    .await
    .map_err(|e| e.to_string())?;
    revoked_jtis.sort_unstable();
    let writer_dids: BTreeSet<String> = sqlx::query_scalar(
        "SELECT writer_did FROM chat.conversation_space_writers WHERE space_uri = $1",
    )
    .bind(&space_uri)
    .fetch_all(&mut **tx)
    .await
    .map_err(|e| e.to_string())?
    .into_iter()
    .collect();
    Ok(Some(PreparedSpaceDeletedFanout {
        space_uri,
        subscribers,
        revoked_jtis,
        writer_dids: writer_dids.into_iter().collect(),
    }))
}

pub async fn deliver_prepared_space_deleted(
    runtime: &SpaceHostRuntime,
    prepared: PreparedSpaceDeletedFanout,
) -> Result<usize, String> {
    let mut delivered = 0_usize;
    let deleted_update = json!({
        "$type": "com.atproto.space.notifySpaceUpdate#spaceDeleted",
    });
    for (endpoint_url, token) in &prepared.subscribers {
        if post_syncer_space_update(
            endpoint_url,
            &prepared.space_uri,
            token,
            deleted_update.clone(),
        )
        .await
        .is_ok()
        {
            delivered += 1;
        }
    }
    delivered += fan_out_revoked_jtis_to_writers(
        runtime,
        &prepared.space_uri,
        &prepared.revoked_jtis,
        &prepared.writer_dids,
    )
    .await;
    Ok(delivered)
}

/// Mark a conversation generation's Space deleted, revoke unexpired credentials, and fan out
/// `com.atproto.space.notifySpaceUpdate#spaceDeleted` to confirmed subscribers plus
/// `com.atproto.space.notifyCredentialsRevoked` to writers' PDSes (`atproto#5187`).
pub async fn fan_out_space_deleted_for_conversation(
    runtime: &SpaceHostRuntime,
    conversation_id: Uuid,
    generation: i64,
) -> Result<usize, String> {
    let now = crate::sim_hooks::current_utc();
    let space_uri: Option<String> = sqlx::query_scalar(
        "UPDATE chat.conversation_spaces \
            SET deleted_at = COALESCE(deleted_at, $3) \
          WHERE conversation_id = $1 AND generation = $2 \
      RETURNING space_uri",
    )
    .bind(conversation_id)
    .bind(generation)
    .bind(now)
    .fetch_optional(runtime.pool())
    .await
    .map_err(|e| e.to_string())?;

    let Some(space_uri) = space_uri else {
        return Ok(0);
    };

    let mut revoked_jtis: Vec<String> = sqlx::query_scalar(
        "UPDATE chat.space_credential_jtis \
            SET revoked_at = $2 \
          WHERE space_uri = $1 AND revoked_at IS NULL AND expires_at > $2 \
      RETURNING jti",
    )
    .bind(&space_uri)
    .bind(now)
    .fetch_all(runtime.pool())
    .await
    .map_err(|e| e.to_string())?;
    revoked_jtis.sort_unstable();

    let subscribers: Vec<(String, String)> = sqlx::query_as(
        "SELECT endpoint_url, token \
           FROM chat.conversation_space_subscribers \
          WHERE space_uri = $1 AND confirmed = TRUE \
          ORDER BY endpoint_url ASC, token ASC",
    )
    .bind(&space_uri)
    .fetch_all(runtime.pool())
    .await
    .map_err(|e| e.to_string())?;

    let writer_dids: BTreeSet<String> = sqlx::query_scalar(
        "SELECT writer_did FROM chat.conversation_space_writers WHERE space_uri = $1",
    )
    .bind(&space_uri)
    .fetch_all(runtime.pool())
    .await
    .map_err(|e| e.to_string())?
    .into_iter()
    .collect();

    deliver_prepared_space_deleted(
        runtime,
        PreparedSpaceDeletedFanout {
            space_uri,
            subscribers,
            revoked_jtis,
            writer_dids: writer_dids.into_iter().collect(),
        },
    )
    .await
}

pub(crate) async fn fan_out_space_update_to_subscribers(
    runtime: &SpaceHostRuntime,
    space_uri: &str,
    space_rev: &str,
    active_update: Value,
) -> Result<usize, String> {
    let now = crate::sim_hooks::current_utc();
    let active_subscribers: Vec<(String, String)> = sqlx::query_as(
        "SELECT endpoint_url, token \
           FROM chat.conversation_space_subscribers \
          WHERE space_uri = $1 AND confirmed = TRUE AND expires_at > $2 \
          ORDER BY endpoint_url ASC, token ASC",
    )
    .bind(space_uri)
    .bind(now)
    .fetch_all(runtime.pool())
    .await
    .map_err(|e| e.to_string())?;

    let expired_subscribers: Vec<(String, String)> = sqlx::query_as(
        "UPDATE chat.conversation_space_subscribers \
            SET notified_expired = TRUE, updated_at = $2 \
          WHERE space_uri = $1 \
            AND confirmed = TRUE \
            AND expires_at <= $2 \
            AND notified_expired = FALSE \
      RETURNING endpoint_url, token",
    )
    .bind(space_uri)
    .bind(now)
    .fetch_all(runtime.pool())
    .await
    .map_err(|e| e.to_string())?;

    let mut delivered = 0_usize;
    for (endpoint_url, token) in &active_subscribers {
        if post_syncer_space_update(endpoint_url, space_uri, token, active_update.clone())
            .await
            .is_ok()
        {
            delivered += 1;
        }
    }

    if !expired_subscribers.is_empty() {
        let mut sorted_expired = expired_subscribers;
        sorted_expired.sort_unstable();
        let expired_update = json!({
            "$type": "com.atproto.space.notifySpaceUpdate#registrationExpired",
            "spaceRev": space_rev,
        });
        for (endpoint_url, token) in &sorted_expired {
            if post_syncer_space_update(endpoint_url, space_uri, token, expired_update.clone())
                .await
                .is_ok()
            {
                delivered += 1;
            }
        }
    }

    Ok(delivered)
}

pub(crate) async fn fan_out_repo_write_to_subscribers(
    runtime: &SpaceHostRuntime,
    space_uri: &str,
    writer_did: &str,
    repo_rev: &str,
    space_rev: &str,
    prev_space_rev: Option<&str>,
    data_cid: &[u8; 32],
) -> Result<usize, String> {
    let mut update = json!({
        "$type": "com.atproto.space.defs#repoWrite",
        "repo": writer_did,
        "repoRev": repo_rev,
        "data": { "$bytes": STANDARD.encode(data_cid) },
        "spaceRev": space_rev,
    });
    if let Some(prev) = prev_space_rev {
        update["prevSpaceRev"] = json!(prev);
    }
    fan_out_space_update_to_subscribers(runtime, space_uri, space_rev, update).await
}

pub(crate) async fn fan_out_repo_removed_to_subscribers(
    runtime: &SpaceHostRuntime,
    space_uri: &str,
    writer_did: &str,
    space_rev: &str,
    prev_space_rev: Option<&str>,
) -> Result<usize, String> {
    let mut update = json!({
        "$type": "com.atproto.space.defs#repoRemoved",
        "repo": writer_did,
        "spaceRev": space_rev,
    });
    if let Some(prev) = prev_space_rev {
        update["prevSpaceRev"] = json!(prev);
    }
    fan_out_space_update_to_subscribers(runtime, space_uri, space_rev, update).await
}
