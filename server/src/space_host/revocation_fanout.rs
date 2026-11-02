//! Post-commit Space revocation (`notifyCredentialRevoked`), Space deletion (`notifySpaceDeleted`),
//! and `notifyWrite` syncer fan-out (`M-F04`).
//!
//! CRITICAL INVARIANT (`M-F04`): Every function in this module runs strictly AFTER the outer
//! PostgreSQL transaction commits so webhook HTTP calls never hold open row locks or transactions.

use std::{collections::BTreeSet, time::Duration};

use base64::{engine::general_purpose::STANDARD, Engine as _};
use chrono::{DateTime, SecondsFormat, Utc};
use serde_json::{json, Value};
use uuid::Uuid;

use super::SpaceHostRuntime;
use crate::push_gateway::ssrf::{system_dns_resolve, validate_https_url_with_resolver};

async fn post_space_notice(
    runtime: &SpaceHostRuntime,
    target_did_or_ref: &str,
    explicit_endpoint_url: Option<&str>,
    nsid: &str,
    body: &Value,
) -> Result<(), String> {
    let (endpoint_base, is_test_override) = match explicit_endpoint_url {
        Some(url) if url.starts_with("http://127.0.0.1:") || url.starts_with("http://[::1]:") => {
            (url.trim_end_matches('/').to_string(), true)
        }
        Some(url) => (url.trim_end_matches('/').to_string(), false),
        None => {
            let (_, ep, is_override) = runtime
                .resolve_did_entry(target_did_or_ref, false)
                .await
                .map_err(|e| e.to_string())?;
            (ep, is_override)
        }
    };
    if endpoint_base.is_empty() {
        return Ok(());
    }

    let full_url = format!("{}/xrpc/{nsid}", endpoint_base.trim_end_matches('/'));
    let http_client = if is_test_override {
        reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(10))
            .build()
            .map_err(|e| e.to_string())?
    } else {
        let validated =
            validate_https_url_with_resolver(&full_url, None, false, system_dns_resolve)
                .map_err(|e| format!("Space notice SSRF check failed: {e}"))?;
        reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(10))
            .resolve_to_addrs(&validated.host, &validated.pinned_addrs)
            .build()
            .map_err(|e| e.to_string())?
    };

    let aud = if target_did_or_ref.contains('#') {
        target_did_or_ref.to_string()
    } else {
        format!("{target_did_or_ref}#atproto_pds")
    };
    let jwt = runtime.mint_service_jwt(&aud, nsid)?;
    let resp = http_client
        .post(&full_url)
        .header(reqwest::header::AUTHORIZATION, format!("Bearer {jwt}"))
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .json(body)
        .send()
        .await
        .map_err(|e| e.to_string())?;

    if !resp.status().is_success() {
        return Err(format!(
            "Space notice {nsid} returned HTTP {}",
            resp.status().as_u16()
        ));
    }
    Ok(())
}

/// Revoke all active Space credential `jti`s for `target_did` in `(conversation_id, generation)`
/// and fan out `com.atproto.space.notifyCredentialRevoked` to ALL writers' PDSes and active syncers!
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
    let revoked_rows: Vec<(String, DateTime<Utc>)> = sqlx::query_as(
        "UPDATE chat.space_credential_jtis \
            SET revoked_at = $3 \
          WHERE space_uri = $1 \
            AND writer_did = $2 \
            AND revoked_at IS NULL \
            AND expires_at > $3 \
      RETURNING jti, expires_at",
    )
    .bind(&space_uri)
    .bind(target_did)
    .bind(now)
    .fetch_all(runtime.pool())
    .await
    .map_err(|e| e.to_string())?;

    if revoked_rows.is_empty() {
        return Ok(0);
    }

    let credentials_json: Vec<Value> = revoked_rows
        .iter()
        .map(|(jti, exp)| {
            json!({
                "jti": jti,
                "expiresAt": exp.to_rfc3339_opts(SecondsFormat::Millis, true),
            })
        })
        .collect();

    let payload = json!({
        "space": space_uri,
        "credentials": credentials_json,
    });

    // Fan out to EVERY writer's PDS in this Space (so cached credentials are evicted across every writer repo host)
    let writer_dids: Vec<String> = sqlx::query_scalar(
        "SELECT writer_did FROM chat.conversation_space_writers WHERE space_uri = $1 ORDER BY writer_did ASC",
    )
    .bind(&space_uri)
    .fetch_all(runtime.pool())
    .await
    .map_err(|e| e.to_string())?;

    let mut delivered = 0_usize;
    for writer_did in &writer_dids {
        if post_space_notice(
            runtime,
            writer_did,
            None,
            "com.atproto.space.notifyCredentialRevoked",
            &payload,
        )
        .await
        .is_ok()
        {
            delivered += 1;
        }
    }

    let syncers: Vec<(String, String)> = sqlx::query_as(
        "SELECT service_ref, endpoint_url \
           FROM chat.conversation_space_syncers \
          WHERE space_uri = $1 AND expires_at > $2",
    )
    .bind(&space_uri)
    .bind(now)
    .fetch_all(runtime.pool())
    .await
    .map_err(|e| e.to_string())?;

    for (service_ref, endpoint_url) in &syncers {
        let _ = post_space_notice(
            runtime,
            service_ref,
            Some(endpoint_url),
            "com.atproto.space.notifyCredentialRevoked",
            &payload,
        )
        .await;
    }

    Ok(delivered)
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

/// Revoke active Space credentials and fan out `notifyCredentialRevoked` for any writer in
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

/// Mark a conversation generation's Space deleted and fan out `com.atproto.space.notifySpaceDeleted`
/// to all registered syncers and writers' PDSes (`atproto#5187`).
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

    let _ = sqlx::query(
        "UPDATE chat.space_credential_jtis \
            SET revoked_at = COALESCE(revoked_at, $2) \
          WHERE space_uri = $1 AND revoked_at IS NULL",
    )
    .bind(&space_uri)
    .bind(now)
    .execute(runtime.pool())
    .await;

    let payload = json!({ "space": space_uri });
    let mut delivered = 0_usize;

    let syncers: Vec<(String, String)> = sqlx::query_as(
        "SELECT service_ref, endpoint_url \
           FROM chat.conversation_space_syncers \
          WHERE space_uri = $1 AND expires_at > $2",
    )
    .bind(&space_uri)
    .bind(now)
    .fetch_all(runtime.pool())
    .await
    .map_err(|e| e.to_string())?;

    for (service_ref, endpoint_url) in &syncers {
        if post_space_notice(
            runtime,
            service_ref,
            Some(endpoint_url),
            "com.atproto.space.notifySpaceDeleted",
            &payload,
        )
        .await
        .is_ok()
        {
            delivered += 1;
        }
    }

    let writer_dids: BTreeSet<String> = sqlx::query_scalar(
        "SELECT writer_did FROM chat.conversation_space_writers WHERE space_uri = $1",
    )
    .bind(&space_uri)
    .fetch_all(runtime.pool())
    .await
    .map_err(|e| e.to_string())?
    .into_iter()
    .collect();

    for writer_did in writer_dids {
        if post_space_notice(
            runtime,
            &writer_did,
            None,
            "com.atproto.space.notifySpaceDeleted",
            &payload,
        )
        .await
        .is_ok()
        {
            delivered += 1;
        }
    }

    Ok(delivered)
}

pub(crate) async fn fan_out_notify_write_to_syncers(
    runtime: &SpaceHostRuntime,
    space_uri: &str,
    writer_did: &str,
    repo_rev: &str,
    space_rev: &str,
    data_cid: &[u8; 32],
) -> Result<usize, String> {
    let now = crate::sim_hooks::current_utc();
    let syncers: Vec<(String, String)> = sqlx::query_as(
        "SELECT service_ref, endpoint_url \
           FROM chat.conversation_space_syncers \
          WHERE space_uri = $1 AND expires_at > $2",
    )
    .bind(space_uri)
    .bind(now)
    .fetch_all(runtime.pool())
    .await
    .map_err(|e| e.to_string())?;

    if syncers.is_empty() {
        return Ok(0);
    }

    let payload = json!({
        "space": space_uri,
        "repo": writer_did,
        "repoRev": repo_rev,
        "spaceRev": space_rev,
        "data": { "$bytes": STANDARD.encode(data_cid) },
    });

    let mut delivered = 0_usize;
    for (service_ref, endpoint_url) in &syncers {
        if post_space_notice(
            runtime,
            service_ref,
            Some(endpoint_url),
            "com.atproto.space.notifyWrite",
            &payload,
        )
        .await
        .is_ok()
        {
            delivered += 1;
        }
    }
    Ok(delivered)
}
