use axum::{extract::State, http::StatusCode, Json};
use jacquard_axum::ExtractXrpc;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tracing::{error, info, warn};

use crate::{
    auth::AuthUser,
    block_sync::BlockSyncService,
    device_utils::parse_device_did,
    generated::blue_catbird::mlsChat::{
        get_key_packages::{GetKeyPackagesOutput, GetKeyPackagesRequest},
        KeyPackageRef,
    },
    storage::DbPool,
};

const NSID: &str = "blue.catbird.mlsChat.getKeyPackages";
const GATE_KEY_PACKAGES_MODE_ENV: &str = "GATE_KEY_PACKAGES_MODE";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GateKeyPackagesMode {
    LogOnly,
    Enforce,
}

impl GateKeyPackagesMode {
    pub fn from_env() -> Self {
        Self::from_env_value(std::env::var(GATE_KEY_PACKAGES_MODE_ENV).ok().as_deref())
    }

    pub fn from_env_value(value: Option<&str>) -> Self {
        match value.map(str::trim).map(str::to_ascii_lowercase).as_deref() {
            Some("log_only") | Some("warn") => Self::LogOnly,
            _ => Self::Enforce, // Enforce is now the default (N26 flip)
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::LogOnly => "log_only",
            Self::Enforce => "enforce",
        }
    }
}

const MAX_FIRST_CONTACT_TARGETS_DEFAULT: usize = 32;
const MAX_FIRST_CONTACT_TARGETS_ENV: &str = "MAX_FIRST_CONTACT_TARGETS";

/// Maximum number of DISTINCT first-contact (non-relationship-authorized) target
/// DIDs permitted in a single getKeyPackages call in Enforce mode. Stopgap until
/// the declared chat-permission policy (Track B) lands. A missing, unparseable,
/// or non-positive value falls back to the default — a zero bound would break
/// legitimate 1:1 first contact.
pub fn max_first_contact_targets() -> usize {
    max_first_contact_targets_from_value(
        std::env::var(MAX_FIRST_CONTACT_TARGETS_ENV).ok().as_deref(),
    )
}

pub fn max_first_contact_targets_from_value(value: Option<&str>) -> usize {
    value
        .map(str::trim)
        .and_then(|s| s.parse::<usize>().ok())
        .filter(|n| *n > 0)
        .unwrap_or(MAX_FIRST_CONTACT_TARGETS_DEFAULT)
}

/// Fetch and consume key packages for the given DIDs.
/// Returns one key package per device (identified by hashed device_id bucket)
/// for each requested DID, so that all of a user's devices can be added to a group.
/// GET /xrpc/blue.catbird.mlsChat.getKeyPackages
///
/// Block filtering: any target DID that has a block edge with the caller
/// (in either direction) is silently removed from the request. This closes
/// the final enforcement gap identified in Phase 3 of
/// docs/superpowers/plans/2026-04-15-block-leave-shared-groups.md
/// (Tasks 3.1 + 3.2 guard commits; this guards the key-package query).
#[tracing::instrument(skip(pool, block_sync, auth_user))]
pub async fn get_key_packages(
    State(pool): State<DbPool>,
    State(block_sync): State<Arc<BlockSyncService>>,
    auth_user: AuthUser,
    ExtractXrpc(input): ExtractXrpc<GetKeyPackagesRequest>,
) -> Result<Json<GetKeyPackagesOutput<'static>>, StatusCode> {
    if let Err(_e) = crate::auth::enforce_standard(&auth_user.claims, NSID) {
        return Err(StatusCode::UNAUTHORIZED);
    }

    if input.dids.len() > 100 {
        return Err(StatusCode::BAD_REQUEST);
    }

    // ── Block edge filter (PDS-first with bsky_blocks fallback) ───────
    // Silently drop any requested DID that has a block edge with the
    // caller in either direction. Mirrors the gate in addMembers /
    // external-commit but returns an empty result instead of a 4xx —
    // this is a query endpoint, not a commit.
    let caller_did_str = match parse_device_did(&auth_user.did) {
        Ok((user_did, _)) => user_did,
        Err(e) => {
            error!("getKeyPackages: invalid caller DID: {}", e);
            return Err(StatusCode::BAD_REQUEST);
        }
    };

    let requested_dids: Vec<String> = input.dids.iter().map(|d| d.to_string()).collect();

    // ── N26 (detection half): enumeration signal ───────────────────────
    // Track per-caller unique-target-DID cardinality over a sliding window,
    // on the RAW requested list (pre block/authz filtering — what the caller
    // asked for is the signal, not what they were given). Detection only:
    // WARN + counter, never a block. The enforce flip is gated on production
    // log observation (backlog N26).
    let enum_detector = super::key_package_enumeration::EnumerationDetector::global();
    if let Some(unique_targets) =
        enum_detector.record(&caller_did_str, requested_dids.iter().map(String::as_str))
    {
        warn!(
            caller = %crate::crypto::redact_for_log(&caller_did_str),
            unique_targets,
            threshold = enum_detector.threshold(),
            window_secs = enum_detector.window_secs(),
            "getKeyPackages: possible key-package enumeration — unique-target cardinality exceeded"
        );
        crate::metrics::record_key_package_enumeration_suspected();

        let mode = GateKeyPackagesMode::from_env();
        if mode == GateKeyPackagesMode::Enforce {
            return Err(StatusCode::TOO_MANY_REQUESTS);
        }
    }

    let mut participants: Vec<String> = requested_dids.clone();
    participants.push(caller_did_str.clone());
    participants.sort();
    participants.dedup();

    let edges: Vec<(String, String)> = if participants.len() >= 2 {
        match block_sync.check_block_conflicts(&participants).await {
            Ok(e) => e,
            Err(e) => {
                warn!(
                    "getKeyPackages: PDS block check failed, falling back to local DB: {}",
                    e
                );
                match sqlx::query_as::<_, (String, String)>(
                    "SELECT user_did, target_did FROM bsky_blocks
                     WHERE (user_did = $1 AND target_did = ANY($2))
                        OR (target_did = $1 AND user_did = ANY($2))",
                )
                .bind(&caller_did_str)
                .bind(&requested_dids)
                .fetch_all(&pool)
                .await
                {
                    Ok(rows) => rows,
                    Err(db_err) => {
                        error!("getKeyPackages: block fallback DB query failed: {}", db_err);
                        return Err(StatusCode::INTERNAL_SERVER_ERROR);
                    }
                }
            }
        }
    } else {
        Vec::new()
    };

    // Any DID on either side of a block edge involving the caller is
    // filtered out of the target list.
    let blocked_from_caller: HashSet<String> = edges
        .iter()
        .filter_map(|(blocker, blocked)| {
            if blocker == &caller_did_str {
                Some(blocked.clone())
            } else if blocked == &caller_did_str {
                Some(blocker.clone())
            } else {
                None
            }
        })
        .collect();

    let filtered_dids: Vec<jacquard_common::types::string::Did<'static>> = input
        .dids
        .iter()
        .filter(|d| !blocked_from_caller.contains(&d.to_string()))
        .map(|d| crate::sqlx_jacquard::string_to_did(d.as_ref()))
        .collect();

    if !blocked_from_caller.is_empty() {
        info!(
            requested = input.dids.len(),
            filtered = blocked_from_caller.len(),
            "getKeyPackages: filtered blocked target DIDs"
        );
    }

    if filtered_dids.is_empty() {
        // Query, not a denial — return OK with empty results.
        return Ok(Json(GetKeyPackagesOutput {
            key_packages: Vec::new(),
            missing: None,
            extra_data: Default::default(),
        }));
    }

    let filtered_did_strs: Vec<String> = filtered_dids
        .iter()
        .map(|d| d.as_ref().to_string())
        .collect();
    let filtered_did_refs: Vec<&str> = filtered_did_strs.iter().map(String::as_str).collect();
    let authorized_dids =
        authorize_get_key_package_targets(&pool, &caller_did_str, &filtered_did_refs)
            .await
            .map_err(|e| {
                error!("getKeyPackages: authz query failed: {}", e);
                StatusCode::INTERNAL_SERVER_ERROR
            })?;

    let mode = GateKeyPackagesMode::from_env();
    let authorized_set: HashSet<&str> = authorized_dids.iter().map(String::as_str).collect();
    let denied_count = filtered_did_strs
        .iter()
        .filter(|did| !authorized_set.contains(did.as_str()))
        .count();
    let first_contact_compat = is_single_first_contact_target(&filtered_did_strs, &authorized_dids);

    if denied_count > 0 {
        warn!(
            requested = filtered_did_strs.len(),
            denied = denied_count,
            first_contact_compat,
            mode = mode.as_str(),
            "getKeyPackages: unauthorized target DIDs"
        );
    }

    let filtered_did_strs =
        apply_key_package_target_authz(&filtered_did_strs, &authorized_dids, mode)?;
    let filtered_dids: Vec<jacquard_common::types::string::Did<'static>> = filtered_did_strs
        .iter()
        .map(|did| crate::sqlx_jacquard::string_to_did(did))
        .collect();

    let mut key_packages: Vec<KeyPackageRef<'static>> = Vec::new();
    let mut missing: Vec<String> = Vec::new();

    // Atomic bulk claim. One SQL round-trip returns one representative
    // (non-last-resort) row per (DID, device_id bucket) for every DID in the
    // request. The helper claims every available row in each selected bucket,
    // so duplicate rows cannot be depleted one at a time by repeat callers.
    //
    // Returns raw bytea — Jacquard's `Bytes` JSON serializer base64-encodes
    // at the wire boundary. Returning `encode(... , 'base64')` here produced
    // a second base64 layer, so iOS FFI received ASCII base64 text as raw KP
    // bytes and failed `tls_deserialize_bytes`.
    let did_strs: Vec<&str> = filtered_dids.iter().map(|d| d.as_ref()).collect();
    let claimed_rows = match claim_available_key_packages_bulk(
        &pool,
        &did_strs,
        input.cipher_suite.as_deref(),
        /* last_resort = */ false,
    )
    .await
    {
        Ok(rows) => rows,
        Err(e) => {
            error!("Bulk key-package claim failed: {}", e);
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };

    // Group claimed rows by DID. Any DID absent from the result set has zero
    // regular rows claimable and falls through to the last-resort pool.
    let mut rows_by_did: HashMap<String, Vec<(String, String, Vec<u8>, Option<String>)>> =
        HashMap::new();
    for row in claimed_rows {
        rows_by_did.entry(row.0.clone()).or_default().push(row);
    }

    // Last-resort fallback: identify DIDs with zero regular rows and run a
    // single bulk claim restricted to those DIDs against the last-resort
    // pool. Last-resort packages are still single-use here (state ->
    // claimed) — true "reusable last-resort" semantics are deferred to the
    // dedicated key-package plan.
    let unmatched_dids: Vec<&str> = did_strs
        .iter()
        .copied()
        .filter(|d| !rows_by_did.contains_key(*d))
        .collect();
    if !unmatched_dids.is_empty() {
        match claim_available_key_packages_bulk(
            &pool,
            &unmatched_dids,
            input.cipher_suite.as_deref(),
            /* last_resort = */ true,
        )
        .await
        {
            Ok(lr_rows) => {
                if !lr_rows.is_empty() {
                    let mut lr_dids: HashSet<String> = HashSet::new();
                    for row in lr_rows {
                        lr_dids.insert(row.0.clone());
                        rows_by_did.entry(row.0.clone()).or_default().push(row);
                    }
                    // One increment per DID that received a last-resort
                    // claim — preserves per-DID metric semantics from the
                    // pre-bulk loop.
                    for _ in 0..lr_dids.len() {
                        crate::metrics::record_key_package_last_resort_use();
                    }
                }
            }
            Err(e) => {
                warn!("Last-resort key-package bulk fallback failed: {}", e);
            }
        }
    }

    // Emit per-DID claim/no_match metrics + assemble response in the
    // requested DID order so the response is deterministic.
    for did in &filtered_dids {
        let did_str = did.as_ref();
        match rows_by_did.remove(did_str) {
            Some(rows) if !rows.is_empty() => {
                for (owner_did, cipher_suite, kp_bytes, kp_hash) in rows {
                    crate::metrics::record_key_package_claim("claimed");
                    key_packages.push(KeyPackageRef {
                        did: crate::sqlx_jacquard::string_to_did(&owner_did),
                        cipher_suite: cipher_suite.into(),
                        key_package: kp_bytes.into(),
                        key_package_hash: kp_hash.map(Into::into),
                        extra_data: Default::default(),
                    });
                }
            }
            _ => {
                crate::metrics::record_key_package_claim("no_match");
                crate::metrics::record_key_package_exhaustion();
                missing.push(did_str.to_string());
            }
        }
    }

    info!(
        requested = input.dids.len(),
        found = key_packages.len(),
        missing = missing.len(),
        "Key packages fetched and consumed (one per device)"
    );

    let missing_dids = if missing.is_empty() {
        None
    } else {
        Some(
            missing
                .into_iter()
                .map(|d| crate::sqlx_jacquard::string_to_did(&d))
                .collect(),
        )
    };

    Ok(Json(GetKeyPackagesOutput {
        key_packages,
        missing: missing_dids,
        extra_data: Default::default(),
    }))
}

/// Return the subset of requested target DIDs the caller may fetch key packages for.
pub async fn authorize_get_key_package_targets(
    pool: &DbPool,
    caller_did: &str,
    requested_dids: &[&str],
) -> Result<Vec<String>, sqlx::Error> {
    if requested_dids.is_empty() {
        return Ok(Vec::new());
    }

    sqlx::query_scalar::<_, String>(
        r#"
        WITH requested AS (
            SELECT did, ord
            FROM unnest($2::text[]) WITH ORDINALITY AS requested(did, ord)
        )
        SELECT r.did
        FROM requested r
        WHERE r.did = $1
           OR EXISTS (
                SELECT 1
                FROM members caller
                JOIN members target ON target.convo_id = caller.convo_id
                WHERE (caller.user_did = $1 OR caller.member_did = $1)
                  AND (target.user_did = r.did OR target.member_did = r.did)
                  AND caller.left_at IS NULL
                  AND target.left_at IS NULL
           )
           OR EXISTS (
                SELECT 1
                FROM chat_requests cr
                WHERE ((cr.sender_did = $1 AND cr.recipient_did = r.did)
                    OR (cr.recipient_did = $1 AND cr.sender_did = r.did))
                  AND cr.status::text IN ('pending', 'accepted')
                  AND cr.expires_at > NOW()
           )
           OR EXISTS (
                SELECT 1
                FROM invites i
                JOIN members caller ON caller.convo_id = i.convo_id
                WHERE (caller.user_did = $1 OR caller.member_did = $1)
                  AND caller.left_at IS NULL
                  AND i.target_did = r.did
                  AND i.revoked = false
                  AND (i.expires_at IS NULL OR i.expires_at > NOW())
                  AND (i.max_uses IS NULL OR i.uses_count < i.max_uses)
           )
        GROUP BY r.did, r.ord
        ORDER BY MIN(r.ord)
        "#,
    )
    .bind(caller_did)
    .bind(requested_dids)
    .fetch_all(pool)
    .await
}

pub fn apply_key_package_target_authz(
    requested_dids: &[String],
    authorized_dids: &[String],
    mode: GateKeyPackagesMode,
    max_first_contact: usize,
) -> Result<Vec<String>, StatusCode> {
    if requested_dids.is_empty() {
        return Ok(Vec::new());
    }

    match mode {
        GateKeyPackagesMode::LogOnly => Ok(requested_dids.to_vec()),
        GateKeyPackagesMode::Enforce => {
            let authorized_set: HashSet<&str> =
                authorized_dids.iter().map(String::as_str).collect();
            let all_authorized = requested_dids
                .iter()
                .all(|did| authorized_set.contains(did.as_str()));

            if all_authorized {
                return Ok(requested_dids.to_vec());
            }

            // Every requested DID that is not relationship-authorized is a
            // first-contact target — block edges are already filtered out
            // upstream in the handler. Bound the number of DISTINCT first-contact
            // targets so a legitimate group-create batch passes while large
            // multi-DID probing/depletion still fails closed. Counting is on the
            // distinct set (duplicate query params cannot inflate the count); the
            // returned vec preserves request order and duplicates for the fetch.
            let first_contact_unique: HashSet<&str> = requested_dids
                .iter()
                .map(String::as_str)
                .filter(|did| !authorized_set.contains(did))
                .collect();

            if first_contact_unique.len() <= max_first_contact {
                Ok(requested_dids.to_vec())
            } else {
                Err(StatusCode::FORBIDDEN)
            }
        }
    }
}

/// Atomically claim one available key package per `(owner_did, device_id)`
/// bucket for the supplied set of DIDs in a single SQL round-trip.
///
/// Returns rows of `(owner_did, cipher_suite, key_package, key_package_hash)`
/// for each successfully claimed package — one row per (DID, device_id)
/// bucket where an available row existed. The transition
/// `state='available' -> state='claimed'` is the atomic gate; concurrent
/// callers see disjoint rows because the row-pick CTE uses
/// `FOR UPDATE OF kp SKIP LOCKED`.
///
/// Replaces the previous per-DID helper that issued N round-trips for N
/// requested DIDs (PR review #23 follow-up). Per-device dedupe is preserved
/// via `ROW_NUMBER() OVER (PARTITION BY owner_did, COALESCE(device_id, ''))`
/// rather than `DISTINCT ON`, because Postgres rejects
/// `SELECT DISTINCT ON ... FOR UPDATE` at parse time
/// (`ERROR: FOR UPDATE is not allowed with DISTINCT clause`). The previous
/// shape was a server-wide regression: every `getKeyPackages` call returned
/// 500 in production.
///
/// `last_resort = false` filters to regular packages; `last_resort = true`
/// claims from the last-resort pool only. Last-resort packages are still
/// transitioned to `claimed` here — single-use semantics — pending the
/// dedicated key-package plan.
pub async fn claim_available_key_packages_bulk(
    pool: &DbPool,
    owner_dids: &[&str],
    cipher_suite: Option<&str>,
    last_resort: bool,
) -> Result<Vec<(String, String, Vec<u8>, Option<String>)>, sqlx::Error> {
    if owner_dids.is_empty() {
        return Ok(Vec::new());
    }

    let lr_predicate = if last_resort {
        "AND is_last_resort = true"
    } else {
        "AND is_last_resort = false"
    };
    let cs_predicate = if cipher_suite.is_some() {
        "AND cipher_suite = $2"
    } else {
        ""
    };

    // Three-stage CTE:
    //   `candidates` ranks rows per (owner_did, device-bucket) by created_at;
    //   `selected`   locks the rank-1 representative row for each bucket;
    //   `claimed`    claims every available row in each selected bucket.
    //
    // N23 requires bucket-wide claiming: returning one representative KP while
    // leaving duplicate rows in the same `(owner_did, COALESCE(device_id, ''))`
    // bucket available lets repeated calls deplete duplicates one at a time.
    //
    // We cannot use the simpler `SELECT DISTINCT ON ... FOR UPDATE` shape:
    // Postgres rejects it (`FOR UPDATE is not allowed with DISTINCT clause`),
    // and that prior shape returned 500 for every call. `FOR UPDATE` cannot
    // attach directly to a CTE name, hence the JOIN against `key_packages`
    // aliased as `kp` — the `OF kp` qualifier locks the underlying base-table
    // rows, which is what we want.
    //
    // Selection policy: NEWEST KP first (`ORDER BY created_at DESC`).
    // The freshest unconsumed KP on the server is the one most likely to
    // still be present in the recipient's local OpenMLS storage — older
    // KPs may have been evicted client-side (app reinstall, DB wipe,
    // device rotation) without the server learning of it until the next
    // `publishKeyPackages action=sync` round-trip. The 7-day TTL +
    // periodic sync handle stale-deadwood cleanup; this ORDER BY
    // optimizes the steady-state Welcome path. Previously this was
    // `ASC` (FIFO) which actively preferred the most-likely-stale KP.
    let sql = format!(
        "WITH candidates AS (
             SELECT id,
                    owner_did,
                    COALESCE(device_id, '') AS device_bucket,
                    ROW_NUMBER() OVER (
                        PARTITION BY owner_did, COALESCE(device_id, '')
                        ORDER BY created_at DESC
                    ) AS rn
             FROM key_packages
             WHERE owner_did = ANY($1::text[])
               AND state = 'available'
               AND expires_at > NOW()
               AND dead_at IS NULL
               {lr}
               {cs}
         ),
         selected AS (
             SELECT c.id, c.owner_did, c.device_bucket
             FROM candidates c
             JOIN key_packages kp ON kp.id = c.id
             WHERE c.rn = 1
             FOR UPDATE OF kp SKIP LOCKED
         ),
         claimed AS (
             UPDATE key_packages kp
             SET state = 'claimed', consumed_at = NOW()
             FROM selected s
             WHERE kp.owner_did = s.owner_did
               AND COALESCE(kp.device_id, '') = s.device_bucket
               AND kp.state = 'available'
               AND kp.expires_at > NOW()
               AND kp.dead_at IS NULL
               {lr}
               {cs}
             RETURNING kp.id
         )
         SELECT kp.owner_did, kp.cipher_suite, kp.key_package, kp.key_package_hash
         FROM selected s
         JOIN claimed c ON c.id = s.id
         JOIN key_packages kp ON kp.id = s.id",
        lr = lr_predicate,
        cs = cs_predicate,
    );

    // Bind the borrowed slice directly — sqlx maps `&[&str]` to Postgres
    // `text[]` without an intermediate `Vec<String>` allocation.
    let mut q =
        sqlx::query_as::<_, (String, String, Vec<u8>, Option<String>)>(&sql).bind(owner_dids);
    if let Some(cs) = cipher_suite {
        q = q.bind(cs);
    }
    q.fetch_all(pool).await
}
