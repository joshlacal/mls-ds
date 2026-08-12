// Gate-only relationship fallback minter.
//
// The Recovery client and fulfillment proofs deliberately refuse to manufacture
// relationship evidence: they only *select* an already-persisted, still-fresh
// `fallback` projection. Something has to have produced that projection through
// production code, and in a shipping deployment that producer is the ordinary
// relationship-refresh path. This module is that producer, and nothing more.
//
// Every column of every row it writes is produced by real production code:
//
//   1. `repository::relationship::load_fixed_relationship_authority_startup_guard`
//      builds the one fixed production configuration and its audited pinned
//      transport. There is no seam to substitute an origin or HTTP client.
//   2. `repository::relationship::allocate_projection_revision` mints each
//      non-reusable revision from the real PostgreSQL allocator function.
//   3. `ProductionRelationshipAuthority::collect_block_projection` performs the
//      real `app.bsky.graph.getRelationships` collection against the real
//      AppView, over the real rate gate, deadline, and response caps, and
//      returns `EvidenceKind::Live` evidence.
//   4. `RelationshipProjection::export_persisted_fallback` runs the production
//      persistence fence (`relationship_projection_persistence_valid`, twice)
//      and derives the `fallback` projection.
//   5. `repository::relationship::persist_relationship_projection` performs the
//      real insert, including `validate_relationship_projection_for_insert` and
//      the forced deferred cross-row constraints.
//
// The only thing this module chooses is *which* DIDs the fixture scope covers,
// which is the same fixture-identity seam `seed_durable_recovery_fixture_for_identity`
// already owns. It never writes a row itself, never relaxes a fence, and never
// constructs a relationship authority for a consumer to reuse.

use super::*;

/// Drive the real collect -> seal -> persist path for one BlockOnly scope.
async fn mint_block_only_fallback(
    pool: &PgPool,
    operation_scope: ProjectionOperationScope,
    label: &str,
    roster: Vec<String>,
) -> Result<(), String> {
    let authority =
        crate::chat_protocol::relationship_policy::ProductionRelationshipAuthority::from_startup_guard(
            crate::chat_protocol::repository::relationship::load_fixed_relationship_authority_startup_guard()
                .map_err(|error| {
                    format!("load fixed {label} relationship authority: {error:?}")
                })?,
        );

    // Two real, non-reusable PostgreSQL revision allocations: one is consumed by
    // the live collection, the other by the exported fallback snapshot. Sequence
    // values intentionally survive rollback, so these are committed on their own.
    let mut allocation_transaction = pool
        .begin()
        .await
        .map_err(|error| format!("begin {label} projection revision allocation: {error}"))?;
    let live_allocation =
        crate::chat_protocol::repository::relationship::allocate_projection_revision(
            &mut allocation_transaction,
        )
        .await
        .map_err(|error| format!("allocate live {label} projection revision: {error:?}"))?;
    let fallback_allocation =
        crate::chat_protocol::repository::relationship::allocate_projection_revision(
            &mut allocation_transaction,
        )
        .await
        .map_err(|error| format!("allocate {label} fallback projection revision: {error:?}"))?;
    allocation_transaction
        .commit()
        .await
        .map_err(|error| format!("commit {label} projection revision allocation: {error}"))?;

    let live = authority
        .collect_block_projection(live_allocation, operation_scope, roster)
        .await
        .map_err(|failure| format!("collect live {label} relationship projection: {failure:?}"))?;

    let observation =
        crate::chat_protocol::repository::relationship::observe_relationship_persistence();
    let sealed = live
        .export_persisted_fallback(fallback_allocation, &authority, &observation)
        .map_err(|error| format!("seal {label} relationship fallback: {error:?}"))?;

    let mut transaction = pool
        .begin()
        .await
        .map_err(|error| format!("begin {label} relationship fallback persistence: {error}"))?;
    crate::chat_protocol::repository::relationship::persist_relationship_projection(
        &mut transaction,
        sealed,
    )
    .await
    .map_err(|error| format!("persist {label} relationship fallback: {error:?}"))?;
    transaction
        .commit()
        .await
        .map_err(|error| format!("commit {label} relationship fallback: {error}"))?;
    Ok(())
}

/// Produce the fresh, exact singleton `recoveryReservation` fallback the client
/// Recovery proofs select. A one-DID BlockOnly scope plans zero graph calls by
/// construction (`plan_block_only_graph` orients every non-sink member at the
/// sink, and a singleton roster has no non-sink member), so this is the genuine
/// production projection for that scope rather than a truncated one.
pub async fn mint_singleton_recovery_reservation_fallback(
    pool: &PgPool,
    did: &str,
) -> Result<(), String> {
    require_local_owned_gate(pool).await?;
    mint_block_only_fallback(
        pool,
        ProjectionOperationScope::RecoveryReservation,
        "singleton recoveryReservation",
        vec![did.to_owned()],
    )
    .await
}

/// Produce the fresh, exact two-party `recoveryReservation` + `recoveryFulfillment`
/// fallback pair the Recovery fulfillment proofs select. Both projections cover
/// the same canonical two-DID BlockOnly scope, so they share one
/// `canonical_did_set_bytes`/`canonical_did_set_sha256` pair as the fulfillment
/// selector's join requires. This shape plans one real AppView graph call.
pub async fn mint_two_party_recovery_fallbacks(
    pool: &PgPool,
    first: &str,
    second: &str,
) -> Result<(), String> {
    require_local_owned_gate(pool).await?;
    let roster = vec![first.to_owned(), second.to_owned()];
    mint_block_only_fallback(
        pool,
        ProjectionOperationScope::RecoveryReservation,
        "two-party recoveryReservation",
        roster.clone(),
    )
    .await?;
    mint_block_only_fallback(
        pool,
        ProjectionOperationScope::RecoveryFulfillment,
        "two-party recoveryFulfillment",
        roster,
    )
    .await
}
