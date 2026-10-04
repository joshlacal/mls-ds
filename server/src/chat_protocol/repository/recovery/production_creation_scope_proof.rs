// Actual creation facade with an enrolled sibling outside the initial MLS tree.
use super::production_proof_fixture::{
    admit_lifecycle, creation_envelope, seed_identity, FixtureIdentity,
};
use super::*;

pub(super) async fn run_creation_with_enrolled_sibling(pool: &PgPool) -> Result<(), String> {
    require_local_owned_gate(pool).await?;
    let creator = FixtureIdentity::fresh(b"creation-event-scope-creator")?;
    let sibling = FixtureIdentity::fresh_for_did(&creator.did, b"creation-event-scope-sibling")?;
    let trusted = TrustedRequestInstant::capture().map_err(|e| format!("clock: {e:?}"))?;
    seed_identity(pool, &creator, &trusted).await?;
    seed_identity(pool, &sibling, &trusted).await?;
    let conversation_id = Uuid::new_v4();
    let envelope = creation_envelope(&creator, conversation_id, &trusted)?;
    let admission = admit_lifecycle(
        pool,
        &creator,
        "blue.catbird.chat.createConversation",
        &envelope,
        &trusted,
    )
    .await?;
    let guard = crate::chat_protocol::repository::relationship::load_fixed_relationship_authority_startup_guard()
        .map_err(|e| format!("relationship guard: {e:?}"))?;
    let relationship = crate::chat_protocol::relationship_policy::ProductionRelationshipAuthority::from_startup_guard(guard);
    let mut tx = pool.begin().await.map_err(|e| e.to_string())?;
    let prepared =
        crate::chat_protocol::repository::prelude::prepare_signed_operation(&mut tx, admission)
            .await
            .map_err(|e| format!("creation signed preparation: {e:?}"))?;
    let outcome = crate::chat_protocol::repository::creation::execute_prepared_creation(
        &mut tx,
        prepared,
        &relationship,
    )
    .await
    .map_err(|e| format!("creation with sibling scope: {e:?}"))?;
    if outcome.status() != 200 {
        return Err(format!("unexpected creation status {}", outcome.status()));
    }
    tx.commit()
        .await
        .map_err(|e| format!("commit creation: {e}"))?;
    let leaves: Vec<Uuid> = sqlx::query_scalar("SELECT device_id FROM chat.member_devices WHERE conversation_id=$1 AND active ORDER BY device_id")
        .bind(conversation_id).fetch_all(pool).await.map_err(|e| e.to_string())?;
    if leaves != vec![creator.device_id] {
        return Err(format!(
            "event lock scope changed actual MLS membership: {leaves:?}"
        ));
    }
    let recipients: Vec<Uuid> = sqlx::query_scalar("SELECT device_id FROM chat.entry_recipients WHERE conversation_id=$1 ORDER BY device_id")
        .bind(conversation_id).fetch_all(pool).await.map_err(|e| e.to_string())?;
    if recipients != vec![creator.device_id] {
        return Err(format!(
            "event lock scope expanded control delivery beyond creator leaf: {recipients:?}"
        ));
    }
    Ok(())
}
