# Task 3 Report: Clean Federation Routing Schema, Advisory Replay, and Fresh DB Tests

## Summary
Completed Task 3 round in `/tmp/clean-fed-tree/mls-ds`.

### Key Changes
1. **Advisory Preflight Replay for `submitTransition` and `createConversation`**:
   - `create_conversation.rs` and `submit_transition.rs` preflight completed idempotency records before undertaking participant routing resolution.
   - Preflight is strictly advisory: a cache hit avoids expensive remote routing resolution while the canonical operation prelude retains transactional replay locking, post-state proof, and verbatim response release under the database transaction.

2. **21-Entry Reviewed Clean Protocol Migration Manifest & Migrator**:
   - `common::chat_protocol::CLEAN_PROTOCOL_13_MANIFEST` and `MIGRATION_VERSIONS` / `MIGRATION_FILES` / `MIGRATION_DESCRIPTIONS` expanded to 21 entries including:
     - `20260214000002_auth_jti_nonce.sql`
     - `20260722000001_chat_protocol_core.sql`
     - `20260722000002_chat_protocol_delivery.sql`
     - `20260722000003_chat_protocol_blobs.sql`
     - `20260725000001_prepare_welcome_provenance_backfill.sql`
     - `20260725000002_refine_welcome_provenance_quarantine.sql`
     - `20260726000001_welcome_supersession_provenance.sql`
     - `20260726000002_restore_welcome_provenance_deferred_triggers.sql`
     - `20260726000003_finalize_welcome_provenance_triggers.sql`
     - `20260728000001_chat_operation_claims.sql`
     - `20260728000002_exact_operation_claim_mutation_kind.sql`
     - `20260728000003_defer_operation_claim_principal_fk.sql`
     - `20260728000004_activate_operation_claim_completeness.sql`
     - `20260729000001_chat_g7_inventory_entitlement.sql`
     - `20260730000001_reset_request_revocation_terminal.sql`
     - `20260816000001_enable_send_message_operation_claims.sql`
     - `20260820000001_chat_service_auth_admissions.sql`
     - `20260820000002_chat_nullable_legacy_dpop_jkt.sql`
     - `20260821000001_fix_expired_inventory_session_gc.sql`
     - `20260824000001_chat_performance_indices.sql`
     - `20260824000003_chat_federation_routing.sql`
   - Self-contained migrator builds directly from the in-memory manifest and verifies exact checksums.

3. **Fresh Database Integration Tests**:
   - `server/tests/chat_protocol_create_conversation_handlers.rs` tests run against disposable PostgreSQL databases created via `common::fresh_db::fresh_clean_protocol_db("chat_convhandlers_", 4)`.
   - Verifies:
     - Cutover disabled returns `CutoverRequired` (400)
     - Cutover enabled missing auth returns `NotAuthorized` (401)
     - `createConversation` happy path with DID-typed participants succeeds (200 OK) with full 21-migration ledger verification, verifies `chat.conversations(is_remote=false, sequencer_ds=NULL, sequencer_term=0)` and `chat.participants(ds_did=NULL)`, validates inventory retrieval (`getConversations`), and proves byte-identical idempotent replay against `chat.idempotency_records`.
     - `submitTransition` policy add with deterministic relationship fallback persistence succeeds (200 OK) and verifies byte-identical idempotent replay.

## Commit
- **Commit ID**: `1de237dd48611468b2c885407d8fc6e3f14176fa`
- **Change ID**: `osypnxsquzymkxwzmpvukomumnyqprlx`
- **Description**: `fix(federation): register clean-chat federation routing migration in reviewed manifest, add submitTransition advisory replay, and cover fresh DB`

## Verification Output
```
running 9 tests
test create_conversation_cutover_disabled_returns_cutover_required ... ok
test create_conversation_cutover_enabled_missing_auth_returns_not_authorized ... ok
test create_conversation_happy_path_with_did_typed_participants_accepts_and_replays ... ok
test create_conversation_negative_corrupted_signature_returns_invalid_signature ... ignored, requires the dedicated clean-chat gate database
test create_conversation_negative_idempotency_conflict_returns_declared_error ... ignored, requires the dedicated clean-chat gate database
test create_then_list_returns_conversation_for_both_creator_and_invitee ... ignored, requires the dedicated clean-chat gate database
test submit_transition_negative_corrupted_signature_returns_invalid_signature ... ignored, requires the dedicated clean-chat gate database
test submit_transition_negative_invalid_request_returns_declared_4xx ... ignored, requires the dedicated clean-chat gate database
test submit_transition_policy_add_against_production_router_replays_byte_identically ... ok

test result: ok. 4 passed; 0 failed; 5 ignored; 0 measured; 0 filtered out; finished in 1.82s
```
