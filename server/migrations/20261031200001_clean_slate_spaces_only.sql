-- Migration: Clean-slate Spaces-only consolidation (G6, I6, I12, I13, I14, 1A, 2A, 3A, D1-D4).
-- Additive forward migration only; historical migrations remain byte-identical.
--
-- 1. Drop all legacy v1 mlsChat, legacy blob, APNs/notification, and actor tables from `public`,
--    retaining strictly S2S federation/nonce tables and `_sqlx_migrations`.
-- 2. Drop all server-side Labyrinth mailbox/thread/MEK/attachment/ORF/virtual-device tables from
--    `labyrinth`, retaining strictly `epoch_heads` (`EpochPublic` chain), `epoch_head_floors`
--    (L-F01 monotonic floor), and short-TTL `operations`.
-- 3. Drop `chat.blob_*` server-blob tables and raw `push_token*` columns on `chat.devices`;
--    add `last_active_at` / `dormant_at` (60-day dormancy), `chat.device_entry_acks`,
--    `chat.conversation_spaces`, `chat.conversation_space_syncers`, `chat.space_credential_jtis`,
--    `chat.space_delegation_jtis`, and `chat.push_gateway_bindings` (D2).
-- 4. Enable non-destructive ciphertext pruning (`accepted_payload_bytes -> NULL`) strictly on
--    `applicationEntry` rows (`chat.entries` + `chat.message_sends`), add `sequencer_receipt_bytes`
--    (`I13`), and add `blue.catbird.chat.defs#accountDeletedEntry`.
-- 5. Allow `C33` 30-day direct-request expiry to transition `chat.conversations.lifecycle` and
--    `chat.generations.lifecycle` to `'superseded'` (`close_transition_id IS NULL`) when backed
--    by a canonical `chat.direct_request_lifecycle.consent = 'expired'` record.
-- 6. Add `chat.wipe_closed_conversation_operational_rows(UUID)` to wipe operational rows of
--    closed/superseded conversations (`G6`, `I14`) while refusing `active` conversations.

-- =============================================================================
-- 1. Drop legacy `public` tables (keep strictly S2S federation/nonce + sqlx)
-- =============================================================================

DROP TABLE IF EXISTS
    public.admin_actions,
    public.auto_reset_history,
    public.blobs,
    public.bsky_blocks,
    public.chat_request_rate_limits,
    public.chat_requests,
    public.commits,
    public.conversation_policy,
    public.conversations,
    public.crypto_sessions,
    public.cursors,
    public.dead_letter_recoveries,
    public.delivery_acks,
    public.delivery_events,
    public.device_auth_binding_challenges,
    public.device_auth_dpop_replay,
    public.devices,
    public.envelopes,
    public.epoch_authenticators,
    public.event_stream,
    public.external_commit_audit,
    public.group_metadata_blobs,
    public.held_messages,
    public.idempotency_cache,
    public.invites,
    public.key_package_audit,
    public.key_packages,
    public.members,
    public.message_reactions,
    public.message_recipients,
    public.messages,
    public.notification_outbox,
    public.opt_in,
    public.pending_device_additions,
    public.pending_welcomes,
    public.read_receipts,
    public.recovery_failures,
    public.reissue_requests,
    public.rejoin_requests,
    public.reports,
    public.reset_reminder_state,
    public.reset_votes,
    public.schema_version,
    public.sequencer_receipts,
    public.sequencer_receipts_v2,
    public.spam_reports,
    public.users,
    public.welcome_messages,
    public.ws_ticket_nonce
CASCADE;

-- =============================================================================
-- 2. Drop server-side `labyrinth` content/mailbox/ORF/virtual-device stores
-- =============================================================================

DROP TABLE IF EXISTS
    labyrinth.attachment_blobs,
    labyrinth.attachment_refs,
    labyrinth.author_usage,
    labyrinth.batch_items,
    labyrinth.batches,
    labyrinth.devices,
    labyrinth.epoch_members,
    labyrinth.epochs,
    labyrinth.mailboxes,
    labyrinth.mek_recipients,
    labyrinth.meks,
    labyrinth.orf_state_tombstones,
    labyrinth.orf_states,
    labyrinth.owner_batch_items,
    labyrinth.owner_batches,
    labyrinth.redacted_messages,
    labyrinth.relay_outbox,
    labyrinth.thread_counters,
    labyrinth.thread_storage,
    labyrinth.virtual_devices
CASCADE;

DROP FUNCTION IF EXISTS labyrinth.redact_items(UUID, TEXT, TEXT[], JSONB, TIMESTAMPTZ) CASCADE;
DROP FUNCTION IF EXISTS labyrinth.drop_virtual_device(TEXT, TEXT, TIMESTAMPTZ) CASCADE;
DROP FUNCTION IF EXISTS labyrinth.expire_virtual_devices(TIMESTAMPTZ, INTEGER) CASCADE;
DROP FUNCTION IF EXISTS labyrinth.sender_message_state(UUID, TEXT, TEXT) CASCADE;
DROP FUNCTION IF EXISTS labyrinth.message_live_for(UUID, TEXT, TEXT, TEXT) CASCADE;
DROP FUNCTION IF EXISTS labyrinth.guard_thread_storage() CASCADE;
DROP FUNCTION IF EXISTS labyrinth.guard_space_batch_metadata() CASCADE;

CREATE OR REPLACE FUNCTION labyrinth.purge_mailbox(owner TEXT)
RETURNS void
LANGUAGE plpgsql
AS $$
DECLARE
    prior_max BIGINT;
BEGIN
    PERFORM labyrinth.open_retention_scope();
    SELECT MAX(epoch_number) INTO prior_max
      FROM labyrinth.epoch_heads
     WHERE did = owner;
    IF prior_max IS NOT NULL THEN
        INSERT INTO labyrinth.epoch_head_floors (did, max_epoch_number, updated_at)
        VALUES (owner, prior_max, clock_timestamp())
        ON CONFLICT (did) DO UPDATE
           SET max_epoch_number = GREATEST(
                   labyrinth.epoch_head_floors.max_epoch_number,
                   EXCLUDED.max_epoch_number
               ),
               updated_at = EXCLUDED.updated_at;
    END IF;
    DELETE FROM labyrinth.epoch_heads WHERE did = owner;
END;
$$;

-- =============================================================================
-- 3. Drop `chat.blob_*` & raw `push_token*`; add clean-slate operational tables
-- =============================================================================

DROP TABLE IF EXISTS
    chat.blob_bindings,
    chat.blob_upload_tickets,
    chat.blobs,
    chat.blob_usage
CASCADE;

DROP FUNCTION IF EXISTS chat.assert_blob_binding_integrity(UUID) CASCADE;
DROP FUNCTION IF EXISTS chat.enforce_blob_binding_integrity() CASCADE;
DROP FUNCTION IF EXISTS chat.assert_blob_ticket_integrity(UUID) CASCADE;
DROP FUNCTION IF EXISTS chat.enforce_blob_ticket_integrity() CASCADE;
DROP FUNCTION IF EXISTS chat.reconcile_blob_usage_counters(TEXT) CASCADE;
DROP FUNCTION IF EXISTS chat.assert_blob_usage_reconciled(TEXT) CASCADE;
DROP FUNCTION IF EXISTS chat.enforce_blob_usage_reconciled() CASCADE;
DROP FUNCTION IF EXISTS chat.enforce_blob_lifecycle_transition() CASCADE;

ALTER TABLE chat.devices
    DROP COLUMN IF EXISTS push_token,
    DROP COLUMN IF EXISTS push_token_updated_at,
    ADD COLUMN last_active_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    ADD COLUMN dormant_at TIMESTAMPTZ;

DROP TRIGGER IF EXISTS devices_identity_immutable ON chat.devices;
CREATE TRIGGER devices_identity_immutable
BEFORE UPDATE OR DELETE ON chat.devices
FOR EACH ROW EXECUTE FUNCTION chat.enforce_immutable_identity(
    'device_name', 'status', 'dpop_jkt', 'auth_generation', 'capabilities',
    'last_active_at', 'dormant_at', 'updated_at', 'revoked_at', 'revocation_id'
);

CREATE TABLE chat.device_entry_acks (
    conversation_id UUID NOT NULL REFERENCES chat.conversations(conversation_id) ON DELETE CASCADE,
    user_did TEXT NOT NULL,
    device_id UUID NOT NULL,
    acked_through_seq BIGINT NOT NULL CHECK (chat.is_safe_integer(acked_through_seq) AND acked_through_seq >= 1),
    updated_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (conversation_id, user_did, device_id),
    CONSTRAINT device_entry_acks_device_fk FOREIGN KEY (user_did, device_id)
        REFERENCES chat.devices(user_did, device_id) ON DELETE CASCADE
);

CREATE TABLE chat.conversation_spaces (
    conversation_id UUID NOT NULL,
    generation BIGINT NOT NULL,
    space_uri TEXT NOT NULL UNIQUE,
    authority_did TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (conversation_id, generation),
    CONSTRAINT conversation_spaces_generation_fk FOREIGN KEY (conversation_id, generation)
        REFERENCES chat.generations(conversation_id, generation) ON DELETE CASCADE,
    CONSTRAINT conversation_spaces_uri_check CHECK (space_uri LIKE 'at://%/space/blue.catbird.labyrinth.conversation/%')
);

CREATE TABLE chat.conversation_space_syncers (
    space_uri TEXT NOT NULL REFERENCES chat.conversation_spaces(space_uri) ON DELETE CASCADE,
    service_did TEXT NOT NULL,
    endpoint_url TEXT NOT NULL,
    registered_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (space_uri, service_did),
    CONSTRAINT conversation_space_syncers_did_check CHECK (chat.is_bare_did(service_did))
);

CREATE TABLE chat.space_credential_jtis (
    jti TEXT PRIMARY KEY,
    space_uri TEXT NOT NULL,
    writer_did TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT space_credential_jtis_did_check CHECK (chat.is_bare_did(writer_did))
);
CREATE INDEX space_credential_jtis_expires_idx ON chat.space_credential_jtis (expires_at);

CREATE TABLE chat.space_delegation_jtis (
    authority_did TEXT NOT NULL,
    jti TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (authority_did, jti)
);
CREATE INDEX space_delegation_jtis_expires_idx ON chat.space_delegation_jtis (expires_at);

CREATE TABLE chat.push_gateway_bindings (
    user_did TEXT NOT NULL,
    device_id UUID NOT NULL,
    gateway_url TEXT NOT NULL,
    app_id TEXT NOT NULL,
    push_key TEXT NOT NULL,
    key_id TEXT NOT NULL,
    auth_generation BIGINT NOT NULL CHECK (chat.is_safe_integer(auth_generation) AND auth_generation >= 1),
    signed_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (user_did, device_id),
    CONSTRAINT push_gateway_bindings_device_fk FOREIGN KEY (user_did, device_id)
        REFERENCES chat.devices(user_did, device_id) ON DELETE CASCADE,
    CONSTRAINT push_gateway_bindings_https_check CHECK (gateway_url LIKE 'https://%/xrpc/blue.catbird.push.deliver'),
    CONSTRAINT push_gateway_bindings_app_id_check CHECK (char_length(app_id) BETWEEN 1 AND 128),
    CONSTRAINT push_gateway_bindings_push_key_check CHECK (char_length(push_key) BETWEEN 16 AND 256)
);

-- =============================================================================
-- 4. Non-destructive `applicationEntry` pruning + `I13` receipts + `accountDeletedEntry`
-- =============================================================================

ALTER TABLE chat.entries
    ALTER COLUMN accepted_payload_bytes DROP NOT NULL,
    ALTER COLUMN signed_request_bytes DROP NOT NULL,
    ADD COLUMN payload_pruned_at TIMESTAMPTZ,
    ADD COLUMN sequencer_receipt_bytes BYTEA;

ALTER TABLE chat.entries DROP CONSTRAINT entries_kind_check;
ALTER TABLE chat.entries ADD CONSTRAINT entries_kind_check CHECK (entry_kind IN (
    'blue.catbird.chat.defs#applicationEntry',
    'blue.catbird.chat.defs#commitEntry',
    'blue.catbird.chat.defs#policyEntry',
    'blue.catbird.chat.defs#metadataEntry',
    'blue.catbird.chat.defs#creationEntry',
    'blue.catbird.chat.defs#participantAcceptanceEntry',
    'blue.catbird.chat.defs#conversationCloseEntry',
    'blue.catbird.chat.defs#resetRequestEntry',
    'blue.catbird.chat.defs#resetActivationEntry',
    'blue.catbird.chat.defs#leafRecoveryFulfillmentEntry',
    'blue.catbird.chat.defs#leaveRequestEntry',
    'blue.catbird.chat.defs#zeroLeafLeaveEntry',
    'blue.catbird.chat.defs#leaveCancellationEntry',
    'blue.catbird.chat.defs#leaveCommitFulfillmentEntry',
    'blue.catbird.chat.defs#directRequestEntry',
    'blue.catbird.chat.defs#directRequestAcceptanceEntry',
    'blue.catbird.chat.defs#accountDeletedEntry'
));

ALTER TABLE chat.entries DROP CONSTRAINT entries_reference_shape_check;
ALTER TABLE chat.entries ADD CONSTRAINT entries_reference_shape_check CHECK ((
    (entry_kind = 'blue.catbird.chat.defs#applicationEntry'
        AND message_id IS NOT NULL AND transition_id IS NULL)
    OR (entry_kind IN (
            'blue.catbird.chat.defs#resetRequestEntry',
            'blue.catbird.chat.defs#leaveRequestEntry',
            'blue.catbird.chat.defs#leaveCancellationEntry',
            'blue.catbird.chat.defs#accountDeletedEntry'
        ) AND transition_id IS NULL AND message_id IS NULL)
    OR (entry_kind NOT IN (
            'blue.catbird.chat.defs#directRequestEntry',
            'blue.catbird.chat.defs#applicationEntry',
            'blue.catbird.chat.defs#resetRequestEntry',
            'blue.catbird.chat.defs#leaveRequestEntry',
            'blue.catbird.chat.defs#leaveCancellationEntry',
            'blue.catbird.chat.defs#accountDeletedEntry'
        )
        AND transition_id IS NOT NULL AND message_id IS NULL)
) OR (
    entry_kind = 'blue.catbird.chat.defs#directRequestEntry'
    AND transition_id IS NOT NULL
    AND message_id IS NULL
));

ALTER TABLE chat.entries DROP CONSTRAINT entries_payload_hash_check;
ALTER TABLE chat.entries ADD CONSTRAINT entries_payload_hash_check CHECK (
    (payload_pruned_at IS NULL
        AND accepted_payload_bytes IS NOT NULL
        AND octet_length(accepted_payload_bytes) BETWEEN 1 AND 16777216
        AND signed_request_bytes IS NOT NULL
        AND octet_length(signed_request_bytes) BETWEEN 1 AND 16777216
        AND octet_length(accepted_payload_sha256) = 32
        AND accepted_payload_sha256 = digest(accepted_payload_bytes, 'sha256'))
    OR (payload_pruned_at IS NOT NULL
        AND entry_kind = 'blue.catbird.chat.defs#applicationEntry'
        AND accepted_payload_bytes IS NULL
        AND signed_request_bytes IS NULL
        AND octet_length(accepted_payload_sha256) = 32)
);

CREATE OR REPLACE FUNCTION chat.open_conversation_wipe_scope()
RETURNS void
LANGUAGE sql
AS $$ SELECT set_config('chat.conversation_wipe_scope', txid_current()::text, true) $$;

CREATE OR REPLACE FUNCTION chat.in_conversation_wipe_scope()
RETURNS boolean
LANGUAGE sql
STABLE
AS $$
    SELECT coalesce(current_setting('chat.conversation_wipe_scope', true), '')
           = txid_current()::text
$$;

CREATE OR REPLACE FUNCTION chat.enforce_immutable_identity()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    mutable_columns TEXT[] := CASE
        WHEN TG_NARGS = 0 THEN ARRAY[]::TEXT[]
        ELSE TG_ARGV
    END;
    delete_scope TEXT;
BEGIN
    IF TG_OP = 'DELETE' THEN
        IF chat.in_conversation_wipe_scope() THEN
            RETURN OLD;
        END IF;
        delete_scope := current_setting('chat.inventory_gc_delete_table', true);
        IF TG_TABLE_SCHEMA = 'chat'
           AND TG_TABLE_NAME IN (
               'inventory_sessions',
               'device_inventory_sessions',
               'inventory_conversation_items',
               'inventory_welcome_items',
               'inventory_recovery_items',
               'subscription_tickets',
               'inventory_page_receipts',
               'event_cursor_receipts',
               'device_inventory_items'
           )
           AND delete_scope = format(
               '%s:%s.%s',
               txid_current(),
               TG_TABLE_SCHEMA,
               TG_TABLE_NAME
           ) THEN
            RETURN OLD;
        END IF;
        RAISE EXCEPTION 'immutable chat row cannot be deleted: %.%', TG_TABLE_SCHEMA, TG_TABLE_NAME
            USING ERRCODE = '23514';
    END IF;
    IF (to_jsonb(NEW) - mutable_columns)
       IS DISTINCT FROM (to_jsonb(OLD) - mutable_columns) THEN
        RAISE EXCEPTION 'immutable chat identity/provenance changed: %.%', TG_TABLE_SCHEMA, TG_TABLE_NAME
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END
$$;

CREATE OR REPLACE FUNCTION chat.guard_direct_request_lifecycle() RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        IF chat.in_conversation_wipe_scope() THEN
            RETURN OLD;
        END IF;
        RAISE EXCEPTION 'direct request consent evidence is retained' USING ERRCODE='23514';
    END IF;
    IF NEW.request_id IS DISTINCT FROM OLD.request_id
       OR NEW.conversation_id IS DISTINCT FROM OLD.conversation_id
       OR NEW.acceptance_proof IS DISTINCT FROM OLD.acceptance_proof
       OR NEW.acceptance_digest IS DISTINCT FROM OLD.acceptance_digest
       OR NEW.accepted_at IS DISTINCT FROM OLD.accepted_at
       OR (OLD.consent='closed' AND NEW IS DISTINCT FROM OLD)
       OR (OLD.consent='accepted' AND NEW.consent NOT IN ('accepted','closed')) THEN
        RAISE EXCEPTION 'direct request consent evidence is immutable and monotonic' USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END $$;

CREATE OR REPLACE FUNCTION chat.preserve_direct_request_attempt() RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        IF chat.in_conversation_wipe_scope() THEN
            RETURN OLD;
        END IF;
        RAISE EXCEPTION 'direct request tombstones cannot be deleted';
    END IF;
    IF OLD.status <> 'prepared' AND NEW IS DISTINCT FROM OLD THEN
        RAISE EXCEPTION 'terminal direct request receipt is immutable';
    END IF;
    IF ROW(NEW.request_id,NEW.actor_did,NEW.actor_device_id,NEW.actor_key_id,NEW.actor_auth_generation,
           NEW.recipient_did,NEW.prepare_digest,NEW.prepare_response,NEW.selected_digest,NEW.prepared_at,
           NEW.lease_expires_at,NEW.created_at)
       IS DISTINCT FROM ROW(OLD.request_id,OLD.actor_did,OLD.actor_device_id,OLD.actor_key_id,OLD.actor_auth_generation,
           OLD.recipient_did,OLD.prepare_digest,OLD.prepare_response,OLD.selected_digest,OLD.prepared_at,
           OLD.lease_expires_at,OLD.created_at) THEN
        RAISE EXCEPTION 'direct request identity and selection are immutable';
    END IF;
    RETURN NEW;
END $$;

CREATE OR REPLACE FUNCTION chat.preserve_direct_request_selection() RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' AND chat.in_conversation_wipe_scope() THEN
        RETURN OLD;
    END IF;
    RAISE EXCEPTION 'direct request device selection is immutable';
END $$;

CREATE OR REPLACE FUNCTION chat.enforce_direct_request_transport_entries_immutable()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        IF chat.in_conversation_wipe_scope() THEN
            RETURN OLD;
        END IF;
        RAISE EXCEPTION 'transport entries are immutable' USING ERRCODE = '23514';
    END IF;
    IF TG_OP = 'UPDATE' THEN
        IF NEW.conversation_id <> OLD.conversation_id
           OR NEW.seq <> OLD.seq
           OR NEW.entry_id <> OLD.entry_id
           OR NEW.entry_bytes <> OLD.entry_bytes THEN
            RAISE EXCEPTION 'transport entries cannot be modified' USING ERRCODE = '23514';
        END IF;
        NEW.created_at := OLD.created_at;
    END IF;
    RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION chat.enforce_direct_request_remote_leases_monotonic()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        IF chat.in_conversation_wipe_scope() THEN
            RETURN OLD;
        END IF;
        RAISE EXCEPTION 'remote lease rows are immutable' USING ERRCODE = '23514';
    END IF;
    IF NEW.lease_id <> OLD.lease_id
       OR NEW.request_id <> OLD.request_id
       OR NEW.coordinator_did <> OLD.coordinator_did
       OR NEW.sender_did <> OLD.sender_did
       OR NEW.recipient_did <> OLD.recipient_did
       OR NEW.key_package_ref <> OLD.key_package_ref
       OR NEW.owner_device_id <> OLD.owner_device_id
       OR NEW.leased_at <> OLD.leased_at
       OR NEW.expires_at <> OLD.expires_at THEN
        RAISE EXCEPTION 'remote lease immutable columns cannot be modified' USING ERRCODE = '23514';
    END IF;
    IF OLD.status NOT IN ('active', 'expired') AND NEW.status <> OLD.status THEN
        RAISE EXCEPTION 'terminal remote lease status is irreversible' USING ERRCODE = '23514';
    END IF;
    IF OLD.status = 'expired' AND NEW.status NOT IN ('expired', 'finalized', 'released') THEN
        RAISE EXCEPTION 'expired remote lease can only be released or finalized' USING ERRCODE = '23514';
    END IF;
    IF OLD.finalized_at IS NOT NULL AND NEW.finalized_at IS DISTINCT FROM OLD.finalized_at THEN
        RAISE EXCEPTION 'finalized_at is irreversible' USING ERRCODE = '23514';
    END IF;
    IF OLD.released_at IS NOT NULL AND NEW.released_at IS DISTINCT FROM OLD.released_at THEN
        RAISE EXCEPTION 'released_at is irreversible' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION chat.enforce_direct_request_transport_inbox_monotonic()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        IF chat.in_conversation_wipe_scope() THEN
            RETURN OLD;
        END IF;
        RAISE EXCEPTION 'transport inbox rows are immutable' USING ERRCODE = '23514';
    END IF;
    IF NEW.delivery_id <> OLD.delivery_id
       OR NEW.request_id <> OLD.request_id
       OR NEW.conversation_id <> OLD.conversation_id
       OR NEW.first_message_id <> OLD.first_message_id
       OR NEW.coordinator_did <> OLD.coordinator_did
       OR NEW.sender_did <> OLD.sender_did
       OR NEW.sender_device_id IS DISTINCT FROM OLD.sender_device_id
       OR NEW.recipient_did <> OLD.recipient_did
       OR NEW.recipient_device_id <> OLD.recipient_device_id
       OR NEW.full_welcome <> OLD.full_welcome
       OR NEW.full_welcome_sha256 <> OLD.full_welcome_sha256
       OR NEW.created_at <> OLD.created_at
       OR NEW.request_entry <> OLD.request_entry
       OR NEW.signed_publication <> OLD.signed_publication
       OR NEW.provenance <> OLD.provenance
       OR NEW.publication_receipt <> OLD.publication_receipt
       OR NEW.import_until <> OLD.import_until THEN
        RAISE EXCEPTION 'transport inbox immutable identity cannot be modified' USING ERRCODE = '23514';
    END IF;
    IF OLD.status <> 'pending' AND NEW.status <> OLD.status THEN
        RAISE EXCEPTION 'terminal transport inbox status is irreversible' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION chat.enforce_entries_immutable()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    mutable_cols CONSTANT TEXT[] := ARRAY[
        'accepted_payload_bytes',
        'signed_request_bytes',
        'payload_pruned_at',
        'sequencer_receipt_bytes'
    ];
BEGIN
    IF TG_OP = 'DELETE' THEN
        IF chat.in_conversation_wipe_scope() THEN
            RETURN OLD;
        END IF;
        RAISE EXCEPTION 'immutable row cannot be deleted: %.%', TG_TABLE_SCHEMA, TG_TABLE_NAME
            USING ERRCODE = '23514';
    END IF;
    IF (to_jsonb(NEW) - mutable_cols) IS DISTINCT FROM (to_jsonb(OLD) - mutable_cols) THEN
        RAISE EXCEPTION 'immutable identity/provenance changed: %.%', TG_TABLE_SCHEMA, TG_TABLE_NAME
            USING ERRCODE = '23514';
    END IF;
    IF OLD.sequencer_receipt_bytes IS NOT NULL
       AND NEW.sequencer_receipt_bytes IS DISTINCT FROM OLD.sequencer_receipt_bytes THEN
        RAISE EXCEPTION 'sequencer receipt cannot be rewritten: %.%', TG_TABLE_SCHEMA, TG_TABLE_NAME
            USING ERRCODE = '23514';
    END IF;
    IF (NEW.accepted_payload_bytes, NEW.signed_request_bytes, NEW.payload_pruned_at)
       IS DISTINCT FROM
       (OLD.accepted_payload_bytes, OLD.signed_request_bytes, OLD.payload_pruned_at) THEN
        IF NOT (
            OLD.entry_kind = 'blue.catbird.chat.defs#applicationEntry'
            AND OLD.payload_pruned_at IS NULL
            AND NEW.payload_pruned_at IS NOT NULL
            AND NEW.accepted_payload_bytes IS NULL
            AND NEW.signed_request_bytes IS NULL
        ) THEN
            RAISE EXCEPTION 'only unpruned applicationEntry ciphertext may be pruned to NULL'
                USING ERRCODE = '23514';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS entries_immutable ON chat.entries;
CREATE TRIGGER entries_immutable
BEFORE UPDATE OR DELETE ON chat.entries
FOR EACH ROW EXECUTE FUNCTION chat.enforce_entries_immutable();

ALTER TABLE chat.message_sends
    ALTER COLUMN signed_request_bytes DROP NOT NULL,
    ALTER COLUMN signing_transcript_bytes DROP NOT NULL,
    ALTER COLUMN outcome_bytes DROP NOT NULL,
    ADD COLUMN payload_pruned_at TIMESTAMPTZ;

ALTER TABLE chat.message_sends DROP CONSTRAINT message_sends_signature_check;
ALTER TABLE chat.message_sends ADD CONSTRAINT message_sends_signature_check CHECK (
    (payload_pruned_at IS NULL
        AND signed_request_bytes IS NOT NULL
        AND signing_transcript_bytes IS NOT NULL
        AND octet_length(signed_request_bytes) BETWEEN 1 AND 16777216
        AND octet_length(signing_transcript_bytes) BETWEEN 1 AND 16777216
        AND octet_length(request_digest) = 32
        AND request_digest = digest(signing_transcript_bytes, 'sha256')
        AND octet_length(signature) = 64)
    OR (payload_pruned_at IS NOT NULL
        AND status = 'accepted'
        AND signed_request_bytes IS NULL
        AND signing_transcript_bytes IS NULL
        AND octet_length(request_digest) = 32
        AND octet_length(signature) = 64)
);

ALTER TABLE chat.message_sends DROP CONSTRAINT message_sends_outcome_hash_check;
ALTER TABLE chat.message_sends ADD CONSTRAINT message_sends_outcome_hash_check CHECK (
    (payload_pruned_at IS NULL
        AND outcome_bytes IS NOT NULL
        AND octet_length(outcome_bytes) BETWEEN 1 AND 16777216
        AND octet_length(outcome_sha256) = 32
        AND outcome_sha256 = digest(outcome_bytes, 'sha256'))
    OR (payload_pruned_at IS NOT NULL
        AND outcome_bytes IS NULL
        AND octet_length(outcome_sha256) = 32)
);

CREATE OR REPLACE FUNCTION chat.enforce_message_sends_immutable()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    mutable_cols CONSTANT TEXT[] := ARRAY[
        'signed_request_bytes',
        'signing_transcript_bytes',
        'outcome_bytes',
        'payload_pruned_at'
    ];
BEGIN
    IF TG_OP = 'DELETE' THEN
        IF chat.in_conversation_wipe_scope() THEN
            RETURN OLD;
        END IF;
        RAISE EXCEPTION 'immutable row cannot be deleted: %.%', TG_TABLE_SCHEMA, TG_TABLE_NAME
            USING ERRCODE = '23514';
    END IF;
    IF (to_jsonb(NEW) - mutable_cols) IS DISTINCT FROM (to_jsonb(OLD) - mutable_cols) THEN
        RAISE EXCEPTION 'immutable identity/provenance changed: %.%', TG_TABLE_SCHEMA, TG_TABLE_NAME
            USING ERRCODE = '23514';
    END IF;
    IF NOT (
        OLD.status = 'accepted'
        AND OLD.payload_pruned_at IS NULL
        AND NEW.payload_pruned_at IS NOT NULL
        AND NEW.signed_request_bytes IS NULL
        AND NEW.signing_transcript_bytes IS NULL
        AND NEW.outcome_bytes IS NULL
    ) THEN
        RAISE EXCEPTION 'only accepted unpruned message_sends payload may be pruned to NULL'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS message_sends_immutable ON chat.message_sends;
CREATE TRIGGER message_sends_immutable
BEFORE UPDATE OR DELETE ON chat.message_sends
FOR EACH ROW EXECUTE FUNCTION chat.enforce_message_sends_immutable();

CREATE OR REPLACE FUNCTION chat.assert_message_send_mapping(
    target_conversation UUID,
    target_message UUID
)
RETURNS void
LANGUAGE plpgsql
AS $$
DECLARE
    remote BOOLEAN;
    cutoff BIGINT;
    entry_seq BIGINT;
    entry_state_version_null BOOLEAN;
    send_row chat.message_sends%ROWTYPE;
    send_found BOOLEAN;
    entry_count BIGINT;
BEGIN
    SELECT is_remote, historical_bootstrap_last_seq
      INTO remote, cutoff
      FROM chat.conversations
     WHERE conversation_id = target_conversation
     FOR UPDATE;

    SELECT * INTO send_row
      FROM chat.message_sends
     WHERE conversation_id = target_conversation
       AND message_id = target_message;
    send_found := FOUND;

    SELECT count(*), min(seq), bool_and(state_version IS NULL)
      INTO entry_count, entry_seq, entry_state_version_null
      FROM chat.entries
     WHERE conversation_id = target_conversation
       AND message_id = target_message;

    IF remote AND cutoff IS NOT NULL AND entry_count = 1 AND entry_seq <= cutoff AND entry_state_version_null THEN
        IF send_found THEN
            RAISE EXCEPTION 'historical bootstrap application entry must have zero message_sends'
                USING ERRCODE = '23514';
        END IF;
        RETURN;
    END IF;

    IF NOT send_found THEN
        IF entry_count <> 0 THEN
            RAISE EXCEPTION 'application message mapping mismatch'
                USING ERRCODE = '23514';
        END IF;
        RETURN;
    END IF;

    IF send_row.status = 'accepted' THEN
        IF entry_count <> 1 OR NOT EXISTS (
            SELECT 1 FROM chat.entries
             WHERE conversation_id = target_conversation
               AND seq = send_row.accepted_entry_seq
               AND message_id = target_message
               AND entry_kind = 'blue.catbird.chat.defs#applicationEntry'
               AND signed_request_bytes IS NOT DISTINCT FROM send_row.signed_request_bytes
               AND (payload_pruned_at IS NULL) = (send_row.payload_pruned_at IS NULL)
               AND request_digest = send_row.request_digest
               AND signature = send_row.signature
               AND received_at = send_row.received_at
        ) THEN
            RAISE EXCEPTION 'application message mapping mismatch'
                USING ERRCODE = '23514';
        END IF;
    ELSIF entry_count <> 0 THEN
        RAISE EXCEPTION 'application message mapping mismatch'
            USING ERRCODE = '23514';
    END IF;
END
$$;

-- =============================================================================
-- 5. C33 30-day direct-request expiry (`lifecycle = 'superseded'` without close transition)
-- =============================================================================

ALTER TABLE chat.conversations DROP CONSTRAINT conversations_close_shape_check;
ALTER TABLE chat.conversations ADD CONSTRAINT conversations_close_shape_check CHECK (
    (lifecycle = 'active' AND close_transition_id IS NULL AND close_generation IS NULL
        AND close_state_version IS NULL AND close_seq IS NULL AND closed_at IS NULL)
    OR
    (lifecycle = 'superseded' AND close_transition_id IS NOT NULL AND close_generation IS NOT NULL
        AND close_state_version IS NOT NULL AND close_seq IS NOT NULL AND closed_at IS NOT NULL)
    OR
    (lifecycle = 'superseded' AND kind = 'direct' AND protocol_version = '2'
        AND close_transition_id IS NULL AND close_generation IS NULL
        AND close_state_version IS NULL AND close_seq IS NULL AND closed_at IS NULL)
);

DROP TRIGGER IF EXISTS conversations_identity_immutable ON chat.conversations;
CREATE TRIGGER conversations_identity_immutable
BEFORE UPDATE OR DELETE ON chat.conversations
FOR EACH ROW EXECUTE FUNCTION chat.enforce_immutable_identity(
    'lifecycle', 'current_generation', 'current_state_version', 'next_entry_seq',
    'close_transition_id', 'close_generation', 'close_state_version', 'close_seq',
    'closed_at', 'historical_bootstrap_last_seq', 'historical_bootstrap_birth_xid',
    'protocol_version', 'is_remote', 'sequencer_ds', 'sequencer_term'
);

CREATE OR REPLACE FUNCTION chat.enforce_conversation_pointer_agreement()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    target_conversation UUID;
    conversation_lifecycle TEXT;
    close_transition UUID;
    target_generation BIGINT;
    target_state_version BIGINT;
    active_generations BIGINT;
    maximum_generation BIGINT;
    pointed_generation_lifecycle TEXT;
    pointed_state_lifecycle TEXT;
    is_expired_direct_request BOOLEAN;
BEGIN
    IF TG_OP = 'DELETE' THEN target_conversation := OLD.conversation_id;
    ELSE target_conversation := NEW.conversation_id;
    END IF;
    PERFORM 1 FROM chat.conversations
     WHERE conversation_id = target_conversation
     FOR UPDATE;
    SELECT c.lifecycle, c.close_transition_id, c.current_generation, c.current_state_version
      INTO conversation_lifecycle, close_transition, target_generation, target_state_version
      FROM chat.conversations c
     WHERE c.conversation_id = target_conversation;
    IF NOT FOUND THEN
        IF TG_OP = 'DELETE' THEN RETURN OLD; END IF;
        RETURN NEW;
    END IF;
    SELECT count(*) INTO active_generations
      FROM chat.generations g
     WHERE g.conversation_id = target_conversation AND g.lifecycle = 'active';
    SELECT max(generation) INTO maximum_generation
      FROM chat.generations
     WHERE conversation_id = target_conversation;
    SELECT g.lifecycle, s.lifecycle
      INTO pointed_generation_lifecycle, pointed_state_lifecycle
      FROM chat.generations g
      JOIN chat.generation_states s
        ON s.conversation_id = g.conversation_id
       AND s.generation = g.generation
       AND s.state_version = g.current_state_version
     WHERE g.conversation_id = target_conversation
       AND g.generation = target_generation
       AND s.state_version = target_state_version;
    IF conversation_lifecycle = 'active' THEN
        IF active_generations <> 1
           OR target_generation IS DISTINCT FROM maximum_generation
           OR pointed_generation_lifecycle IS DISTINCT FROM 'active'
           OR pointed_state_lifecycle IS DISTINCT FROM 'active' THEN
            RAISE EXCEPTION 'active conversation pointer disagreement' USING ERRCODE = '23514';
        END IF;
    ELSE
        SELECT EXISTS (
            SELECT 1 FROM chat.direct_request_lifecycle l
             WHERE l.conversation_id = target_conversation
               AND l.consent = 'expired'
        ) INTO is_expired_direct_request;
        IF active_generations <> 0
           OR target_generation IS DISTINCT FROM maximum_generation
           OR (close_transition IS NOT NULL AND pointed_state_lifecycle IS DISTINCT FROM 'superseded')
           OR (close_transition IS NULL AND NOT is_expired_direct_request) THEN
            RAISE EXCEPTION 'terminal conversation pointer disagreement' USING ERRCODE = '23514';
        END IF;
    END IF;
    RETURN NEW;
END
$$;

CREATE OR REPLACE FUNCTION chat.enforce_generation_pointer_agreement()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    target_conversation UUID;
    target_generation BIGINT;
    generation_lifecycle TEXT;
    generation_current_state_version BIGINT;
    maximum_state_version BIGINT;
    pointed_lifecycle TEXT;
    pointed_kind TEXT;
    is_expired_direct_request BOOLEAN;
BEGIN
    IF TG_OP = 'DELETE' THEN
        target_conversation := OLD.conversation_id;
        target_generation := OLD.generation;
    ELSE
        target_conversation := NEW.conversation_id;
        target_generation := NEW.generation;
    END IF;
    PERFORM 1 FROM chat.conversations
     WHERE conversation_id = target_conversation
     FOR UPDATE;
    SELECT g.lifecycle, g.current_state_version
      INTO generation_lifecycle, generation_current_state_version
      FROM chat.generations g
     WHERE g.conversation_id = target_conversation AND g.generation = target_generation;
    IF NOT FOUND THEN
        IF TG_OP = 'DELETE' THEN RETURN OLD; END IF;
        RETURN NEW;
    END IF;
    SELECT s.lifecycle, s.state_kind INTO pointed_lifecycle, pointed_kind
      FROM chat.generation_states s
     WHERE s.conversation_id = target_conversation
       AND s.generation = target_generation
       AND s.state_version = generation_current_state_version;
    SELECT max(state_version) INTO maximum_state_version
      FROM chat.generation_states
     WHERE conversation_id = target_conversation
       AND generation = target_generation;
    SELECT EXISTS (
        SELECT 1 FROM chat.direct_request_lifecycle l
         WHERE l.conversation_id = target_conversation
           AND l.consent = 'expired'
    ) INTO is_expired_direct_request;
    IF generation_current_state_version IS DISTINCT FROM maximum_state_version
       OR (pointed_lifecycle IS DISTINCT FROM generation_lifecycle
           AND NOT (
               generation_lifecycle = 'superseded'
               AND pointed_lifecycle = 'active'
               AND pointed_kind = 'directRequestPublication'
               AND is_expired_direct_request
           )) THEN
        RAISE EXCEPTION 'generation pointer disagreement' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END
$$;

CREATE OR REPLACE FUNCTION chat.assert_conversation_entry_contiguity(target_conversation UUID)
RETURNS void
LANGUAGE plpgsql
AS $$
DECLARE
    conversation_row chat.conversations%ROWTYPE;
    entry_count BIGINT;
    minimum_seq BIGINT;
    maximum_seq BIGINT;
    is_expired_direct_request BOOLEAN;
BEGIN
    SELECT * INTO conversation_row
      FROM chat.conversations
     WHERE conversation_id = target_conversation
     FOR UPDATE;
    IF NOT FOUND THEN RETURN; END IF;

    SELECT count(*), min(seq), max(seq)
      INTO entry_count, minimum_seq, maximum_seq
      FROM chat.entries
     WHERE conversation_id = target_conversation;

    SELECT EXISTS (
        SELECT 1 FROM chat.direct_request_lifecycle l
         WHERE l.conversation_id = target_conversation
           AND l.consent = 'expired'
    ) INTO is_expired_direct_request;

    IF (entry_count = 0 AND conversation_row.next_entry_seq <> 1)
       OR (entry_count > 0 AND (
            minimum_seq <> 1
            OR maximum_seq <> entry_count
            OR conversation_row.next_entry_seq <> maximum_seq + 1
       ))
       OR (conversation_row.lifecycle = 'superseded' AND (
            (conversation_row.close_seq IS NOT NULL AND maximum_seq IS DISTINCT FROM conversation_row.close_seq)
            OR (conversation_row.close_seq IS NULL AND NOT is_expired_direct_request)
       )) THEN
        RAISE EXCEPTION 'conversation entry sequence is not contiguous'
            USING ERRCODE = '23514';
    END IF;
END
$$;

CREATE OR REPLACE FUNCTION chat.assert_conversation_terminal_schedules(target_conversation UUID)
RETURNS void
LANGUAGE plpgsql
AS $$
DECLARE
    conversation_row chat.conversations%ROWTYPE;
    schedule_count BIGINT;
    proof_count BIGINT;
BEGIN
    SELECT * INTO conversation_row
      FROM chat.conversations
     WHERE conversation_id = target_conversation
     FOR UPDATE;
    IF NOT FOUND THEN RETURN; END IF;
    SELECT count(*) INTO schedule_count FROM (
        SELECT DISTINCT recipient_did, recipient_device_id
          FROM chat.application_intervals
         WHERE conversation_id = target_conversation
    ) schedules;
    SELECT count(*) INTO proof_count
      FROM chat.application_schedule_terminal_proofs
     WHERE conversation_id = target_conversation;

    IF conversation_row.lifecycle = 'active' THEN
        IF proof_count <> 0 THEN
            RAISE EXCEPTION 'active conversation has terminal schedule proof'
                USING ERRCODE = '23514';
        END IF;
        RETURN;
    END IF;

    IF conversation_row.close_transition_id IS NULL THEN
        IF NOT EXISTS (
            SELECT 1 FROM chat.direct_request_lifecycle l
             WHERE l.conversation_id = target_conversation
               AND l.consent = 'expired'
        ) OR proof_count <> 0 THEN
            RAISE EXCEPTION 'expired direct request terminal schedule state invalid'
                USING ERRCODE = '23514';
        END IF;
        RETURN;
    END IF;

    IF schedule_count <> proof_count OR EXISTS (
        SELECT 1
          FROM (
            SELECT DISTINCT recipient_did, recipient_device_id
              FROM chat.application_intervals
             WHERE conversation_id = target_conversation
          ) schedule
          LEFT JOIN chat.application_schedule_terminal_proofs proof
            ON proof.conversation_id = target_conversation
           AND proof.recipient_did = schedule.recipient_did
           AND proof.recipient_device_id = schedule.recipient_device_id
         WHERE proof.conversation_id IS NULL
    ) OR EXISTS (
        SELECT 1
          FROM chat.application_schedule_terminal_proofs proof
         WHERE proof.conversation_id = target_conversation
           AND (
                proof.terminal_seq <> conversation_row.close_seq
                OR proof.transition_id <> conversation_row.close_transition_id
                OR proof.received_at <> conversation_row.closed_at
                OR NOT EXISTS (
                    SELECT 1
                      FROM chat.application_intervals interval
                     WHERE interval.conversation_id = proof.conversation_id
                       AND interval.recipient_did = proof.recipient_did
                       AND interval.recipient_device_id = proof.recipient_device_id
                       AND interval.start_seq < proof.terminal_seq
                )
                OR NOT EXISTS (
                    SELECT 1
                      FROM chat.entry_recipients recipient
                     WHERE recipient.conversation_id = proof.conversation_id
                       AND recipient.seq = proof.terminal_seq
                       AND recipient.user_did = proof.recipient_did
                       AND recipient.device_id = proof.recipient_device_id
                       AND recipient.entitlement_kind = 'scheduleTerminal'
                )
                OR EXISTS (
                    SELECT 1
                      FROM chat.application_intervals later
                     WHERE later.conversation_id = proof.conversation_id
                       AND later.recipient_did = proof.recipient_did
                       AND later.recipient_device_id = proof.recipient_device_id
                       AND later.start_seq >= proof.terminal_seq
                )
           )
    ) THEN
        RAISE EXCEPTION 'terminal conversation schedule proof set mismatch'
            USING ERRCODE = '23514';
    END IF;
END
$$;

-- =============================================================================
-- 6. Closed/superseded conversation operational wipe (`G6`, `I14`)
-- =============================================================================

CREATE OR REPLACE FUNCTION chat.wipe_closed_conversation_operational_rows(target_conversation UUID)
RETURNS BOOLEAN
LANGUAGE plpgsql
AS $$
DECLARE
    conv_lifecycle TEXT;
    req_ids UUID[];
    gross_retained BIGINT := 0;
BEGIN
    SELECT lifecycle INTO conv_lifecycle
      FROM chat.conversations
     WHERE conversation_id = target_conversation
     FOR UPDATE;
    IF NOT FOUND THEN
        RETURN FALSE;
    END IF;
    IF conv_lifecycle = 'active' THEN
        RAISE EXCEPTION 'cannot wipe operational rows of active conversation %', target_conversation
            USING ERRCODE = '23514';
    END IF;

    PERFORM chat.open_conversation_wipe_scope();

    SELECT array_agg(request_id) INTO req_ids
      FROM chat.direct_request_publications
     WHERE conversation_id = target_conversation;

    DELETE FROM chat.device_entry_acks WHERE conversation_id = target_conversation;
    DELETE FROM chat.conversation_space_syncers
     WHERE space_uri IN (
         SELECT space_uri FROM chat.conversation_spaces WHERE conversation_id = target_conversation
     );
    DELETE FROM chat.space_credential_jtis
     WHERE space_uri IN (
         SELECT space_uri FROM chat.conversation_spaces WHERE conversation_id = target_conversation
     );
    DELETE FROM chat.conversation_spaces WHERE conversation_id = target_conversation;

    DELETE FROM chat.direct_request_transport_entries WHERE conversation_id = target_conversation;
    DELETE FROM chat.direct_request_transport_inbox WHERE conversation_id = target_conversation;

    IF req_ids IS NOT NULL THEN
        SELECT COALESCE(sum(charged_bytes), 0) INTO gross_retained
          FROM chat.direct_request_retained_charges
         WHERE request_id = ANY(req_ids);

        DELETE FROM chat.key_packages
         WHERE terminal_remote_lease_id IN (
             SELECT lease_id FROM chat.direct_request_remote_leases WHERE request_id = ANY(req_ids)
         );
        DELETE FROM chat.direct_request_push_event_recipients WHERE request_id = ANY(req_ids);
        DELETE FROM chat.direct_request_push_events WHERE request_id = ANY(req_ids);
        DELETE FROM chat.direct_request_welcome_outcomes WHERE request_id = ANY(req_ids);
        DELETE FROM chat.direct_request_decision_slots WHERE request_id = ANY(req_ids);
        DELETE FROM chat.direct_request_expiry_receipts WHERE request_id = ANY(req_ids);
        DELETE FROM chat.direct_request_acceptance_claims WHERE request_id = ANY(req_ids);
        DELETE FROM chat.direct_request_retained_releases WHERE request_id = ANY(req_ids);
        DELETE FROM chat.direct_request_retained_charges WHERE request_id = ANY(req_ids);
        IF gross_retained > 0 THEN
            UPDATE chat.direct_request_budget
               SET retained_bytes = GREATEST(0, retained_bytes - gross_retained)
             WHERE singleton;
        END IF;
        DELETE FROM chat.direct_request_pending_releases WHERE request_id = ANY(req_ids);
        DELETE FROM chat.direct_request_lifecycle_reserves WHERE request_id = ANY(req_ids);
        DELETE FROM chat.direct_request_lifecycle WHERE request_id = ANY(req_ids);
        DELETE FROM chat.direct_request_reserved_remote_packages WHERE request_id = ANY(req_ids);
        DELETE FROM chat.direct_request_reservation_intents WHERE request_id = ANY(req_ids);
        DELETE FROM chat.direct_request_outbound_routes WHERE request_id = ANY(req_ids);
        DELETE FROM chat.direct_request_remote_leases WHERE request_id = ANY(req_ids);
        DELETE FROM chat.direct_request_device_deliveries WHERE request_id = ANY(req_ids);
        DELETE FROM chat.direct_request_selected_devices WHERE request_id = ANY(req_ids);
        DELETE FROM chat.direct_request_publications WHERE request_id = ANY(req_ids);
        DELETE FROM chat.direct_request_attempts WHERE request_id = ANY(req_ids);
    END IF;

    DELETE FROM public.federation_outbox WHERE conversation_id = target_conversation::text;
    DELETE FROM public.outbound_queue WHERE convo_id = target_conversation::text;
    DELETE FROM public.federation_sync_state WHERE convo_id = target_conversation::text;
    DELETE FROM chat.federation_delivery_receipts WHERE conversation_id = target_conversation;
    DELETE FROM chat.key_packages
     WHERE terminal_transition_id IN (
         SELECT transition_id FROM chat.transitions WHERE conversation_id = target_conversation
     );
    DELETE FROM chat.inventory_conversation_items WHERE conversation_id = target_conversation;
    DELETE FROM chat.inventory_welcome_items WHERE conversation_id = target_conversation;
    DELETE FROM chat.inventory_recovery_items WHERE conversation_id = target_conversation;
    DELETE FROM chat.welcome_dispositions WHERE conversation_id = target_conversation;
    DELETE FROM chat.welcome_deliveries WHERE conversation_id = target_conversation;
    DELETE FROM chat.welcome_bundles WHERE conversation_id = target_conversation;
    DELETE FROM chat.recovery_work_items WHERE conversation_id = target_conversation;
    DELETE FROM chat.leaf_recovery_requests WHERE conversation_id = target_conversation;
    DELETE FROM chat.key_package_reservations WHERE conversation_id = target_conversation;
    DELETE FROM chat.leave_requests WHERE conversation_id = target_conversation;
    DELETE FROM chat.reset_requests WHERE conversation_id = target_conversation;
    DELETE FROM chat.application_schedule_terminal_proofs WHERE conversation_id = target_conversation;
    DELETE FROM chat.application_intervals WHERE conversation_id = target_conversation;
    DELETE FROM chat.entry_recipients WHERE conversation_id = target_conversation;
    DELETE FROM chat.message_sends WHERE conversation_id = target_conversation;
    DELETE FROM chat.metadata_snapshots WHERE conversation_id = target_conversation;
    DELETE FROM chat.member_devices WHERE conversation_id = target_conversation;
    DELETE FROM chat.participants WHERE conversation_id = target_conversation;
    DELETE FROM chat.entries WHERE conversation_id = target_conversation;
    DELETE FROM chat.transitions WHERE conversation_id = target_conversation;
    DELETE FROM chat.generation_states WHERE conversation_id = target_conversation;
    DELETE FROM chat.generations WHERE conversation_id = target_conversation;
    DELETE FROM chat.conversations WHERE conversation_id = target_conversation;

    RETURN TRUE;
END;
$$;

-- =============================================================================
-- 7. Scope-aware `key_packages_lifetime_check` for Spec §6.5 `C33` (>= 35d)
-- =============================================================================
-- `recovery` KeyPackages preserve the strict 2,595,600s (30d + 1h) ceiling,
-- while `direct-request` KeyPackages allow up to 3,891,600s (45d + 1h) so
-- clients can mint `not_after >= 35d` past the 30-day C33 request consent window.
ALTER TABLE chat.key_packages DROP CONSTRAINT IF EXISTS key_packages_lifetime_check;
ALTER TABLE chat.key_packages ADD CONSTRAINT key_packages_lifetime_check CHECK (
    not_before < created_at AND created_at < not_after
    AND not_after >= created_at + INTERVAL '600 seconds'
    AND (
        (usage_scope = 'recovery' AND not_after <= not_before + INTERVAL '2595600 seconds')
        OR (usage_scope = 'direct-request' AND not_after <= not_before + INTERVAL '3891600 seconds')
    )
);

