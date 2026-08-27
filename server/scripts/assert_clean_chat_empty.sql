-- =============================================================================
-- assert_clean_chat_empty.sql
--
-- Read-only Clean Chat zero-state preflight gate for OpenMLS 0.9 cutover.
--
-- This script validates that the Clean Chat database is in a strictly empty,
-- uncorrupted state suitable for forward deployment or pre-distribution
-- rollback. It performs NO writes (no INSERT, UPDATE, DELETE, TRUNCATE, DDL).
--
-- Sealed _sqlx_migrations modes:
--   1. Pre-cutover: 19 migrations through 20260821000001 (52 chat tables)
--   2. Post-c855:   23 migrations through 20260824000005 (53 chat tables)
--
-- Requirements:
--   - Exactly one sealed migration catalog matches with dirty=false.
--   - Exact chat schema table set (3 infrastructure + 49 or 50 semantic tables).
--   - Infrastructure initialized:
--       * chat.protocol_instances: exactly 1 row (singleton=true, v1, UUIDv4)
--       * chat.event_retention: exactly 1 row (bound to protocol singleton, floor=0)
--       * chat.operation_claim_completeness_cutover: exactly 1 row (singleton=true, count=0)
--   - Every semantic chat table contains zero rows.
--   - Public transport tables (federation_outbox, outbound_queue, federation_sync_state)
--     contain zero Clean Chat lowercase UUIDv4 rows for any status.
--
-- Aborts with an exception on any failure.
-- =============================================================================

DO $assert_clean_chat_empty$
DECLARE
    v_mode TEXT;
    v_mig_count INT;
    v_dirty_count INT;
    v_max_version BIGINT;
    v_protocol_instance_id UUID;
    v_singleton BOOLEAN;
    v_protocol_version TEXT;
    v_retained_floor BIGINT;
    v_retention_instance_id UUID;
    v_completeness_count BIGINT;
    v_table_count INT;
    v_expected_table TEXT;
    v_semantic_table TEXT;
    v_row_count BIGINT;
    v_uuid_pattern TEXT := '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$';

    -- Expected migrations: version, description, sha384_hex
    v_expected_versions BIGINT[] := ARRAY[
        20260214000002::BIGINT,
        20260722000001::BIGINT,
        20260722000002::BIGINT,
        20260722000003::BIGINT,
        20260725000001::BIGINT,
        20260725000002::BIGINT,
        20260726000001::BIGINT,
        20260726000002::BIGINT,
        20260726000003::BIGINT,
        20260728000001::BIGINT,
        20260728000002::BIGINT,
        20260728000003::BIGINT,
        20260728000004::BIGINT,
        20260729000001::BIGINT,
        20260730000001::BIGINT,
        20260816000001::BIGINT,
        20260820000001::BIGINT,
        20260820000002::BIGINT,
        20260821000001::BIGINT,
        -- Post-migration additions:
        20260824000001::BIGINT,
        20260824000003::BIGINT,
        20260824000004::BIGINT,
        20260824000005::BIGINT
    ];

    v_expected_descriptions TEXT[] := ARRAY[
        'auth jti nonce',
        'chat protocol core',
        'chat protocol delivery',
        'chat protocol blobs',
        'prepare welcome provenance backfill',
        'refine welcome provenance quarantine',
        'welcome supersession provenance',
        'restore welcome provenance deferred triggers',
        'finalize welcome provenance triggers',
        'chat operation claims',
        'exact operation claim mutation kind',
        'defer operation claim principal fk',
        'activate operation claim completeness',
        'chat g7 inventory entitlement',
        'reset request revocation terminal',
        'enable send message operation claims',
        'chat service auth admissions',
        'chat nullable legacy dpop jkt',
        'fix expired inventory session gc',
        -- Post-migration additions:
        'chat performance indices',
        'chat federation routing',
        'chat federation delivery receipts',
        'chat federation outbox retry'
    ];

    v_expected_checksums TEXT[] := ARRAY[
        'a653190a473ce3535c946769e8e269173fcf22c1cc6196063eb9461e4766bc084a57c61d2b3a4ffee4b5a1b4da06856b',
        'dd48feea7beafae59fbc11516e8c1ae91382b356b80366056f71d2493c10923bd39ff0739fe08cb4b0452b0ec82132ff',
        '86952763aaeb8f4cf8a8a18dd5d022a5357d450193e265a18da5a771513b9d4c7c8408bad27c4f4ba3b712b41b80e504',
        '310101886f60d3a663ee5df829bbc86a96a45e23adee754220d3b06fd74acfd708d23a138124872a5177244d3e14e8eb',
        '3f3d1660193bc37aa8c9876e636a4918f59404f0e055f509b9a67158b6028d947adc299c4d776a693bf8b75e647d90a8',
        '8dd0a595288182e2c36aed67d7155138a0817deb5d236dd1eaea50f066a90d7949f60c0de6bff5c9e8bd28e4a1c50de2',
        '78c31ff78db5b8889fb00cb7024186a0f048975fc7a059c667e326162e3f338396d9760143367c9206802d21269484f4',
        '1b29d045575aea2552ac10bdb61451662d51bca5afa75827e030e5dd859eee0d1664e12a69ecea9692e0fadb2a8df4af',
        '8bd956b8383bea542c6d591ae7721b92b898cb07e49b503131bedfbb511937147766569bcd2b23da11b226decffec495',
        'fd71f2eb5235226371f113b5738b752b27e901b72810e9ec1e1f201e979606e0b09a16be087103e4146b4fb9f8bdff8f',
        'a5c0225818e350415e0ad3a88c5016d621a75bb64563f97023de9d27498cf113d8ef9d95c98621036c15ac3398dbee17',
        'd42c64d98f6af2042ecf5d08b925aaadae01efcd7d1f6d1887c5485e0862d80304bb9ba54506a1876eba54b505d4114a',
        '7de97f6f84a9cfcbf535b990b5aec87930450cf6661c7d8cf11920bdf53fd0fe94623e9ed222a8eeb562c1ee596c5bd6',
        '2c00fc11f1d96b79c3c86320e769d70d52fecb477a8a2bc351151fd2d01e3d4c5df19cbf7a3ac482edbe16a33a0dd60e',
        '36ea55abb2cc644213fad4edd21df3e3ee10e680d63e714a22193eaf483fb022cf76106bf79fdd8a4ba1c285eb64d28b',
        'ae9cc21dd145c3608a57e1f96654b67d53709dba17e3f347758aa8b93830c725d380230751d83f85c497132b8669a30e',
        '2e8cb6bf47498402e56ba5c2fc753114c1d46e0767c98aa243c47993eb4f51a84de89469a8ae9af6bfac751ddadd18ac',
        'd1914c731e0fbf81f5b0a9bf9cd77c12f2943fd940c36b9a351b1156b5ca09b55f2b4b44c6810012b4377f6ac283955d',
        '42790274fbeb43bce44aa9638d23328223042933af03e6453a0c8c3640b9bcf236d0bc0b8cd76e1e5d846be7c6bfc78a',
        -- Post-migration additions:
        'e5f3f169724d2afc84043d80057bf9e494fbc9ad617ced0feaebb469d1be68788e7c19e19a67fb36296b85ee803139e0',
        '0a70985a3b5811483791911b6ae3b9d0ebd0fbcd9fc53363e65c59ca1c71a1cbd2a74fc02e87ba22dd0321c7f30713e6',
        '37ce660ad4630345dfdb0c106631b8926b2d2dfed0780210c072825e3a93f6455ba16a017ffdaaba243afe4c83f5f222',
        'b8b925e08f1da6b2f2932afa11e2434cc96d0f8a8f79c51b2f37e7e5da1dd59b188d6e96c98358f398578ba95935a2f9'
    ];

    -- Base semantic tables (49 tables present in both modes)
    v_base_semantic_tables TEXT[] := ARRAY[
        'principals',
        'devices',
        'device_keys',
        'device_revocations',
        'dpop_replays',
        'idempotency_records',
        'key_packages',
        'conversations',
        'generations',
        'generation_states',
        'participants',
        'member_devices',
        'metadata_snapshots',
        'key_package_reservations',
        'reset_requests',
        'leaf_recovery_requests',
        'leave_requests',
        'relationship_projection_revision_allocations',
        'relationship_projection_snapshots',
        'relationship_projection_relationships',
        'relationship_projection_declarations',
        'transitions',
        'entries',
        'message_sends',
        'application_intervals',
        'application_schedule_terminal_proofs',
        'entry_recipients',
        'welcome_bundles',
        'welcome_deliveries',
        'welcome_dispositions',
        'recovery_work_items',
        'events',
        'event_recipients',
        'outbox',
        'inventory_sessions',
        'inventory_conversation_items',
        'inventory_welcome_items',
        'inventory_recovery_items',
        'device_inventory_sessions',
        'device_inventory_items',
        'subscription_tickets',
        'blob_usage',
        'blobs',
        'blob_upload_tickets',
        'blob_bindings',
        'operation_claims',
        'inventory_page_receipts',
        'event_cursor_receipts',
        'service_auth_admissions'
    ];

    v_expected_semantic_tables TEXT[];
    v_expected_all_tables TEXT[];

    -- Public transport tables scanned for Clean Chat identifiers: (table, id column)
    v_transport_targets TEXT[] := ARRAY[
        ['federation_outbox', 'conversation_id'],
        ['outbound_queue', 'convo_id'],
        ['federation_sync_state', 'convo_id']
    ];
    v_transport_pair TEXT[];
    v_transport_table TEXT;
    v_transport_column TEXT;

    v_rec RECORD;
    v_idx INT := 1;
BEGIN
    -- -------------------------------------------------------------------------
    -- 1. Verify schema and migration ledger existence
    -- -------------------------------------------------------------------------
    IF to_regclass('public._sqlx_migrations') IS NULL THEN
        RAISE EXCEPTION 'preflight failed: public._sqlx_migrations table does not exist';
    END IF;

    IF to_regnamespace('chat') IS NULL THEN
        RAISE EXCEPTION 'preflight failed: chat schema does not exist';
    END IF;

    -- -------------------------------------------------------------------------
    -- 2. Verify migration ledger dirty status and count
    -- -------------------------------------------------------------------------
    SELECT COUNT(*) INTO v_dirty_count
    FROM public._sqlx_migrations
    WHERE success = FALSE;

    IF v_dirty_count > 0 THEN
        RAISE EXCEPTION 'preflight failed: _sqlx_migrations contains % dirty/unsuccessful migration(s)', v_dirty_count;
    END IF;

    SELECT COUNT(*), MAX(version) INTO v_mig_count, v_max_version
    FROM public._sqlx_migrations;

    IF v_mig_count = 19 AND v_max_version = 20260821000001 THEN
        v_mode := 'pre-cutover';
    ELSIF v_mig_count = 23 AND v_max_version = 20260824000005 THEN
        v_mode := 'post-c855';
    ELSE
        RAISE EXCEPTION 'preflight failed: unrecognized _sqlx_migrations catalog (count=%, max_version=%; expected count=19 max=20260821000001 or count=23 max=20260824000005)',
            v_mig_count, v_max_version;
    END IF;

    -- Verify exact migrations in order
    v_idx := 1;
    FOR v_rec IN
        SELECT version, description, checksum
        FROM public._sqlx_migrations
        ORDER BY version
    LOOP
        IF v_idx > v_mig_count THEN
            RAISE EXCEPTION 'preflight failed: extra migration found in _sqlx_migrations at index %: version=%',
                v_idx, v_rec.version;
        END IF;

        IF v_rec.version <> v_expected_versions[v_idx] THEN
            RAISE EXCEPTION 'preflight failed: migration version mismatch at index %: got %, expected %',
                v_idx, v_rec.version, v_expected_versions[v_idx];
        END IF;

        IF v_rec.description <> v_expected_descriptions[v_idx] THEN
            RAISE EXCEPTION 'preflight failed: migration description mismatch for version %: got %, expected %',
                v_rec.version, v_rec.description, v_expected_descriptions[v_idx];
        END IF;

        IF v_rec.checksum <> decode(v_expected_checksums[v_idx], 'hex') THEN
            RAISE EXCEPTION 'preflight failed: migration checksum mismatch for version %: got %, expected %',
                v_rec.version, encode(v_rec.checksum, 'hex'), v_expected_checksums[v_idx];
        END IF;

        v_idx := v_idx + 1;
    END LOOP;

    IF v_idx - 1 <> v_mig_count THEN
        RAISE EXCEPTION 'preflight failed: migration count mismatch: iterated %, expected %',
            v_idx - 1, v_mig_count;
    END IF;

    -- -------------------------------------------------------------------------
    -- 3. Verify chat schema table catalog
    -- -------------------------------------------------------------------------
    IF v_mode = 'pre-cutover' THEN
        v_expected_semantic_tables := v_base_semantic_tables;
    ELSE
        v_expected_semantic_tables := array_append(v_base_semantic_tables, 'federation_delivery_receipts');
    END IF;

    -- All expected tables = 3 infrastructure + semantic tables
    v_expected_all_tables := ARRAY['protocol_instances', 'event_retention', 'operation_claim_completeness_cutover'] || v_expected_semantic_tables;

    -- Check for missing expected tables
    FOREACH v_expected_table IN ARRAY v_expected_all_tables
    LOOP
        IF NOT EXISTS (
            SELECT 1 FROM pg_catalog.pg_tables
            WHERE schemaname = 'chat' AND tablename = v_expected_table
        ) THEN
            RAISE EXCEPTION 'preflight failed: missing expected table chat.% in % mode',
                v_expected_table, v_mode;
        END IF;
    END LOOP;

    -- Check for unexpected extra tables in chat schema
    FOR v_rec IN
        SELECT tablename
        FROM pg_catalog.pg_tables
        WHERE schemaname = 'chat'
    LOOP
        IF NOT (v_rec.tablename = ANY(v_expected_all_tables)) THEN
            RAISE EXCEPTION 'preflight failed: unexpected table chat.% in % mode',
                v_rec.tablename, v_mode;
        END IF;
    END LOOP;

    -- Verify total table count in chat schema
    SELECT COUNT(*) INTO v_table_count
    FROM pg_catalog.pg_tables
    WHERE schemaname = 'chat';

    IF v_table_count <> cardinality(v_expected_all_tables) THEN
        RAISE EXCEPTION 'preflight failed: chat schema table count mismatch in % mode: got %, expected %',
            v_mode, v_table_count, cardinality(v_expected_all_tables);
    END IF;

    -- -------------------------------------------------------------------------
    -- 4. Verify infrastructure tables
    -- -------------------------------------------------------------------------
    -- 4a. chat.protocol_instances
    SELECT COUNT(*) INTO v_row_count FROM chat.protocol_instances;
    IF v_row_count <> 1 THEN
        RAISE EXCEPTION 'preflight failed: chat.protocol_instances must contain exactly 1 row, found %', v_row_count;
    END IF;

    SELECT singleton, protocol_version, protocol_instance_id
    INTO v_singleton, v_protocol_version, v_protocol_instance_id
    FROM chat.protocol_instances;

    IF v_singleton IS NOT TRUE THEN
        RAISE EXCEPTION 'preflight failed: chat.protocol_instances singleton column must be TRUE';
    END IF;

    IF v_protocol_version <> '1' THEN
        RAISE EXCEPTION 'preflight failed: chat.protocol_instances protocol_version must be ''1'', got %', v_protocol_version;
    END IF;

    IF v_protocol_instance_id IS NULL OR v_protocol_instance_id::TEXT !~ v_uuid_pattern THEN
        RAISE EXCEPTION 'preflight failed: chat.protocol_instances protocol_instance_id must be a valid lowercase UUIDv4, got %',
            v_protocol_instance_id;
    END IF;

    -- 4b. chat.event_retention
    SELECT COUNT(*) INTO v_row_count FROM chat.event_retention;
    IF v_row_count <> 1 THEN
        RAISE EXCEPTION 'preflight failed: chat.event_retention must contain exactly 1 row, found %', v_row_count;
    END IF;

    SELECT protocol_instance_id, retained_floor
    INTO v_retention_instance_id, v_retained_floor
    FROM chat.event_retention;

    IF v_retention_instance_id <> v_protocol_instance_id THEN
        RAISE EXCEPTION 'preflight failed: chat.event_retention protocol_instance_id (%) does not match chat.protocol_instances singleton (%)',
            v_retention_instance_id, v_protocol_instance_id;
    END IF;

    IF v_retained_floor <> 0 THEN
        RAISE EXCEPTION 'preflight failed: chat.event_retention retained_floor must be 0, got %', v_retained_floor;
    END IF;

    -- 4c. chat.operation_claim_completeness_cutover
    SELECT COUNT(*) INTO v_row_count FROM chat.operation_claim_completeness_cutover;
    IF v_row_count <> 1 THEN
        RAISE EXCEPTION 'preflight failed: chat.operation_claim_completeness_cutover must contain exactly 1 row, found %', v_row_count;
    END IF;

    SELECT singleton, legacy_receipt_count
    INTO v_singleton, v_completeness_count
    FROM chat.operation_claim_completeness_cutover;

    IF v_singleton IS NOT TRUE THEN
        RAISE EXCEPTION 'preflight failed: chat.operation_claim_completeness_cutover singleton column must be TRUE';
    END IF;

    IF v_completeness_count <> 0 THEN
        RAISE EXCEPTION 'preflight failed: chat.operation_claim_completeness_cutover legacy_receipt_count must be 0, got %', v_completeness_count;
    END IF;

    -- -------------------------------------------------------------------------
    -- 5. Verify every semantic chat table is completely empty (zero rows)
    -- -------------------------------------------------------------------------
    FOREACH v_semantic_table IN ARRAY v_expected_semantic_tables
    LOOP
        EXECUTE format('SELECT COUNT(*) FROM chat.%I', v_semantic_table) INTO v_row_count;
        IF v_row_count > 0 THEN
            RAISE EXCEPTION 'preflight failed: semantic table chat.% is dirty (% row(s) found)',
                v_semantic_table, v_row_count;
        END IF;
    END LOOP;

    -- -------------------------------------------------------------------------
    -- 6. Verify public transport and federation tables contain zero Clean Chat UUIDv4 rows
    -- -------------------------------------------------------------------------
    FOREACH v_transport_pair SLICE 1 IN ARRAY v_transport_targets
    LOOP
        v_transport_table := v_transport_pair[1];
        v_transport_column := v_transport_pair[2];

        -- Legacy deployments may lack the table or the identifier column entirely.
        IF to_regclass('public.' || quote_ident(v_transport_table)) IS NULL THEN
            CONTINUE;
        END IF;

        IF NOT EXISTS (
            SELECT 1 FROM information_schema.columns
            WHERE table_schema = 'public'
              AND table_name = v_transport_table
              AND column_name = v_transport_column
        ) THEN
            CONTINUE;
        END IF;

        EXECUTE format(
            'SELECT COUNT(*) FROM public.%I WHERE %I ~ $1',
            v_transport_table, v_transport_column
        ) INTO v_row_count USING v_uuid_pattern;

        IF v_row_count > 0 THEN
            RAISE EXCEPTION 'preflight failed: public.% contains % Clean Chat UUIDv4 row(s)',
                v_transport_table, v_row_count;
        END IF;
    END LOOP;

    RAISE NOTICE 'preflight passed: clean chat zero-state verified in % mode', v_mode;
END;
$assert_clean_chat_empty$;
