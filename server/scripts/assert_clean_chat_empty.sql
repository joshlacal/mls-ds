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
--   1. Pre-cutover: 74 migrations through 20260821000001 (52 chat tables)
--   2. Post-c855:   79 migrations through 20260824000005 (53 chat tables)
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
--     exist, have text-compatible identifier columns, and contain zero Clean Chat
--     lowercase UUIDv4 rows for any status.
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
    v_col_type TEXT;
    v_uuid_pattern TEXT := '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$';

    -- Expected migrations: version, description, sha384_hex (79 total)
    v_expected_versions BIGINT[] := ARRAY[
        20250101000000::BIGINT,
        20251125000001::BIGINT,
        20251125000002::BIGINT,
        20251125000003::BIGINT,
        20251125000004::BIGINT,
        20251125000005::BIGINT,
        20251125000006::BIGINT,
        20251127000001::BIGINT,
        20251206000001::BIGINT,
        20251210000000::BIGINT,
        20251213000001::BIGINT,
        20260213000001::BIGINT,
        20260214000001::BIGINT,
        20260214000002::BIGINT,
        20260214000003::BIGINT,
        20260214000004::BIGINT,
        20260214000005::BIGINT,
        20260214000006::BIGINT,
        20260215000000::BIGINT,
        20260215000001::BIGINT,
        20260219000001::BIGINT,
        20260222000001::BIGINT,
        20260311000001::BIGINT,
        20260312000001::BIGINT,
        20260313000001::BIGINT,
        20260316000001::BIGINT,
        20260403000000::BIGINT,
        20260403100000::BIGINT,
        20260404100000::BIGINT,
        20260405100000::BIGINT,
        20260406100000::BIGINT,
        20260407100000::BIGINT,
        20260418100000::BIGINT,
        20260425100000::BIGINT,
        20260426100000::BIGINT,
        20260427100000::BIGINT,
        20260428100000::BIGINT,
        20260429000001::BIGINT,
        20260429000002::BIGINT,
        20260429000003::BIGINT,
        20260429000004::BIGINT,
        20260429000005::BIGINT,
        20260429000006::BIGINT,
        20260429000007::BIGINT,
        20260508100000::BIGINT,
        20260508110000::BIGINT,
        20260515000001::BIGINT,
        20260515000002::BIGINT,
        20260618120000::BIGINT,
        20260621000001::BIGINT,
        20260622000001::BIGINT,
        20260627000001::BIGINT,
        20260630000001::BIGINT,
        20260712000001::BIGINT,
        20260713000001::BIGINT,
        20260716000001::BIGINT,
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
        20260821000001::BIGINT, -- 74: pre-cutover cutoff
        20260824000001::BIGINT, -- 75: post-c855 cutoff start
        20260824000002::BIGINT,
        20260824000003::BIGINT,
        20260824000004::BIGINT,
        20260824000005::BIGINT
    ];

    v_expected_descriptions TEXT[] := ARRAY[
        'greenfield schema',
        'opt in table',
        'read receipts',
        'add warn action',
        'max members',
        'pending device additions',
        'add moderator role',
        'welcome error tracking',
        'message reactions',
        'chat requests',
        'federation support',
        'remove sender did storage',
        'federation peer policy',
        'auth jti nonce',
        'federation commits',
        'sequencer receipts',
        'delivery acks',
        'delivery acks unique',
        'idempotency cache caller did',
        'delivery ack verified',
        'federation clean break hardening',
        'federation peer policy audit log',
        'create blobs table',
        'group metadata blobs',
        'blob convo id',
        'messages convo seq unique',
        'replace reports with spam reports',
        'drop read receipts',
        'add confirmation tag',
        'group reset support',
        'drop message reactions',
        'recovery failures',
        'reset votes and epoch authenticators',
        'messages wire epoch',
        'reset votes failure mode',
        'commit health columns',
        'groupinfo 404 health columns',
        'crypto sessions and delivery events',
        'key package state',
        'durable outbox',
        'reset reminder state',
        'message timeline seq index',
        'group metadata conversation scope',
        'drop plaintext metadata',
        'external commit audit and freeze',
        'inline 404 bootstrap gate',
        'reissue welcome requests',
        'kp audit',
        'welcome messages recipient device id',
        'unique open reissue requests',
        'reissue request status',
        'key package reserved state',
        'kp first served at',
        'mls transition authority',
        'device auth binding',
        'sequencer receipt generation',
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
        'fix expired inventory session gc', -- 74: pre-cutover cutoff
        'chat performance indices',
        'chat actor ds mapping',
        'chat federation routing',
        'chat federation delivery receipts',
        'chat federation outbox retry'
    ];

    v_expected_checksums TEXT[] := ARRAY[
        'c576503a14746c83ea90b19d3e370012efe9a244830cbe9188be669fe8cfefb321f6a771d880f8cc205761b671079bfe',
        '110ade98598f25b55445eaf7ca7987a54ddb3200238faf2955c410a389e1cc9d7fb78d31c6b5e9e947b0dd325c50109e',
        '7b6851f0beba789559c48e9ef2e08df7d422a75d68a824e4b5a388f49e9a1c44ce4a84ba78644596c9ec9c98271bc50b',
        '682d1a58ac3a609cd2c37ef823b7ce18bca0139897e976e546b1e1daf6a0efa9e2da0f9e946917cd7dec47a6d698e8ae',
        '99fa7ca60529ef2336c65a2499eda11d9ef52bd94ac87aafb5a4ebfdcd94ccc5444639e9b5a0fa65da1084c307ce11c0',
        '4f2d852085ee4b26dc1342a0cac11c0792f9fef4fe04956a31b24c4c3b947a23cdee53fcce7b2bd38c2021b3bbced55e',
        'ba0a93d9cb5e3d22731b550f8c293b2c9a1d5b7a93702fe34540c822abd24dbb0ec6762857b723aafdffbcf34e1a075b',
        'f6a317ded9426f0e5f6a5c426c699f625ad78c2f12268ecbe68f139838c1653cb30828b156a681d4940cc102d413054c',
        '6db4bf11bd02a7c756c2a8c73544a83677773b35b374a4dd0f5dc1e52512634453a9c48259aa48057c3519fdba39774f',
        '8e53bee9e3b613c2838a2ab97f63ae80cf13138f863dc30b46df48490dcfb80b57d20ed90237148413d0da5763165173',
        'e304ec2af1fed912f801764a55e914bf530a16e2a44ca2481d58d8f2d6acda0cde9ceb927241f1dc2ee25f18559f15fa',
        'dafb956de7fd1cbe46a22ca1066fbfa0ef904f1eea198ba8cc0e9f54a5b9f47a51ada04f184f97c5a75a9f6affcf0faf',
        '6f53140fc1191cfc67a008c35abc7aa786364fb3e427c1404053782c1fa3c64bcc7e1d0a438ec263906db4285a37271a',
        'a653190a473ce3535c946769e8e269173fcf22c1cc6196063eb9461e4766bc084a57c61d2b3a4ffee4b5a1b4da06856b',
        '8c68047ef3c3010d38bc7668a28eec61f0d70c36d6dfdec70fe4017fcf22acf52e52a77ecd7eefc87d69b51cd3796949',
        '12fcc8c8b446d37176dbe5f644dd2bd6cb52314c6eb22d47d6d77bbe86062cba7c72182250264d112b6c3b06569479dc',
        'a376b5cfabe46f25deafa58e780588a2d3e8f2d8dd3c6af96f15239f563652da06c8e748504ff4cb13faed9a88fc6c93',
        '674f31ce93a1d4887465b3567303b0e744d523ecabce9dbf5ecf2f56d9783b165deff3432f7bee6f1f98c9cee4d5bb53',
        'fd66c11ba60c87caf4efdee3e4bef6aea8224963b9c848e124c93127177e4956e4278ec0c9b4200c3eaac69df2382023',
        'd5e4d3278b6bd6bb1ac5320a4879f5827747a5d244bb9d4bc1e97137b786823121ecc367ea033d6fe8c6691a168db78a',
        'c84fbe5d28ac614353208dd2b8357d5be5c943161ae1a6e1dc93ccc6be79c9891e1374c685547b2e1bd52ab6aab76d88',
        'ca9820176cdf6b5ee95dd22c089bf1a3c2650520c194d528d7bd0fbf47a08caf9ad791cd11a2773b45f4fc7c655b2e58',
        '99d73fedb97233bbc08245607d98681bc4c27424b920e584a62e292cb9cecf55c5d42e07fda084a4675c17426fe472a0',
        '5ac3c48ef3f94735334c704ce9cef4208793d2d7ed1e4e2f6459d4a87cc980ff9c0e51894ebd029ad860d3e347f8b948',
        'a6b2ca40d0db4d6926117fc0a66f3f225324737fd257554609f3dfb7b22c9654faedf2148bafb14793735ac4f9ca16e2',
        '495b17877fec10c7e2197c0fe9012ed02d3c9b36883bcb339082afc86b347568089ad3845c41408d21eb3d9d5f1d0bf2',
        '4729f4e5552c743fcd30aba9c6d868cf5e0f4e3aa5a421ae4b22431170ef6c082ac1fa226a57cbf306d9472c1ff71763',
        '8828c6d81fbfdc6e90cfda2a78856e40b6c95005e8c1cfcf870eef037881a013fad4f1d15dc712dcfbb6d4f0d9517b45',
        'bb87e7076ae562744562491c80e5b6e3a22d4be3866964e53f814c73e6eae904766c626cf8914bd4c04784775b047b0f',
        'f9f391d25bebec023ce0be4264b65e2938920dedd68c4bb5cf62cce30eaae70d2a2f02fc8368a0c64b57d5c74c599d3c',
        '44fe4959f49b81b88ee73ae89ec28b6bf162417a3a57ca09351ab07319be964b0a3e1884122a495c009bb47d028f0e20',
        '21c4341c16804297a58efdb9fb33a0cb7716bde28bb72c311debe5b76af4292b437b899f0fcda5ad0d46a5216891426d',
        '8c746805af909ed4720aa7ad2f97c02b69f593ca8886e2b01f7d5c4c459b8b8b2bae5fe3e1a31ad5b26cac837ed12f1a',
        '56fae1ad437e6e2def1c67c0b4d112cd926b4350fc20d0f32ddd98fc581cab4f6f98af915fa10508a8f27cd43e3437e5',
        'b7c4e5dd366214f34853a2fa7b890f9bea9ad7f6362cf413368b3eb8e6f97d843f76cfb2cd44e4132e1a312343c5dbfb',
        '27dc8b75d106103ac465847a800562ac4db9667de082d8f9ae78a28b817293f4a3f7b7225938a9a236de608266595157',
        '4fc14ba4c6752e62b234f08a5fa3c53118f417205a311c07148bb295ace302cf781f64caa1955cfc519d02c215460d57',
        '8e7efe2830d0c9800bd57763e827a98299905119a5f75735470175aff965188ac020217892b370f59f7ef9bf1275d2f3',
        '73e141e451b0c0fb9fc3a37a028e6406b542c54ca2a7b046b9f46a50933bace6cfd71c0b5cfa04dc66b2719194b63761',
        '047a332b3f7e87bab4d911c026f5a472fc34d62a53c7fabcea03d3b2fcb5b96be8009779cb4e290cde781518efcf0b74',
        '3d031d2176a963bf20d8af29ab8a38e26425f8ff2f73f4752ea97590d7206e7369c1b7bab93240666f749965453cef96',
        '3d78a24e20947734b43a790418b20643e8c671e766d8d1a761ad01feb4b28ccf3e763f6cdd8fff90f08c32c19c2814ad',
        '2deb305652dbf872858212aae3e9144dfc989a1c3300ed237a4dc146e95b36e902fca3e058b37b8f68ccc9edfd6d39b7',
        'f0eda6dc4a152f6158298c7186ea7ed7a9a0b913565544f525ddf1ea0b2855da936d857754bece2c322b85bcccecd5f9',
        'dfabfec6d3ce41bac0f456356f83df0b3b1362f97db710e0d0085c30e52fec85345327f4b12396364f9718b5fa375df6',
        'b5a13b49c640f2fc9d270eefba9a3133d6a7db97b3a352feb0ca6509f7ae8fea69407cf0ce7cb734852b619d30e91bd0',
        '3a82b38436e479c3733924ec0d02b838de1c64ca02e3107fbb95fd4262b283c672d5de038637982b2cd909114afdd768',
        '6f18c30f0164c6cbef1a08de8f8996ac4c09e59196d83c5fe49f2f2004e4cab2304c103f7f7175abed21ebdc4e334283',
        '88815f2c9b11d28df5242f2da360646e8d9161b3db501352aab96375cca7400d5d2991025acb6044340759d4fe08da0d',
        'e6f237fea6c4f8fecc7126cc30da9029a2a27b181e76d9d042288e0ddaf2d0890fae7a6f17cab88e3c893503d0e957d9',
        'b8296ead5b85c7f160643c91c8c8e3b8fc524f5a7180cb0cedb3474bd80fc3dfd7086720c1ceadf17f980e0ccc2051d3',
        'a0783c08ff0788e5b9cab7e711769d2b673307dc39d751c0260e40fc620812c3ab5bcbb350cd24fec1307c096eb349e1',
        'c88584a6d44c225ae0ad637d0c4051cc73487b6e13dd6aa69b2ec755bac2e81f0e3f0b2e6dba0fd9501cd1a1d14785b9',
        'db4df9d83f7030f5d9b4617a28d7d1130fb93acc8fc99a317e03ed2854aba2991dc262de3b21bf91b17680239b0c80ce',
        '97c6abc525bc50bab175130625551db85574d977e5d96b074554724fcd0cb1d7a620f31cf17cb6b765752193daaf3a66',
        'e178cc268e01aa4687b7b619d075368de481b55f437f1411713298efde61ce0669b45b70ae9a720425484689c0d1983b',
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
        '42790274fbeb43bce44aa9638d23328223042933af03e6453a0c8c3640b9bcf236d0bc0b8cd76e1e5d846be7c6bfc78a', -- 74: pre-cutover cutoff
        'e5f3f169724d2afc84043d80057bf9e494fbc9ad617ced0feaebb469d1be68788e7c19e19a67fb36296b85ee803139e0',
        '57b80b7f4e753c12bd97553fc8308b4eb04f9f2e39809cc32ed2b65337319721d73c31d9acf33b3c8c64c8f516d60c31',
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

    IF v_dirty_count IS DISTINCT FROM 0 THEN
        RAISE EXCEPTION 'preflight failed: _sqlx_migrations contains % dirty/unsuccessful migration(s)', v_dirty_count;
    END IF;

    SELECT COUNT(*), MAX(version) INTO v_mig_count, v_max_version
    FROM public._sqlx_migrations;

    IF v_mig_count = 74 AND v_max_version = 20260821000001 THEN
        v_mode := 'pre-cutover';
    ELSIF v_mig_count = 79 AND v_max_version = 20260824000005 THEN
        v_mode := 'post-c855';
    ELSE
        RAISE EXCEPTION 'preflight failed: unrecognized _sqlx_migrations catalog (count=%, max_version=%; expected count=74 max=20260821000001 or count=79 max=20260824000005)',
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

        IF v_rec.version IS DISTINCT FROM v_expected_versions[v_idx] THEN
            RAISE EXCEPTION 'preflight failed: migration version mismatch at index %: got %, expected %',
                v_idx, v_rec.version, v_expected_versions[v_idx];
        END IF;

        IF v_rec.description IS DISTINCT FROM v_expected_descriptions[v_idx] THEN
            RAISE EXCEPTION 'preflight failed: migration description mismatch for version %: got %, expected %',
                v_rec.version, v_rec.description, v_expected_descriptions[v_idx];
        END IF;

        IF v_rec.checksum IS DISTINCT FROM decode(v_expected_checksums[v_idx], 'hex') THEN
            RAISE EXCEPTION 'preflight failed: migration checksum mismatch for version %: got %, expected %',
                v_rec.version, encode(v_rec.checksum, 'hex'), v_expected_checksums[v_idx];
        END IF;

        v_idx := v_idx + 1;
    END LOOP;

    IF v_idx - 1 IS DISTINCT FROM v_mig_count THEN
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
            SELECT 1
            FROM pg_catalog.pg_class c
            JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
            WHERE n.nspname = 'chat'
              AND c.relname = v_expected_table
              AND c.relkind = 'r'
        ) THEN
            RAISE EXCEPTION 'preflight failed: missing expected table chat.% in % mode',
                v_expected_table, v_mode;
        END IF;
    END LOOP;

    -- Check for unexpected extra relations in chat schema (tables, views, matviews, foreign tables, partitioned tables)
    FOR v_rec IN
        SELECT c.relname, c.relkind
        FROM pg_catalog.pg_class c
        JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = 'chat'
          AND c.relkind IN ('r', 'p', 'v', 'm', 'f')
    LOOP
        IF v_rec.relkind IS DISTINCT FROM 'r' OR NOT (v_rec.relname = ANY(v_expected_all_tables)) THEN
            RAISE EXCEPTION 'preflight failed: unexpected relation chat.% (relkind=%) in % mode',
                v_rec.relname, v_rec.relkind, v_mode;
        END IF;
    END LOOP;

    -- Verify total table/relation count in chat schema
    SELECT COUNT(*) INTO v_table_count
    FROM pg_catalog.pg_class c
    JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = 'chat'
      AND c.relkind IN ('r', 'p', 'v', 'm', 'f');

    IF v_table_count IS DISTINCT FROM cardinality(v_expected_all_tables) THEN
        RAISE EXCEPTION 'preflight failed: chat schema table count mismatch in % mode: got %, expected %',
            v_mode, v_table_count, cardinality(v_expected_all_tables);
    END IF;

    -- -------------------------------------------------------------------------
    -- 4. Verify infrastructure tables
    -- -------------------------------------------------------------------------
    -- 4a. chat.protocol_instances
    SELECT COUNT(*) INTO v_row_count FROM chat.protocol_instances;
    IF v_row_count IS DISTINCT FROM 1 THEN
        RAISE EXCEPTION 'preflight failed: chat.protocol_instances must contain exactly 1 row, found %', v_row_count;
    END IF;

    SELECT singleton, protocol_version, protocol_instance_id
    INTO v_singleton, v_protocol_version, v_protocol_instance_id
    FROM chat.protocol_instances;

    IF v_singleton IS DISTINCT FROM TRUE THEN
        RAISE EXCEPTION 'preflight failed: chat.protocol_instances singleton column must be TRUE';
    END IF;

    IF v_protocol_version IS DISTINCT FROM '1' THEN
        RAISE EXCEPTION 'preflight failed: chat.protocol_instances protocol_version must be ''1'', got %', v_protocol_version;
    END IF;

    IF v_protocol_instance_id IS NULL OR v_protocol_instance_id::TEXT !~ v_uuid_pattern THEN
        RAISE EXCEPTION 'preflight failed: chat.protocol_instances protocol_instance_id must be a valid lowercase UUIDv4, got %',
            v_protocol_instance_id;
    END IF;

    -- 4b. chat.event_retention
    SELECT COUNT(*) INTO v_row_count FROM chat.event_retention;
    IF v_row_count IS DISTINCT FROM 1 THEN
        RAISE EXCEPTION 'preflight failed: chat.event_retention must contain exactly 1 row, found %', v_row_count;
    END IF;

    SELECT protocol_instance_id, retained_floor
    INTO v_retention_instance_id, v_retained_floor
    FROM chat.event_retention;

    IF v_retention_instance_id IS DISTINCT FROM v_protocol_instance_id THEN
        RAISE EXCEPTION 'preflight failed: chat.event_retention protocol_instance_id (%) does not match chat.protocol_instances singleton (%)',
            v_retention_instance_id, v_protocol_instance_id;
    END IF;

    IF v_retained_floor IS DISTINCT FROM 0 THEN
        RAISE EXCEPTION 'preflight failed: chat.event_retention retained_floor must be 0, got %', v_retained_floor;
    END IF;

    -- 4c. chat.operation_claim_completeness_cutover
    SELECT COUNT(*) INTO v_row_count FROM chat.operation_claim_completeness_cutover;
    IF v_row_count IS DISTINCT FROM 1 THEN
        RAISE EXCEPTION 'preflight failed: chat.operation_claim_completeness_cutover must contain exactly 1 row, found %', v_row_count;
    END IF;

    SELECT singleton, legacy_receipt_count
    INTO v_singleton, v_completeness_count
    FROM chat.operation_claim_completeness_cutover;

    IF v_singleton IS DISTINCT FROM TRUE THEN
        RAISE EXCEPTION 'preflight failed: chat.operation_claim_completeness_cutover singleton column must be TRUE';
    END IF;

    IF v_completeness_count IS DISTINCT FROM 0 THEN
        RAISE EXCEPTION 'preflight failed: chat.operation_claim_completeness_cutover legacy_receipt_count must be 0, got %', v_completeness_count;
    END IF;

    -- -------------------------------------------------------------------------
    -- 5. Verify every semantic chat table is completely empty (zero rows)
    -- -------------------------------------------------------------------------
    FOREACH v_semantic_table IN ARRAY v_expected_semantic_tables
    LOOP
        EXECUTE format('SELECT COUNT(*) FROM chat.%I', v_semantic_table) INTO v_row_count;
        IF v_row_count IS DISTINCT FROM 0 THEN
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

        -- 1. Table existence and relation kind in public schema via pg_catalog
        IF NOT EXISTS (
            SELECT 1
            FROM pg_catalog.pg_class c
            JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
            WHERE n.nspname = 'public'
              AND c.relname = v_transport_table
              AND c.relkind IN ('r', 'p', 'v', 'm', 'f')
        ) THEN
            RAISE EXCEPTION 'preflight failed: required public transport table public.% is missing in % mode',
                v_transport_table, v_mode;
        END IF;

        -- 2. Identifier column existence and text-compatible data type via pg_catalog
        SELECT t.typname INTO v_col_type
        FROM pg_catalog.pg_attribute a
        JOIN pg_catalog.pg_class c ON a.attrelid = c.oid
        JOIN pg_catalog.pg_namespace n ON c.relnamespace = n.oid
        JOIN pg_catalog.pg_type t ON a.atttypid = t.oid
        WHERE n.nspname = 'public'
          AND c.relname = v_transport_table
          AND a.attname = v_transport_column
          AND a.attnum > 0
          AND NOT a.attisdropped;

        IF v_col_type IS NULL THEN
            RAISE EXCEPTION 'preflight failed: required identifier column %.% is missing in % mode',
                v_transport_table, v_transport_column, v_mode;
        END IF;

        IF v_col_type NOT IN ('text', 'varchar', 'bpchar', 'name') THEN
            RAISE EXCEPTION 'preflight failed: column %.% in public.% is not text-compatible (type=%)',
                v_transport_table, v_transport_column, v_transport_table, v_col_type;
        END IF;

        -- 3. Execute scan for Clean Chat UUIDv4 rows
        EXECUTE format(
            'SELECT COUNT(*) FROM public.%I WHERE %I ~ $1',
            v_transport_table, v_transport_column
        ) INTO v_row_count USING v_uuid_pattern;

        IF v_row_count IS DISTINCT FROM 0 THEN
            RAISE EXCEPTION 'preflight failed: public.% contains % Clean Chat UUIDv4 row(s)',
                v_transport_table, v_row_count;
        END IF;
    END LOOP;

    RAISE NOTICE 'preflight passed: clean chat zero-state verified in % mode', v_mode;
END;
$assert_clean_chat_empty$;
