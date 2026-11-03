// One reviewed ledger for server and end-to-end direct-request tests.
// Keep historical SQL bytes/checksums pinned in one place so either harness
// can migrate the shared guarded database before the other.

// Required before the actor-to-DS migration; also replayed by faketime_postgres.py.
pub const FEDERATION_CACHE_SCHEMA: &str =
    include_str!("fixtures/direct_request_federation_cache.sql");

#[derive(Clone, Debug)]
pub struct BaselineMigration {
    pub filename: &'static str,
    pub version: i64,
    pub description: &'static str,
    pub reviewed_sha384: &'static str,
    pub sql: &'static str,
}

macro_rules! baseline {
    ($version:literal, $description:literal, $filename:literal, $sha384:literal) => {
        BaselineMigration {
            filename: $filename,
            version: $version,
            description: $description,
            reviewed_sha384: $sha384,
            sql: include_str!(concat!("../../migrations/", $filename)),
        }
    };
}

pub fn reviewed_baseline() -> [BaselineMigration; 14] {
    [
        baseline!(20260722000001, "chat protocol core", "20260722000001_chat_protocol_core.sql", "dd48feea7beafae59fbc11516e8c1ae91382b356b80366056f71d2493c10923bd39ff0739fe08cb4b0452b0ec82132ff"),
        baseline!(20260722000002, "chat protocol delivery", "20260722000002_chat_protocol_delivery.sql", "86952763aaeb8f4cf8a8a18dd5d022a5357d450193e265a18da5a771513b9d4c7c8408bad27c4f4ba3b712b41b80e504"),
        baseline!(20260722000003, "chat protocol blobs", "20260722000003_chat_protocol_blobs.sql", "310101886f60d3a663ee5df829bbc86a96a45e23adee754220d3b06fd74acfd708d23a138124872a5177244d3e14e8eb"),
        baseline!(20260725000001, "prepare welcome provenance backfill", "20260725000001_prepare_welcome_provenance_backfill.sql", "3f3d1660193bc37aa8c9876e636a4918f59404f0e055f509b9a67158b6028d947adc299c4d776a693bf8b75e647d90a8"),
        baseline!(20260725000002, "refine welcome provenance quarantine", "20260725000002_refine_welcome_provenance_quarantine.sql", "8dd0a595288182e2c36aed67d7155138a0817deb5d236dd1eaea50f066a90d7949f60c0de6bff5c9e8bd28e4a1c50de2"),
        baseline!(20260726000001, "welcome supersession provenance", "20260726000001_welcome_supersession_provenance.sql", "78c31ff78db5b8889fb00cb7024186a0f048975fc7a059c667e326162e3f338396d9760143367c9206802d21269484f4"),
        baseline!(20260726000002, "restore welcome provenance deferred triggers", "20260726000002_restore_welcome_provenance_deferred_triggers.sql", "1b29d045575aea2552ac10bdb61451662d51bca5afa75827e030e5dd859eee0d1664e12a69ecea9692e0fadb2a8df4af"),
        baseline!(20260726000003, "finalize welcome provenance triggers", "20260726000003_finalize_welcome_provenance_triggers.sql", "8bd956b8383bea542c6d591ae7721b92b898cb07e49b503131bedfbb511937147766569bcd2b23da11b226decffec495"),
        baseline!(20260728000001, "chat operation claims", "20260728000001_chat_operation_claims.sql", "fd71f2eb5235226371f113b5738b752b27e901b72810e9ec1e1f201e979606e0b09a16be087103e4146b4fb9f8bdff8f"),
        baseline!(20260728000002, "exact operation claim mutation kind", "20260728000002_exact_operation_claim_mutation_kind.sql", "a5c0225818e350415e0ad3a88c5016d621a75bb64563f97023de9d27498cf113d8ef9d95c98621036c15ac3398dbee17"),
        baseline!(20260728000003, "defer operation claim principal fk", "20260728000003_defer_operation_claim_principal_fk.sql", "d42c64d98f6af2042ecf5d08b925aaadae01efcd7d1f6d1887c5485e0862d80304bb9ba54506a1876eba54b505d4114a"),
        baseline!(20260728000004, "activate operation claim completeness", "20260728000004_activate_operation_claim_completeness.sql", "7de97f6f84a9cfcbf535b990b5aec87930450cf6661c7d8cf11920bdf53fd0fe94623e9ed222a8eeb562c1ee596c5bd6"),
        baseline!(20260729000001, "chat g7 inventory entitlement", "20260729000001_chat_g7_inventory_entitlement.sql", "2c00fc11f1d96b79c3c86320e769d70d52fecb477a8a2bc351151fd2d01e3d4c5df19cbf7a3ac482edbe16a33a0dd60e"),
        baseline!(20260730000001, "reset request revocation terminal", "20260730000001_reset_request_revocation_terminal.sql", "36ea55abb2cc644213fad4edd21df3e3ee10e680d63e714a22193eaf483fb022cf76106bf79fdd8a4ba1c285eb64d28b"),
    ]
}

pub fn reviewed_request_migrations() -> [BaselineMigration; 56] {
    [
        baseline!(20260919000001, "direct request preparation", "20260919000001_direct_request_preparation.sql", "d4d3527aa77b8fe91d8d754f72290b682571cc6731866d72c059f10d4b2f7cf8ef629069737addeedaabd6f6eee682ca"),
        baseline!(20260919000002, "direct request publication", "20260919000002_direct_request_publication.sql", "7fda0b09fcdef20e4da2e1701f6a56c12f636f7881b46e2f6e249cb0d5fc2aa63c734dc07cbb543169398253e29cec9e"),
        baseline!(20260919000003, "direct request lifecycle", "20260919000003_direct_request_lifecycle.sql", "c51bc3851c68556437867249e163fd320fd792f62401695df1c5e9182aa5141687c5e193fdb9d11a37d7ff6be3811572"),
        baseline!(20260919000004, "direct request welcome delivery", "20260919000004_direct_request_welcome_delivery.sql", "a93682f234ab1c2efdf98d6da51c444d89d750a224b67117f65e34045d54e6ada28c69858433bfc93be70c8e4b7827c4"),
        baseline!(20260919000005, "direct request budget release", "20260919000005_direct_request_budget_release.sql", "0c2e4c2b2b5f3fe662e5d91ae85969825ac932ad708e4840cfa3f426414462d678547e49e481ff9eeda531f40828fad0"),
        baseline!(20260919000006, "direct request attempt null fences", "20260919000006_direct_request_attempt_null_fences.sql", "871e44752b1f8e35a684589ada95e2bdfdf88c667c6e371bdbae15f8ff2e6bb513fbc369b74bc4bd9244c6e693f9ac4c"),
        baseline!(20260919000007, "direct request publication integrity", "20260919000007_direct_request_publication_integrity.sql", "6f6192cd5d620becadd5bcd47cb38e50b30ab999ea7c3c410804a527bcb23aaa10f3913098211ce072cafdb6591af6db"),
        baseline!(20260919000008, "direct request lifecycle fences", "20260919000008_direct_request_lifecycle_fences.sql", "64dcfb75a6adc3ed3509cdb6e439ff745813286e7baad2b0ad3c71bc5722694eef13bd4e12e048636e5c27a2964e65d0"),
        baseline!(20260919000009, "direct request acceptance claims", "20260919000009_direct_request_acceptance_claims.sql", "c1210eb15ecc821c380acd4fbc3fff471d6b42304d38f60f6c6acb9e7b91f233421e32ce18d99802b9e6fdd050d72e9a"),
        baseline!(20260919000010, "direct request retained artifacts", "20260919000010_direct_request_retained_artifacts.sql", "598aea96b9a02d6c3c24937e81929c14496cdb24698dd8be9a091609c8d40975f5957242a5a81aeeedab2cb79cb36288"),
        baseline!(20260919000011, "direct request lifecycle slots", "20260919000011_direct_request_lifecycle_slots.sql", "158cee3681184afb77ba824c3357717f945027d93ba75c33b1f5d5cc568d6098e33b0874a5465a6d76cbca72a2d604bf"),
        baseline!(20260919000012, "direct request welcome slot digest", "20260919000012_direct_request_welcome_slot_digest.sql", "dbe9835b66cba3edd3c21ca1756ae1ee2b13a8c0fbb67fea3dc3b1f754bc5eca90d7a36fff1ff10c6ad568f52eb3312d"),
        baseline!(20260919000013, "direct request signed json projection", "20260919000013_direct_request_signed_json_projection.sql", "d8170f613b3c2c2fc087b8ab7c5f24d15dd4379ba3605048390beccbdecdd85a525f5d70c3b340d98d053c543d924156"),
        baseline!(20260919000014, "direct request nul comparison", "20260919000014_direct_request_nul_comparison.sql", "2f47a3019d459b7989f544773da035e10914af95b85ad553afd70e84367189085a3c8507b7314bfa84d4cc4335a1d8b8"),
        baseline!(20260919000015, "direct request entry identity", "20260919000015_direct_request_entry_identity.sql", "157cac50d04bd77388897fe386acd915ece5046c40923dec21675726ed091ac5b709691664a57241f67c8415e73cf29d"),
        baseline!(20260919000016, "direct request push bindings", "20260919000016_direct_request_push_bindings.sql", "483aee1650f60a488d2a6498c11e4ce229906889ca1a655c37f080fefccf610bc4f552b06a63719ff471f95c060360f8"),
        baseline!(20260919000017, "direct request push outbox", "20260919000017_direct_request_push_outbox.sql", "813c165f4e1739fb81d1cd26b2e1cea505745b1df77d22d6ca4882ba44bf2a9446a0929be20320e04a22c93e2bdc380b"),
        baseline!(20260919000018, "fix direct request lifecycle close fence", "20260919000018_fix_direct_request_lifecycle_close_fence.sql", "db45c270c4f162078319724213518f3d3186ab5883ff75729e253663874738a001fa61af41791065eeca2f8c76bc1974"),
        baseline!(20260919000019, "variable receipt authority keys", "20260919000019_variable_receipt_authority_keys.sql", "dc201702f4e21d124b664a81d8cc60105d92c2ba7fa9e7fe3ea8523e4a091adfc54b0f57663efab00cb46815cf6029ea"),
        baseline!(20260919000021, "direct request capacity abuse fix", "20260919000021_direct_request_capacity_abuse_fix.sql", "5b6d18e3f9a43bccf357ee37f0df7b322d956369fb55cd036fbbbdb4e63f5c291730ac10885b6de511a697cb365939ca"),
        baseline!(20260919000022, "federated transport inbox", "20260919000022_federated_transport_inbox.sql", "392d0137456574b46aeb05d71fdd6a9084bc364c102fa206f64a48c26441355fad52b3568386b5574aa8bedc15882e5a"),
        baseline!(20260919000023, "expired federated lease release", "20260919000023_expired_federated_lease_release.sql", "f8b78fd5368f0d9521ec0498f14aaf7f928be8ca4cef35c7e794aac7ed72970a7337e348675ab9eaf873351df3c5b0c5"),
        baseline!(20260919000024, "C33 coordinator hardening", "20260919000024_c33_coordinator_hardening.sql", "ebc8d84f7b7ad0dd3005fb268956f52a4b9c8bea8134ae5fdeee94fda232e222d816dbbbf16a45d7420f3a5099a7c5e7"),
        baseline!(20260919000025, "federated inventory conversation items", "20260919000025_federated_inventory_conversation_items.sql", "c8cd858bc6805485334ad90e96673123b215591282f9625c55e2315a624430f77460fdda0e444a61abffe45433f0a9b1"),
        baseline!(20261004000001, "reconcile conversation identity whitelist", "20261004000001_reconcile_conversation_identity_whitelist.sql", "10579dbb921d3e024a5bdc6ac221e1906d381375849a127da3b3784dc36630d0e50ff624485464d04d66b1a10e074a53"),
        baseline!(20261004100001, "labyrinth mailbox and directory", "20261004100001_labyrinth_mailbox_and_directory.sql", "78413b0611149fe8b7208d065ea455d05cef061ee2f213030bc41a70ee96739928dcdc126d550c0f6898dbf6e95c74c3"),
        baseline!(20261004100002, "labyrinth threads", "20261004100002_labyrinth_threads.sql", "0c57cba0d98367123234c154be7e6d1f26a304aff48b34ea192d2698f0f564629ac15ad6b5e32237c12d1aecc9e46b04"),
        baseline!(20261004100003, "labyrinth orf and attachments", "20261004100003_labyrinth_orf_and_attachments.sql", "118124f987ae00db52e938aaa627a14721becb8ceda48bd4aa0dbfe799cc0004f3120c7297c1956db3b772a3f1413764"),
        baseline!(20261004100004, "labyrinth device binding", "20261004100004_labyrinth_device_binding.sql", "c5f6e9627a9ff1fb5d2da93c17a73dcef74679d57a5c3d7cf12e86f45c814d8e9e45797b2547abaa37621e99f39ac50e"),
        baseline!(20261004100005, "labyrinth attachment refs v2", "20261004100005_labyrinth_attachment_refs_v2.sql", "2dcc30aeebbe4d2de63ef0b794beef8a9958665f6df391011b56515c963cce6cec89c0c60e7e357bb54a32d4e9be12c4"),
        baseline!(20261004100006, "labyrinth retention", "20261004100006_labyrinth_retention.sql", "b7ce72e7f162c626695739dbf5a62c6eb59126c95629e24c6c5c94857f0638f1e29c6f71a7eac5a2798e6b820e2a7b53"),
        baseline!(20261004100007, "labyrinth blob gc pin", "20261004100007_labyrinth_blob_gc_pin.sql", "e3efe50d180d6250c722918628ed7334cde492246460f18dc92ca6ebc2a3ae7b43f5be9dfdb35a341439f7f25994f740"),
        baseline!(20261004100008, "labyrinth lookup indexes", "20261004100008_labyrinth_lookup_indexes.sql", "0e5908d59cbe9758b1de17fb06aefff6461c3592df05a3493012d892b23ef0d045476b14d97b41a895c52c896a672f54"),
        baseline!(20261004100009, "labyrinth review2 hardening", "20261004100009_labyrinth_review2_hardening.sql", "990321ab67d1bb32f19e5f98cb1647f7c6267663b91b69d922efacb50a5fac3c1c384724c8c10ba18bf6afc7b02ce61f"),
        baseline!(20261023000001, "labyrinth space references", "20261023000001_labyrinth_space_references.sql", "1011321e3d877785ecb846e84a44d347d6478e6ecaa015b2aa0833f571eb6a784eb8cc1c2e69bfe6aaf9efa6f3ec0748"),
        baseline!(20261025000001, "generated transition wrapper kind", "20261025000001_generated_transition_wrapper_kind.sql", "ab163acf42140744e86c5892e434068f14c31830e396e38ed07d814d4ca4936c6f7c348ec92bfa7993b4acbe525db983"),
        baseline!(20261031100001, "labyrinth security hardening", "20261031100001_labyrinth_security_hardening.sql", "e21a41990ae1234c2b438fc69011636037a7bd83ace728c30afafb2b16ab4e22221cd1215638ac3348d8336e99402051"),
        baseline!(20261031200001, "clean slate spaces only", "20261031200001_clean_slate_spaces_only.sql", "9680fd2643b146edb6168f68d39ed3f164429243a4777273a89e63cbb081bfc9847eba4fecef998ee102766d09d1a829"),
        baseline!(20261031200002, "space host operational state", "20261031200002_space_host_operational_state.sql", "7b332d3e52efd64bafd7275c078dff9bd06769582f811974639f35600afcbb9988eb17c8783acb57f66cbcfa8c1a1dbe"),
        baseline!(20261031200003, "fix wipe closed conversation operational rows", "20261031200003_fix_wipe_closed_conversation_operational_rows.sql", "4853b31de7c5960b546089db2128d2c9095ac661734ba8991b484b5a4bedb8420ee70bb063d8642278a362ca23bab96f"),
        baseline!(20261102000001, "group transport entry recipients", "20261102000001_group_transport_entry_recipients.sql", "918fb25c2c7c6826ae18eed9c38241efee20d27214e7c42dce5fdcccd7a02adcc73af45f0aa69747aa1e2ecfe40f2195"),
        baseline!(20261102000002, "group key package exports", "20261102000002_group_key_package_exports.sql", "17d3d172e4c8340a80f2677fac9387ae69c8210a3cf4c4a9bc6d08375a99ac1fbf78488f891a114bc96da3b56d300554"),
        baseline!(20261102000003, "conversation close terminal entries", "20261102000003_conversation_close_terminal_entries.sql", "3b32d6d3b3dab9d0f785d48d8b9a1b352e7c5329ff3697bcf83fc00744fe91edf4b1763243e4a17dbab885c344c57e30"),
        baseline!(20261103000001, "remote application ciphertext pruning", "20261103000001_remote_application_ciphertext_pruning.sql", "466647e8460b4adc227121657ec018efaf3090418738a70c696810171a9f38cf69e80eacf8886310ecfd8829bc5ce733"),
        baseline!(20261103000002, "remote device key history", "20261103000002_remote_device_key_history.sql", "91b930f69cace280a19491183245f1f9a8264ef29d764ed140eab1b51620711ecaf27c23dda653e90d7ae76d7ea6d403"),
        baseline!(20261103000003, "remote close authority", "20261103000003_remote_close_authority.sql", "be9da0be3ad629454e6a9bb363d62da4dc57039ec23ea14d10fc9e23fd1c97f36ab3fc89484208c12aded25709c1ee6c"),
        baseline!(20261103000004, "federated key package reservations", "20261103000004_federated_key_package_reservations.sql", "eae9b35f98c3ed6bc1317f6cee98b48826088fd84177dc4db00212b603c787771f2418ad441a1444f12013cd9498efd0"),
        baseline!(20261103000010, "direct request opening pruning", "20261103000010_direct_request_opening_pruning.sql", "bd09b55f977c4f553dd73b7acef87070998e705166b3c9d1ba3fd10a546d7a2810f78ca238d300de220ec748edfdaf39"),
        baseline!(20261104000001, "remote group memberships", "20261104000001_remote_group_memberships.sql", "83b71d0b116da7807a4ee1238d44b91407fdaf561c3b1b0315cfd757f7803b78d992517fd55d32a3cffbff535a9a5e42"),
        baseline!(20261104000002, "direct request opening pruned bytes", "20261104000002_direct_request_opening_pruned_bytes.sql", "60334191b8c21241f5d8b437f060dad185d27258dda758c476412074fdd44500992a8dd5e1f2ac365ce2d4b468734213"),
        baseline!(20261104000005, "idempotency payload erasure", "20261104000005_idempotency_payload_erasure.sql", "101b2b1d966f50650a5edc27f303d91b44b2282124a91e2d9ae7782f19cf4ceb8b674d3fef5d0aa45a0d388ade50382e"),
        baseline!(20261104000006, "direct request transport wakes", "20261104000006_direct_request_transport_wakes.sql", "98d111c435d605aefc99581798b4a904e3f000081cf904788e1b6b78f0e8bf1b525b941396b0955cf71e36b79c63e4b4"),
        baseline!(20261104000007, "drop request push bindings", "20261104000007_drop_request_push_bindings.sql", "9a8a8aa3209fe676c70d7c84eac3b00b57e480513809228f3b3df8c4204efba0ee9e8c281f97a65709d0d259c43a37a0"),
        baseline!(20261104000008, "queued copy conversation indexes", "20261104000008_queued_copy_conversation_indexes.sql", "4f815c232b88a8ff6b7b885288926493d24ce3ec418445fbd52f4bdc60dfda7f0021ca96c3f92c14ede138cd66bc75c1"),
        baseline!(20261104000010, "wipe returns whole retained charge", "20261104000010_wipe_returns_whole_retained_charge.sql", "2683e751903eadd28ba7b7df9a2d43a7eb10c62fb5a6bf644582dcc92565ddca85b0cccd1e7efcefcbb7f9d2f3880a8b"),
        baseline!(20261104000011, "direct request route answers", "20261104000011_direct_request_route_answers.sql", "6a8bce9ce6af92567d62820ca40464860a14b56b47d72f91f51649b1e98ea095ce9ea233258b7cc7cbf26e379516617d"),
    ]
}
pub fn reviewed_auth_replay_prerequisite() -> BaselineMigration {
    baseline!(20260214000002, "auth jti nonce", "20260214000002_auth_jti_nonce.sql", "a653190a473ce3535c946769e8e269173fcf22c1cc6196063eb9461e4766bc084a57c61d2b3a4ffee4b5a1b4da06856b")
}

fn reviewed_send_message_prerequisite() -> BaselineMigration {
    baseline!(20260816000001, "enable send message operation claims", "20260816000001_enable_send_message_operation_claims.sql", "ae9cc21dd145c3608a57e1f96654b67d53709dba17e3f347758aa8b93830c725d380230751d83f85c497132b8669a30e")
}

fn reviewed_inventory_gc_prerequisite() -> BaselineMigration {
    baseline!(20260821000001, "fix expired inventory session gc", "20260821000001_fix_expired_inventory_session_gc.sql", "42790274fbeb43bce44aa9638d23328223042933af03e6453a0c8c3640b9bcf236d0bc0b8cd76e1e5d846be7c6bfc78a")
}

fn reviewed_pending_inventory_prerequisite() -> BaselineMigration {
    baseline!(20260907000001, "chat direct pending inventory", "20260907000001_chat_direct_pending_inventory.sql", "82708d24b2deb72452ebdaf28749aa86ed95075f7ed920c4cc5526962e2ae9f9d8561a5029fc853ba654564d76ef63f1")
}

fn reviewed_service_auth_prerequisite() -> BaselineMigration {
    baseline!(20260820000001, "chat service auth admissions", "20260820000001_chat_service_auth_admissions.sql", "2e8cb6bf47498402e56ba5c2fc753114c1d46e0767c98aa243c47993eb4f51a84de89469a8ae9af6bfac751ddadd18ac")
}

fn reviewed_legacy_dpop_prerequisite() -> BaselineMigration {
    baseline!(20260820000002, "chat nullable legacy dpop jkt", "20260820000002_chat_nullable_legacy_dpop_jkt.sql", "d1914c731e0fbf81f5b0a9bf9cd77c12f2943fd940c36b9a351b1156b5ca09b55f2b4b44c6810012b4377f6ac283955d")
}

fn reviewed_performance_indices_prerequisite() -> BaselineMigration {
    baseline!(20260824000001, "chat performance indices", "20260824000001_chat_performance_indices.sql", "e5f3f169724d2afc84043d80057bf9e494fbc9ad617ced0feaebb469d1be68788e7c19e19a67fb36296b85ee803139e0")
}

/// Every reviewed prerequisite between the immutable baseline and the request
/// migrations, in production version order. The guarded ledger prefix must
/// match this exact sequence.
pub fn reviewed_prerequisites() -> [BaselineMigration; 16] {
    [
        reviewed_send_message_prerequisite(),
        reviewed_service_auth_prerequisite(),
        reviewed_legacy_dpop_prerequisite(),
        reviewed_inventory_gc_prerequisite(),
        reviewed_performance_indices_prerequisite(),
        baseline!(20260824000002, "chat actor ds mapping", "20260824000002_chat_actor_ds_mapping.sql", "57b80b7f4e753c12bd97553fc8308b4eb04f9f2e39809cc32ed2b65337319721d73c31d9acf33b3c8c64c8f516d60c31"),
        baseline!(20260824000003, "chat federation routing", "20260824000003_chat_federation_routing.sql", "0a70985a3b5811483791911b6ae3b9d0ebd0fbcd9fc53363e65c59ca1c71a1cbd2a74fc02e87ba22dd0321c7f30713e6"),
        baseline!(20260824000004, "chat federation delivery receipts", "20260824000004_chat_federation_delivery_receipts.sql", "37ce660ad4630345dfdb0c106631b8926b2d2dfed0780210c072825e3a93f6455ba16a017ffdaaba243afe4c83f5f222"),
        baseline!(20260824000005, "chat federation outbox retry", "20260824000005_chat_federation_outbox_retry.sql", "6d20fd054646d7da6de338b9ae27fea7c81a19569dfebc6231de5bc23bc79ca9aa22ab790cead55d82b06846f81dd799"),
        baseline!(20260828000001, "chat historical bootstrap quota", "20260828000001_chat_historical_bootstrap_quota.sql", "c063fd2991cb28ce6947c587f11e2316bb5e02587873d86e89ff74476f880796c63ca1a90064f70c10fe7ed7cc0eb293"),
        baseline!(20260828000002, "chat historical bootstrap application", "20260828000002_chat_historical_bootstrap_application.sql", "7095f7c32b74c6660fcf8c03610ee88c8db5330639088a907fc996a20d7f47f948ca43ff64cef014a1107bf9626c0013"),
        baseline!(20260828000003, "chat historical bootstrap cutoff validate", "20260828000003_chat_historical_bootstrap_cutoff_validate.sql", "4e2387ebf31369278e1504a8e00e548a0fd80eafc2adb5a461c01ceab30be2bd84e841eba12a366f51f5a1b1617a3917"),
        baseline!(20260828000004, "chat device push tokens", "20260828000004_chat_device_push_tokens.sql", "f8f4da493f6a3bf6261d2e09d6706ec6b4a395511a1eed6c5a557b5bb119b6f04aeabd9d3514db984e5e695894fe2fb1"),
        baseline!(20260828000005, "fix inventory session gc scoping", "20260828000005_fix_inventory_session_gc_scoping.sql", "cae43253509fd13c468a741f360d1371e0d9a099a67ed951c683b23fb98960861e2d00ed3522d341ff026801f86059a2"),
        baseline!(20260905000001, "chat historical recovery package mapping", "20260905000001_chat_historical_recovery_package_mapping.sql", "a66f9dc9bd5f8f1cb3da0f3ddfcb64c08fc068de39602891e584c86cdbaebd1de2d29b6bb46959155496639ad12f9c5d"),
        reviewed_pending_inventory_prerequisite(),
    ]
}
pub fn reviewed_migrations() -> impl Iterator<Item = BaselineMigration> {
    std::iter::once(reviewed_auth_replay_prerequisite())
        .chain(reviewed_baseline())
        .chain(reviewed_prerequisites())
        .chain(reviewed_request_migrations())
}

/// Fail before running handlers if the current schema outgrows this reviewed
/// manifest. Hash and exact-ledger validation remain independent in each caller.
pub fn assert_current_migration_frontier(migrations_dir: &std::path::Path) {
    let reviewed = reviewed_request_migrations();
    for entry in std::fs::read_dir(migrations_dir).expect("read current migrations directory") {
        let path = entry.expect("read current migration entry").path();
        if path.extension().and_then(|value| value.to_str()) != Some("sql") {
            continue;
        }
        let filename = path.file_name().and_then(|value| value.to_str()).unwrap();
        let version: i64 = filename.split_once('_').unwrap().0.parse().unwrap();
        if version >= 20261004000001 {
            assert!(
                reviewed
                    .iter()
                    .any(|migration| migration.version == version && migration.filename == filename),
                "unreviewed current migration {filename}; update the shared request manifest"
            );
        }
    }
}
