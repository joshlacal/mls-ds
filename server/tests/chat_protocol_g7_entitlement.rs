//! G7 Checkpoint P: direct production-hydration proof for the corpus-bound
//! genuine signed Creation fixture.
//!
//! This integration crate path-includes the production `chat_protocol` module
//! tree (so `repository::core`'s `super::super::…` paths resolve) and drives
//! the REAL `hydrate_locked_conversation_state` aggregate over a private RAII
//! per-run executor database seeded through the frozen
//! `executor_seed::seed_hydratable_genuine_creation_graph` fixture. No-DB
//! source guards pin the frozen seed helper and the production hydrator path
//! against drift.

#![allow(dead_code)]

mod common;

#[allow(dead_code)]
#[path = "../src/chat_protocol/cursor.rs"]
mod cursor;
#[allow(dead_code)]
#[path = "../src/chat_protocol/dpop.rs"]
mod dpop;
#[allow(dead_code)]
#[path = "../src/chat_protocol/model.rs"]
mod model;
#[allow(dead_code)]
#[path = "../src/chat_protocol/relationship_policy.rs"]
mod relationship_policy_source;
mod repository {
    pub use crate::chat_protocol::repository::{auth, blobs, inventory, key_packages, prelude};
}
#[allow(dead_code)]
mod snapshot {
    pub use catbird_server::chat_protocol::snapshot::*;
}
#[allow(dead_code)]
#[path = "../src/chat_protocol/transcript.rs"]
mod transcript;
#[allow(dead_code)]
#[path = "../src/chat_protocol/validation.rs"]
mod validation;

mod chat_protocol {
    pub mod cursor {
        pub use crate::cursor::*;
    }
    pub mod model {
        pub use crate::model::*;
    }
    pub mod validation {
        pub use crate::validation::*;
    }
    pub mod transcript {
        pub use crate::transcript::*;
    }
    pub mod dpop {
        pub use crate::dpop::*;
    }
    pub mod snapshot {
        pub use catbird_server::chat_protocol::snapshot::*;
    }
    pub mod error {
        pub use catbird_server::chat_protocol::error::*;
    }
    pub mod wire {
        pub use catbird_server::chat_protocol::wire::*;
    }
    pub mod public_state {
        #![allow(dead_code)]
        include!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/chat_protocol/public_state.rs"
        ));
    }
    pub mod relationship_policy {
        pub use crate::relationship_policy_source::*;
    }
    pub mod repository {
        pub mod auth {
            #![allow(dead_code)]
            include!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/src/chat_protocol/repository/auth.rs"
            ));
        }
        pub mod blobs {
            #![allow(dead_code)]
            include!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/src/chat_protocol/repository/blobs.rs"
            ));
        }
        pub mod key_packages {
            #![allow(dead_code)]
            include!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/src/chat_protocol/repository/key_packages.rs"
            ));
        }
        pub mod prelude {
            #![allow(dead_code)]
            include!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/src/chat_protocol/repository/prelude.rs"
            ));
        }
        pub mod inventory {
            #![allow(dead_code)]
            include!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/src/chat_protocol/repository/inventory.rs"
            ));
        }
        pub mod recovery {
            #![allow(dead_code)]
            include!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/src/chat_protocol/repository/recovery.rs"
            ));
        }
        pub mod core {
            #![allow(dead_code)]
            include!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/src/chat_protocol/repository/core.rs"
            ));
        }
        pub mod transition {
            #![allow(dead_code)]
            include!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/src/chat_protocol/repository/transition.rs"
            ));
        }
        pub mod delivery {
            #![allow(dead_code)]
            include!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/src/chat_protocol/repository/delivery.rs"
            ));
        }
        pub mod execution_context {
            #![allow(dead_code)]
            include!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/src/chat_protocol/repository/execution_context.rs"
            ));
        }
        pub mod welcome_terminal {
            #![allow(dead_code)]
            include!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/src/chat_protocol/repository/welcome_terminal.rs"
            ));
        }
        pub mod relationship {
            #![allow(dead_code)]
            include!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/src/chat_protocol/repository/relationship.rs"
            ));
        }
    }
    pub mod state_machine {
        #![allow(dead_code)]
        include!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/chat_protocol/state_machine.rs"
        ));
    }
}

#[path = "common/executor_seed.rs"]
mod executor_seed;

use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};
use sqlx::{postgres::PgPoolOptions, PgPool, Postgres, Transaction};
use std::time::Duration;
use uuid::Uuid;

async fn rollback_with_constraints(mut tx: Transaction<'_, Postgres>) {
    sqlx::query("SET CONSTRAINTS ALL IMMEDIATE")
        .execute(&mut *tx)
        .await
        .expect("force G7 deferred constraints");
    tx.rollback().await.expect("roll back G7 fixture");
}

async fn private_genuine_graph() -> (
    PgPool,
    executor_seed::FreshDbGuard,
    executor_seed::GenuineCreationGraph,
) {
    let (pool, guard) = executor_seed::setup().await;
    let conversation_id = Uuid::new_v4();
    let graph = executor_seed::seed_hydratable_genuine_creation_graph(&pool, conversation_id).await;
    sqlx::query(
        "INSERT INTO chat.event_retention(protocol_instance_id,retained_floor,updated_at) \
         VALUES($1,0,date_trunc('milliseconds',clock_timestamp()))",
    )
    .bind(graph.protocol_instance_id)
    .execute(&pool)
    .await
    .expect("seed exact private G7 retention fence");
    (pool, guard, graph)
}

/// Equivalent of `^chat_exec_[0-9a-f]{32}$` without a regex dependency.
fn assert_private_executor_db_name(db_name: &str) {
    let suffix = db_name
        .strip_prefix("chat_exec_")
        .expect("private executor database name carries the chat_exec_ prefix");
    assert_eq!(
        suffix.len(),
        32,
        "private executor database suffix must be a 32-character simple UUID"
    );
    assert!(
        suffix
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f')),
        "private executor database suffix must be lowercase hex"
    );
}

/// `FreshDbGuard::drop` joins its cleanup thread before returning, but every
/// failure inside that thread is deliberately swallowed (best-effort drop). A
/// bounded retry turns any residual completion-timing window into either a
/// clean pass or a deterministic failure instead of a flake.
async fn assert_executor_db_absent(maintenance_url: &str, db_name: &str) {
    let admin = PgPoolOptions::new()
        .max_connections(1)
        .connect(maintenance_url)
        .await
        .expect("reconnect to the maintenance database after guard drop");
    let mut remaining_attempts = 40_u32;
    loop {
        let leftover: Option<String> =
            sqlx::query_scalar("SELECT datname FROM pg_database WHERE datname=$1")
                .bind(db_name)
                .fetch_optional(&admin)
                .await
                .expect("inspect pg_database for the private executor database");
        if leftover.is_none() {
            break;
        }
        remaining_attempts -= 1;
        assert!(
            remaining_attempts > 0,
            "private executor database {db_name} survived its guard drop"
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    admin.close().await;
}

#[tokio::test]
async fn production_hydrated_genuine_creation_round_trips_locked_aggregate() {
    let (pool, guard, graph) = private_genuine_graph().await;
    let maintenance_url = guard.maintenance_url.clone();
    let db_name = guard.db_name.clone();
    assert_private_executor_db_name(&db_name);

    let locked_at: DateTime<Utc> =
        sqlx::query_scalar("SELECT date_trunc('milliseconds', clock_timestamp())")
            .fetch_one(&pool)
            .await
            .expect("sample millisecond-precision aggregate hydration instant");
    let mut tx = pool.begin().await.expect("begin exact P aggregate read");
    let locked = chat_protocol::repository::core::hydrate_locked_conversation_state(
        &mut tx,
        graph.conversation_id,
        locked_at,
    )
    .await
    .expect("corpus-bound genuine Creation hydrates through production");

    assert_eq!(
        locked.state().leaves().len(),
        1,
        "genesis aggregate carries exactly the creator leaf"
    );
    let leaf = &locked.state().leaves()[0];
    assert_eq!(leaf.leaf_index(), 0, "creator occupies leaf zero");
    assert_eq!(
        leaf.device().principal().as_bytes(),
        graph.creator_did.as_bytes(),
        "leaf-zero DID must equal the seeded creator DID"
    );
    assert_eq!(
        leaf.device().device_id(),
        graph.creator_device_id.as_bytes(),
        "leaf-zero device must equal the seeded creator device"
    );
    assert_ne!(
        locked.locked_graph_digest(),
        &[0_u8; 32],
        "sealed aggregate must carry a nonzero locked graph digest"
    );
    assert_ne!(
        locked
            .locked_snapshot_digest()
            .expect("active aggregate snapshot digest"),
        &[0_u8; 32],
        "sealed aggregate must carry a nonzero snapshot digest"
    );

    drop(locked);
    rollback_with_constraints(tx).await;
    pool.close().await;
    drop(guard);

    assert_executor_db_absent(&maintenance_url, &db_name).await;
}

const FROZEN_EXECUTOR_SEED_SHA256: &str =
    "f2d0f424d13524c75c91091f2d4f2a3382f89d61c86539ed36602a92755e6748";
const SEALED_REPOSITORY_CORE_SHA256: &str =
    "60f07e0cc88d454c5c90957b06d4544c7f841735ce97875c2c9db9025a2fd2c4";

#[test]
fn frozen_executor_seed_helper_is_byte_identical_to_the_sealed_baseline() {
    assert_eq!(
        hex::encode(Sha256::digest(include_bytes!("common/executor_seed.rs"))),
        FROZEN_EXECUTOR_SEED_SHA256,
        "tests/common/executor_seed.rs must stay byte-identical to the frozen P helper"
    );
}

#[test]
fn production_repository_core_is_byte_identical_to_the_sealed_baseline() {
    assert_eq!(
        hex::encode(Sha256::digest(include_bytes!(
            "../src/chat_protocol/repository/core.rs"
        ))),
        SEALED_REPOSITORY_CORE_SHA256,
        "src/chat_protocol/repository/core.rs must stay byte-identical to the sealed baseline"
    );
}

const PRODUCTION_HYDRATOR_SIGNATURE: &str = concat!(
    "pub(crate) async fn hydrate_locked_conversation_state(\n",
    "    transaction: &mut Transaction<'_, Postgres>,\n",
    "    conversation_id: Uuid,\n",
    "    locked_at: DateTime<Utc>,\n",
    ") -> Result<LockedConversationStateGuard, ConversationStateHydrationError> {",
);

/// Ordered structural anchors of the production hydrator body: head lock,
/// snapshot validate/reload, leaves/intervals/work hydration, nonzero sealed
/// graph digest, and the repository-internal aggregate seal.
const PRODUCTION_HYDRATOR_ORDERED_ANCHORS: &[&str] = &[
    "let head = hydrate_locked_conversation_head(transaction, conversation_id, locked_at)",
    ".map_err(ConversationStateHydrationError::Head)?",
    "hydrate_public_state_under_locked_head(transaction, &head)",
    ".map_err(ConversationStateHydrationError::PublicState)?",
    "seal_locked_public_state_hydration(",
    "load_persisted_active_snapshot(public_guard)",
    ".map_err(ConversationStateHydrationError::Snapshot)?",
    "historical_authority_for_locked_head(&head)",
    "hydration_authority_for_locked_head(&head)",
    "load_producer_transition_evidence(transaction, &historical, conversation_id)",
    "load_metadata_provenance(transaction, &historical, conversation_id)",
    "load_participant_hydration_rows(transaction, &historical, conversation_id)",
    "load_leaf_hydration_rows(transaction, conversation_id, public_state.binding())",
    ".map_err(ConversationStateHydrationError::Leaves)?",
    "load_interval_hydration_rows(transaction, &historical, conversation_id)",
    "load_recovery_work_hydration_rows(transaction, &historical, conversation_id)",
    "load_reset_request_hydration_rows(transaction, &historical, conversation_id)",
    "load_leave_request_hydration_rows(transaction, &historical, conversation_id)",
    "load_welcome_hydration_rows(transaction, &historical, conversation_id)",
    "conversation_graph_digest(&head, snapshot_digest.as_ref(), &rows)",
    "if graph_digest == [0; 32]",
    "ConversationStateHydrationError::GraphDigest",
    "hydrate_conversation_state(&hydration, rows)",
    ".map_err(ConversationStateHydrationError::State)?",
    "seal_locked_conversation(state, head, graph_digest, snapshot_digest)",
    ".ok_or(ConversationStateHydrationError::Seal)",
];

fn require_ordered_anchors(source: &str, start: usize, anchors: &[&str]) {
    let mut position = start;
    for anchor in anchors {
        match source[position..].find(anchor) {
            Some(offset) => position += offset + anchor.len(),
            None => panic!("production hydrator lost its ordered anchor {anchor:?}"),
        }
    }
}

#[test]
fn production_hydrator_retains_the_direct_locked_aggregate_path() {
    let core = include_str!("../src/chat_protocol/repository/core.rs");
    assert_eq!(
        core.matches("fn hydrate_locked_conversation_state").count(),
        1,
        "exactly one production hydrator definition"
    );
    let signature_offset = core
        .find(PRODUCTION_HYDRATOR_SIGNATURE)
        .expect("exact production hydrator signature");
    require_ordered_anchors(
        core,
        signature_offset + PRODUCTION_HYDRATOR_SIGNATURE.len(),
        PRODUCTION_HYDRATOR_ORDERED_ANCHORS,
    );
}

#[test]
fn locked_aggregate_has_no_unchecked_or_shipping_test_hydration_constructor() {
    let core = include_str!("../src/chat_protocol/repository/core.rs");
    let state_machine = include_str!("../src/chat_protocol/state_machine.rs");
    let public_state = include_str!("../src/chat_protocol/public_state.rs");
    let module_root = include_str!("../src/chat_protocol/mod.rs");
    for (name, source) in [
        ("repository/core.rs", core),
        ("state_machine.rs", state_machine),
        ("public_state.rs", public_state),
        ("mod.rs", module_root),
    ] {
        assert!(
            !source.contains("unchecked"),
            "{name} must not grow an unchecked hydration path"
        );
    }

    let private_struct = concat!(
        "pub(crate) struct LockedConversationStateGuard {\n",
        "    state: ConversationState,\n",
        "    head: LockedConversationHeadGuard,\n",
        "    locked_graph_digest: [u8; 32],\n",
        "    locked_snapshot_digest: Option<[u8; 32]>,\n",
        "}",
    );
    assert!(
        core.contains(private_struct),
        "sealed aggregate fields must stay private"
    );
    assert_eq!(
        core.matches("from_locked_hydration").count(),
        3,
        "checked constructor: one definition, one production seal call, one gated test call"
    );
    assert!(
        core.contains("\n    fn from_locked_hydration(\n"),
        "checked aggregate constructor must stay private"
    );
    assert_eq!(
        core.matches("pub(super) fn seal_locked_conversation(")
            .count(),
        1,
        "exactly one repository-internal aggregate seal"
    );
    assert_eq!(
        core.matches("seal_locked_conversation(").count(),
        2,
        "aggregate seal: definition plus the single production hydrator call"
    );
    let gated_aggregate_test_constructor = concat!(
        "    #[cfg(test)]\n",
        "    pub(crate) fn for_test(\n",
        "        state: ConversationState,\n",
        "        head: LockedConversationHeadGuard,\n",
    );
    assert!(
        core.contains(gated_aggregate_test_constructor),
        "the sole aggregate test constructor must stay #[cfg(test)]-gated"
    );
    assert_eq!(
        public_state
            .matches("pub(crate) fn load_persisted_active_snapshot(")
            .count(),
        1,
        "exactly one production snapshot loader"
    );
    let gated_parts_loader = concat!(
        "#[cfg(test)]\n",
        "pub(crate) fn load_persisted_active_snapshot_from_parts_for_test(",
    );
    assert!(
        public_state.contains(gated_parts_loader),
        "the parts-level snapshot loader must stay #[cfg(test)]-gated"
    );
}
