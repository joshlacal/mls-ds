//! Finding-3 wedge: a pending Reset row whose original requester loses live
//! device authority permanently disables Reset for the WHOLE conversation.
//!
//! `prepare_reset_read_set_inner` seals any pending row it finds before either
//! endpoint can classify it, and `seal_pending_reset` re-verifies the ORIGINAL
//! requester's live device. `load_locked_pending_row` selects by
//! `conversation_id` alone, so after the requester is revoked or rebound the
//! seal fails for every caller — including the `requestReset` arm that is
//! supposed to expire the stale row.
//!
//! This target exists because neither existing harness can host the proof:
//! `chat_protocol_reset_repository.rs` includes `reset.rs` but draws its
//! fixtures from the shared database, which holds zero `chat.reset_requests`
//! rows, while the harnesses carrying `common/executor_seed.rs` (and its
//! per-run databases) do not include `reset.rs`.
//!
//! Run:
//!   CHAT_OPERATION_CLAIM_ACTIVATION_APPROVED=handlers-and-legacy-apis-sealed \
//!   TEST_DATABASE_URL=postgres://localhost/catbird_chat_protocol_test_20260722 \
//!   cargo test --test chat_protocol_reset_wedge -- --test-threads=1

#![allow(dead_code)]

mod common;

#[allow(dead_code)]
#[path = "../src/chat_protocol/model.rs"]
mod model;
#[allow(dead_code)]
#[path = "../src/chat_protocol/relationship_policy.rs"]
mod relationship_policy_source;
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
    pub mod validation {
        pub use crate::validation::*;
    }
    pub mod model {
        pub(crate) use crate::model::*;
    }
    pub mod transcript {
        pub use crate::transcript::*;
    }
    pub mod snapshot {
        pub use catbird_server::chat_protocol::snapshot::*;
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
    #[allow(dead_code)]
    pub mod dpop {
        include!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/chat_protocol/dpop.rs"
        ));
    }
    pub mod relationship_policy {
        pub use crate::relationship_policy_source::*;
    }
    pub mod repository {
        // Every module the executor's dependency closure names — `auth`,
        // `blobs`, `core`, `delivery`, `execution_context`, `prelude`,
        // `recovery`, `relationship`, `transition` — is the REAL production
        // source, path-included the way the sibling harnesses do it (see
        // `tests/chat_protocol_conversation_substrate.rs`). Several are
        // `#[cfg(not(test))]` in the lib (`core`, `execution_context`,
        // `relationship`), so a `#[path]`-including harness must include the
        // real module itself rather than link it.
        #[allow(dead_code)]
        pub mod execution_context {
            include!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/src/chat_protocol/repository/execution_context.rs"
            ));
        }
        // Unconditionally compiled in the lib for exactly this reason (see the
        // comments on `repository::blobs` / `key_packages` in repository/mod.rs).
        #[allow(dead_code)]
        pub mod blobs {
            include!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/src/chat_protocol/repository/blobs.rs"
            ));
        }
        #[allow(dead_code)]
        pub mod key_packages {
            include!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/src/chat_protocol/repository/key_packages.rs"
            ));
        }
        #[allow(dead_code)]
        pub mod auth {
            include!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/src/chat_protocol/repository/auth.rs"
            ));
        }
        #[allow(dead_code)]
        pub mod prelude {
            include!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/src/chat_protocol/repository/prelude.rs"
            ));
        }
        // `recovery` is `#[allow(dead_code)] pub(crate)` (unconditional) in the
        // lib, and supplies the REAL `RecoveryPersistenceWitness`,
        // `RecoveryExecutorWriteAuthority`, `PreparedRecoveryExecutionGraph`, and
        // `RecoverySqlAuthoritySeal` that `execution_context` and the executor
        // name in their signatures. Path-included here — exactly as
        // `tests/chat_protocol_conversation_substrate.rs` does — so this harness
        // exercises the production Recovery persistence boundary rather than
        // opaque stand-ins.
        pub mod recovery {
            #![allow(dead_code)]
            include!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/src/chat_protocol/repository/recovery.rs"
            ));
        }
        pub mod relationship {
            #![allow(dead_code)]
            include!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/src/chat_protocol/repository/relationship.rs"
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
        // The module under test. `reset.rs` carries no `#[cfg(test)]`
        // prohibition (unlike `read_authority.rs`), so including it here makes
        // the harness a DESCENDANT of it: a child module below can reach
        // `load_locked_pending_row` and `seal_pending_reset` without widening
        // any production visibility.
        pub mod reset {
            #![allow(dead_code)]
            include!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/src/chat_protocol/repository/reset.rs"
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

use executor_seed::private_genuine_pending_reset_graph;

/// Proves the fixture itself: a genuine, live, PENDING `chat.reset_requests`
/// row exists in a private per-run database, with both principals current.
/// Everything downstream reads `DeviceOrKeyDrift` off this exact state, so a
/// silently empty or already-consumed fixture would make the wedge tests
/// vacuous.
#[tokio::test]
async fn pending_reset_fixture_leaves_one_live_unconsumed_request() {
    let fixture = private_genuine_pending_reset_graph().await;

    let (status, terminal_transition_id, terminal_at, requester_did, requester_device_id): (
        String,
        Option<uuid::Uuid>,
        Option<chrono::DateTime<chrono::Utc>>,
        String,
        uuid::Uuid,
    ) = sqlx::query_as(
        r#"SELECT status,terminal_transition_id,terminal_at,requester_did,requester_device_id
             FROM chat.reset_requests
            WHERE conversation_id=$1"#,
    )
    .bind(fixture.conversation_id)
    .fetch_one(&fixture.pool)
    .await
    .expect("exactly one seeded reset request");

    assert_eq!(status, "pending");
    assert!(terminal_transition_id.is_none());
    assert!(terminal_at.is_none());
    assert_eq!(requester_did, fixture.requester_did);
    assert_eq!(requester_device_id, fixture.requester_device_id);
    assert_eq!(fixture.reset_request_id.get_version_num(), 4);

    // Live, not expired: the wedge is about authority drift, not expiry.
    assert!(fixture.expires_at > fixture.received_at);
    assert_ne!(fixture.other_did, fixture.requester_did);
}
