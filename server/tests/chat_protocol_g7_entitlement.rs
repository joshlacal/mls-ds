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

// DELIBERATELY NO CRATE-LEVEL `#![allow(dead_code)]`.
//
// This suite's entire value is that its negatives RUN. A blanket dead-code
// allow at crate root is precisely the mechanism that let two security helpers
// (`get_devices_attempt_verifies` and `proof_rejects_foreign_transaction`) sit
// in this file with zero callers while every drift negative silently never
// executed. The allow is therefore narrowed to the path-included production
// modules and the shared fixture helpers below, where "not every consuming
// test uses every helper" is genuinely true. Anything this file DEFINES for
// itself — bridge functions, fixtures, guards — is now covered by the
// `dead_code` lint, so an unwired negative is a compiler warning again.

#[allow(dead_code)]
mod common;

#[allow(dead_code)]
#[path = "../src/chat_protocol/cursor.rs"]
mod cursor;
#[allow(dead_code)]
#[path = "../src/chat_protocol/model.rs"]
mod model;
#[allow(dead_code)]
#[path = "../src/chat_protocol/relationship_policy.rs"]
mod relationship_policy_source;
#[allow(unused_imports)]
mod repository {
    pub use crate::chat_protocol::repository::{auth, blobs, inventory, key_packages, prelude};
}
#[allow(dead_code)]
mod snapshot {
    pub use catbird_server::chat_protocol::snapshot::*;
}
#[allow(dead_code)]
#[path = "../src/chat_protocol/read_projection.rs"]
mod read_projection;
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
        #![allow(dead_code)]
        include!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/chat_protocol/dpop.rs"
        ));
    }
    pub mod snapshot {
        pub use catbird_server::chat_protocol::snapshot::*;
    }
    pub mod error {
        pub use catbird_server::chat_protocol::error::*;
    }
    pub mod read_projection {
        pub use crate::read_projection::*;
    }
    /// Test-crate visibility bridge for the B-auth read authority.
    ///
    /// The budgets, attempts, locked row, and row proof are
    /// `pub(in crate::chat_protocol)`. A `#[test] fn` must live at the crate
    /// root for the sealed `--exact` gate commands to name it, and the crate
    /// root is outside that visibility. This module sits INSIDE
    /// `crate::chat_protocol`, so it can reach them and hand the crate root
    /// only plain counts, booleans, and the `pub(crate)` error type.
    ///
    /// It adds **no constructor**. Every function here calls the production
    /// constructor and cannot fabricate a `VerifiedReadAdmission`: that still
    /// requires `seal_read_admission` over a real committed
    /// `VerifiedChatDeviceRequest`. It widens no production visibility — it
    /// exists only in this test crate.
    pub mod b_auth_bridge {
        use super::dpop::{
            LockedReadDatabaseRow, ReadAdmissionAttempt, ReadAdmissionBindingError,
            VerifiedExistingDeviceReadRow, VerifiedReadAdmission,
        };
        use chrono::{DateTime, Utc};
        use sha2::{Digest, Sha256};
        use sqlx::{FromRow, PgPool};
        use uuid::Uuid;

        /// The two ordered `FOR UPDATE` statements, replicated in the test so
        /// the attempt/row bridge can be exercised without the
        /// `cfg(not(test))` facade.
        const LOCK_DEVICE_SQL: &str = r#"
            SELECT user_did, device_id, status, dpop_jkt, auth_generation
              FROM chat.devices
             WHERE user_did = $1 AND device_id = $2
             FOR UPDATE
        "#;
        const LOCK_KEY_SQL: &str = r#"
            SELECT key_id, signing_public_key, revoked_at
              FROM chat.device_keys
             WHERE user_did = $1 AND device_id = $2
             FOR UPDATE
        "#;

        #[derive(FromRow)]
        struct DeviceRow {
            user_did: String,
            device_id: Uuid,
            status: String,
            dpop_jkt: String,
            auth_generation: i64,
        }

        #[derive(FromRow)]
        struct KeyRow {
            key_id: String,
            signing_public_key: Vec<u8>,
            revoked_at: Option<DateTime<Utc>>,
        }

        /// The protected query every verified row proof gates. It runs ONLY
        /// after `verify_same_transaction` returns `Ok`, so a nonzero
        /// `protected_queries` count is proof that the gate opened, and a zero
        /// count on a negative is proof that it did not.
        const PROTECTED_QUERY_SQL: &str =
            "SELECT count(*) FROM chat.devices WHERE user_did = $1 AND device_id = $2";

        /// How far one attempt got before it was refused.
        #[derive(Debug, PartialEq, Eq)]
        pub enum AttemptStage {
            /// One of the two ordered `FOR UPDATE` statements returned no row.
            RowsAbsent,
            /// The structural constructor `from_repository_lock` refused.
            ConstructorRefused,
            /// The consuming verifier `consume_verify_locked_row` refused.
            VerifierRefused,
            /// The row proof failed its same-transaction check.
            TransactionRefused,
            /// Verified, and the protected query ran under the proof.
            Verified,
        }

        /// Exactly what one drift shape reached.
        pub struct AttemptOutcome {
            pub stage: AttemptStage,
            pub error: Option<ReadAdmissionBindingError>,
            /// Protected queries actually ISSUED — an execution counter
            /// incremented by the statement that runs `PROTECTED_QUERY_SQL`,
            /// never a per-arm literal. See the counter's declaration in
            /// `get_devices_attempt_verifies` for why that distinction is the
            /// whole value of this field.
            pub protected_queries: usize,
        }

        /// What a row proof minted under transaction A did in transaction B.
        pub struct ForeignTransactionOutcome {
            /// The proof accepts the transaction it was minted under. This is
            /// the positive control: without it, a proof that rejected
            /// EVERYTHING would satisfy the negative below.
            pub own_transaction_accepted: bool,
            /// The two sampled transaction identities really differ.
            pub transactions_differ: bool,
            /// The refusal under the foreign transaction.
            pub foreign_error: ReadAdmissionBindingError,
            /// Protected queries actually ISSUED under the foreign transaction
            /// — an execution counter, not a boolean re-encoding of
            /// `foreign_error`.
            pub protected_queries: usize,
        }

        /// What one full three-attempt run actually spent.
        ///
        /// TWO FIELDS WERE REMOVED FROM THIS LEDGER, DELIBERATELY.
        /// `attempts_minted` was `attempts.len()` on a `[T; 3]`, i.e. a
        /// compile-time constant, so `assert_eq!(attempts_minted, 3)` was
        /// `assert_eq!(3, 3)`; the three-ness of the budget is enforced by the
        /// exact-length `let [first, second, third]` binding below (a fourth
        /// element is a compile error) and by `assert_attempt_minting_sites`.
        /// `protected_queries` could never differ from `attempts_verified` —
        /// the two increments sit in the same straight-line block with only a
        /// `?` between them, which aborts the whole helper — so asserting both
        /// was one assertion reported twice.
        pub struct AttemptLedger {
            /// Attempts whose consuming verification returned a row proof.
            pub attempts_verified: usize,
            /// Distinct database transaction identities used.
            pub distinct_transactions: usize,
            /// Times the PREVIOUS attempt's row proof was refused by the
            /// successor attempt's fresh transaction. The prior transaction is
            /// rolled back and its proof dropped before the next array element
            /// is used; this counts the refusals that prove it.
            pub prior_proof_rejections: usize,
        }

        /// Try to convert an admission into the closed `GetDevices` budget and
        /// spend its single attempt. The attempt is dropped unspent on purpose:
        /// this probes the endpoint gate, which runs before any SQL.
        pub fn try_mint_get_devices_budget(
            admission: VerifiedReadAdmission,
        ) -> Result<(), ReadAdmissionBindingError> {
            let budget = admission.into_get_devices_read_admission()?;
            let _attempt: ReadAdmissionAttempt = budget.into_attempt();
            Ok(())
        }

        /// Same probe for the closed `GetOwnDevices` budget.
        ///
        /// The `let [_, _, _] = …` pattern is an exact-length binding: it
        /// compiles only while `into_attempts` returns exactly three elements.
        /// A fourth element would be a compile error here, which is what
        /// "a fourth attempt is unrepresentable" means operationally.
        pub fn try_mint_get_own_devices_budget(
            admission: VerifiedReadAdmission,
        ) -> Result<usize, ReadAdmissionBindingError> {
            let budget = admission.into_get_own_devices_read_admission()?;
            let attempts = budget.into_attempts();
            let [_first, _second, _third] = attempts;
            Ok(3)
        }

        /// Read the two ordered locks and build the structural row.
        ///
        /// `drift` may alter exactly one column so the consuming verifier has
        /// something to reject. Drift is applied to the value handed to the
        /// production constructor, never to the database.
        ///
        /// `Ok(None)` means a lock returned no row (missing device or missing
        /// key); `Err` means the production structural constructor refused the
        /// shape. The two are distinguished because they are different sealed
        /// negatives and collapsing them would let either one vanish.
        #[allow(clippy::too_many_arguments)]
        async fn locked_row_in(
            transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
            did: &str,
            device_id: Uuid,
            transaction_id: &str,
            drift: RowDrift,
        ) -> Result<Option<LockedReadDatabaseRow>, ReadAdmissionBindingError> {
            let device: Option<DeviceRow> = sqlx::query_as(LOCK_DEVICE_SQL)
                .bind(did)
                .bind(device_id)
                .fetch_optional(&mut **transaction)
                .await
                .expect("ordered device FOR UPDATE lock");
            let Some(device) = device else {
                return Ok(None);
            };
            let key: Option<KeyRow> = sqlx::query_as(LOCK_KEY_SQL)
                .bind(did)
                .bind(device_id)
                .fetch_optional(&mut **transaction)
                .await
                .expect("ordered device-key FOR UPDATE lock");
            let Some(key) = key else {
                return Ok(None);
            };
            let signing_sha: [u8; 32] = Sha256::digest(&key.signing_public_key).into();

            let status = drift.status.unwrap_or(device.status);
            let jkt = drift.textual_jkt.unwrap_or(device.dpop_jkt);
            let generation = drift.auth_generation.unwrap_or(device.auth_generation);
            let key_id = drift.key_id.unwrap_or(key.key_id);
            let signing_sha = drift.signing_sha256.unwrap_or(signing_sha);
            let revoked_at = drift.key_revoked_at.or(key.revoked_at);
            let row_did = drift.did.unwrap_or(device.user_did);
            let row_device = drift.device_id.unwrap_or(device.device_id);

            LockedReadDatabaseRow::from_repository_lock(
                transaction_id.to_owned().into_boxed_str(),
                row_did.into_boxed_str(),
                row_device,
                status.into_boxed_str(),
                jkt.into_boxed_str(),
                generation,
                key_id.into_boxed_str(),
                signing_sha,
                revoked_at,
            )
            .map(Some)
        }

        /// Run the REAL structural constructor over synthetic column values.
        ///
        /// No database, no unchecked constructor: this is
        /// `LockedReadDatabaseRow::from_repository_lock`, the production
        /// constructor, called with the exact shapes the sealed authority says
        /// it must refuse. It lets the malformed / padded / noncanonical /
        /// wrong-length / double-hashed thumbprint and nonpositive generation
        /// negatives EXECUTE in the no-database gate rather than waiting on a
        /// database-marked case.
        #[allow(clippy::too_many_arguments)]
        pub fn structural_row_outcome(
            transaction_id: &str,
            did: &str,
            device_id: Uuid,
            device_status: &str,
            textual_jkt: &str,
            auth_generation: i64,
            key_id: &str,
            signing_public_key_sha256: [u8; 32],
            key_revoked_at: Option<DateTime<Utc>>,
        ) -> Result<(), ReadAdmissionBindingError> {
            LockedReadDatabaseRow::from_repository_lock(
                transaction_id.to_owned().into_boxed_str(),
                did.to_owned().into_boxed_str(),
                device_id,
                device_status.to_owned().into_boxed_str(),
                textual_jkt.to_owned().into_boxed_str(),
                auth_generation,
                key_id.to_owned().into_boxed_str(),
                signing_public_key_sha256,
                key_revoked_at,
            )
            .map(|_| ())
        }

        /// Exactly one column of drift, or none.
        #[derive(Default)]
        pub struct RowDrift {
            pub did: Option<String>,
            pub device_id: Option<Uuid>,
            pub status: Option<String>,
            pub textual_jkt: Option<String>,
            pub auth_generation: Option<i64>,
            pub key_id: Option<String>,
            pub signing_sha256: Option<[u8; 32]>,
            pub key_revoked_at: Option<DateTime<Utc>>,
        }

        /// Spend the single `GetDevices` attempt against the real ordered
        /// locks, optionally drifting one row column first.
        ///
        /// `lock_coordinates` is read BEFORE the attempt is consumed. That is
        /// the non-consuming proof: if it took `self`, the
        /// `consume_verify_locked_row` call below would not compile.
        pub async fn get_devices_attempt_verifies(
            pool: &PgPool,
            admission: VerifiedReadAdmission,
            drift: RowDrift,
        ) -> Result<AttemptOutcome, ReadAdmissionBindingError> {
            let attempt = admission.into_get_devices_read_admission()?.into_attempt();
            let (did, device_id) = {
                let coordinates = attempt.lock_coordinates();
                (coordinates.did.to_owned(), coordinates.device_id)
            };
            let mut transaction = pool.begin().await.expect("begin read attempt transaction");
            let transaction_id: String = sqlx::query_scalar("SELECT txid_current()::text")
                .fetch_one(&mut *transaction)
                .await
                .expect("sample the attempt transaction identity");
            // THE PROTECTED-QUERY COUNTER IS AN EXECUTION COUNTER, AND THAT IS
            // THE ENTIRE POINT OF THIS BINDING.
            //
            // The previous form typed `protected_queries: 0` as a literal into
            // every refusal arm and `1` into the verified arm. A count is then
            // a restatement of the arm label: `assert_eq!(stage, VerifierRefused)`
            // already pins the arm, so `assert_eq!(protected_queries, 0)` could
            // not fail independently — and, worse, it would still have read
            // zero if the refusal path HAD issued protected SQL, which is the
            // exact regression the caption claims to exclude.
            //
            // Bound to the statement instead, a zero is a measurement. Hoisting
            // the `PROTECTED_QUERY_SQL` call above the `verify_same_transaction`
            // gate makes every negative in the drift matrix fail.
            let mut protected_queries = 0_usize;
            let outcome = match locked_row_in(
                &mut transaction,
                &did,
                device_id,
                &transaction_id,
                drift,
            )
            .await
            {
                Ok(None) => AttemptOutcome {
                    stage: AttemptStage::RowsAbsent,
                    error: None,
                    protected_queries,
                },
                Err(error) => AttemptOutcome {
                    stage: AttemptStage::ConstructorRefused,
                    error: Some(error),
                    protected_queries,
                },
                // The attempt is STILL spendable here, which is the point:
                // `lock_coordinates` borrowed it rather than consuming it.
                Ok(Some(row)) => match attempt.consume_verify_locked_row(row) {
                    Err(error) => AttemptOutcome {
                        stage: AttemptStage::VerifierRefused,
                        error: Some(error),
                        protected_queries,
                    },
                    Ok(verified) => match verified.verify_same_transaction(&transaction_id) {
                        Err(error) => AttemptOutcome {
                            stage: AttemptStage::TransactionRefused,
                            error: Some(error),
                            protected_queries,
                        },
                        Ok(()) => {
                            let _: i64 = sqlx::query_scalar(PROTECTED_QUERY_SQL)
                                .bind(&did)
                                .bind(device_id)
                                .fetch_one(&mut *transaction)
                                .await
                                .expect("protected query under a verified row proof");
                            protected_queries += 1;
                            AttemptOutcome {
                                stage: AttemptStage::Verified,
                                error: None,
                                protected_queries,
                            }
                        }
                    },
                },
            };
            let _ = transaction.rollback().await;
            Ok(outcome)
        }

        /// Mint a row proof under one transaction and check it against a
        /// different transaction's identity.
        ///
        /// Reports the positive control alongside the negative: the same proof
        /// must ACCEPT its own transaction, or a proof that refused everything
        /// would satisfy the foreign-transaction assertion while proving
        /// nothing.
        pub async fn proof_rejects_foreign_transaction(
            pool: &PgPool,
            admission: VerifiedReadAdmission,
        ) -> Result<ForeignTransactionOutcome, ReadAdmissionBindingError> {
            let attempt = admission.into_get_devices_read_admission()?.into_attempt();
            let (did, device_id) = {
                let coordinates = attempt.lock_coordinates();
                (coordinates.did.to_owned(), coordinates.device_id)
            };
            let mut first = pool.begin().await.expect("begin transaction A");
            let first_id: String = sqlx::query_scalar("SELECT txid_current()::text")
                .fetch_one(&mut *first)
                .await
                .expect("transaction A identity");
            let row = locked_row_in(&mut first, &did, device_id, &first_id, RowDrift::default())
                .await?
                .expect("transaction A locks both requester rows");
            let verified = attempt.consume_verify_locked_row(row)?;
            let own_transaction_accepted = verified.verify_same_transaction(&first_id).is_ok();
            let _ = first.rollback().await;

            let mut second = pool.begin().await.expect("begin transaction B");
            let second_id: String = sqlx::query_scalar("SELECT txid_current()::text")
                .fetch_one(&mut *second)
                .await
                .expect("transaction B identity");
            // The protected query is gated on that check. It is ISSUED here
            // when the gate opens rather than inferred from `outcome.is_ok()`,
            // so a zero below means the statement did not execute instead of
            // meaning "we already decided it would not".
            let mut protected_queries = 0_usize;
            let outcome = verified.verify_same_transaction(&second_id);
            if outcome.is_ok() {
                let _: i64 = sqlx::query_scalar(PROTECTED_QUERY_SQL)
                    .bind(&did)
                    .bind(device_id)
                    .fetch_one(&mut *second)
                    .await
                    .expect("protected query under a verified row proof");
                protected_queries += 1;
            }
            let _ = second.rollback().await;
            Ok(ForeignTransactionOutcome {
                own_transaction_accepted,
                transactions_differ: first_id != second_id,
                foreign_error: outcome
                    .expect_err("a foreign transaction must be rejected before protected SQL"),
                protected_queries,
            })
        }

        /// The retained trusted instant, reduced to a whole second.
        pub async fn bounded_created_at(
            pool: &PgPool,
            admission: VerifiedReadAdmission,
        ) -> Result<DateTime<Utc>, ReadAdmissionBindingError> {
            let attempt = admission.into_get_devices_read_admission()?.into_attempt();
            let (did, device_id) = {
                let coordinates = attempt.lock_coordinates();
                (coordinates.did.to_owned(), coordinates.device_id)
            };
            let mut transaction = pool
                .begin()
                .await
                .expect("begin bounded-instant transaction");
            let transaction_id: String = sqlx::query_scalar("SELECT txid_current()::text")
                .fetch_one(&mut *transaction)
                .await
                .expect("bounded-instant transaction identity");
            let row = locked_row_in(
                &mut transaction,
                &did,
                device_id,
                &transaction_id,
                RowDrift::default(),
            )
            .await?
            .expect("bounded-instant fixture locks both requester rows");
            let verified = attempt.consume_verify_locked_row(row)?;
            let created_at = verified.bounded_snapshot_created_at()?;
            let _ = transaction.rollback().await;
            Ok(created_at)
        }

        /// Run the whole fixed three-attempt budget, each element in its own
        /// fresh transaction, and report exactly what was spent.
        pub async fn own_devices_attempt_ledger(
            pool: &PgPool,
            admission: VerifiedReadAdmission,
        ) -> Result<AttemptLedger, ReadAdmissionBindingError> {
            // Exact-length binding: three, or this does not compile.
            let [first, second, third] = admission
                .into_get_own_devices_read_admission()?
                .into_attempts();
            let attempts = [first, second, third];

            let mut attempts_verified = 0_usize;
            let mut prior_proof_rejections = 0_usize;
            let mut transaction_ids: Vec<String> = Vec::new();
            let mut prior_proof: Option<VerifiedExistingDeviceReadRow> = None;

            for attempt in attempts {
                let (did, device_id) = {
                    let coordinates = attempt.lock_coordinates();
                    (coordinates.did.to_owned(), coordinates.device_id)
                };
                let mut transaction = pool.begin().await.expect("begin a fresh attempt");
                let transaction_id: String = sqlx::query_scalar("SELECT txid_current()::text")
                    .fetch_one(&mut *transaction)
                    .await
                    .expect("fresh attempt transaction identity");
                // PRIOR-TRANSACTION DROP. The previous attempt's transaction
                // was rolled back above; its row proof must therefore be
                // refused by this fresh transaction. If it were accepted, a
                // dropped transaction would still be authorizing protected SQL.
                if let Some(previous) = prior_proof.take() {
                    if previous.verify_same_transaction(&transaction_id).is_err() {
                        prior_proof_rejections += 1;
                    }
                }
                transaction_ids.push(transaction_id.clone());
                let Some(row) = locked_row_in(
                    &mut transaction,
                    &did,
                    device_id,
                    &transaction_id,
                    RowDrift::default(),
                )
                .await?
                else {
                    let _ = transaction.rollback().await;
                    continue;
                };
                let verified = attempt.consume_verify_locked_row(row)?;
                attempts_verified += 1;
                // Every protected query is gated on the same-transaction proof.
                verified.verify_same_transaction(&transaction_id)?;
                let _: i64 = sqlx::query_scalar(PROTECTED_QUERY_SQL)
                    .bind(&did)
                    .bind(device_id)
                    .fetch_one(&mut *transaction)
                    .await
                    .expect("protected own-device query");
                // Roll the whole attempt back before the next array element,
                // and carry its proof forward only so the successor can refuse
                // it.
                let _ = transaction.rollback().await;
                prior_proof = Some(verified);
            }

            transaction_ids.sort();
            transaction_ids.dedup();
            Ok(AttemptLedger {
                attempts_verified,
                distinct_transactions: transaction_ids.len(),
                prior_proof_rejections,
            })
        }
    }
    /// Test-crate visibility bridge for the B-read authority module.
    ///
    /// The B-read budgets, conversions, lock entry point, and fence types are
    /// `pub(in crate::chat_protocol)`. A `#[test] fn` must live at the crate
    /// root for the sealed `--exact` gate commands to name it, and the crate
    /// root is outside that visibility. This module sits INSIDE
    /// `crate::chat_protocol`, so it can reach them and hand the crate root
    /// only plain values and `pub(crate)` view DTOs.
    ///
    /// It adds **no constructor**: every function here calls a production
    /// constructor or accessor and cannot fabricate a budget, attempt,
    /// authority, or fence.
    pub mod read_authority_bridge {
        use super::dpop::{ReadAdmissionAttempt, VerifiedReadAdmission};
        use super::read_authority::{
            ControlRecipientFenceWitness, ConversationInventoryArm, ConversationInventoryAuthority,
            ConversationStateReadAuthority, CurrentConversationRelationshipWitness,
            EntryIntervalTerminalWitness, EntryIntervalWitness, EntryReadAuthority,
            InventoryFenceWitness, LockedDurableInventoryFenceRow, LockedInventoryFenceRecord,
            LockedReadDeviceAuthority, ReadAuthorityError, VerifiedInventoryFence,
        };
        use chrono::{DateTime, Utc};
        use sqlx::{PgPool, Postgres, Transaction};
        use uuid::Uuid;

        /// Mint the ordinary budget and spend its single attempt, dropping it
        /// unspent on purpose: this probes the endpoint gate, which runs
        /// before any SQL.
        pub fn try_single_read_admission(
            admission: VerifiedReadAdmission,
            endpoint: OrdinaryReadEndpoint,
        ) -> Result<(), ReadAuthorityError> {
            let budget = super::read_authority::into_single_read_admission(
                admission,
                endpoint.into_production(),
            )?;
            let _attempt: ReadAdmissionAttempt = budget.into_attempt();
            Ok(())
        }

        /// Mint the inventory budget and bind its exactly-three attempts. The
        /// `let [_, _, _] = …` pattern is an exact-length binding: it compiles
        /// only while `into_attempts` returns exactly three elements, so a
        /// fourth attempt is unrepresentable here as well as in production.
        pub fn try_inventory_read_admission(
            admission: VerifiedReadAdmission,
            endpoint: InventoryReadEndpoint,
        ) -> Result<usize, ReadAuthorityError> {
            let budget = super::read_authority::into_inventory_read_admission(
                admission,
                endpoint.into_production(),
            )?;
            let attempts = budget.into_attempts();
            let [_first, _second, _third] = attempts;
            Ok(3)
        }

        /// The production lock entry point, handed to the crate root.
        pub async fn lock_read_device_authority_once(
            tx: &mut Transaction<'_, Postgres>,
            attempt: ReadAdmissionAttempt,
        ) -> Result<LockedReadDeviceAuthority, ReadAuthorityError> {
            super::read_authority::lock_read_device_authority_once(tx, attempt).await
        }

        /// Test-crate mirrors of the closed endpoint enums. The production
        /// enums are `pub(in crate::chat_protocol)` and cannot be named or
        /// re-exported wider; these mirrors carry the SAME closed variant set
        /// and are converted into the production enums at the production
        /// conversion call. They add no endpoint and no method: they are
        /// argument carriers for the tests, and the production conversions
        /// still perform the hidden endpoint/method revalidation.
        #[derive(Clone, Copy)]
        pub(crate) enum OrdinaryReadEndpoint {
            GetConversationState,
            GetEntries,
            GetPendingWelcomes,
            GetLeafRecoveryInbox,
            GetBlob,
            GetSubscriptionTicket,
            SubscribeEvents,
            PublishTyping,
        }

        impl OrdinaryReadEndpoint {
            fn into_production(self) -> super::read_authority::OrdinaryReadEndpoint {
                match self {
                    Self::GetConversationState => {
                        super::read_authority::OrdinaryReadEndpoint::GetConversationState
                    }
                    Self::GetEntries => super::read_authority::OrdinaryReadEndpoint::GetEntries,
                    Self::GetPendingWelcomes => {
                        super::read_authority::OrdinaryReadEndpoint::GetPendingWelcomes
                    }
                    Self::GetLeafRecoveryInbox => {
                        super::read_authority::OrdinaryReadEndpoint::GetLeafRecoveryInbox
                    }
                    Self::GetBlob => super::read_authority::OrdinaryReadEndpoint::GetBlob,
                    Self::GetSubscriptionTicket => {
                        super::read_authority::OrdinaryReadEndpoint::GetSubscriptionTicket
                    }
                    Self::SubscribeEvents => {
                        super::read_authority::OrdinaryReadEndpoint::SubscribeEvents
                    }
                    Self::PublishTyping => {
                        super::read_authority::OrdinaryReadEndpoint::PublishTyping
                    }
                }
            }
        }

        #[derive(Clone, Copy)]
        pub(crate) enum InventoryReadEndpoint {
            GetConversations,
        }

        impl InventoryReadEndpoint {
            fn into_production(self) -> super::read_authority::InventoryReadEndpoint {
                super::read_authority::InventoryReadEndpoint::GetConversations
            }
        }

        /// Mint the ordinary budget, spend its single attempt, and lock the
        /// exact device. The transaction stays alive in the returned handle so
        /// the test can authorize against it and then roll back with forced
        /// deferred constraints.
        pub async fn lock_single_attempt(
            pool: &PgPool,
            admission: VerifiedReadAdmission,
            endpoint: OrdinaryReadEndpoint,
        ) -> Result<(LockedReadDeviceAuthority, Transaction<'static, Postgres>), ReadAuthorityError>
        {
            let budget = super::read_authority::into_single_read_admission(
                admission,
                endpoint.into_production(),
            )?;
            let attempt = budget.into_attempt();
            let mut tx = pool
                .begin()
                .await
                .map_err(|_| ReadAuthorityError::Storage)?;
            let guard = lock_read_device_authority_once(&mut tx, attempt).await?;
            Ok((guard, tx))
        }

        /// Mint the ordinary budget, spend its single attempt, and lock the
        /// exact device inside an ALREADY-open transaction (used by the drift
        /// cases that stage row mutations before the lock).
        pub async fn single_attempt_lock_in(
            tx: &mut Transaction<'_, Postgres>,
            admission: VerifiedReadAdmission,
            endpoint: OrdinaryReadEndpoint,
        ) -> Result<LockedReadDeviceAuthority, ReadAuthorityError> {
            let budget = super::read_authority::into_single_read_admission(
                admission,
                endpoint.into_production(),
            )?;
            let attempt = budget.into_attempt();
            lock_read_device_authority_once(tx, attempt).await
        }

        /// Mint the inventory budget, spend its first attempt, and lock the
        /// exact device. The transaction stays alive in the returned handle.
        pub async fn lock_inventory_attempt(
            pool: &PgPool,
            admission: VerifiedReadAdmission,
        ) -> Result<(LockedReadDeviceAuthority, Transaction<'static, Postgres>), ReadAuthorityError>
        {
            let budget = super::read_authority::into_inventory_read_admission(
                admission,
                super::read_authority::InventoryReadEndpoint::GetConversations,
            )?;
            let attempts = budget.into_attempts();
            let [first, _second, _third] = attempts;
            let mut tx = pool
                .begin()
                .await
                .map_err(|_| ReadAuthorityError::Storage)?;
            let guard = lock_read_device_authority_once(&mut tx, first).await?;
            Ok((guard, tx))
        }

        pub fn device_txid(device: &LockedReadDeviceAuthority) -> i64 {
            device.txid()
        }

        pub fn device_verify_same_transaction(
            device: &LockedReadDeviceAuthority,
            txid: i64,
        ) -> Result<(), ReadAuthorityError> {
            device.verify_same_transaction(txid)
        }

        pub fn device_binding_sha256(device: &LockedReadDeviceAuthority) -> [u8; 32] {
            *device.device_row_sha256()
        }

        pub fn device_identity(device: &LockedReadDeviceAuthority) -> (String, Uuid) {
            (device.user_did().to_owned(), device.device_id())
        }

        /// Probe the validating durable-record constructor: `Some(error)` when
        /// the material is rejected, `None` when it is structurally accepted.
        /// The record itself never leaves the bridge.
        #[allow(clippy::too_many_arguments)]
        pub(crate) fn fence_material_rejected(
            protocol_instance_id: Uuid,
            cursor_key_id: String,
            event_position: u64,
            event_cursor_sha256: [u8; 32],
            retained_floor: u64,
            captured_at: DateTime<Utc>,
        ) -> Option<ReadAuthorityError> {
            LockedInventoryFenceRecord::from_lock_material(
                protocol_instance_id,
                cursor_key_id,
                event_position,
                event_cursor_sha256,
                retained_floor,
                captured_at,
            )
            .err()
        }

        /// Verify one fence built from durable lock material against the
        /// given transaction and locked device. The record and durable row
        /// never leave the bridge.
        #[allow(clippy::too_many_arguments)]
        pub(crate) async fn verify_fence_material(
            tx: &mut Transaction<'_, Postgres>,
            device: LockedReadDeviceAuthority,
            protocol_instance_id: Uuid,
            cursor_key_id: String,
            event_position: u64,
            event_cursor_sha256: [u8; 32],
            retained_floor: u64,
            captured_at: DateTime<Utc>,
        ) -> Result<VerifiedInventoryFence, ReadAuthorityError> {
            let record = LockedInventoryFenceRecord::from_lock_material(
                protocol_instance_id,
                cursor_key_id,
                event_position,
                event_cursor_sha256,
                retained_floor,
                captured_at,
            )?;
            let row = super::read_authority::from_locked_inventory_fence_record(record);
            super::read_authority::verify_inventory_fence(tx, device, row).await
        }

        /// Probe the B-read seam methods directly: the hidden endpoint/method
        /// revalidation runs before any SQL, and the seam's OWN redacted error
        /// (not the free function's mapping) is returned.
        pub fn seam_single_outcome(
            admission: VerifiedReadAdmission,
            endpoint: OrdinaryReadEndpoint,
        ) -> Result<(), super::dpop::ReadAdmissionBindingError> {
            let production = endpoint.into_production();
            let attempt = admission
                .into_single_read_attempt(production.nsid(), production.canonical_method())?;
            let _ = attempt;
            Ok(())
        }

        /// Probe the inventory seam directly.
        pub fn seam_inventory_outcome(
            admission: VerifiedReadAdmission,
            endpoint: InventoryReadEndpoint,
        ) -> Result<(), super::dpop::ReadAdmissionBindingError> {
            let production = endpoint.into_production();
            let attempts = admission
                .into_inventory_read_attempts(production.nsid(), production.canonical_method())?;
            let [_first, _second, _third] = attempts;
            Ok(())
        }

        /// What one full three-attempt inventory run actually spent.
        pub struct FreshGuardLedger {
            /// Distinct transaction identities the three guards were minted
            /// under.
            pub distinct_transactions: usize,
            /// Times the PREVIOUS attempt's guard was refused by the successor
            /// attempt's fresh transaction.
            pub prior_refusals: usize,
            /// Attempts whose lock+verify succeeded.
            pub verified: usize,
        }

        /// Spend the fixed three-attempt inventory budget: each attempt locks
        /// fresh rows in its own fresh transaction and mints a guard for that
        /// transaction; the previous transaction is rolled back and its guard
        /// dropped before the next array element is used.
        pub async fn inventory_fresh_guard_ledger(
            pool: &PgPool,
            admission: VerifiedReadAdmission,
        ) -> Result<FreshGuardLedger, ReadAuthorityError> {
            let budget = super::read_authority::into_inventory_read_admission(
                admission,
                super::read_authority::InventoryReadEndpoint::GetConversations,
            )?;
            let attempts = budget.into_attempts();
            // The exact-length binding: a fourth element is a compile error.
            let [first, second, third] = attempts;
            let mut verified = 0_usize;
            let mut prior_refusals = 0_usize;
            let mut transaction_ids: Vec<i64> = Vec::with_capacity(3);
            let mut prior_guard: Option<LockedReadDeviceAuthority> = None;
            for attempt in [first, second, third] {
                let mut tx = pool
                    .begin()
                    .await
                    .map_err(|_| ReadAuthorityError::Storage)?;
                let txid: i64 = sqlx::query_scalar("SELECT txid_current()::bigint")
                    .fetch_one(&mut *tx)
                    .await
                    .map_err(|_| ReadAuthorityError::Storage)?;
                // PRIOR-TRANSACTION DROP: the previous attempt's transaction
                // was rolled back above, so its guard must be refused by this
                // fresh transaction.
                if let Some(prior) = prior_guard.take() {
                    if prior.verify_same_transaction(txid).is_err() {
                        prior_refusals += 1;
                    }
                }
                let guard = lock_read_device_authority_once(&mut tx, attempt).await?;
                verified += 1;
                transaction_ids.push(device_txid(&guard));
                prior_guard = Some(guard);
                let _ = tx.rollback().await;
            }
            transaction_ids.sort();
            transaction_ids.dedup();
            Ok(FreshGuardLedger {
                distinct_transactions: transaction_ids.len(),
                prior_refusals,
                verified,
            })
        }

        /// Lock one single-attempt ordinary guard under transaction A, then
        /// authorize a conversation under transaction B.
        ///
        /// Returns `(locked_ok, transactions_differ, outcome)` where `outcome`
        /// is the refusal the foreign transaction produced. The conversation
        /// id is deliberately nonexistent: if the same-transaction check runs
        /// before any conversation lookup, the refusal is the transaction
        /// identity error and never `ConversationNotFound`.
        pub async fn single_foreign_transaction_outcome(
            pool: &PgPool,
            admission: VerifiedReadAdmission,
        ) -> Result<(bool, bool, ReadAuthorityError), ReadAuthorityError> {
            let budget = super::read_authority::into_single_read_admission(
                admission,
                super::read_authority::OrdinaryReadEndpoint::GetConversationState,
            )?;
            let attempt = budget.into_attempt();
            let mut tx_a = pool
                .begin()
                .await
                .map_err(|_| ReadAuthorityError::Storage)?;
            let guard = lock_read_device_authority_once(&mut tx_a, attempt).await?;
            let txid_a = device_txid(&guard);
            let _ = tx_a.rollback().await;

            let mut tx_b = pool
                .begin()
                .await
                .map_err(|_| ReadAuthorityError::Storage)?;
            let txid_b: i64 = sqlx::query_scalar("SELECT txid_current()::bigint")
                .fetch_one(&mut *tx_b)
                .await
                .map_err(|_| ReadAuthorityError::Storage)?;
            let outcome = super::read_authority::authorize_conversation_state(
                &mut tx_b,
                guard,
                Uuid::new_v4(),
            )
            .await
            .err()
            .expect("a guard minted under transaction A cannot authorize under B");
            let _ = tx_b.rollback().await;
            Ok((true, txid_a != txid_b, outcome))
        }

        /// One full inventory run: budget attempt, device lock, fence
        /// verification, authorities, and a constraint-forced rollback.
        pub struct InventoryRunOutcome {
            pub device_txid: i64,
            pub device_binding: [u8; 32],
            pub authorities: Vec<InventoryAuthorityView>,
        }

        #[allow(clippy::too_many_arguments)]
        pub async fn inventory_run(
            pool: &PgPool,
            admission: VerifiedReadAdmission,
            protocol_instance_id: Uuid,
            cursor_key_id: String,
            event_position: u64,
            event_cursor_sha256: [u8; 32],
            retained_floor: u64,
            captured_at: DateTime<Utc>,
        ) -> Result<InventoryRunOutcome, ReadAuthorityError> {
            let budget = super::read_authority::into_inventory_read_admission(
                admission,
                super::read_authority::InventoryReadEndpoint::GetConversations,
            )?;
            let attempts = budget.into_attempts();
            let [first, _second, _third] = attempts;
            let mut tx = pool
                .begin()
                .await
                .map_err(|_| ReadAuthorityError::Storage)?;
            let guard = lock_read_device_authority_once(&mut tx, first).await?;
            let device_txid = device_txid(&guard);
            let device_binding = device_binding_sha256(&guard);
            let fence = verify_fence_material(
                &mut tx,
                guard,
                protocol_instance_id,
                cursor_key_id,
                event_position,
                event_cursor_sha256,
                retained_floor,
                captured_at,
            )
            .await?;
            let authorities = super::read_authority::inventory_authorities(&mut tx, fence).await?;
            let views: Vec<InventoryAuthorityView> =
                authorities.iter().map(inventory_authority_view).collect();
            sqlx::query("SET CONSTRAINTS ALL IMMEDIATE")
                .execute(&mut *tx)
                .await
                .map_err(|_| ReadAuthorityError::Storage)?;
            tx.rollback()
                .await
                .map_err(|_| ReadAuthorityError::Storage)?;
            Ok(InventoryRunOutcome {
                device_txid,
                device_binding,
                authorities: views,
            })
        }

        // -------------------------------------------------------------------
        // Minimum-immutable-view DTOs. The production accessors are
        // `pub(in crate::chat_protocol)` (BREAD-08); this bridge converts them
        // into plain `pub(crate)` views for the crate root.
        // -------------------------------------------------------------------

        #[derive(Debug, Clone)]
        pub(crate) enum RelationshipArmView {
            OpenLeaf,
            ActiveParticipant,
            GroupPendingParticipant,
        }

        #[derive(Debug, Clone)]
        pub(crate) struct RelationshipWitnessView {
            pub arm: RelationshipArmView,
            pub participant_period_id: Uuid,
            pub leaf_period_id: Option<Uuid>,
            pub open_membership_interval_id: Option<Uuid>,
        }

        #[derive(Debug, Clone)]
        pub(crate) struct StateAuthorityView {
            pub conversation_id: Uuid,
            pub graph_digest: [u8; 32],
            pub snapshot_digest: [u8; 32],
            pub user_did: String,
            pub device_id: Uuid,
            pub relationship: RelationshipWitnessView,
        }

        #[derive(Debug, Clone)]
        pub(crate) enum IntervalTerminalView {
            Open {
                observed_head_seq: u64,
                row_sha256: [u8; 32],
            },
            Closed {
                terminal_seq: u64,
                closing_transition_id: Uuid,
                closing_outer_entry_fingerprint: [u8; 32],
                closing_kind: String,
                row_sha256: [u8; 32],
            },
        }

        #[derive(Debug, Clone)]
        pub(crate) struct IntervalWitnessView {
            pub membership_interval_id: Uuid,
            pub conversation_id: Uuid,
            pub recipient_did: String,
            pub recipient_device_id: Uuid,
            pub start_seq: u64,
            pub opening_transition_id: Uuid,
            pub opening_outer_entry_fingerprint: [u8; 32],
            pub terminal: IntervalTerminalView,
        }

        #[derive(Debug, Clone)]
        pub(crate) struct ControlRecipientFenceView {
            pub maximum_event_position: u64,
            pub maximum_entry_seq: u64,
            pub ordered_recipient_rows_sha256: [u8; 32],
        }

        #[derive(Debug, Clone)]
        pub(crate) struct EntryAuthorityView {
            pub ordered_intervals: Vec<IntervalWitnessView>,
            pub ordered_intervals_sha256: [u8; 32],
            pub control_recipient_fence: ControlRecipientFenceView,
        }

        #[derive(Debug, Clone)]
        pub(crate) struct InventoryFenceWitnessView {
            pub protocol_instance_id: Uuid,
            pub cursor_key_id: String,
            pub event_position: u64,
            pub event_cursor_sha256: [u8; 32],
            pub retained_floor: u64,
            pub captured_at: DateTime<Utc>,
        }

        #[derive(Debug, Clone)]
        pub(crate) enum InventoryArmView {
            State {
                participant_period_id: Uuid,
            },
            Removal {
                membership_interval_id: Uuid,
                terminal_seq: u64,
                closing_transition_id: Uuid,
                closing_outer_entry_fingerprint: Vec<u8>,
                removed_at: DateTime<Utc>,
            },
            Close {
                terminal_seq: u64,
                closing_transition_id: Uuid,
                closing_outer_entry_fingerprint: Vec<u8>,
            },
        }

        #[derive(Debug, Clone)]
        pub(crate) struct InventoryAuthorityView {
            pub txid: i64,
            pub device_binding_sha256: [u8; 32],
            pub conversation_id: Uuid,
            pub graph_digest: [u8; 32],
            pub snapshot_digest: [u8; 32],
            pub fence: InventoryFenceWitnessView,
            pub arm: InventoryArmView,
        }

        pub(crate) fn state_authority_view(
            authority: &ConversationStateReadAuthority,
        ) -> StateAuthorityView {
            let relationship = match authority.relationship() {
                CurrentConversationRelationshipWitness::CurrentOpenLeaf {
                    participant_period_id,
                    leaf_period_id,
                    open_membership_interval_id,
                } => RelationshipWitnessView {
                    arm: RelationshipArmView::OpenLeaf,
                    participant_period_id: *participant_period_id,
                    leaf_period_id: Some(*leaf_period_id),
                    open_membership_interval_id: Some(*open_membership_interval_id),
                },
                CurrentConversationRelationshipWitness::CurrentActiveParticipant {
                    participant_period_id,
                } => RelationshipWitnessView {
                    arm: RelationshipArmView::ActiveParticipant,
                    participant_period_id: *participant_period_id,
                    leaf_period_id: None,
                    open_membership_interval_id: None,
                },
                CurrentConversationRelationshipWitness::CurrentGroupPendingParticipant {
                    participant_period_id,
                } => RelationshipWitnessView {
                    arm: RelationshipArmView::GroupPendingParticipant,
                    participant_period_id: *participant_period_id,
                    leaf_period_id: None,
                    open_membership_interval_id: None,
                },
            };
            StateAuthorityView {
                conversation_id: authority.conversation_id(),
                graph_digest: *authority.graph_digest(),
                snapshot_digest: *authority.snapshot_digest(),
                user_did: authority.user_did().to_owned(),
                device_id: authority.device_id(),
                relationship,
            }
        }

        fn interval_terminal_view(terminal: &EntryIntervalTerminalWitness) -> IntervalTerminalView {
            match terminal {
                EntryIntervalTerminalWitness::Open {
                    observed_head_seq,
                    row_sha256,
                } => IntervalTerminalView::Open {
                    observed_head_seq: *observed_head_seq,
                    row_sha256: *row_sha256,
                },
                EntryIntervalTerminalWitness::Closed {
                    terminal_seq,
                    closing_transition_id,
                    closing_outer_entry_fingerprint,
                    closing_kind,
                    row_sha256,
                } => IntervalTerminalView::Closed {
                    terminal_seq: *terminal_seq,
                    closing_transition_id: *closing_transition_id,
                    closing_outer_entry_fingerprint: *closing_outer_entry_fingerprint,
                    closing_kind: closing_kind.clone(),
                    row_sha256: *row_sha256,
                },
            }
        }

        fn interval_view(interval: &EntryIntervalWitness) -> IntervalWitnessView {
            IntervalWitnessView {
                membership_interval_id: interval.membership_interval_id(),
                conversation_id: interval.conversation_id(),
                recipient_did: interval.recipient_did().to_owned(),
                recipient_device_id: interval.recipient_device_id(),
                start_seq: interval.start_seq(),
                opening_transition_id: interval.opening_transition_id(),
                opening_outer_entry_fingerprint: *interval.opening_outer_entry_fingerprint(),
                terminal: interval_terminal_view(interval.terminal()),
            }
        }

        fn control_recipient_fence_view(
            fence: &ControlRecipientFenceWitness,
        ) -> ControlRecipientFenceView {
            ControlRecipientFenceView {
                maximum_event_position: fence.maximum_event_position(),
                maximum_entry_seq: fence.maximum_entry_seq(),
                ordered_recipient_rows_sha256: *fence.ordered_recipient_rows_sha256(),
            }
        }

        pub(crate) fn entry_authority_view(authority: &EntryReadAuthority) -> EntryAuthorityView {
            EntryAuthorityView {
                ordered_intervals: authority
                    .ordered_intervals()
                    .iter()
                    .map(interval_view)
                    .collect(),
                ordered_intervals_sha256: *authority.ordered_intervals_sha256(),
                control_recipient_fence: control_recipient_fence_view(
                    authority.control_recipient_fence(),
                ),
            }
        }

        fn inventory_fence_view(fence: &InventoryFenceWitness) -> InventoryFenceWitnessView {
            InventoryFenceWitnessView {
                protocol_instance_id: fence.protocol_instance_id(),
                cursor_key_id: fence.cursor_key_id().to_owned(),
                event_position: fence.event_position(),
                event_cursor_sha256: *fence.event_cursor_sha256(),
                retained_floor: fence.retained_floor(),
                captured_at: fence.captured_at(),
            }
        }

        pub(crate) fn inventory_authority_view(
            authority: &ConversationInventoryAuthority,
        ) -> InventoryAuthorityView {
            let arm = match authority.arm() {
                ConversationInventoryArm::State {
                    participant_period_id,
                } => InventoryArmView::State {
                    participant_period_id: *participant_period_id,
                },
                ConversationInventoryArm::Removal {
                    membership_interval_id,
                    terminal_seq,
                    closing_transition_id,
                    closing_outer_entry_fingerprint,
                    removed_at,
                } => InventoryArmView::Removal {
                    membership_interval_id: *membership_interval_id,
                    terminal_seq: *terminal_seq,
                    closing_transition_id: *closing_transition_id,
                    closing_outer_entry_fingerprint: closing_outer_entry_fingerprint.clone(),
                    removed_at: *removed_at,
                },
                ConversationInventoryArm::Close {
                    terminal_seq,
                    closing_transition_id,
                    closing_outer_entry_fingerprint,
                } => InventoryArmView::Close {
                    terminal_seq: *terminal_seq,
                    closing_transition_id: *closing_transition_id,
                    closing_outer_entry_fingerprint: closing_outer_entry_fingerprint.clone(),
                },
            };
            InventoryAuthorityView {
                txid: authority.txid(),
                device_binding_sha256: *authority.device_binding_sha256(),
                conversation_id: authority.conversation_id(),
                graph_digest: *authority.graph_digest(),
                snapshot_digest: *authority.snapshot_digest(),
                fence: inventory_fence_view(authority.fence()),
                arm,
            }
        }
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
    pub mod read_authority {
        #![allow(dead_code)]
        include!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/chat_protocol/read_authority.rs"
        ));

        /// Pure coverage for the interval-witness validator's boundary rules. These run
        /// wherever a harness `include!`s this file as a module of the test crate, so
        /// they need no database and no fixture corpus.
        #[cfg(test)]
        mod interval_witness_boundary_tests {
            use super::*;

            const OPENING_FINGERPRINT: [u8; 32] = [7u8; 32];
            const UNRELATED_FINGERPRINT: [u8; 32] = [9u8; 32];

            /// One closed row that ends at `terminal_seq` with the given closing
            /// evidence, followed by one open row that starts at `start_seq`.
            fn touching_pair(
                closing_kind: &str,
                opening_kind: &str,
                terminal_seq: i64,
                start_seq: i64,
                boundary_transition: Uuid,
                opening_transition: Uuid,
                closing_fingerprint: [u8; 32],
            ) -> Vec<ExactDeviceIntervalRow> {
                let conversation_id = Uuid::new_v4();
                let recipient_device_id = Uuid::new_v4();
                let base = |start: i64, opening_kind: &str, opening_transition: Uuid| {
                    ExactDeviceIntervalRow {
                        membership_interval_id: Uuid::new_v4(),
                        conversation_id,
                        generation: 0,
                        recipient_did: "did:plc:reader".to_owned(),
                        recipient_device_id,
                        start_seq: start,
                        opening_transition_id: opening_transition,
                        opening_outer_entry_fingerprint: OPENING_FINGERPRINT.to_vec(),
                        opening_kind: opening_kind.to_owned(),
                        terminal_seq: None,
                        closing_transition_id: None,
                        closing_outer_entry_fingerprint: None,
                        closing_kind: None,
                    }
                };
                let mut closed = base(1, "creation", Uuid::new_v4());
                closed.terminal_seq = Some(terminal_seq);
                closed.closing_transition_id = Some(boundary_transition);
                closed.closing_outer_entry_fingerprint = Some(closing_fingerprint.to_vec());
                closed.closing_kind = Some(closing_kind.to_owned());
                vec![closed, base(start_seq, opening_kind, opening_transition)]
            }

            #[test]
            fn reset_touching_boundary_is_accepted() {
                // The reset activator's own pair: `chat.assert_application_interval_schedule`
                // REQUIRES the successor to open exactly at the reset terminal.
                let boundary = Uuid::new_v4();
                let rows = touching_pair(
                    "reset",
                    "reset",
                    6,
                    6,
                    boundary,
                    boundary,
                    OPENING_FINGERPRINT,
                );
                let witnesses = build_ordered_interval_witnesses(rows, 12)
                    .expect("a mandated reset->reset touch is not an overlap");
                assert_eq!(witnesses.len(), 2);
                assert_eq!(witnesses[1].start_seq, 6);
            }

            #[test]
            fn replace_touching_boundary_is_accepted() {
                // The leaf-recovery-replaced device's pair; `replace` without a touching
                // successor is itself a schema violation.
                let boundary = Uuid::new_v4();
                let rows = touching_pair(
                    "replace",
                    "add",
                    4,
                    4,
                    boundary,
                    boundary,
                    OPENING_FINGERPRINT,
                );
                let witnesses = build_ordered_interval_witnesses(rows, 9)
                    .expect("a mandated replace->add touch is not an overlap");
                assert_eq!(witnesses.len(), 2);
            }

            #[test]
            fn touching_boundary_needs_the_same_transition_on_both_sides() {
                let rows = touching_pair(
                    "reset",
                    "reset",
                    6,
                    6,
                    Uuid::new_v4(),
                    Uuid::new_v4(),
                    OPENING_FINGERPRINT,
                );
                // `matches!` rather than `unwrap_err`: the witness stays non-Debug.
                assert!(matches!(
                    build_ordered_interval_witnesses(rows, 12),
                    Err(ReadAuthorityError::Invariant)
                ));
            }

            #[test]
            fn touching_boundary_needs_the_same_entry_fingerprint() {
                let boundary = Uuid::new_v4();
                let rows = touching_pair(
                    "reset",
                    "reset",
                    6,
                    6,
                    boundary,
                    boundary,
                    UNRELATED_FINGERPRINT,
                );
                // `matches!` rather than `unwrap_err`: the witness stays non-Debug.
                assert!(matches!(
                    build_ordered_interval_witnesses(rows, 12),
                    Err(ReadAuthorityError::Invariant)
                ));
            }

            #[test]
            fn only_replace_add_and_reset_reset_may_touch() {
                // `remove` closes a genuine gap, so its successor must start strictly
                // later; the trigger rejects a `remove` touch as illegal.
                let boundary = Uuid::new_v4();
                let rows = touching_pair(
                    "remove",
                    "add",
                    6,
                    6,
                    boundary,
                    boundary,
                    OPENING_FINGERPRINT,
                );
                // `matches!` rather than `unwrap_err`: the witness stays non-Debug.
                assert!(matches!(
                    build_ordered_interval_witnesses(rows, 12),
                    Err(ReadAuthorityError::Invariant)
                ));
            }

            #[test]
            fn a_terminal_close_may_not_touch_a_successor() {
                // Terminal finality: the trigger admits a touch only for
                // 'replace' and 'reset', so a 'terminal' close touching any
                // successor stays rejected. Guards against the loosened
                // boundary overshooting into accepting illegal touches.
                let boundary = Uuid::new_v4();
                for opening_kind in ["add", "reset", "creation"] {
                    let rows = touching_pair(
                        "terminal",
                        opening_kind,
                        6,
                        6,
                        boundary,
                        boundary,
                        OPENING_FINGERPRINT,
                    );
                    assert!(matches!(
                        build_ordered_interval_witnesses(rows, 12),
                        Err(ReadAuthorityError::Invariant)
                    ));
                }
            }

            #[test]
            fn a_legal_pair_may_not_touch_with_the_wrong_opening_kind() {
                // The kind PAIR is load-bearing, not just the closing kind:
                // 'replace' pairs only with 'add' and 'reset' only with 'reset'.
                let boundary = Uuid::new_v4();
                for (closing, opening) in [("replace", "reset"), ("reset", "add")] {
                    let rows = touching_pair(
                        closing,
                        opening,
                        6,
                        6,
                        boundary,
                        boundary,
                        OPENING_FINGERPRINT,
                    );
                    assert!(matches!(
                        build_ordered_interval_witnesses(rows, 12),
                        Err(ReadAuthorityError::Invariant)
                    ));
                }
            }

            #[test]
            fn a_remove_close_still_requires_a_strict_gap() {
                // 'remove' closes a genuine gap: a successor must start strictly
                // later, and that successor is accepted.
                let boundary = Uuid::new_v4();
                let rows = touching_pair(
                    "remove",
                    "add",
                    6,
                    7,
                    boundary,
                    Uuid::new_v4(),
                    OPENING_FINGERPRINT,
                );
                assert!(build_ordered_interval_witnesses(rows, 12).is_ok());
            }

            #[test]
            fn a_true_overlap_is_still_rejected() {
                // The loosened boundary must not admit `start_seq < terminal_seq`.
                let boundary = Uuid::new_v4();
                let rows = touching_pair(
                    "reset",
                    "reset",
                    6,
                    5,
                    boundary,
                    boundary,
                    OPENING_FINGERPRINT,
                );
                // `matches!` rather than `unwrap_err`: the witness stays non-Debug.
                assert!(matches!(
                    build_ordered_interval_witnesses(rows, 12),
                    Err(ReadAuthorityError::Invariant)
                ));
            }
        }
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

#[allow(dead_code)]
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

// Re-pinned after the C2 lane. The previous value was set at `e98ef5da` and
// three later sealed commits changed the helper without re-pinning it, so both
// guards below asserted a baseline that no longer existed:
//   b2f7ae9e  production's single-clock time model in the executor fixtures
//   a63bc3fa  the signing authority production always mints
//   0c6290a0  the planner's own due-expiry rows in coordinate-changing arms
// Re-pin only alongside a reviewed change to `tests/common/executor_seed.rs`;
// an unexplained mismatch here still means the seed drifted.
const FROZEN_EXECUTOR_SEED_SHA256: &str =
    "d7a4e316c3292ea7958a9d454154ebf1957a2e24735fc20d18cb1d42773f92f8";
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

// ===========================================================================
// Stage-B B-auth: the exact entitlement test matrix (Task B4, core half).
//
// Everything above this banner is the preserved Stage-T successor: the P
// hydration proof, the frozen-helper guard, and the production-hydrator source
// guards. Nothing above is rewritten.
//
// The eight tests below are the sealed B-auth entitlement matrix. Four are
// nonignored pure/source/compile guards that run in the no-database gate. Four
// are `#[ignore]`d Tokio database cases classified `commit-write`; Task B6
// executes them.
//
// WHY THE DATABASE CASES USE THE PRIVATE PER-RUN EXECUTOR DATABASE
// ----------------------------------------------------------------
// They commit real replay rows. `executor_seed::setup()` gives each case its
// own RAII `chat_exec_*` database, so a `commit-write` case leaves no residue
// in the shared clean-chat database and none attributable to the run. This is
// the same harness the preserved P case above already uses.
//
// WHY THE FACADE IS NOT EXERCISED HERE
// ------------------------------------
// B3 gated the whole `inventory.rs` B-auth section behind `#[cfg(not(test))]`
// (documented at `inventory.rs:2854`) because three unowned integration crates
// provide no `chat_protocol::dpop` module at all. `cfg(test)` is set for an
// integration crate, so the facade is ABSENT from this crate's path-included
// `mod inventory`. Facade and handler behaviour is therefore proved by B3's
// `chat_protocol_device_handlers.rs` through the real router, and by source
// guard here. This file proves the receipt/budget/attempt/row layer, which is
// exactly the split the authority assigns to the entitlement test.
// ===========================================================================

use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine as _,
};
use ed25519_dalek::{Signer, SigningKey};
use serde_json::json;

/// Fixed registered-device facts. These are the same constants
/// `dpop::repository_test_evidence::ordinary_registered_device` binds, so the
/// seeded row and the cryptographic evidence address the same device.
const B_AUTH_DID: &str = "did:plc:ewvi7nxzyoun6zhxrhs64oiz";
const B_AUTH_DEVICE: &str = "3b241101-e2bb-4255-8caf-4136c566a962";
const B_AUTH_JKT: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const B_AUTH_KEY_ID: &str = "If4x36FUomFia_hUBG_SJxt77UtqvkWqWId-9H-XIbk";
const B_AUTH_RFC8032_SEED: &str =
    "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
const B_AUTH_T: &str = "2026-07-22T14:05:09.123Z";

// THE SENTINEL LIST IS GONE, AND ITS ABSENCE IS THE POINT.
//
// `B_AUTH_REDACTION_SENTINELS` held 13 needles that were swept against
// `format!("{:?}")` of a thirteen-UNIT-VARIANT enum. No sentinel is a substring
// of any variant name, so not one of those ~240 assertions could ever fail.
// Deleting the sweeps left the constant unreferenced, and the `dead_code` lint
// — re-enabled at the top of this file precisely so unused test machinery
// cannot hide — flagged it immediately. That is the mechanism working.
//
// Sentinel sweeping is genuinely discriminating only where request material
// could actually reach the rendering. That is the HTTP response body, and it
// is done over the real router in `chat_protocol_device_handlers.rs`. Here the
// redaction is held instead by assertions that can fail: the unit-variant
// shape guard, the derived-`Debug`/no-`Display` guard, and exact equality
// between each rendering and its declared variant name.

fn b_auth_signing_key() -> SigningKey {
    let bytes: [u8; 32] = hex::decode(B_AUTH_RFC8032_SEED)
        .expect("fixed RFC8032 seed is hex")
        .try_into()
        .expect("fixed RFC8032 seed is 32 bytes");
    SigningKey::from_bytes(&bytes)
}

fn b_auth_proof_jti() -> [u8; 12] {
    Uuid::new_v4().as_bytes()[..12]
        .try_into()
        .expect("UUID prefix has the fixed proof-JTI length")
}

/// Seed exactly one active device plus its unrevoked immutable key.
async fn seed_b_auth_device(pool: &PgPool) {
    sqlx::query(
        "INSERT INTO chat.principals(user_did, created_at) \
         VALUES($1,$2::timestamptz) ON CONFLICT DO NOTHING",
    )
    .bind(B_AUTH_DID)
    .bind(B_AUTH_T)
    .execute(pool)
    .await
    .expect("seed the B-auth principal");
    sqlx::query(
        r#"
        INSERT INTO chat.devices (
            user_did, device_id, device_name, status, dpop_jkt,
            auth_generation, capabilities, created_at, updated_at
        ) VALUES ($1,$2,$3,'active',$4,1,chat.protocol_capabilities(),
                  $5::timestamptz,$5::timestamptz)
        "#,
    )
    .bind(B_AUTH_DID)
    .bind(Uuid::parse_str(B_AUTH_DEVICE).expect("fixed device UUID"))
    .bind("b-auth-entitlement-device")
    .bind(B_AUTH_JKT)
    .bind(B_AUTH_T)
    .execute(pool)
    .await
    .expect("seed the B-auth device row");
    sqlx::query(
        r#"
        INSERT INTO chat.device_keys (
            user_did, device_id, key_id, signing_public_key,
            enrollment_auth_generation, created_at
        ) VALUES ($1,$2,$3,$4,1,$5::timestamptz)
        "#,
    )
    .bind(B_AUTH_DID)
    .bind(Uuid::parse_str(B_AUTH_DEVICE).expect("fixed device UUID"))
    .bind(B_AUTH_KEY_ID)
    .bind(
        b_auth_signing_key()
            .verifying_key()
            .as_bytes()
            .as_slice()
            .to_vec(),
    )
    .bind(B_AUTH_T)
    .execute(pool)
    .await
    .expect("seed the B-auth device key row");
}

/// A second device for the same principal that deliberately has NO
/// `chat.device_keys` row, so the ordered key lock finds nothing.
const B_AUTH_KEYLESS_DEVICE: &str = "4b241101-e2bb-4255-8caf-4136c566a963";

/// Seed the keyless device and return its canonical thumbprint.
///
/// This is an INSERT of a new row, never a mutation of the fixture rows:
/// `chat.devices` and `chat.device_keys` carry `BEFORE UPDATE OR DELETE`
/// immutability triggers, so the "missing key" negative cannot be staged by
/// deleting the seeded key.
async fn seed_b_auth_keyless_device(pool: &PgPool) -> String {
    let jkt = URL_SAFE_NO_PAD.encode([2_u8; 32]);
    sqlx::query(
        r#"
        INSERT INTO chat.devices (
            user_did, device_id, device_name, status, dpop_jkt,
            auth_generation, capabilities, created_at, updated_at
        ) VALUES ($1,$2,$3,'active',$4,1,chat.protocol_capabilities(),
                  $5::timestamptz,$5::timestamptz)
        "#,
    )
    .bind(B_AUTH_DID)
    .bind(Uuid::parse_str(B_AUTH_KEYLESS_DEVICE).expect("keyless device UUID"))
    .bind("b-auth-entitlement-keyless-device")
    .bind(&jkt)
    .bind(B_AUTH_T)
    .execute(pool)
    .await
    .expect("seed the keyless B-auth device row");
    jkt
}

/// A private per-run database with exactly one seeded B-auth device.
async fn b_auth_pool() -> (PgPool, executor_seed::FreshDbGuard) {
    let (pool, guard) = executor_seed::setup().await;
    seed_b_auth_device(&pool).await;
    (pool, guard)
}

/// Drive the REAL repository authorization for one unsigned read request.
/// This commits the replay set and mints the committed receipt.
async fn committed_read_authority(
    pool: &PgPool,
    endpoint: &str,
) -> chat_protocol::dpop::VerifiedChatDeviceRequest {
    repository::auth::authorize_unsigned_request(
        pool,
        chat_protocol::dpop::repository_test_evidence::ordinary_registered_device(
            Uuid::new_v4(),
            b_auth_proof_jti(),
            endpoint,
            B_AUTH_T,
        ),
    )
    .await
    .expect("the seeded active device authorizes an unsigned read")
}

/// A real, sealed admission for `endpoint`.
async fn real_read_admission(
    pool: &PgPool,
    endpoint: &str,
) -> chat_protocol::dpop::VerifiedReadAdmission {
    let authority = committed_read_authority(pool, endpoint).await;
    chat_protocol::dpop::seal_read_admission(authority)
        .expect("a committed existing-device receipt seals a read admission")
}

async fn consumed_replay_rows(pool: &PgPool) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM chat.dpop_replays WHERE subject_did = $1")
        .bind(B_AUTH_DID)
        .fetch_one(pool)
        .await
        .expect("count the committed replay rows for the test identity")
}

/// Exact signed `deleteBlob` wrapper bytes, signed by the seeded device key.
/// This is a legitimate repository variant, not an unchecked constructor: it
/// goes through `authorize_signed_request`, which commits its replay set before
/// any seal is attempted.
fn signed_blob_deletion_bytes(operation_id: Uuid, blob_id: Uuid) -> Vec<u8> {
    let body = json!({
        "$type": "blue.catbird.chat.defs#blobDeletionBody",
        "signatureDomain": "CATBIRD-CHAT-BLOB-DELETE\u{0000}",
        "blobId": blob_id,
        "actorDid": B_AUTH_DID,
        "actorDeviceId": B_AUTH_DEVICE,
        "keyId": B_AUTH_KEY_ID,
        "authGeneration": 1,
        "idempotencyKey": operation_id,
        "signedAt": B_AUTH_T,
    });
    let placeholder = serde_json::to_vec(&json!({
        "body": body.clone(),
        "signature": STANDARD.encode([0_u8; 64]),
    }))
    .expect("serialize the signing placeholder");
    let canonical = transcript::decode_canonical_signed_mutation(&placeholder)
        .expect("placeholder decodes canonically");
    let signature = b_auth_signing_key().sign(canonical.transcript_bytes());
    serde_json::to_vec(&json!({
        "body": body,
        "signature": STANDARD.encode(signature.to_bytes()),
    }))
    .expect("serialize the signed wrapper")
}

// ---------------------------------------------------------------------------
// Source-guard inputs. `include_str!` is compile-time: these are the exact
// candidate bytes, not a re-read of something that could have drifted.
// ---------------------------------------------------------------------------

const B_AUTH_DPOP_SOURCE: &str = include_str!("../src/chat_protocol/dpop.rs");
const B_AUTH_AUTH_SOURCE: &str = include_str!("../src/chat_protocol/repository/auth.rs");
const B_AUTH_PRELUDE_SOURCE: &str = include_str!("../src/chat_protocol/repository/prelude.rs");
const B_AUTH_CONTEXT_SOURCE: &str = include_str!("../src/handlers/chat/context.rs");
const B_AUTH_INVENTORY_SOURCE: &str = include_str!("../src/chat_protocol/repository/inventory.rs");
const B_AUTH_GET_DEVICES_SOURCE: &str = include_str!("../src/handlers/chat/get_devices.rs");
const B_AUTH_GET_OWN_DEVICES_SOURCE: &str = include_str!("../src/handlers/chat/get_own_devices.rs");
const B_AUTH_DEVICE_DIRECTORY_SOURCE: &str =
    include_str!("../src/chat_protocol/repository/device_directory.rs");
const B_AUTH_DEVICE_VIEWS_SOURCE: &str = include_str!("../src/handlers/chat/device_views.rs");
/// Read-only. The live schema floor that makes the nonpositive-generation
/// shapes unreachable from a real row.
const B_AUTH_CORE_MIGRATION_SOURCE: &str =
    include_str!("../migrations/20260722000001_chat_protocol_core.sql");

/// Every source file that could hold a `locked_auth_generation()` call.
///
/// The count predicate below is deliberately whole-file and never truncated: a
/// truncated search can support a positive finding but never a negative one.
const B_AUTH_MUTATION_GETTER_SOURCES: &[(&str, &str)] = &[
    ("repository/auth.rs", B_AUTH_AUTH_SOURCE),
    ("repository/prelude.rs", B_AUTH_PRELUDE_SOURCE),
    ("dpop.rs", B_AUTH_DPOP_SOURCE),
    ("handlers/chat/context.rs", B_AUTH_CONTEXT_SOURCE),
    ("repository/inventory.rs", B_AUTH_INVENTORY_SOURCE),
    ("handlers/chat/get_devices.rs", B_AUTH_GET_DEVICES_SOURCE),
    (
        "handlers/chat/get_own_devices.rs",
        B_AUTH_GET_OWN_DEVICES_SOURCE,
    ),
    (
        "repository/device_directory.rs",
        B_AUTH_DEVICE_DIRECTORY_SOURCE,
    ),
    ("handlers/chat/device_views.rs", B_AUTH_DEVICE_VIEWS_SOURCE),
];

/// The read-authority types whose privacy the guards assert.
const B_AUTH_READ_AUTHORITY_TYPES: &[&str] = &[
    "VerifiedReadAdmission",
    "ReadAdmissionBinding",
    "GetDevicesReadAdmission",
    "GetOwnDevicesReadAdmission",
    "ReadAdmissionAttempt",
    "ReadLockCoordinates",
    "LockedReadDatabaseRow",
    "VerifiedExistingDeviceReadRow",
];

/// Count non-overlapping occurrences of `needle` in `haystack`.
fn count_occurrences(haystack: &str, needle: &str) -> usize {
    haystack.matches(needle).count()
}

/// `source` with every whole-line `//` comment removed.
///
/// The "this handler contains no SQL / no retry loop" guards are claims about
/// CODE. Run naively they also match the doc comments that describe the
/// absence, so a handler documenting "no retry loop" fails its own guard. That
/// is a false positive, but the same looseness would let a real construct hide
/// behind a comment, so the guards below run over stripped code.
fn code_only(source: &str) -> String {
    source
        .lines()
        .filter(|line| {
            let trimmed = line.trim_start();
            !trimmed.starts_with("//")
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Find `item` as a WHOLE declaration, not as a prefix.
///
/// `find("enum ReadAdmissionBinding")` matches `enum ReadAdmissionBindingError`,
/// which silently pointed one guard at the wrong type. The character after the
/// name must therefore not be an identifier character.
fn find_declaration(source: &str, item: &str) -> Option<usize> {
    let mut from = 0_usize;
    while let Some(offset) = source[from..].find(item) {
        let index = from + offset;
        let next = source[index + item.len()..].chars().next();
        match next {
            Some(character) if character.is_alphanumeric() || character == '_' => {
                from = index + item.len();
            }
            _ => return Some(index),
        }
    }
    None
}

/// The declaration line of `item`, plus everything between it and the previous
/// blank line, so attribute lines such as `#[derive(..)]` are visible.
fn declaration_with_attributes<'a>(source: &'a str, item: &str) -> &'a str {
    let index =
        find_declaration(source, item).unwrap_or_else(|| panic!("source must declare {item}"));
    let start = source[..index].rfind("\n\n").map_or(0, |offset| offset + 2);
    let end = source[index..]
        .find('\n')
        .map_or(source.len(), |offset| index + offset);
    &source[start..end]
}

// ---------------------------------------------------------------------------
// 1. Nonignored pure/source: every invalid receipt shape is rejected, and every
//    rejection is redacted.
// ---------------------------------------------------------------------------

/// The rejection branches of `seal_read_admission`, in the order the sealed
/// authority requires them: shape first, then class/operation, then the
/// endpoint-owned method, then the single receipt coordinate seam, then
/// DID/device, JKT, and generation.
const B_AUTH_SEAL_ORDERED_REJECTIONS: &[&str] = &[
    "if request.mutation().is_some()",
    "ReadAdmissionBindingError::OperationShape",
    "pre_replay.enrollment.is_some()",
    "pre_replay.enrollment_body.is_some()",
    "pre_replay.rebind.is_some()",
    "pre_replay.auth_transaction_replay.is_some()",
    "ReadAdmissionBindingError::OperationShape",
    "receipt.class() != RepositoryAuthorityClass::ExistingDevice",
    "ReadAdmissionBindingError::AuthorityClass",
    "receipt.operation_id().is_some()",
    "ReadAdmissionBindingError::OperationShape",
    "endpoint\n        .dpop_method()",
    "pre_replay.method() != &endpoint_owned_method",
    "ReadAdmissionBindingError::MethodBinding",
    ".locked_existing_device_read_coordinates()",
    "ReadAdmissionBindingError::RequesterCoordinates",
    "coordinates.did != pre_replay.subject().as_str()",
    "coordinates.device_id.as_bytes() != pre_replay.device_id().as_bytes()",
    "ReadAdmissionBindingError::RequesterCoordinates",
    "coordinates.textual_jkt != pre_replay.dpop_jkt().as_str()",
    "ReadAdmissionBindingError::Thumbprint",
    "decode_canonical_thumbprint_digest(coordinates.textual_jkt)",
    "coordinates.auth_generation <= 0",
    "ReadAdmissionBindingError::Generation",
];

/// The rejection branches of `consume_verify_locked_row`, in order.
///
/// The seal chain above covers the RECEIPT shapes. This chain covers the ROW
/// drift shapes, which is where `KeyBinding`, `DeviceStatus` and `KeyRevoked`
/// actually live — none of them appears in `seal_read_admission`, so anchoring
/// only the seal would leave the key-mismatch branch unmapped.
const B_AUTH_VERIFIER_ORDERED_REJECTIONS: &[&str] = &[
    "let binding = self.binding;",
    "if &*row.device_status != \"active\"",
    "ReadAdmissionBindingError::DeviceStatus",
    "if row.key_revoked_at.is_some()",
    "ReadAdmissionBindingError::KeyRevoked",
    "if &*row.did != binding.locked_did.as_str() || row.device_id != binding.locked_device_id",
    "ReadAdmissionBindingError::RequesterCoordinates",
    "if decode_canonical_thumbprint_digest(&row.textual_jkt)? != binding.locked_jkt_digest",
    "ReadAdmissionBindingError::Thumbprint",
    "if row.auth_generation <= 0 || row.auth_generation != binding.locked_auth_generation",
    "ReadAdmissionBindingError::Generation",
    "if &*row.key_id != binding.locked_key_id.as_str()",
    "|| row.signing_public_key_sha256 != binding.locked_signing_key_sha256",
    "ReadAdmissionBindingError::KeyBinding",
    "Ok(VerifiedExistingDeviceReadRow {",
];

/// The variant name of a binding outcome, so negatives can be compared
/// EXACTLY without adding a `PartialEq` impl to the production error, which
/// deliberately derives nothing but `Debug`. `matches!` would silently pass a
/// pattern that no longer exists after a rename; a name comparison would not.
fn binding_outcome_name(
    outcome: &Result<(), chat_protocol::dpop::ReadAdmissionBindingError>,
) -> String {
    match outcome {
        Ok(()) => "Ok".to_owned(),
        Err(error) => format!("{error:?}"),
    }
}

/// The variant name of an optional binding error.
fn binding_error_name(error: &Option<chat_protocol::dpop::ReadAdmissionBindingError>) -> String {
    error
        .as_ref()
        .map_or_else(|| "None".to_owned(), |error| format!("{error:?}"))
}

/// The SHA-256 of the seeded device's signing public key — the exact value the
/// admission binds and the locked key row must reproduce.
fn b_auth_signing_key_sha256() -> [u8; 32] {
    Sha256::digest(b_auth_signing_key().verifying_key().as_bytes()).into()
}

/// Render a captured panic payload as text.
fn panic_message(payload: &Box<dyn std::any::Any + Send>) -> String {
    if let Some(text) = payload.downcast_ref::<String>() {
        return text.clone();
    }
    if let Some(text) = payload.downcast_ref::<&'static str>() {
        return (*text).to_owned();
    }
    panic!("a test panic payload must be a string");
}

/// A `tracing` writer that captures every emitted byte.
#[derive(Clone)]
struct CaptureWriter(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

impl std::io::Write for CaptureWriter {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        self.0
            .lock()
            .expect("the capture buffer is not poisoned")
            .extend_from_slice(buffer);
        Ok(buffer.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for CaptureWriter {
    type Writer = CaptureWriter;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

/// Run `emit` with a capturing `tracing` subscriber installed and return every
/// byte the log channel produced.
fn captured_log_channel(emit: impl FnOnce()) -> String {
    let buffer = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let subscriber = tracing_subscriber::fmt()
        .with_writer(CaptureWriter(std::sync::Arc::clone(&buffer)))
        .with_ansi(false)
        .with_max_level(tracing::Level::TRACE)
        .finish();
    tracing::subscriber::with_default(subscriber, emit);
    let bytes = buffer.lock().expect("the capture buffer is not poisoned");
    String::from_utf8_lossy(&bytes).into_owned()
}

/// Every variant of the redacted error, constructed for real.
fn b_auth_every_binding_error() -> Vec<chat_protocol::dpop::ReadAdmissionBindingError> {
    use chat_protocol::dpop::ReadAdmissionBindingError as E;
    vec![
        E::AuthorityClass,
        E::OperationShape,
        E::EndpointBinding,
        E::MethodBinding,
        E::RequesterCoordinates,
        E::Thumbprint,
        E::Generation,
        E::KeyBinding,
        E::DeviceStatus,
        E::KeyRevoked,
        E::LockedRowShape,
        E::TransactionIdentity,
        E::BoundedTimestamp,
    ]
}

#[test]
fn b_auth_read_admission_rejects_invalid_receipt_shapes_redacted() {
    // --- the rejection branches exist, in order, inside `seal_read_admission`
    let seal_start = B_AUTH_DPOP_SOURCE
        .find("pub(crate) fn seal_read_admission(")
        .expect("exact seal entry point");
    let seal_end = B_AUTH_DPOP_SOURCE[seal_start..]
        .find("\nimpl VerifiedReadAdmission {")
        .map(|offset| seal_start + offset)
        .expect("seal body ends before the budget conversions");
    require_ordered_anchors(
        &B_AUTH_DPOP_SOURCE[..seal_end],
        seal_start,
        B_AUTH_SEAL_ORDERED_REJECTIONS,
    );

    // --- canonical JKT decode: url-safe no-pad, exact 32 bytes, re-encode
    //     equality; and the text is never hashed.
    let decode_start = B_AUTH_DPOP_SOURCE
        .find("fn decode_canonical_thumbprint_digest(")
        .expect("exact canonical thumbprint decoder");
    let decode_end = decode_start
        + B_AUTH_DPOP_SOURCE[decode_start..]
            .find("\n}\n")
            .expect("decoder body terminates");
    let decoder = &B_AUTH_DPOP_SOURCE[decode_start..decode_end];
    assert!(
        decoder.contains("URL_SAFE_NO_PAD\n        .decode(textual_jkt)"),
        "the decoder must url-safe no-pad DECODE the textual JKT"
    );
    assert!(
        decoder.contains("let digest: [u8; 32] = decoded"),
        "the decoder must convert to EXACTLY 32 bytes"
    );
    assert!(
        decoder.contains("if URL_SAFE_NO_PAD.encode(digest) != textual_jkt"),
        "the decoder must re-encode and compare for canonicity"
    );
    assert!(
        !decoder.contains("Sha256"),
        "the JKT text must never be hashed — double-hashing yields a different value"
    );

    // --- the whole read path never SHA-256s a thumbprint text.
    for forbidden in [
        "Sha256::digest(textual_jkt",
        "Sha256::digest(coordinates.textual_jkt",
        "Sha256::digest(row.textual_jkt",
        "Sha256::digest(jkt",
    ] {
        assert_eq!(
            count_occurrences(B_AUTH_DPOP_SOURCE, forbidden),
            0,
            "the read path must never double-hash a JKT text ({forbidden})"
        );
    }

    // --- nonpositive generation is rejected in BOTH directions: at the seal and
    //     again inside the consuming verifier.
    assert_eq!(
        count_occurrences(B_AUTH_DPOP_SOURCE, "auth_generation <= 0"),
        3,
        "nonpositive generation is rejected at the seal, in the structural row \
         constructor, and in the consuming verifier"
    );
    assert!(
        B_AUTH_AUTH_SOURCE.contains("if auth_generation <= 0 {\n            return None;"),
        "the receipt coordinate seam yields nothing for a nonpositive generation"
    );

    // --- the ROW drift rejections, in order, inside the consuming verifier.
    //     `KeyBinding`, `DeviceStatus` and `KeyRevoked` live here, not in the
    //     seal, so the seal chain alone would leave them unanchored.
    let verifier_start = B_AUTH_DPOP_SOURCE
        .find("    pub(in crate::chat_protocol) fn consume_verify_locked_row(")
        .expect("exact consuming verifier entry point");
    let verifier_end = verifier_start
        + B_AUTH_DPOP_SOURCE[verifier_start..]
            .find("\n    }\n")
            .expect("the consuming verifier terminates");
    require_ordered_anchors(
        &B_AUTH_DPOP_SOURCE[..verifier_end],
        verifier_start,
        B_AUTH_VERIFIER_ORDERED_REJECTIONS,
    );

    // --- CONSTRUCTOR-WITHOUT-VERIFIER DENIAL, asserted rather than assumed.
    //     The success token has exactly one construction site in the whole
    //     module, and it is inside the consuming verifier. A structural row can
    //     therefore never become authority without being spent through it.
    //
    //     NOTE ON THE PREDICATE. `VerifiedExistingDeviceReadRow {` alone occurs
    //     three times — the declaration, the `impl` line, and the construction
    //     — which is exactly the counting mistake this suite has already made
    //     once. The predicate below is the construction expression `Ok(… {`,
    //     which no declaration or `impl` line can match.
    assert_eq!(
        count_occurrences(B_AUTH_DPOP_SOURCE, "Ok(VerifiedExistingDeviceReadRow {"),
        1,
        "the verified row proof has exactly one construction site"
    );
    let construction = B_AUTH_DPOP_SOURCE
        .find("Ok(VerifiedExistingDeviceReadRow {")
        .expect("the sole construction site");
    assert!(
        construction > verifier_start && construction < verifier_end,
        "the sole construction site lies inside `consume_verify_locked_row` \
         (bytes {verifier_start}..{verifier_end}), found at {construction}"
    );
    assert_eq!(
        count_occurrences(B_AUTH_DPOP_SOURCE, "struct VerifiedExistingDeviceReadRow"),
        1,
        "exactly one declaration of the verified row proof"
    );
    // The predicate is narrower than the bare type name, and demonstrably so.
    assert!(
        count_occurrences(B_AUTH_DPOP_SOURCE, "VerifiedExistingDeviceReadRow {")
            > count_occurrences(B_AUTH_DPOP_SOURCE, "Ok(VerifiedExistingDeviceReadRow {"),
        "the bare brace form occurs more often than the construction predicate, \
         so the predicate genuinely isolates the construction"
    );

    // --- the variants really are data-free, so no future payload can leak,
    //     and the redaction sweep below covers EVERY declared variant.
    let enum_start = B_AUTH_DPOP_SOURCE
        .find("pub(crate) enum ReadAdmissionBindingError {")
        .expect("exact redacted error enum");
    let enum_end = enum_start
        + B_AUTH_DPOP_SOURCE[enum_start..]
            .find("\n}\n")
            .expect("error enum terminates");
    let body = &B_AUTH_DPOP_SOURCE[enum_start..enum_end];
    let mut declared_variants: Vec<&str> = Vec::new();
    for line in body.lines().skip(1) {
        let line = line.trim();
        if line.is_empty() || line.starts_with("///") || line.starts_with("//") {
            continue;
        }
        assert!(
            !line.contains('(') && !line.contains('{'),
            "every error variant must be a unit variant, found: {line}"
        );
        declared_variants.push(
            line.strip_suffix(',')
                .unwrap_or_else(|| panic!("a unit variant line ends with a comma: {line}")),
        );
    }

    // --- WHAT ACTUALLY GUARANTEES THE REDACTION, AND WHY THERE IS NO SENTINEL
    //     SWEEP BELOW.
    //
    // A sentinel sweep over `format!("{:?}")` of a THIRTEEN-UNIT-VARIANT enum
    // cannot fail: the rendering is the variant name, and no sentinel is a
    // substring of any variant name. Roughly 240 such assertions were written
    // into this file and every one of them was decoration — the same defect
    // this suite exists to prevent, reproduced inside its own fix. They are
    // deleted rather than dressed up.
    //
    // The property is real and is held by three assertions that CAN fail, all
    // of which a mutation moves:
    //
    //   1. the unit-variant parse above — a variant that ever carried a
    //      payload (`Thumbprint(String)`) fails it;
    //   2. the derive/impl guard immediately below — the derived `Debug` of a
    //      unit variant can only print its own name, so the guarantee rests on
    //      the derive being what is actually in force. A hand-written `Debug`
    //      or a `Display` could print anything, and NOTHING in this file
    //      previously noticed one. That was a genuine hole, opened by relying
    //      on a sweep that could not see it;
    //   3. the exact-equality assertion below — the rendering must EQUAL the
    //      declared variant name, so any added payload, prefix or suffix
    //      fails. This is the discriminating form the sweep was pretending to
    //      be.
    //
    // End-to-end HTTP-body redaction is proved separately, over the real
    // router, by `chat_protocol_device_handlers.rs`.
    let error_declaration =
        declaration_with_attributes(B_AUTH_DPOP_SOURCE, "enum ReadAdmissionBindingError");
    assert!(
        error_declaration.contains("#[derive(Debug)]"),
        "the redacted error must render through the DERIVED Debug — a unit \
         variant's derived Debug can only print its own name, which is the \
         whole basis of the redaction claim; found: {error_declaration}"
    );
    for forbidden in [
        "impl std::fmt::Debug for ReadAdmissionBindingError",
        "impl fmt::Debug for ReadAdmissionBindingError",
        "impl Debug for ReadAdmissionBindingError",
        "impl std::fmt::Display for ReadAdmissionBindingError",
        "impl fmt::Display for ReadAdmissionBindingError",
        "impl Display for ReadAdmissionBindingError",
    ] {
        assert_eq!(
            count_occurrences(B_AUTH_DPOP_SOURCE, forbidden),
            0,
            "a hand-written `{forbidden}` could print anything, defeating the \
             derived-Debug redaction the read path depends on"
        );
    }

    // The count is DERIVED from the enum body rather than written as a
    // literal. A fourteenth variant would otherwise be added to production and
    // silently escape this check, since only a removal or rename is a compile
    // error.
    let errors = b_auth_every_binding_error();
    assert!(
        declared_variants.len() >= 13,
        "the redacted error enum must still declare its variants, found {declared_variants:?}"
    );
    assert_eq!(
        errors.len(),
        declared_variants.len(),
        "every DECLARED variant must be covered by the redaction sweep; \
         declared {declared_variants:?}, swept {}",
        errors.len()
    );
    for (index, error) in errors.iter().enumerate() {
        assert_eq!(
            format!("{error:?}"),
            declared_variants[index],
            "the rendering must EQUAL the declared variant name, in the \
             declared order — any payload, prefix or suffix fails here"
        );
    }

    // --- PANIC-CHANNEL RENDERING (executed).
    //
    // SCOPE, STATED HONESTLY: this proves what `.expect()` on one of these
    // errors PRINTS. It does NOT prove that any production panic site is
    // redacted — no production code runs here. R6/D4's panic leg is therefore
    // **OPEN**, not closed, and is recorded as open in the report.
    //
    // No sentinel sweep: see the note above. The assertion is exact equality
    // against the message `expect` is documented to build, which a payload on
    // any variant, or a changed panic format, would break.
    let previous_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let mut panic_renderings: Vec<String> = Vec::new();
    for error in &errors {
        let payload = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let outcome: Result<(), &chat_protocol::dpop::ReadAdmissionBindingError> = Err(error);
            outcome.expect("read admission binding refused");
        }))
        .err()
        .expect("expecting an Err must panic");
        panic_renderings.push(panic_message(&payload));
    }
    std::panic::set_hook(previous_hook);

    for (index, rendered) in panic_renderings.iter().enumerate() {
        assert_eq!(
            *rendered,
            format!(
                "read admission binding refused: {}",
                declared_variants[index]
            ),
            "the panic text must be exactly the expect message plus the \
             variant name — nothing else may reach a crash report"
        );
    }

    // --- LOG-CHANNEL RENDERING (executed).
    //
    // SCOPE, STATED HONESTLY: this emits from THIS TEST, through a real
    // `tracing` subscriber, in the two forms production would use (`?error`
    // and `error = ?error`). It proves the rendering the log channel would
    // carry. It does NOT prove any production log site is redacted — no
    // production log site executes here. R6/D4's log leg is **OPEN**, not
    // closed, and is recorded as open in the report.
    //
    // No sentinel sweep: see the note above. What is asserted instead is that
    // each captured line's rendered error field is EXACTLY the variant name,
    // which a payload-carrying variant would break.
    let logged = captured_log_channel(|| {
        for error in &errors {
            tracing::error!(?error, "read admission binding refused");
            tracing::warn!(error = ?error, "read admission binding refused");
        }
    });
    assert!(
        !logged.is_empty(),
        "the log channel capture produced nothing, so nothing below is proved"
    );
    // Each variant is emitted twice, in the two field forms, and each emission
    // must render the error field as EXACTLY the variant name. Counting the
    // exact `error=Variant` token rather than merely finding the name is what
    // makes this fail if a payload is ever added.
    for variant in &declared_variants {
        assert_eq!(
            count_occurrences(&logged, &format!("error={variant}\n")),
            2,
            "both log forms must render the error field as exactly `{variant}`; \
             captured: {logged}"
        );
    }

    // --- EXECUTED structural negatives over the REAL production constructor.
    //
    // `LockedReadDatabaseRow::from_repository_lock` is pure, so the malformed /
    // padded / noncanonical / wrong-length thumbprint shapes and the
    // nonpositive generation run HERE, in the no-database gate, rather than
    // only being anchored in source. No unchecked authority constructor is
    // involved: this IS the production constructor, and returning `Ok` from it
    // still proves nothing about authority.
    let signing_sha = b_auth_signing_key_sha256();
    let device_uuid = Uuid::parse_str(B_AUTH_DEVICE).expect("the fixed device UUID is canonical");
    let structural = |jkt: &str, generation: i64| {
        chat_protocol::b_auth_bridge::structural_row_outcome(
            "1234",
            B_AUTH_DID,
            device_uuid,
            "active",
            jkt,
            generation,
            B_AUTH_KEY_ID,
            signing_sha,
            None,
        )
    };

    // POSITIVE CONTROL FIRST: the well-shaped row is accepted, so the refusals
    // below discriminate rather than reflecting a constructor that refuses
    // everything.
    assert_eq!(
        binding_outcome_name(&structural(B_AUTH_JKT, 1)),
        "Ok",
        "POSITIVE CONTROL: a well-shaped locked row is structurally accepted"
    );
    assert_eq!(
        URL_SAFE_NO_PAD.encode([0_u8; 32]),
        B_AUTH_JKT,
        "the fixture JKT is exactly the canonical encoding of 32 zero bytes, \
         so the malformed shapes below really are perturbations of a valid one"
    );

    let padded_jkt = STANDARD.encode([0_u8; 32]);
    let short_jkt = URL_SAFE_NO_PAD.encode([0_u8; 31]);
    let long_jkt = URL_SAFE_NO_PAD.encode([0_u8; 33]);
    let noncanonical_jkt = format!("{}B", &B_AUTH_JKT[..B_AUTH_JKT.len() - 1]);
    for (label, jkt) in [
        ("malformed", "not*a*thumbprint!!"),
        ("padded", padded_jkt.as_str()),
        ("wrong-length (31 bytes)", short_jkt.as_str()),
        ("wrong-length (33 bytes)", long_jkt.as_str()),
        ("noncanonical trailing bits", noncanonical_jkt.as_str()),
        ("empty", ""),
    ] {
        assert_eq!(
            binding_outcome_name(&structural(jkt, 1)),
            "LockedRowShape",
            "a {label} thumbprint must be refused by the structural constructor"
        );
    }
    for generation in [0_i64, -1, i64::MIN] {
        assert_eq!(
            binding_outcome_name(&structural(B_AUTH_JKT, generation)),
            "LockedRowShape",
            "a nonpositive generation ({generation}) must be refused structurally"
        );
    }
    // Empty / nil coordinate shapes are refused too.
    for (label, transaction_id, did, device_id, status, key_id) in [
        (
            "empty transaction id",
            "",
            B_AUTH_DID,
            device_uuid,
            "active",
            B_AUTH_KEY_ID,
        ),
        (
            "empty did",
            "1234",
            "",
            device_uuid,
            "active",
            B_AUTH_KEY_ID,
        ),
        (
            "nil device uuid",
            "1234",
            B_AUTH_DID,
            Uuid::nil(),
            "active",
            B_AUTH_KEY_ID,
        ),
        (
            "empty status",
            "1234",
            B_AUTH_DID,
            device_uuid,
            "",
            B_AUTH_KEY_ID,
        ),
        (
            "empty key id",
            "1234",
            B_AUTH_DID,
            device_uuid,
            "active",
            "",
        ),
    ] {
        assert_eq!(
            binding_outcome_name(&chat_protocol::b_auth_bridge::structural_row_outcome(
                transaction_id,
                did,
                device_id,
                status,
                B_AUTH_JKT,
                1,
                key_id,
                signing_sha,
                None,
            )),
            "LockedRowShape",
            "a locked row with an {label} must be refused structurally"
        );
    }
    // A DOUBLE-HASHED thumbprint is well-SHAPED, so the structural constructor
    // accepts it. That is the point of the split: structural evidence proves
    // nothing about authority, and the double hash is caught by the consuming
    // verifier's digest comparison instead — executed in
    // `b_auth_endpoint_method_and_budget_foreign_use_fail_before_sql`.
    let double_hashed_jkt =
        URL_SAFE_NO_PAD.encode::<[u8; 32]>(Sha256::digest(B_AUTH_JKT.as_bytes()).into());
    assert_eq!(
        binding_outcome_name(&structural(&double_hashed_jkt, 1)),
        "Ok",
        "a double-hashed thumbprint is well-shaped; only the verifier can \
         refuse it, which is why the drift matrix must execute"
    );

    // --- the seal maps to a redacted endpoint invariant at its only caller.
    assert!(
        B_AUTH_CONTEXT_SOURCE.contains(
            "dpop::seal_read_admission(authority).map_err(|_| ChatFailure::invariant(endpoint))"
        ),
        "every seal error becomes a redacted endpoint invariant"
    );
}

// ---------------------------------------------------------------------------
// 2 & 3. Nonignored pure/source/compile: the two closed budgets.
// ---------------------------------------------------------------------------

#[test]
fn b_auth_get_devices_budget_mints_exactly_one_attempt() {
    // --- the budget holds exactly one attempt and nothing else.
    assert!(
        B_AUTH_DPOP_SOURCE.contains(concat!(
            "pub(in crate::chat_protocol) struct GetDevicesReadAdmission {\n",
            "    attempt: ReadAdmissionAttempt,\n",
            "}",
        )),
        "the GetDevices budget is exactly one private attempt"
    );
    assert!(
        B_AUTH_DPOP_SOURCE.contains(concat!(
            "    pub(in crate::chat_protocol) fn into_attempt(self) -> ReadAdmissionAttempt {\n",
            "        self.attempt\n",
            "    }",
        )),
        "the only way out of the budget consumes it and yields one attempt"
    );

    // --- the conversion mints exactly one attempt and owns its closed endpoint.
    let conversion_start = B_AUTH_DPOP_SOURCE
        .find("pub(in crate::chat_protocol) fn into_get_devices_read_admission(")
        .expect("exact GetDevices conversion");
    let conversion_end = conversion_start
        + B_AUTH_DPOP_SOURCE[conversion_start..]
            .find("\n    }\n")
            .expect("GetDevices conversion terminates");
    let conversion = &B_AUTH_DPOP_SOURCE[conversion_start..conversion_end];
    assert_eq!(
        count_occurrences(conversion, "ReadAdmissionAttempt {"),
        1,
        "the GetDevices conversion mints EXACTLY one attempt"
    );
    assert!(
        conversion.contains("GET_DEVICES_ENDPOINT_NSID")
            && conversion.contains("READ_ENDPOINT_CANONICAL_METHOD"),
        "the conversion owns the closed endpoint and its endpoint-owned method"
    );
    assert!(
        !conversion.contains("endpoint:") && !conversion.contains("method:"),
        "the conversion accepts no caller endpoint or method"
    );
    assert!(
        B_AUTH_DPOP_SOURCE.contains(concat!(
            "    pub(in crate::chat_protocol) fn into_get_devices_read_admission(\n",
            "        self,\n",
            "    ) -> Result<GetDevicesReadAdmission, ReadAdmissionBindingError> {",
        )),
        "the conversion signature takes only `self`"
    );

    // --- the closed endpoint constants are exactly the two read endpoints.
    assert!(
        B_AUTH_DPOP_SOURCE
            .contains("const GET_DEVICES_ENDPOINT_NSID: &str = \"blue.catbird.chat.getDevices\";"),
        "the GetDevices endpoint constant is exact"
    );
    assert!(
        B_AUTH_DPOP_SOURCE.contains("const READ_ENDPOINT_CANONICAL_METHOD: &str = \"GET\";"),
        "the endpoint-owned canonical method is exact"
    );

    // WHAT THIS TEST MEASURES, STATED WITHOUT DECORATION: a source-text pattern
    // in `dpop.rs`. It does not mint anything.
    //
    // It used to end with `let mint: fn(..) = try_mint_get_devices_budget;
    // let _ = mint;` under a "COMPILE proof" caption. That was a coercion plus a
    // dead store, not an assertion: the bridge is a module of this crate and is
    // type-checked whether or not any test names it, and the signature being
    // coerced is the BRIDGE's own, declared 1700 lines above in this same file.
    // It is the same family as the retired "the function address is nonzero"
    // defect with the fake `assert!` removed rather than the vacuity.
    //
    // The executed minting proof lives where a real committed receipt exists:
    // `b_auth_endpoint_method_and_budget_foreign_use_fail_before_sql` calls
    // `try_mint_get_devices_budget` against a real `VerifiedReadAdmission` and
    // asserts both the refusal of a foreign endpoint and the acceptance of the
    // matching one.
}

#[test]
fn b_auth_get_own_devices_budget_mints_fixed_three_attempts() {
    // --- the budget is a FIXED-LENGTH array, not a growable collection.
    assert!(
        B_AUTH_DPOP_SOURCE.contains(concat!(
            "pub(in crate::chat_protocol) struct GetOwnDevicesReadAdmission {\n",
            "    attempts: [ReadAdmissionAttempt; GET_OWN_DEVICES_ATTEMPT_BUDGET],\n",
            "}",
        )),
        "the GetOwnDevices budget is a fixed-length attempt array"
    );
    assert!(
        B_AUTH_DPOP_SOURCE.contains("const GET_OWN_DEVICES_ATTEMPT_BUDGET: usize = 3;"),
        "the fixed budget is exactly three"
    );
    assert!(
        B_AUTH_DPOP_SOURCE.contains(concat!(
            "    pub(in crate::chat_protocol) fn into_attempts(\n",
            "        self,\n",
            "    ) -> [ReadAdmissionAttempt; GET_OWN_DEVICES_ATTEMPT_BUDGET] {\n",
            "        self.attempts\n",
            "    }",
        )),
        "the only way out consumes the budget and yields the same fixed array"
    );

    // --- the conversion mints exactly three attempts.
    let conversion_start = B_AUTH_DPOP_SOURCE
        .find("pub(in crate::chat_protocol) fn into_get_own_devices_read_admission(")
        .expect("exact GetOwnDevices conversion");
    let conversion_end = conversion_start
        + B_AUTH_DPOP_SOURCE[conversion_start..]
            .find("\n    }\n")
            .expect("GetOwnDevices conversion terminates");
    let conversion = &B_AUTH_DPOP_SOURCE[conversion_start..conversion_end];
    assert_eq!(
        count_occurrences(conversion, "ReadAdmissionAttempt {"),
        3,
        "the GetOwnDevices conversion mints EXACTLY three attempts — no fourth"
    );
    assert!(
        conversion.contains("GET_OWN_DEVICES_ENDPOINT_NSID"),
        "the conversion owns its closed endpoint"
    );

    // --- there is no growth, reset, counter, or general mint anywhere.
    for forbidden in [
        "fn begin_attempt",
        "fn next_attempt",
        "fn reset",
        "fn mint_attempt",
        "attempts.push",
        "Vec<ReadAdmissionAttempt>",
        "remaining",
    ] {
        assert_eq!(
            count_occurrences(B_AUTH_DPOP_SOURCE, forbidden),
            0,
            "the budget must expose no {forbidden}"
        );
    }

    // --- COMPILE proof: the bridge destructures `into_attempts()` with an
    //     exact-length `[_, _, _]` pattern. A fourth element would not compile.
    //
    // The proof is the DESTRUCTURING's existence, asserted below over this
    // file's own bytes — not a `let mint: fn(..) = ..; let _ = mint;` dead
    // store, which is what stood here. That store coerced the bridge's own
    // declared signature to a function pointer and dropped it; the bridge
    // compiles as part of this crate regardless, so the store excluded nothing.
    // Like its `getDevices` twin, this test measures a SOURCE-TEXT pattern; the
    // executed three-attempt spend is
    // `b_auth_get_own_devices_fourth_attempt_fails_before_sql`.
    //
    // THE NEEDLE IS SPLIT ON PURPOSE. This file `include_str!`s itself, so a
    // literal needle also occurs inside the assertion's own argument and the
    // search can never fail: deleting the real destructuring outright left this
    // assertion green. `concat!` is evaluated at compile time, so the joined
    // needle exists only in the binary; the file text contains the two halves
    // separately and matches nothing.
    //
    // THE COUNT IS THREE, NOT ONE, AS OF B-READ. The sealed B-auth guard pinned
    // exactly one site (the `b_auth_bridge`'s own-devices spend). B-read added
    // the `read_authority_bridge`, whose ordinary-attempt and inventory-attempt
    // spends destructure the same arrays the same way — amendment §4 requires
    // the guard to track the B-read reality, so the exact-length proof now has
    // three sites, all in bridges. The lines are not pinned (they move on every
    // edit); the COUNT and the requirement that each site sit between the two
    // bridge banners are the load-bearing facts.
    let destructuring = concat!("let [_first, _second, _third] = ", "attempts;");
    let sites: Vec<usize> = {
        let mut from = 0_usize;
        let mut found = Vec::new();
        while let Some(offset) = B_AUTH_G7_SELF_SOURCE[from..].find(destructuring) {
            let index = from + offset;
            let line = B_AUTH_G7_SELF_SOURCE[..index].matches('\n').count() + 1;
            found.push(line);
            from = index + destructuring.len();
        }
        found
    };
    assert_eq!(
        sites.len(),
        3,
        "the exact-length destructuring that makes a fourth attempt a compile \
         error occurs exactly three times, once per bridge, and nowhere else; \
         found {sites:?}"
    );
    let b_auth_bridge_start = B_AUTH_G7_SELF_SOURCE
        .find("pub mod b_auth_bridge {")
        .expect("the B-auth bridge banner");
    let read_authority_bridge_start = B_AUTH_G7_SELF_SOURCE
        .find("pub mod read_authority_bridge {")
        .expect("the B-read bridge banner");
    // Convert each site's LINE NUMBER back to its byte offset (a line number
    // is not a byte index) before comparing against the banner offsets.
    let site_offsets: Vec<usize> = sites
        .iter()
        .map(|line| {
            B_AUTH_G7_SELF_SOURCE
                .split('\n')
                .take(*line - 1)
                .map(|part| part.len() + 1)
                .sum()
        })
        .collect();
    assert_eq!(
        site_offsets
            .iter()
            .filter(
                |offset| **offset >= b_auth_bridge_start && **offset < read_authority_bridge_start
            )
            .count(),
        1,
        "exactly one destructuring site lies in the B-auth bridge"
    );
    assert_eq!(
        site_offsets
            .iter()
            .filter(|offset| **offset >= read_authority_bridge_start)
            .count(),
        2,
        "exactly two destructuring sites lie in the B-read bridge"
    );
}

/// This test file's own bytes, so a compile-time proof can also be shown to
/// exist in source rather than only asserted in prose.
const B_AUTH_G7_SELF_SOURCE: &str = include_str!("chat_protocol_g7_entitlement.rs");

// ---------------------------------------------------------------------------
// 8. Nonignored source/compile: privacy, call graph, and the exact thirteen.
// ---------------------------------------------------------------------------

#[test]
fn b_auth_read_authority_privacy_and_call_graph_guards() {
    // === THE EXACT THIRTEEN MUTATION-GETTER CALLSITES =====================
    //
    // PREDICATE: occurrences of the 24-byte fixed string
    // `locked_auth_generation()` — the identifier followed by an EMPTY argument
    // list. The trailing `()` excludes the field declaration, every struct
    // literal initialiser, and the definition, whose signature is `(&self)`.
    // Counted over WHOLE files, never a truncated view.
    let mut per_file: Vec<(&str, usize)> = Vec::new();
    for (name, source) in B_AUTH_MUTATION_GETTER_SOURCES {
        per_file.push((name, count_occurrences(source, "locked_auth_generation()")));
    }
    let total: usize = per_file.iter().map(|(_, count)| count).sum();
    assert_eq!(
        total, 13,
        "exactly thirteen pre-existing mutation-only callsites; found {per_file:?}"
    );
    assert_eq!(
        per_file
            .iter()
            .find(|(name, _)| *name == "repository/auth.rs")
            .expect("auth.rs is in the search set")
            .1,
        11,
        "eleven successor containing functions in auth.rs"
    );
    assert_eq!(
        per_file
            .iter()
            .find(|(name, _)| *name == "repository/prelude.rs")
            .expect("prelude.rs is in the search set")
            .1,
        2,
        "two byte-identical prelude.rs callsites"
    );
    // No read-path use: every other searched file must contribute zero.
    for (name, count) in &per_file {
        if *name == "repository/auth.rs" || *name == "repository/prelude.rs" {
            continue;
        }
        assert_eq!(
            *count, 0,
            "{name} must not call the mutation generation getter on a read path"
        );
    }
    // The predicate is capable of separating a call from the definition: the
    // definition IS present in auth.rs and is NOT part of the eleven.
    assert!(
        B_AUTH_AUTH_SOURCE.contains("pub(crate) fn locked_auth_generation(&self) -> Option<i64>"),
        "the definition exists"
    );
    assert!(
        count_occurrences(B_AUTH_AUTH_SOURCE, "locked_auth_generation")
            > count_occurrences(B_AUTH_AUTH_SOURCE, "locked_auth_generation()"),
        "the bare name occurs more often than the call predicate, so the \
         predicate is genuinely narrower than a substring search"
    );

    // === CALL GRAPH ========================================================
    // Exactly one non-test `seal_read_admission` call, in context.rs.
    assert_eq!(
        count_occurrences(B_AUTH_CONTEXT_SOURCE, "dpop::seal_read_admission("),
        1,
        "context.rs holds the single non-test seal callsite"
    );
    assert_eq!(
        count_occurrences(B_AUTH_DPOP_SOURCE, "pub(crate) fn seal_read_admission("),
        1,
        "exactly one seal definition"
    );
    for (name, source) in [
        ("inventory.rs", B_AUTH_INVENTORY_SOURCE),
        ("get_devices.rs", B_AUTH_GET_DEVICES_SOURCE),
        ("get_own_devices.rs", B_AUTH_GET_OWN_DEVICES_SOURCE),
    ] {
        assert_eq!(
            count_occurrences(source, "seal_read_admission("),
            0,
            "{name} must not seal an admission"
        );
    }

    // The old raw bridge is gone, with no alias, wrapper, or Deref substitute.
    for (name, source) in [
        ("context.rs", B_AUTH_CONTEXT_SOURCE),
        ("get_devices.rs", B_AUTH_GET_DEVICES_SOURCE),
        ("get_own_devices.rs", B_AUTH_GET_OWN_DEVICES_SOURCE),
        ("inventory.rs", B_AUTH_INVENTORY_SOURCE),
    ] {
        assert_eq!(
            count_occurrences(source, "admit_unsigned("),
            0,
            "{name} must not define or call the removed raw helper"
        );
    }
    assert_eq!(
        count_occurrences(
            B_AUTH_CONTEXT_SOURCE,
            "pub(crate) async fn admit_unsigned_read("
        ),
        1,
        "exactly one read admission bridge"
    );
    assert_eq!(
        count_occurrences(B_AUTH_CONTEXT_SOURCE, "VerifiedChatDeviceRequest"),
        0,
        "context.rs cannot even name the raw authority type"
    );

    // Exactly one production `from_repository_lock` call, in inventory.rs,
    // reachable only after BOTH ordered locks.
    assert_eq!(
        count_occurrences(B_AUTH_INVENTORY_SOURCE, "from_repository_lock("),
        1,
        "exactly one production locked-row constructor callsite"
    );
    assert_eq!(
        count_occurrences(B_AUTH_DPOP_SOURCE, "fn from_repository_lock("),
        1,
        "exactly one locked-row constructor definition"
    );
    for (name, source) in [
        ("get_devices.rs", B_AUTH_GET_DEVICES_SOURCE),
        ("get_own_devices.rs", B_AUTH_GET_OWN_DEVICES_SOURCE),
    ] {
        assert_eq!(
            count_occurrences(source, "from_repository_lock"),
            0,
            "{name} must not construct a locked row"
        );
    }
    let lock_helper_start = B_AUTH_INVENTORY_SOURCE
        .find("async fn lock_and_verify_read_requester(")
        .expect("the ordered-lock helper");
    let lock_helper_end = lock_helper_start
        + B_AUTH_INVENTORY_SOURCE[lock_helper_start..]
            .find("\n}\n")
            .expect("ordered-lock helper terminates");
    require_ordered_anchors(
        &B_AUTH_INVENTORY_SOURCE[..lock_helper_end],
        lock_helper_start,
        &[
            "attempt.lock_coordinates()",
            "LOCK_READ_REQUESTER_DEVICE_SQL",
            "let Some(device) = device else",
            "LOCK_READ_REQUESTER_DEVICE_KEY_SQL",
            "let Some(key) = key else",
            "from_repository_lock(",
            "consume_verify_locked_row(",
        ],
    );
    assert!(
        B_AUTH_INVENTORY_SOURCE.contains("FOR UPDATE OF device, device_key"),
        "the pre-existing joined lock still exists elsewhere in the file"
    );
    let ordered_device_sql = B_AUTH_INVENTORY_SOURCE
        .find("const LOCK_READ_REQUESTER_DEVICE_SQL")
        .expect("the B-auth device lock SQL");
    let ordered_key_sql = B_AUTH_INVENTORY_SOURCE
        .find("const LOCK_READ_REQUESTER_DEVICE_KEY_SQL")
        .expect("the B-auth key lock SQL");
    assert!(
        ordered_device_sql < ordered_key_sql,
        "the device lock statement precedes the key lock statement"
    );
    for sql_name in [
        "LOCK_READ_REQUESTER_DEVICE_SQL",
        "LOCK_READ_REQUESTER_DEVICE_KEY_SQL",
    ] {
        let start = B_AUTH_INVENTORY_SOURCE
            .find(&format!("const {sql_name}"))
            .expect("lock SQL constant");
        let end = start
            + B_AUTH_INVENTORY_SOURCE[start..]
                .find("\"#;")
                .expect("lock SQL terminates");
        let sql = &B_AUTH_INVENTORY_SOURCE[start..end];
        assert!(
            !sql.contains("FOR UPDATE OF"),
            "{sql_name} must be a single-table FOR UPDATE, never a joined one"
        );
        assert_eq!(
            count_occurrences(sql, "FROM"),
            1,
            "{sql_name} locks exactly one table"
        );
    }

    // === PRIVACY ===========================================================
    // No read-authority type derives or implements a forbidden trait.
    for type_name in B_AUTH_READ_AUTHORITY_TYPES {
        for keyword in ["struct", "enum"] {
            let needle = format!("{keyword} {type_name}");
            if find_declaration(B_AUTH_DPOP_SOURCE, &needle).is_none() {
                continue;
            }
            let declaration = declaration_with_attributes(B_AUTH_DPOP_SOURCE, &needle);
            assert!(
                !declaration.contains("#[derive"),
                "{type_name} must derive nothing, found: {declaration}"
            );
        }
        for forbidden in [
            format!("impl Clone for {type_name}"),
            format!("impl Copy for {type_name}"),
            format!("impl std::fmt::Debug for {type_name}"),
            format!("impl fmt::Debug for {type_name}"),
            format!("impl Serialize for {type_name}"),
            format!("impl<'de> Deserialize<'de> for {type_name}"),
            format!("impl std::ops::Deref for {type_name}"),
            format!("for {type_name} {{\n    type Target"),
        ] {
            assert_eq!(
                count_occurrences(B_AUTH_DPOP_SOURCE, &forbidden),
                0,
                "{type_name} must not have `{forbidden}`"
            );
        }
        // No `From`/`Into` conversion into or out of any read-authority type.
        assert_eq!(
            count_occurrences(B_AUTH_DPOP_SOURCE, &format!("impl From<{type_name}>")),
            0,
            "{type_name} must have no From conversion"
        );
        assert_eq!(
            count_occurrences(B_AUTH_DPOP_SOURCE, &format!("> for {type_name} {{")),
            0,
            "{type_name} must be the target of no trait conversion"
        );
    }

    // The exhaustive method surface of the read-authority types. Anything not
    // in this list is a new seam and fails the guard.
    const ALLOWED_METHODS: &[&str] = &[
        // The two FREE functions of the section: the private canonical
        // thumbprint decoder and the single seal entry point. Neither is a
        // method on a read-authority type.
        "fn decode_canonical_thumbprint_digest(",
        "fn seal_read_admission(",
        // Methods.
        "fn into_closed_endpoint_binding(",
        "fn into_get_devices_read_admission(",
        "fn into_get_own_devices_read_admission(",
        "fn into_attempt(",
        "fn into_attempts(",
        "fn from_repository_lock(",
        "fn lock_coordinates(",
        "fn consume_verify_locked_row(",
        "fn verify_same_transaction(",
        "fn bounded_snapshot_created_at(",
    ];
    let read_section_start = B_AUTH_DPOP_SOURCE
        .find("// Opaque existing-device read admission (Stage B).")
        .expect("the B-auth read section banner");
    let read_section = &B_AUTH_DPOP_SOURCE[read_section_start..];
    let read_section_end = read_section
        .find("#[derive(Debug, Deserialize)]")
        .expect("the read section ends before the pre-existing JWT types");
    let read_section = &read_section[..read_section_end];
    //
    // THE FILTER IS DELIBERATELY LIBERAL. An earlier version matched only
    // `fn `, `pub(in crate::chat_protocol) fn ` and `pub(crate) fn `, so a seam
    // declared `async fn`, `pub fn`, `pub(super) fn`, or
    // `pub(in crate::chat_protocol) async fn` would have been skipped in
    // silence — the one failure mode a guard like this must not have. Every
    // line of the comment-stripped section that declares a function is now
    // considered; a false positive fails loudly and is added to the list
    // above, which is the safe direction.
    let read_section_code = code_only(read_section);
    let mut found: Vec<&str> = Vec::new();
    for line in read_section_code.lines() {
        let trimmed = line.trim();
        let Some((prefix, rest)) = trimmed.split_once("fn ") else {
            continue;
        };
        // A declaration's prefix carries only visibility and modifier tokens.
        // Anything else (a type position, a string, an expression) is skipped.
        let declaration = prefix.is_empty()
            || prefix
                .split_whitespace()
                .all(|word| matches!(word, "pub" | "async" | "const" | "unsafe" | "extern"))
            || prefix.starts_with("pub(");
        if !declaration {
            continue;
        }
        let signature = format!("fn {rest}");
        found.push(
            ALLOWED_METHODS
                .iter()
                .find(|allowed| signature.starts_with(*allowed))
                .copied()
                .unwrap_or_else(|| {
                    panic!("undeclared read-authority seam: {signature}");
                }),
        );
    }
    // THE FILTER'S REACH IS ITSELF ASSERTED. Containment checks alone cannot
    // notice a declaration the filter silently skipped, which is exactly the
    // failure mode the widened prefix rule above exists to remove. Pinning the
    // number of declarations the filter SAW, and requiring every allow-list
    // entry to have been matched, makes both directions observable: a skipped
    // declaration lowers the count, and a stale allow-list entry is reported.
    assert_eq!(
        found.len(),
        ALLOWED_METHODS.len(),
        "the filter must reach every declaration in the read section and the \
         allow-list must carry no stale entry; saw {found:?}"
    );
    assert_eq!(
        found.len(),
        12,
        "the read section declares exactly twelve functions"
    );
    for allowed in ALLOWED_METHODS {
        assert!(
            found.contains(allowed),
            "the allow-list entry `{allowed}` matched no declaration — either \
             the seam was removed or the filter no longer reaches it"
        );
    }
    // The free functions in the section are not methods; both are accounted for.
    assert!(
        found.contains(&"fn consume_verify_locked_row(")
            && found.contains(&"fn lock_coordinates(")
            && found.contains(&"fn verify_same_transaction(")
            && found.contains(&"fn bounded_snapshot_created_at("),
        "the amendment seams are present in the surface: {found:?}"
    );

    // No raw getter for the values the authority says have none.
    for forbidden in [
        "fn dpop_jkt(&self)",
        "fn auth_generation(&self)",
        "fn generation(&self)",
        "fn key_id(&self)",
        "fn signing_key_sha256(&self)",
        "fn replay_ids(&self)",
        "fn transaction_id(&self)",
        "fn trusted_instant(&self) -> &TrustedRequestInstant {\n        &self.trusted_instant\n    }\n}\n\nimpl VerifiedExistingDeviceReadRow",
    ] {
        assert_eq!(
            count_occurrences(read_section, forbidden),
            0,
            "the read authority must expose no `{forbidden}`"
        );
    }

    // === THE EXACT ATTEMPT-MINTING SITES ===================================
    // Pure source arithmetic, so it runs HERE, in the no-database gate, rather
    // than only inside the database-marked fourth-attempt case where a
    // statically decidable failure would not surface until Task B6.
    assert_attempt_minting_sites();

    // === THE VACUOUS-DRIFT-CHECK GUARD =====================================
    //
    // `ReadLockCoordinates` must carry ONLY the two SQL bind parameters. If the
    // JKT, generation, key, or digest ever reached the repository through this
    // carrier, the repository would hand them straight back and
    // `consume_verify_locked_row` would compare the hidden binding AGAINST
    // ITSELF — every drift check would silently become vacuous while still
    // looking like a guard.
    let carrier_start = B_AUTH_DPOP_SOURCE
        .find("pub(in crate::chat_protocol) struct ReadLockCoordinates<'a> {")
        .expect("the lock-coordinate carrier");
    let carrier_end = carrier_start
        + B_AUTH_DPOP_SOURCE[carrier_start..]
            .find("\n}\n")
            .expect("carrier terminates");
    let carrier = &B_AUTH_DPOP_SOURCE[carrier_start..carrier_end];
    let fields: Vec<&str> = carrier
        .lines()
        .skip(1)
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with("///"))
        .collect();
    assert_eq!(
        fields.len(),
        2,
        "the lock-coordinate carrier must have EXACTLY two fields, found {fields:?}"
    );
    assert!(
        fields[0].contains("did: &'a str") && fields[1].contains("device_id: Uuid"),
        "the two fields are exactly the DID and the device UUID, found {fields:?}"
    );
    for banned in [
        "jkt",
        "generation",
        "key",
        "digest",
        "sha256",
        "replay",
        "transaction",
        "instant",
        "budget",
        "attempt",
        "receipt",
    ] {
        assert!(
            !carrier
                .to_ascii_lowercase()
                .contains(&format!(": {banned}"))
                && !fields
                    .iter()
                    .any(|field| field.to_ascii_lowercase().contains(banned)),
            "the lock-coordinate carrier must not carry {banned} — that would make \
             every drift check vacuous"
        );
    }
    // And it must be NON-CONSUMING, or one attempt could authorize a lock it
    // never verified.
    assert!(
        B_AUTH_DPOP_SOURCE.contains(
            "pub(in crate::chat_protocol) fn lock_coordinates(&self) -> ReadLockCoordinates<'_> {"
        ),
        "lock_coordinates must borrow, never consume, the attempt"
    );

    // === AMENDMENT 1: TRUNCATION AT THE `dpop.rs` BOUNDARY =================
    //
    // WHY THIS LIVES HERE. The sealed eight-name table contains no truncation
    // test, and minting a ninth name would be inventing authorized vocabulary.
    // By coordinator ruling the STRUCTURAL half is folded into this test — it
    // is a source/compile guard, which is exactly this test's sealed class —
    // and the BEHAVIOURAL half is folded into the DB-marked
    // `b_auth_real_repository_receipt_seals_endpoint_bound_admission_once`.
    // A B5 reviewer diffing tests against the sealed table should read this
    // as coverage relocated by ruling, not as coverage missing.
    //
    // The property: a sub-second instant cannot cross the boundary. It is
    // enforced on BOTH sides — `dpop.rs` truncates on the way out, and
    // `inventory.rs::unix_seconds` rejects any sub-second value on the way in.
    assert_eq!(
        count_occurrences(read_section, "fn bounded_snapshot_created_at("),
        1,
        "exactly one bounded base-timestamp derivation"
    );
    let bounded_start = B_AUTH_DPOP_SOURCE
        .find("pub(in crate::chat_protocol) fn bounded_snapshot_created_at(")
        .expect("the bounded base-timestamp derivation");
    let bounded_end = bounded_start
        + B_AUTH_DPOP_SOURCE[bounded_start..]
            .find("\n    }\n")
            .expect("the derivation terminates");
    let bounded = &B_AUTH_DPOP_SOURCE[bounded_start..bounded_end];
    // It returns a truncated timestamp, never the retained instant.
    assert!(
        bounded.contains(") -> Result<DateTime<Utc>, ReadAdmissionBindingError> {"),
        "the derivation yields a timestamp, not the trusted instant"
    );
    // THE truncation: seconds from the instant, and a LITERAL zero nanoseconds.
    assert!(
        bounded
            .contains("DateTime::from_timestamp(self.trusted_instant.datetime().timestamp(), 0)"),
        "the instant is reduced to whole seconds INSIDE dpop.rs, with an \
         explicit zero-nanosecond component"
    );
    assert!(
        bounded.contains("ReadAdmissionBindingError::BoundedTimestamp"),
        "an unrepresentable base timestamp is a redacted binding error"
    );
    // No sub-second escape hatch anywhere in the read section.
    //
    // Over CODE ONLY: the derivation's own doc comment names
    // `timestamp_subsec_nanos()` when explaining why the truncation matters,
    // and a guard that matches its own documentation is a guard that fails
    // while nothing is wrong — and would equally let a real call hide behind a
    // comment.
    let read_code = code_only(read_section);
    for forbidden in [
        "timestamp_millis()",
        "timestamp_micros()",
        "timestamp_nanos",
        "timestamp_subsec",
        "Utc::now()",
    ] {
        assert_eq!(
            count_occurrences(&read_code, forbidden),
            0,
            "the read section must not reach for {forbidden}"
        );
    }
    // The retained instant itself never leaves the row proof.
    assert_eq!(
        count_occurrences(&read_code, "-> &TrustedRequestInstant"),
        0,
        "the row proof exposes no raw trusted-instant getter"
    );
    assert_eq!(
        count_occurrences(&read_code, "-> TrustedRequestInstant"),
        0,
        "the row proof yields no owned trusted instant either"
    );
    // The repository takes its base timestamp ONLY from this derivation: it has
    // no independent clock, so nothing can bypass the truncation.
    assert_eq!(
        count_occurrences(B_AUTH_INVENTORY_SOURCE, "bounded_snapshot_created_at()"),
        1,
        "the facade derives its base timestamp exactly once"
    );
    assert_eq!(
        count_occurrences(B_AUTH_INVENTORY_SOURCE, "Utc::now()"),
        0,
        "the facade has no independent clock that could bypass the truncation"
    );
    // The receiving check that makes the truncation load-bearing rather than
    // cosmetic: a sub-second value is rejected as an invalid durable row.
    assert!(
        B_AUTH_INVENTORY_SOURCE.contains(concat!(
            "fn unix_seconds(value: DateTime<Utc>) -> Option<u64> {\n",
            "    if value.timestamp_subsec_nanos() != 0 {\n",
            "        return None;\n",
            "    }",
        )),
        "the durable-row validator still rejects any sub-second timestamp"
    );
    // The behavioural half in `b_auth_real_repository_receipt_seals_..._once`
    // is only meaningful if its fixture instant is genuinely sub-second. That
    // precondition is pure arithmetic, so it is proved HERE, in the no-database
    // gate, rather than waiting on Task B6: if `B_AUTH_T` ever became a whole
    // second, the DB assertion would still pass while proving nothing.
    let fixture_instant = DateTime::parse_from_rfc3339(B_AUTH_T)
        .expect("the fixed trusted instant is RFC3339")
        .with_timezone(&Utc);
    assert_ne!(
        fixture_instant.timestamp_subsec_nanos(),
        0,
        "the shared fixture instant must carry a sub-second remainder, or the \
         truncation assertion in the database case discriminates nothing"
    );
    assert_eq!(
        fixture_instant.timestamp_subsec_nanos(),
        123_000_000,
        "the fixture instant is the millisecond-precision shape that \
         TrustedRequestInstant::capture actually produces"
    );

    // And the TTL stays repository-owned: the seam accepts no duration.
    assert!(
        B_AUTH_INVENTORY_SOURCE.contains("const OWN_DEVICE_SNAPSHOT_TTL_MINUTES: i64 = 10;"),
        "the session TTL is the repository's constant, relocated not chosen"
    );
    for forbidden in ["ttl", "expires_at", "Duration::minutes"] {
        assert_eq!(
            count_occurrences(&code_only(read_section), forbidden),
            0,
            "the admission module must hold no session-policy {forbidden}"
        );
    }

    // === HANDLERS ==========================================================
    for (name, source) in [
        ("get_devices.rs", B_AUTH_GET_DEVICES_SOURCE),
        ("get_own_devices.rs", B_AUTH_GET_OWN_DEVICES_SOURCE),
    ] {
        let code = code_only(source);
        for forbidden in [
            "sqlx::",
            "SELECT ",
            "INSERT ",
            "UPDATE ",
            "FOR UPDATE",
            "begin()",
            "commit()",
            "rollback()",
            "ISOLATION LEVEL",
            // NOT `loop {` / `while `: `get_devices.rs` legitimately loops in
            // `parse_user_dids`/`percent_decode` over the public query string,
            // which is neither a retry nor SQL. "No handler-driven retry" is
            // asserted precisely instead, by the exactly-once admission and
            // exactly-once facade-transfer counts below: one admission and one
            // facade call cannot be a retry loop.
            "attempts",
            "device_directory",
            "CreateDeviceInventorySession",
            "lock_coordinates",
            "consume_verify_locked_row",
            "into_attempt",
            "ownDeviceView",
            "addressableDevice",
            "serde_json::to_vec",
        ] {
            assert_eq!(
                count_occurrences(&code, forbidden),
                0,
                "{name} must contain no {forbidden}"
            );
        }
        assert_eq!(
            count_occurrences(source, "context::admit_unsigned_read("),
            1,
            "{name} admits exactly once"
        );
        assert_eq!(
            count_occurrences(source, "context::json_ok("),
            1,
            "{name} renders exactly once"
        );
        assert_eq!(
            count_occurrences(source, "into_response_bytes()"),
            1,
            "{name} consumes the facade result exactly once"
        );
    }
    assert_eq!(
        count_occurrences(
            B_AUTH_GET_DEVICES_SOURCE,
            "read_addressable_devices_for_admission(pool, admission, &dids)"
        ),
        1,
        "getDevices transfers the admission into its facade exactly once"
    );
    assert_eq!(
        count_occurrences(
            B_AUTH_GET_OWN_DEVICES_SOURCE,
            "create_own_device_snapshot_for_admission(pool, admission)"
        ),
        1,
        "getOwnDevices transfers the admission into its facade exactly once"
    );

    // === THE NONPOSITIVE-GENERATION FLOOR =================================
    //
    // Sealed shapes 5 and 6 (zero / negative generation) are UNREACHABLE from
    // a real row: the live schema refuses to store one. The defence-in-depth
    // branches in `from_repository_lock` and `consume_verify_locked_row` are
    // still executed against synthetic values (in
    // `b_auth_read_admission_rejects_invalid_receipt_shapes_redacted` and the
    // drift matrix), but the reason they cannot be reached through the
    // database is this constraint — so the constraint is pinned. If it is ever
    // dropped, the "unreachable" claim stops being true and this gate says so.
    assert!(
        B_AUTH_CORE_MIGRATION_SOURCE.contains(
            "CONSTRAINT devices_auth_generation_check CHECK (chat.is_safe_integer(auth_generation) AND auth_generation >= 1)"
        ),
        "the live schema floor `auth_generation >= 1` is what makes the \
         nonpositive-generation shapes unreachable from a stored row"
    );
    assert_eq!(
        count_occurrences(B_AUTH_DPOP_SOURCE, "auth_generation <= 0"),
        3,
        "the nonpositive branches remain as defence in depth at the seal, the \
         structural constructor, and the consuming verifier"
    );

    // === D7: THE THREE-ATTEMPT CEILING, AND ITS REACHABILITY ===============
    //
    // COORDINATOR RULING (F-3), as amended by the D-2 rewiring. At the B-auth
    // baseline the retry path was unreachable in production: the sole
    // constructor of `InventoryRepositoryError::SnapshotConflict` lived in
    // `create_inventory_session`, which the B-auth facade never called (the
    // B-auth facade called `create_device_inventory_session`, whose every
    // failure maps to `Database` / `DurableRowInvalid` /
    // `DeviceAuthorityMismatch` / `InvalidMaterialization`). Stage B moved the
    // fixed three-attempt loop from the handler into the facade and preserved
    // reachability exactly.
    //
    // The D-2 inventory facade (`create_inventory_snapshot_and_first_page` ->
    // `create_inventory_snapshot_attempt`) now DOES call
    // `create_inventory_session`: the single `SnapshotConflict` return is
    // genuinely reachable through the facade's retry loop, which exhausts into
    // the `RetryCeiling` variant. D7 is covered by the D-3 source and DB-gate
    // evidence; the integration target cannot invoke this cfg(not(test)),
    // crate-private facade directly. It is deliberately NOT discharged via a
    // fault-injection seam, a mock, or a test-only error constructor — adding
    // one to make a 503 fire is exactly what the ruling forbids.
    //
    // The own-devices facade still calls only `create_device_inventory_session`
    // (whose every failure maps to the non-retryable set); the per-attempt
    // callee extraction below pins that half. The part worth having is that
    // pin: the day someone routes a retryable condition into
    // `create_device_inventory_session`, this gate fails and says the own-
    // devices retry loop came alive untested.
    assert!(
        B_AUTH_GET_OWN_DEVICES_SOURCE.contains("StatusCode::SERVICE_UNAVAILABLE")
            && B_AUTH_GET_OWN_DEVICES_SOURCE.contains("const RETRY_AFTER_SECONDS: &str = \"1\";"),
        "the three-attempt ceiling still renders 503 + Retry-After: 1"
    );
    assert_eq!(
        count_occurrences(
            &code_only(B_AUTH_GET_OWN_DEVICES_SOURCE),
            "retry_ceiling_response"
        ),
        2,
        "getOwnDevices declares and calls the ceiling response exactly once each"
    );
    for absent in [
        "retry_ceiling_response",
        "RETRY_AFTER",
        "SERVICE_UNAVAILABLE",
    ] {
        assert_eq!(
            count_occurrences(&code_only(B_AUTH_GET_DEVICES_SOURCE), absent),
            0,
            "getDevices has a one-attempt budget and therefore no ceiling: {absent}"
        );
    }
    assert!(
        B_AUTH_INVENTORY_SOURCE.contains("Err(InventoryRepositoryError::SnapshotConflict) => {"),
        "the facade still maps a snapshot conflict onto its retry outcome"
    );
    // THE UNREACHABILITY PIN. The single `return Err(…SnapshotConflict)` in the
    // whole repository lies OUTSIDE `create_device_inventory_session`, which is
    // the only function the facade's retry loop calls. Both halves are
    // measured, so either a new conflict return inside the facade's callee or
    // the disappearance of the existing one fails this assertion.
    assert_eq!(
        count_occurrences(
            B_AUTH_INVENTORY_SOURCE,
            "return Err(InventoryRepositoryError::SnapshotConflict)"
        ),
        1,
        "exactly one snapshot-conflict return exists in the repository"
    );
    let device_session_start = B_AUTH_INVENTORY_SOURCE
        .find("async fn create_device_inventory_session(")
        .expect("the facade's per-attempt callee");
    let device_session_end = device_session_start
        + B_AUTH_INVENTORY_SOURCE[device_session_start..]
            .find("\n}\n")
            .expect("the facade's per-attempt callee terminates");
    let device_session = &B_AUTH_INVENTORY_SOURCE[device_session_start..device_session_end];
    // EXTRACTION-INTEGRITY ANCHOR (B10, replacing a guard that could not fail).
    //
    // What stood here was
    //   `!device_session.is_empty() && device_session.len() < SOURCE.len()`,
    // captioned "a genuine narrowing". Both operands are structurally forced:
    // the slice starts at the offset of `"async fn create_device_inventory_\
    // session("` so it begins with `async` and cannot be empty, and `find` on
    // `SOURCE[start..]` returns an index strictly below `SOURCE.len() - start`
    // so the length comparison holds for every possible input. No edit to
    // `inventory.rs` or to this file could make it fail, so it guarded nothing.
    //
    // The hazard it was reaching for is real, and this replaces it with the
    // check that actually sees it. `find("\n}\n")` takes the FIRST line-start
    // closing brace after the signature — not the function's own. Any nested
    // item whose closing brace sits at column 0 (legal Rust: indentation is
    // free) truncates the slice to a PREFIX of the body, and the
    // `count_occurrences(device_session, "SnapshotConflict") == 0` immediately
    // below then passes vacuously, because the text it would have counted was
    // never in the slice. A false zero read as an unreachability proof is
    // exactly the F-3 claim's failure mode.
    //
    // The anchor is the function's terminal expression, which occurs EXACTLY
    // ONCE in `inventory.rs` (whole-file count, measured) and is the last
    // statement of `create_device_inventory_session`. A truncated slice cannot
    // contain it.
    //
    // FAILING INPUT, EXECUTED (B10 mutant M-B10-1): insert
    //     mod _extraction_probe {
    //     }
    // — closing brace at column 0 — anywhere inside the body. That is
    // compile-valid, leaves the old guard green, and fails this one.
    assert!(
        device_session.contains("Ok(CreatedDeviceInventorySession {"),
        "the extracted per-attempt-callee slice must reach the function's \
         terminal expression. It does not, so `find(\"\\n}}\\n\")` stopped at a \
         nested column-0 closing brace and the slice is a PREFIX of the body — \
         the zero below would then be a claim about text that was never \
         examined. Extend the extraction, do not delete this guard."
    );
    assert_eq!(
        count_occurrences(device_session, "SnapshotConflict"),
        0,
        "the own-devices facade's per-attempt callee \
         (`create_device_inventory_session`) cannot produce a snapshot \
         conflict, so the own-devices retry loop stays inert. (The D-2 \
         inventory facade's retry loop IS live: its callee \
         `create_inventory_snapshot_attempt` reaches the single conflict \
         return through `create_inventory_session`; D-3 source and DB-gate \
         evidence covers the wiring, while direct runtime invocation awaits \
         the production handler path.) If this \
         assertion fails, a conflict return has just entered the own-devices \
         callee and its retry loop is UNTESTED — raise it as an authority \
         question, do not delete this guard"
    );
    // POSITIVE CONTROL — the conflict return really does exist, INSIDE the
    // other session builder's body.
    //
    // The previous form compared two `find` OFFSETS
    // (`other_session_start < device_session_start`) and so asserted only that
    // one function name is typed above another. It controlled nothing: moving
    // the `return Err(..SnapshotConflict)` into a brand-new function appended
    // to the end of `inventory.rs` left it green while the claim it captions —
    // "the conflict return lives in `create_inventory_session`" — became false.
    // The body is extracted and searched instead, by the same technique used
    // for the callee above, so the control fails on exactly that relocation.
    let other_session_start = B_AUTH_INVENTORY_SOURCE
        .find("async fn create_inventory_session(")
        .expect("the unrelated conversation-inventory session builder");
    let other_session_end = other_session_start
        + B_AUTH_INVENTORY_SOURCE[other_session_start..]
            .find("\n}\n")
            .expect("the unrelated conversation-inventory session builder terminates");
    let other_session = &B_AUTH_INVENTORY_SOURCE[other_session_start..other_session_end];
    // NO NARROWING GUARD HERE — DELETED IN B10, AND THIS IS A CORRECTION.
    //
    // `!other_session.is_empty() && other_session.len() < SOURCE.len()` stood
    // here and could not fail, for the same structural reason given at the
    // callee extraction above.
    //
    // Unlike there, nothing needs to replace it. The assertion immediately
    // below counts the snapshot-conflict return in this slice and requires
    // EXACTLY ONE. That is strictly stronger than any extraction-integrity
    // guard could be here: a truncated slice that lost the return counts 0 and
    // fails, and a slice that kept it is a subset of the body, which is all the
    // positive control claims ("the return lies INSIDE this function"). A
    // narrowing guard would only have restated what a passing count already
    // proves.
    assert_eq!(
        count_occurrences(
            other_session,
            "return Err(InventoryRepositoryError::SnapshotConflict)"
        ),
        1,
        "POSITIVE CONTROL: the repository's single snapshot-conflict return lies \
         INSIDE `create_inventory_session`'s body — which, with the zero above, \
         is what makes the F-3 unreachability a placement claim rather than a \
         claim that the string vanished"
    );
    assert!(
        other_session_end <= device_session_start,
        "the two extracted bodies must not overlap, or the two counts above are \
         reading the same text"
    );

    // === FROZEN / READ-ONLY BYTE IDENTITY ==================================
    // `read_authority.rs` is B-read-exclusive and NOW EXISTS: B-read created
    // it under the seam authority amendment. The absence check that stood here
    // is superseded for B-read only (amendment §4). The sealed B-auth budget
    // guards above remain untouched.
    let read_authority_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("src/chat_protocol/read_authority.rs");
    assert!(
        read_authority_path.exists(),
        "read_authority.rs exists: B-read owns it under the seam authority amendment"
    );
    assert_eq!(
        count_occurrences(B_AUTH_DPOP_SOURCE, "fn into_single_read_attempt("),
        1,
        "exactly one B-read single-attempt seam definition"
    );
    assert_eq!(
        count_occurrences(B_AUTH_DPOP_SOURCE, "fn into_inventory_read_attempts("),
        1,
        "exactly one B-read inventory seam definition"
    );
    // The seam methods live OUTSIDE the sealed read-section window (after the
    // pre-existing JWT types), so the twelve-function filter above still sees
    // exactly the sealed B-auth surface. This placement is asserted absolutely:
    // the seam banner sits strictly after the window's terminal anchor.
    let read_section_start = B_AUTH_DPOP_SOURCE
        .find("// Opaque existing-device read admission (Stage B).")
        .expect("the B-auth read section banner");
    let window_end = read_section_start
        + B_AUTH_DPOP_SOURCE[read_section_start..]
            .find("#[derive(Debug, Deserialize)]")
            .expect("the read section ends before the pre-existing JWT types");
    let seam_start = B_AUTH_DPOP_SOURCE
        .find("// B-read seam (seam authority amendment")
        .expect("the B-read seam banner");
    assert!(
        seam_start > window_end,
        "the B-read seam methods must lie OUTSIDE the sealed B-auth read-section \
         window so the twelve-function surface stays unchanged"
    );
    // Source guards per amendment §4: the two seam methods are the ONLY
    // `ReadAdmissionAttempt` mints for B-read endpoints, the budgets have no
    // other constructor, and no test-only constructor exists.
    let read_authority_source: &str = include_str!("../src/chat_protocol/read_authority.rs");
    // The needle is `ReadAdmissionAttempt {` as a STRUCT-LITERAL position: a
    // function signature (`-> ReadAdmissionAttempt {`) also contains the text,
    // so the count is taken over the comment-stripped code with the exact
    // binding field following the brace, which only a real construction has.
    let mint_needle = "ReadAdmissionAttempt {\n            binding:";
    assert_eq!(
        count_occurrences(&code_only(read_authority_source), mint_needle),
        0,
        "B-read never mints an attempt: the budgets hold and consume attempts, \
         the seam methods in dpop.rs are the only mint boundary"
    );
    assert_eq!(
        count_occurrences(read_authority_source, "from_repository_lock("),
        1,
        "exactly one production locked-row constructor callsite in read_authority.rs \
         (the B-read lock entry point); the inventory.rs callsite above stays \
         the other one"
    );
    assert_eq!(
        count_occurrences(
            read_authority_source,
            "pub(in crate::chat_protocol) struct SingleReadAdmission {"
        ),
        1,
        "the ordinary budget has exactly one declaration and no other constructor"
    );
    assert_eq!(
        count_occurrences(
            read_authority_source,
            "pub(in crate::chat_protocol) struct InventoryReadAdmission {"
        ),
        1,
        "the inventory budget has exactly one declaration and no other constructor"
    );
    assert_eq!(
        count_occurrences(read_authority_source, "#[cfg(test)]"),
        0,
        "read_authority.rs contains no test-only module or constructor"
    );
    assert_eq!(
        count_occurrences(read_authority_source, "seal_read_admission("),
        0,
        "B-read may not seal an admission: sealing remains B-auth/handler-owned"
    );
    assert_eq!(
        count_occurrences(read_authority_source, "admit_unsigned_read("),
        0,
        "B-read may not admit unsigned reads: that bridge remains B-auth-owned"
    );
    // === THE FENCE-CONSTRUCTOR BOUNDARY (amendment §8 / BREAD-03) ==========
    // `from_locked_inventory_fence_record` is the sole constructor of the
    // durable fence row and `from_lock_material` the record's validating
    // constructor. D's ordinal-35 loader seam (`verify_locked_inventory_fence`
    // in inventory.rs) is their EXACTLY-ONE production caller — the
    // BREAD-03 freeze ("a caller-assembled coordinate bundle is never proof")
    // held until D landed the loader, and the four other B-read files still
    // carry zero call sites. A second production caller must trip this gate,
    // or the freeze silently erodes.
    assert_eq!(
        count_occurrences(
            read_authority_source,
            "pub(in crate::chat_protocol) fn from_locked_inventory_fence_record("
        ),
        1,
        "exactly one durable fence-row constructor definition"
    );
    assert_eq!(
        count_occurrences(
            read_authority_source,
            "pub(in crate::chat_protocol) fn from_lock_material("
        ),
        1,
        "exactly one validating fence-record constructor definition"
    );
    for (name, source) in [
        ("dpop.rs", B_AUTH_DPOP_SOURCE),
        ("context.rs", B_AUTH_CONTEXT_SOURCE),
        ("get_devices.rs", B_AUTH_GET_DEVICES_SOURCE),
        ("get_own_devices.rs", B_AUTH_GET_OWN_DEVICES_SOURCE),
    ] {
        assert_eq!(
            count_occurrences(source, "from_locked_inventory_fence_record("),
            0,
            "{name} must not call the fence-row constructor: D's loader in \
             inventory.rs is the sole production caller"
        );
        assert_eq!(
            count_occurrences(source, "from_lock_material("),
            0,
            "{name} must not call the fence-record constructor"
        );
    }
    assert_eq!(
        count_occurrences(
            B_AUTH_INVENTORY_SOURCE,
            "from_locked_inventory_fence_record("
        ),
        1,
        "inventory.rs calls the fence-row constructor exactly once: the D \
         loader seam (`verify_locked_inventory_fence`) is the sole production \
         caller"
    );
    assert_eq!(
        count_occurrences(B_AUTH_INVENTORY_SOURCE, "from_lock_material("),
        1,
        "inventory.rs calls the fence-record constructor exactly once: the D \
         loader seam (`verify_locked_inventory_fence`) is the sole production \
         caller"
    );
    // The definitions are the ONLY occurrences of either name in
    // read_authority.rs itself (each body constructs a struct literal, not a
    // recursive call); a second definition or a stray call site fails here.
    assert_eq!(
        count_occurrences(read_authority_source, "from_locked_inventory_fence_record("),
        1,
        "the fence-row constructor name appears exactly once in read_authority.rs: \
         the definition; any caller or second definition changes this count"
    );
    assert_eq!(
        count_occurrences(read_authority_source, "from_lock_material("),
        1,
        "the fence-record constructor name appears exactly once in read_authority.rs: \
         the definition; any caller or second definition changes this count"
    );
    assert_eq!(
        hex::encode(Sha256::digest(B_AUTH_DEVICE_DIRECTORY_SOURCE.as_bytes())),
        B_AUTH_DEVICE_DIRECTORY_SHA256,
        "device_directory.rs is read-only through Stage B"
    );
    assert_eq!(
        hex::encode(Sha256::digest(B_AUTH_DEVICE_VIEWS_SOURCE.as_bytes())),
        B_AUTH_DEVICE_VIEWS_SHA256,
        "device_views.rs is read-only through Stage B"
    );
    assert_eq!(
        hex::encode(Sha256::digest(include_bytes!("common/executor_seed.rs"))),
        FROZEN_EXECUTOR_SEED_SHA256,
        "the frozen executor seed helper is unchanged by Stage B"
    );
}

/// Lane-P pins for the paths that stay byte-identical through Stage B.
const B_AUTH_DEVICE_DIRECTORY_SHA256: &str =
    "0e0933e7a20bc5abf5744b2e322fde0d7ac55677ce6bddb87c350665cb35be36";
const B_AUTH_DEVICE_VIEWS_SHA256: &str =
    "aa154f2dd7043cb15b05a6293228ae866929cde78ace6ced468984e6777959a0";

// ---------------------------------------------------------------------------
// 4-7. Ignored Tokio database cases, class `commit-write`. Task B6 runs these.
//      Each takes its own private RAII `chat_exec_*` database.
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore]
async fn b_auth_real_repository_receipt_seals_endpoint_bound_admission_once() {
    let (pool, guard) = b_auth_pool().await;
    let db_name = guard.db_name.clone();
    let maintenance_url = guard.maintenance_url.clone();
    assert_private_executor_db_name(&db_name);

    assert_eq!(
        consumed_replay_rows(&pool).await,
        0,
        "no replay material is consumed before the request"
    );

    // Pin the replay identity so the retry below is a genuine replay.
    let token_jti = Uuid::new_v4();
    let proof_jti = b_auth_proof_jti();
    let authority = repository::auth::authorize_unsigned_request(
        &pool,
        chat_protocol::dpop::repository_test_evidence::ordinary_registered_device(
            token_jti,
            proof_jti,
            "blue.catbird.chat.getDevices",
            B_AUTH_T,
        ),
    )
    .await
    .expect("the seeded active device authorizes an unsigned read");

    let committed = consumed_replay_rows(&pool).await;
    assert!(
        committed > 0,
        "the authority transaction committed its replay set"
    );

    // The seal consumes the committed authority BY VALUE. There is no second
    // seal of the same request: `authority` is moved here.
    let admission = chat_protocol::dpop::seal_read_admission(authority)
        .expect("a committed existing-device receipt seals a read admission");

    // The admission is bound to the endpoint it was authorized for: it cannot
    // mint the OTHER endpoint's budget. The conversion is pure, so this fails
    // before any SQL.
    let foreign = chat_protocol::b_auth_bridge::try_mint_get_own_devices_budget(admission);
    assert!(
        matches!(
            foreign,
            Err(chat_protocol::dpop::ReadAdmissionBindingError::EndpointBinding)
        ),
        "a getDevices admission cannot authorize the getOwnDevices budget"
    );

    // Replaying the exact same token/proof identity is denied, and consumes no
    // further replay rows: the seal happened exactly once.
    let replayed = repository::auth::authorize_unsigned_request(
        &pool,
        chat_protocol::dpop::repository_test_evidence::ordinary_registered_device(
            token_jti,
            proof_jti,
            "blue.catbird.chat.getDevices",
            B_AUTH_T,
        ),
    )
    .await;
    assert!(
        matches!(
            replayed,
            Err(repository::auth::AuthRepositoryError::ReplayDetected)
        ),
        "the exact replay identity is refused a second admission"
    );
    assert_eq!(
        consumed_replay_rows(&pool).await,
        committed,
        "exactly one replay set remains consumed for the test identity"
    );

    // A fresh identity still works, so the denial is replay-specific.
    let fresh = real_read_admission(&pool, "blue.catbird.chat.getDevices").await;
    assert!(
        chat_protocol::b_auth_bridge::try_mint_get_devices_budget(fresh).is_ok(),
        "a fresh committed receipt still seals and mints its own budget"
    );

    // --- AMENDMENT 1, BEHAVIOURAL HALF ---------------------------------
    //
    // Folded into this sealed name by coordinator ruling: the sealed table has
    // no truncation case and a ninth name may not be invented. The structural
    // half lives in `b_auth_read_authority_privacy_and_call_graph_guards`.
    //
    // The check discriminates in BOTH directions, so it cannot pass while
    // proving nothing: the fixture instant is asserted to be sub-second FIRST,
    // and the derived base timestamp is then asserted to be whole-second on
    // the same second.
    let fixture_instant = DateTime::parse_from_rfc3339(B_AUTH_T)
        .expect("the fixed trusted instant is RFC3339")
        .with_timezone(&Utc);
    assert_ne!(
        fixture_instant.timestamp_subsec_nanos(),
        0,
        "the fixture instant must be SUB-SECOND, or the truncation below \
         would be proving nothing"
    );

    let instant_admission = real_read_admission(&pool, "blue.catbird.chat.getDevices").await;
    let created_at = chat_protocol::b_auth_bridge::bounded_created_at(&pool, instant_admission)
        .await
        .expect("the verified row derives its repository-owned base timestamp");

    assert_eq!(
        created_at.timestamp_subsec_nanos(),
        0,
        "the base timestamp crosses the boundary already truncated to a whole \
         second; a sub-second value would be rejected as DurableRowInvalid"
    );
    assert_eq!(
        created_at.timestamp(),
        fixture_instant.timestamp(),
        "truncation drops the sub-second remainder and nothing else"
    );
    assert!(
        created_at <= fixture_instant,
        "truncation never rounds the retained instant forward"
    );

    pool.close().await;
    drop(guard);
    assert_executor_db_absent(&maintenance_url, &db_name).await;
}

#[tokio::test]
#[ignore]
async fn b_auth_postcommit_seal_failure_keeps_replay_consumed() {
    let (pool, guard) = b_auth_pool().await;
    let db_name = guard.db_name.clone();
    let maintenance_url = guard.maintenance_url.clone();

    // A legitimate repository variant that commits its replay set and then
    // yields an authority the READ seal must refuse: it carries a mutation.
    let token_jti = Uuid::new_v4();
    let proof_jti = b_auth_proof_jti();
    let raw = signed_blob_deletion_bytes(Uuid::new_v4(), Uuid::new_v4());
    let outcome = repository::auth::authorize_signed_request(
        &pool,
        chat_protocol::dpop::repository_test_evidence::ordinary_registered_device(
            token_jti,
            proof_jti,
            "blue.catbird.chat.deleteBlob",
            B_AUTH_T,
        ),
        transcript::decode_canonical_signed_mutation(&raw)
            .expect("the signed deletion wrapper decodes canonically"),
    )
    .await
    .expect("the seeded device authorizes its own signed mutation");
    let repository::auth::AuthorizationOutcome::FirstExecution(authority) = outcome else {
        panic!("a first signed execution must not replay");
    };

    let committed = consumed_replay_rows(&pool).await;
    assert!(
        committed > 0,
        "the signed authority transaction committed its replay set BEFORE the seal"
    );

    // POST-COMMIT seal failure.
    let sealed = chat_protocol::dpop::seal_read_admission(authority);
    assert!(
        matches!(
            sealed,
            Err(chat_protocol::dpop::ReadAdmissionBindingError::OperationShape)
        ),
        "an authority carrying a mutation is not a read admission"
    );

    // The failure does NOT roll the replay set back.
    assert_eq!(
        consumed_replay_rows(&pool).await,
        committed,
        "the original replay rows remain consumed after the seal failed"
    );

    // And the same replay identity cannot be retried into a successful
    // admission.
    let retry = repository::auth::authorize_unsigned_request(
        &pool,
        chat_protocol::dpop::repository_test_evidence::ordinary_registered_device(
            token_jti,
            proof_jti,
            "blue.catbird.chat.getDevices",
            B_AUTH_T,
        ),
    )
    .await;
    assert!(
        matches!(
            retry,
            Err(repository::auth::AuthRepositoryError::ReplayDetected)
        ),
        "a retry on the consumed replay identity cannot create a second admission"
    );
    assert_eq!(
        consumed_replay_rows(&pool).await,
        committed,
        "the denied retry consumed nothing further"
    );

    pool.close().await;
    drop(guard);
    assert_executor_db_absent(&maintenance_url, &db_name).await;
}

#[tokio::test]
#[ignore]
async fn b_auth_endpoint_method_and_budget_foreign_use_fail_before_sql() {
    let (pool, guard) = b_auth_pool().await;
    let db_name = guard.db_name.clone();
    let maintenance_url = guard.maintenance_url.clone();

    // --- SUBCASE 1: WRONG CLASS AND WRONG METHOD.
    //
    // The previous version of this subcase cast a function item to `usize` and
    // asserted the address was nonzero, then compared a replay counter with
    // itself across two statements that touched no database. Neither could
    // fail. What follows is executed instead.
    //
    // (1a) An endpoint that is not a read endpoint is refused by the REAL
    //      repository entry point and yields no authority at all, so nothing
    //      downstream can mint a budget or reach a protected read.
    let before = consumed_replay_rows(&pool).await;
    let wrong_class = repository::auth::authorize_unsigned_request(
        &pool,
        chat_protocol::dpop::repository_test_evidence::ordinary_registered_device(
            Uuid::new_v4(),
            b_auth_proof_jti(),
            "blue.catbird.chat.deleteBlob",
            B_AUTH_T,
        ),
    )
    .await;
    assert!(
        matches!(
            wrong_class,
            Err(repository::auth::AuthRepositoryError::UnsupportedAuthorizationShape)
        ),
        "an unsigned request to a signed-mutation endpoint yields no authority"
    );
    // Fail-closed, not fail-open: the replay set IS committed by the refusal.
    // Asserting the direction matters — a counter compared with itself would
    // have passed whatever the repository did.
    let after_wrong_class = consumed_replay_rows(&pool).await;
    assert!(
        after_wrong_class > before,
        "the refused request still committed its replay set (fail-closed)"
    );

    // (1b) The METHOD the seal compares against is owned by the endpoint, and
    //      is derived by the real `dpop_method()`. Both inputs that make
    //      `seal_read_admission` return `MethodBinding` are executed here:
    //      an endpoint that owns no request-DPoP method at all, and an
    //      endpoint whose owned method is not the read canonical method.
    let subscription =
        chat_protocol::validation::ValidatedChatNsid::parse("blue.catbird.chat.subscribeEvents")
            .expect("the subscription endpoint is in the closed set");
    assert!(
        subscription.dpop_method().is_err(),
        "a subscription endpoint owns no request-DPoP method — the exact input \
         that the seal maps to MethodBinding"
    );
    let mutation_endpoint =
        chat_protocol::validation::ValidatedChatNsid::parse("blue.catbird.chat.deleteBlob")
            .expect("the mutation endpoint is in the closed set");
    assert_eq!(
        mutation_endpoint
            .dpop_method()
            .expect("a mutation endpoint owns a method")
            .as_str(),
        "POST",
        "a mutation endpoint owns POST, never the read canonical method"
    );
    for read_endpoint in [
        "blue.catbird.chat.getDevices",
        "blue.catbird.chat.getOwnDevices",
    ] {
        assert_eq!(
            chat_protocol::validation::ValidatedChatNsid::parse(read_endpoint)
                .expect("the read endpoint is in the closed set")
                .dpop_method()
                .expect("a read endpoint owns a method")
                .as_str(),
            "GET",
            "POSITIVE CONTROL: {read_endpoint} owns exactly the read canonical method"
        );
    }
    // A residual limitation, stated rather than papered over: a
    // cryptographically verified request whose proof method DISAGREES with its
    // endpoint cannot be built in this crate, because every
    // `repository_test_evidence` builder derives `method` from
    // `endpoint.dpop_method()` and the field is private to `dpop`. Building one
    // would need a full `TrustedNestVerifier` and real ES256 JWTs. The seal's
    // comparison is anchored in source by
    // `b_auth_read_admission_rejects_invalid_receipt_shapes_redacted`, and both
    // of its inputs are executed above.

    // --- SUBCASE 2: THE AMENDMENT'S PHASE-MANIFEST LEG (line 668) —
    //     "a separate VALID subcase … fails closed facade endpoint/budget
    //     binding before protected SQL".
    //
    //     THIS LEG IS ONLY DISCHARGEABLE HERE. It cannot be reached over HTTP:
    //     each handler seals its admission with its own `ChatEndpoint` and
    //     hands it to its own facade, so no request can ever present a
    //     `getDevices` admission to the `getOwnDevices` budget. Only this
    //     crate's `b_auth_bridge`, which calls the closed conversions
    //     directly, can put a valid admission in front of the foreign budget.
    //
    //     A VALID request commits real replay material, and only then is its
    //     budget used foreign. Both directions fail.
    //
    //     "NO PROTECTED SQL WAS REACHED" IS NOT PROVED BY A ROW COUNT HERE.
    //     This caption used to cite "the durable-session count below"; C-N1
    //     deleted that count as unfalsifiable, and the citation outlived it,
    //     pointing at nothing (B9-2, corrected in B10). What carries the claim
    //     now is stated in full at the "NO `chat.device_inventory_sessions`
    //     COUNT HERE" block further down, and is in short: the two
    //     `try_mint_*_budget` conversions take no `PgPool`, so a refused
    //     foreign use cannot issue SQL of any kind, and the replay-row
    //     EQUALITY below is a live counter that fails if a refusal rolls
    //     anything back or consumes anything further.
    let own_devices = real_read_admission(&pool, "blue.catbird.chat.getOwnDevices").await;
    let after_valid = consumed_replay_rows(&pool).await;
    assert!(
        after_valid > before,
        "the valid subcase committed its replay rows"
    );

    let foreign_get_devices =
        chat_protocol::b_auth_bridge::try_mint_get_devices_budget(own_devices);
    assert!(
        matches!(
            foreign_get_devices,
            Err(chat_protocol::dpop::ReadAdmissionBindingError::EndpointBinding)
        ),
        "a getOwnDevices admission cannot authorize the getDevices budget"
    );

    let get_devices = real_read_admission(&pool, "blue.catbird.chat.getDevices").await;
    let after_second_valid = consumed_replay_rows(&pool).await;
    assert!(
        after_second_valid > after_valid,
        "the second valid admission committed its own replay set"
    );
    let foreign_own_devices =
        chat_protocol::b_auth_bridge::try_mint_get_own_devices_budget(get_devices);
    assert!(
        matches!(
            foreign_own_devices,
            Err(chat_protocol::dpop::ReadAdmissionBindingError::EndpointBinding)
        ),
        "a getDevices admission cannot authorize the getOwnDevices budget"
    );

    // The valid subcases' replay rows stay committed, EXACTLY. `>=` on a
    // monotonically growing counter is nearly unfalsifiable; the equality
    // below fails if a refused foreign use either rolls anything back or
    // consumes anything further.
    assert_eq!(
        consumed_replay_rows(&pool).await,
        after_second_valid,
        "a refused foreign budget use neither rolls back nor consumes replay material"
    );
    // NO `chat.device_inventory_sessions` COUNT HERE — DELIBERATELY, AND THIS
    // IS A CORRECTION.
    //
    // A `SELECT count(*) … = 0` on that table stood here captioned "a foreign
    // budget use must reach no protected SQL". It could not fail. The table has
    // exactly one writer, `create_device_inventory_session`, whose only caller
    // is `create_own_device_snapshot_for_admission` — and that whole facade
    // section is `#[cfg(not(test))]` (`inventory.rs:2854`), so it is ABSENT
    // from this crate's path-included `mod inventory`, as this file itself
    // documents at the Stage-B banner above. Nothing in this crate writes the
    // table, so the count was zero by construction and no mutation of `dpop.rs`,
    // `inventory.rs`, or this test could have made it non-zero. It read as
    // before-SQL evidence and was a tautology.
    //
    // The property it claimed is carried by assertions that CAN fail:
    //   - `try_mint_get_devices_budget` / `try_mint_get_own_devices_budget`
    //     take no `PgPool` at all, so a refused foreign use cannot issue SQL of
    //     any kind — a type-level guarantee, not a row count;
    //   - the replay-row equality directly above is a live counter on a
    //     committed table, and fails if a refused foreign use either rolls
    //     back or consumes anything further;
    //   - the durable no-session claim for the REAL facade is measured over
    //     the real router in `chat_protocol_device_handlers.rs`, where the
    //     facade exists.

    // A correctly matched admission still converts, so the gate is a binding
    // check and not a blanket refusal.
    let matched = real_read_admission(&pool, "blue.catbird.chat.getDevices").await;
    assert!(
        chat_protocol::b_auth_bridge::try_mint_get_devices_budget(matched).is_ok(),
        "the matching endpoint still mints its own budget"
    );

    // =====================================================================
    // SUBCASE 3: THE ROW-DRIFT MATRIX, EXECUTED.
    //
    // WHY THIS LIVES HERE. The sealed eight-name table has no drift test and a
    // ninth name may not be invented, so — exactly as the amendment-1
    // truncation coverage was folded into two existing names — the sealed
    // "inactive/missing device; malformed/drifted JKT; zero/negative/drifted
    // generation; wrong key ID/digest; missing/revoked key" matrix is folded
    // into this name, whose stated invariant ("fail before SQL") is precisely
    // what every row below asserts.
    //
    // These are DYNAMIC negatives. Each one spends a real attempt minted from a
    // real committed receipt, reads the two ordered `FOR UPDATE` locks, and is
    // refused by the real production code: `from_repository_lock` for the
    // structural shapes, `consume_verify_locked_row` for the authority drift.
    // WHAT `protected_queries == 0` ACTUALLY BUYS — stated accurately in B10,
    // replacing a caption (B9-3) that overstated it.
    //
    // The counter is now incremented by the statement that issues
    // `PROTECTED_QUERY_SQL`, and only after `verify_same_transaction` returns
    // `Ok` — so it is bound to real SQL issuance rather than typed per arm,
    // which is what N3 fixed. It is NOT, however, an independent
    // "before protected SQL" proof for production inputs: in the drift matrix
    // below, `assert_eq!(outcome.stage, expected_stage)` fires BEFORE
    // `assert_eq!(outcome.protected_queries, 0)`, and in this harness
    // `protected_queries == 1` iff `stage == Verified`. So for every drift a
    // production change could produce, the stage assertion is what fails, and
    // the zero restates it.
    //
    // Its remaining, genuine job is to catch a defect in THIS CRATE'S BRIDGE:
    // if `get_devices_attempt_verifies` were rewired to issue
    // `PROTECTED_QUERY_SQL` before the verifier gate, or to report a refused
    // stage while still having queried, `stage` would still read as expected
    // and only this assertion would fail. That is worth keeping — it guards the
    // instrument the rest of this matrix is read through — but it is a claim
    // about the harness, not about production, and the real before-SQL property
    // is carried by the `stage` + `binding_error_name` pair.
    // =====================================================================

    use chat_protocol::b_auth_bridge::{AttemptStage, RowDrift};

    // POSITIVE CONTROL FIRST. Without it, a harness that refused everything —
    // or never reached the verifier at all — would satisfy every negative.
    let control = chat_protocol::b_auth_bridge::get_devices_attempt_verifies(
        &pool,
        real_read_admission(&pool, "blue.catbird.chat.getDevices").await,
        RowDrift::default(),
    )
    .await
    .expect("the undrifted attempt converts its budget");
    assert_eq!(
        control.stage,
        AttemptStage::Verified,
        "POSITIVE CONTROL: an undrifted locked row verifies"
    );
    assert_eq!(
        control.protected_queries, 1,
        "POSITIVE CONTROL: a verified row proof DOES open the protected query, \
         so a zero count on the negatives below is meaningful"
    );

    let drifted_jkt = URL_SAFE_NO_PAD.encode([1_u8; 32]);
    let double_hashed_jkt =
        URL_SAFE_NO_PAD.encode::<[u8; 32]>(Sha256::digest(B_AUTH_JKT.as_bytes()).into());
    let foreign_device = Uuid::parse_str("4b241101-e2bb-4255-8caf-4136c566a964")
        .expect("the foreign device UUID is canonical");

    // (label, drift, stage the refusal must occur at, exact variant name)
    let drift_matrix: Vec<(&str, RowDrift, AttemptStage, &str)> = vec![
        (
            "inactive device",
            RowDrift {
                status: Some("revoked".to_owned()),
                ..RowDrift::default()
            },
            AttemptStage::VerifierRefused,
            "DeviceStatus",
        ),
        (
            "revoked key",
            RowDrift {
                key_revoked_at: Some(Utc::now()),
                ..RowDrift::default()
            },
            AttemptStage::VerifierRefused,
            "KeyRevoked",
        ),
        (
            "drifted DID",
            RowDrift {
                did: Some("did:plc:aaaaaaaaaaaaaaaaaaaaaaaa".to_owned()),
                ..RowDrift::default()
            },
            AttemptStage::VerifierRefused,
            "RequesterCoordinates",
        ),
        (
            "drifted device",
            RowDrift {
                device_id: Some(foreign_device),
                ..RowDrift::default()
            },
            AttemptStage::VerifierRefused,
            "RequesterCoordinates",
        ),
        (
            "malformed JKT",
            RowDrift {
                textual_jkt: Some("not*a*thumbprint!!".to_owned()),
                ..RowDrift::default()
            },
            AttemptStage::ConstructorRefused,
            "LockedRowShape",
        ),
        (
            "drifted JKT",
            RowDrift {
                textual_jkt: Some(drifted_jkt.clone()),
                ..RowDrift::default()
            },
            AttemptStage::VerifierRefused,
            "Thumbprint",
        ),
        (
            "double-hashed JKT",
            RowDrift {
                textual_jkt: Some(double_hashed_jkt.clone()),
                ..RowDrift::default()
            },
            AttemptStage::VerifierRefused,
            "Thumbprint",
        ),
        (
            "zero generation",
            RowDrift {
                auth_generation: Some(0),
                ..RowDrift::default()
            },
            AttemptStage::ConstructorRefused,
            "LockedRowShape",
        ),
        (
            "negative generation",
            RowDrift {
                auth_generation: Some(-1),
                ..RowDrift::default()
            },
            AttemptStage::ConstructorRefused,
            "LockedRowShape",
        ),
        (
            "drifted generation",
            RowDrift {
                auth_generation: Some(2),
                ..RowDrift::default()
            },
            AttemptStage::VerifierRefused,
            "Generation",
        ),
        (
            "wrong key ID",
            RowDrift {
                key_id: Some("a-different-key-id".to_owned()),
                ..RowDrift::default()
            },
            AttemptStage::VerifierRefused,
            "KeyBinding",
        ),
        (
            "wrong key digest",
            RowDrift {
                signing_sha256: Some([7_u8; 32]),
                ..RowDrift::default()
            },
            AttemptStage::VerifierRefused,
            "KeyBinding",
        ),
    ];
    assert_eq!(
        drift_matrix.len(),
        12,
        "the sealed drift matrix must not silently shrink"
    );

    for (label, drift, expected_stage, expected_error) in drift_matrix {
        let outcome = chat_protocol::b_auth_bridge::get_devices_attempt_verifies(
            &pool,
            real_read_admission(&pool, "blue.catbird.chat.getDevices").await,
            drift,
        )
        .await
        .unwrap_or_else(|error| panic!("{label}: the budget conversion itself failed: {error:?}"));
        assert_eq!(
            outcome.stage, expected_stage,
            "{label} must be refused at the {expected_stage:?} stage"
        );
        assert_eq!(
            binding_error_name(&outcome.error),
            expected_error,
            "{label} must be refused with {expected_error}"
        );
        assert_eq!(
            outcome.protected_queries, 0,
            "{label} must reach NO protected SQL"
        );
        // NO SENTINEL SWEEP HERE — DELIBERATELY, AND THIS IS A CORRECTION.
        //
        // An earlier version of this fix swept every rejection for 13
        // sentinels and 7 live needles: 12 cases x 20 = 240 assertions, none
        // of which could fail. `outcome.error` renders through the derived
        // `Debug` of a thirteen-unit-variant enum, so the rendering is the
        // variant name and no sentinel or live needle is a substring of any
        // variant name. It read as end-to-end coverage and was decoration.
        //
        // The exact-variant assertion above is the discriminating form: a
        // rendering carrying ANY row material would no longer equal the
        // expected variant name, and would fail here.
        //
        // The property is guarded, and the guards can fail:
        //   - unit-variant shape + derived-`Debug`/no-`Display` guards, in
        //     `b_auth_read_admission_rejects_invalid_receipt_shapes_redacted`;
        //   - end-to-end HTTP-body redaction over the real router, in
        //     `chat_protocol_device_handlers.rs`.
    }

    // MISSING DEVICE. The repository refuses before any authority exists, so
    // there is nothing to seal, no budget to mint, and no attempt to spend.
    let missing_device = repository::auth::authorize_unsigned_request(
        &pool,
        chat_protocol::dpop::repository_test_evidence::ordinary_missing_device_with_replay(
            Uuid::new_v4(),
            b_auth_proof_jti(),
        ),
    )
    .await;
    assert!(
        matches!(
            missing_device,
            Err(repository::auth::AuthRepositoryError::DeviceNotRegistered)
        ),
        "an unregistered device is refused before any read authority exists"
    );

    // MISSING KEY. A device with no `chat.device_keys` row cannot authorize at
    // all: the second ordered lock returns nothing. Seeded as an INSERT, never
    // as a mutation of the fixture rows, which the schema's immutability
    // triggers forbid.
    let keyless_jkt = seed_b_auth_keyless_device(&pool).await;
    let missing_key = repository::auth::authorize_unsigned_request(
        &pool,
        chat_protocol::dpop::repository_test_evidence::ordinary_device_with_binding(
            Uuid::new_v4(),
            b_auth_proof_jti(),
            "blue.catbird.chat.getDevices",
            B_AUTH_T,
            B_AUTH_DID,
            Uuid::parse_str(B_AUTH_KEYLESS_DEVICE).expect("the keyless device UUID is canonical"),
            &keyless_jkt,
        ),
    )
    .await;
    assert!(
        matches!(
            missing_key,
            Err(repository::auth::AuthRepositoryError::DeviceKeyMissing)
        ),
        "a device with no key row is refused before any read authority exists"
    );

    // =====================================================================
    // SUBCASE 4: FOREIGN TRANSACTION, EXECUTED.
    //
    // A row proof minted under transaction A is refused under transaction B,
    // BEFORE the protected query. The helper reports the positive control in
    // the same value, so a proof that refused every transaction could not pass.
    // =====================================================================
    let foreign_transaction = chat_protocol::b_auth_bridge::proof_rejects_foreign_transaction(
        &pool,
        real_read_admission(&pool, "blue.catbird.chat.getDevices").await,
    )
    .await
    .expect("the foreign-transaction probe mints its row proof");
    assert!(
        foreign_transaction.transactions_differ,
        "the two sampled transaction identities must genuinely differ"
    );
    assert!(
        foreign_transaction.own_transaction_accepted,
        "POSITIVE CONTROL: the proof accepts the transaction it was minted under"
    );
    assert_eq!(
        format!("{:?}", foreign_transaction.foreign_error),
        "TransactionIdentity",
        "a proof from transaction A is refused under transaction B"
    );
    assert_eq!(
        foreign_transaction.protected_queries, 0,
        "the foreign transaction reached NO protected SQL"
    );

    // NO POST-MATRIX `chat.device_inventory_sessions` COUNT — same correction as
    // in subcase 2, same reason: the sole writer's only caller is inside the
    // `#[cfg(not(test))]` facade, which does not exist in this crate, so the
    // count was zero by construction whatever the drift matrix did. What the
    // matrix actually measures is the per-row execution counter
    // (`outcome.protected_queries`, incremented by the statement that issues
    // `PROTECTED_QUERY_SQL`) together with its positive control of 1 on the
    // undrifted attempt.

    pool.close().await;
    drop(guard);
    assert_executor_db_absent(&maintenance_url, &db_name).await;
}

/// The exact attempt-minting sites in `dpop.rs`.
///
/// THE PREDICATE. `ReadAdmissionAttempt {` over the WHOLE of `dpop.rs`
/// measures SEVEN, not four: the struct declaration, the four minting
/// literals, the `into_attempt` return type, and the `impl` line all match. An
/// earlier version of the fourth-attempt case asserted the whole-file count
/// was 4 and would have failed deterministically the moment Task B6 ran it —
/// and, sitting ahead of the pool close, would have destroyed that run's
/// residue proof as a side effect.
///
/// The count is therefore taken over the two conversion BODIES, exactly as
/// tests 4 and 5 do, and the whole-file total is reconciled against the four
/// literals plus the three named non-minting occurrences — so this stays
/// capable of failing rather than merely matching today's number. A fifth
/// minting site anywhere in the module breaks the reconciliation.
///
/// It is a pure source derivation, so it is called from the NONIGNORED
/// `b_auth_read_authority_privacy_and_call_graph_guards` (where it runs in the
/// no-database gate today) as well as from the database-marked
/// `b_auth_get_own_devices_fourth_attempt_fails_before_sql`, before that case
/// creates any private database.
fn assert_attempt_minting_sites() {
    // ===================================================================
    // SOURCE GUARDS RUN FIRST, BEFORE ANY DATABASE EXISTS.
    //
    // A source-drift panic here used to sit after the run's work and AHEAD of
    // `pool.close()` / `assert_executor_db_absent`, so it destroyed the
    // residue proof as a side effect. Nothing below this block can create a
    // private `chat_exec_*` database, so a failure here leaves nothing to
    // prove absent.
    //
    // THE PREDICATE. `ReadAdmissionAttempt {` over the WHOLE of `dpop.rs`
    // measures SEVEN, not four: the struct declaration, the four literals, the
    // `into_attempt` return type, and the `impl` line all match. The previous
    // literal `4` was a deterministic failure. The count is therefore taken
    // over the two conversion BODIES, exactly as tests 4 and 5 do, and the
    // whole-file total is asserted separately with its non-literal occurrences
    // enumerated — so this stays capable of failing rather than merely
    // matching today's number.
    let get_devices_conversion = {
        let start = B_AUTH_DPOP_SOURCE
            .find("pub(in crate::chat_protocol) fn into_get_devices_read_admission(")
            .expect("exact GetDevices conversion");
        let end = start
            + B_AUTH_DPOP_SOURCE[start..]
                .find("\n    }\n")
                .expect("GetDevices conversion terminates");
        &B_AUTH_DPOP_SOURCE[start..end]
    };
    let get_own_devices_conversion = {
        let start = B_AUTH_DPOP_SOURCE
            .find("pub(in crate::chat_protocol) fn into_get_own_devices_read_admission(")
            .expect("exact GetOwnDevices conversion");
        let end = start
            + B_AUTH_DPOP_SOURCE[start..]
                .find("\n    }\n")
                .expect("GetOwnDevices conversion terminates");
        &B_AUTH_DPOP_SOURCE[start..end]
    };
    let minted_in_conversions = count_occurrences(get_devices_conversion, "ReadAdmissionAttempt {")
        + count_occurrences(get_own_devices_conversion, "ReadAdmissionAttempt {");
    assert_eq!(
        minted_in_conversions, 4,
        "one attempt for getDevices plus exactly three for getOwnDevices"
    );
    assert_eq!(
        count_occurrences(get_devices_conversion, "ReadAdmissionAttempt {"),
        1,
        "the getDevices conversion mints exactly one"
    );
    assert_eq!(
        count_occurrences(get_own_devices_conversion, "ReadAdmissionAttempt {"),
        3,
        "the getOwnDevices conversion mints exactly three — no fourth"
    );
    // The B-read seam bodies (B-read-owned, outside the sealed read section)
    // mint exactly one ordinary attempt and exactly three inventory attempts.
    let seam_single_conversion = {
        let start = B_AUTH_DPOP_SOURCE
            .find("pub(in crate::chat_protocol) fn into_single_read_attempt(")
            .expect("exact B-read single-attempt seam");
        let end = start
            + B_AUTH_DPOP_SOURCE[start..]
                .find("\n    }\n")
                .expect("B-read single-attempt seam terminates");
        &B_AUTH_DPOP_SOURCE[start..end]
    };
    let seam_inventory_conversion = {
        let start = B_AUTH_DPOP_SOURCE
            .find("pub(in crate::chat_protocol) fn into_inventory_read_attempts(")
            .expect("exact B-read inventory seam");
        let end = start
            + B_AUTH_DPOP_SOURCE[start..]
                .find("\n    }\n")
                .expect("B-read inventory seam terminates");
        &B_AUTH_DPOP_SOURCE[start..end]
    };
    assert_eq!(
        count_occurrences(seam_single_conversion, "ReadAdmissionAttempt {"),
        1,
        "the B-read single-attempt seam mints exactly one"
    );
    assert_eq!(
        count_occurrences(seam_inventory_conversion, "ReadAdmissionAttempt {"),
        3,
        "the B-read inventory seam mints exactly three — no fourth"
    );
    let minted_in_seams = count_occurrences(seam_single_conversion, "ReadAdmissionAttempt {")
        + count_occurrences(seam_inventory_conversion, "ReadAdmissionAttempt {");
    // The two B-read conversions are the ONLY places attempts are minted. The
    // remaining whole-file occurrences are named individually, so a new minting
    // site anywhere in the module fails this assertion instead of hiding in a
    // slack total.
    let non_minting: &[&str] = &[
        "pub(in crate::chat_protocol) struct ReadAdmissionAttempt {",
        "fn into_attempt(self) -> ReadAdmissionAttempt {",
        "impl ReadAdmissionAttempt {",
    ];
    for occurrence in non_minting {
        assert_eq!(
            count_occurrences(B_AUTH_DPOP_SOURCE, occurrence),
            1,
            "the non-minting occurrence `{occurrence}` must appear exactly once"
        );
    }
    assert_eq!(
        count_occurrences(B_AUTH_DPOP_SOURCE, "ReadAdmissionAttempt {"),
        minted_in_conversions + minted_in_seams + non_minting.len(),
        "the whole-file count must be exactly the eight minting literals plus \
     the declaration, the return type, and the impl line — a fifth minting \
     site would show up here"
    );
}

#[tokio::test]
#[ignore]
async fn b_auth_get_own_devices_fourth_attempt_fails_before_sql() {
    assert_attempt_minting_sites();

    let (pool, guard) = b_auth_pool().await;
    let db_name = guard.db_name.clone();
    let maintenance_url = guard.maintenance_url.clone();

    let replay_rows_before = consumed_replay_rows(&pool).await;
    let admission = real_read_admission(&pool, "blue.catbird.chat.getOwnDevices").await;
    let replay_rows_committed = consumed_replay_rows(&pool).await;
    assert!(
        replay_rows_committed > replay_rows_before,
        "the admission's authority transaction committed its replay set"
    );
    let ledger = chat_protocol::b_auth_bridge::own_devices_attempt_ledger(&pool, admission)
        .await
        .expect("the fixed three-attempt budget spends against the seeded device");

    // NO `attempts_minted == 3` AND NO `protected_queries == 3` — both were
    // reported-back constants. `attempts_minted` was `attempts.len()` on a
    // `[T; 3]`, a compile-time constant, so the assertion was `assert_eq!(3, 3)`
    // and a four-element budget is a compile error rather than a test failure.
    // `protected_queries` could not differ from `attempts_verified`: the two
    // increments sit in the same straight-line block of the ledger helper with
    // only a `?` between them, and that `?` aborts the helper entirely. Both
    // fields are gone from `AttemptLedger`, which the re-enabled `dead_code`
    // lint enforces.
    assert_eq!(
        ledger.attempts_verified, 3,
        "each of the three attempts verified exactly one locked row"
    );
    assert_eq!(
        ledger.distinct_transactions, 3,
        "every attempt ran in its own fresh transaction"
    );
    // PRIOR-TRANSACTION DROP. Each attempt's transaction is rolled back before
    // the next array element is used, so the previous attempt's row proof must
    // be refused by the successor's fresh transaction. Two successors, two
    // refusals. If a dropped transaction's proof were still accepted, a rolled
    // back attempt would keep authorizing protected SQL.
    assert_eq!(
        ledger.prior_proof_rejections, 2,
        "the second and third attempts each refuse their predecessor's row proof"
    );

    // REPLAY ROWS REMAIN COMMITTED. Spending the whole budget — including the
    // rollback of every attempt — rolls back nothing that was already
    // committed by the authority transaction.
    assert_eq!(
        consumed_replay_rows(&pool).await,
        replay_rows_committed,
        "the admission's replay rows remain exactly as committed after the \
         whole three-attempt budget was spent and rolled back"
    );

    // NO `chat.device_inventory_sessions` COUNT — same correction as in
    // `b_auth_endpoint_method_and_budget_foreign_use_fail_before_sql`. The
    // table's only writer is unreachable from this crate, so "a rolled-back
    // attempt leaves no durable session" was zero by construction here. What is
    // measured instead, and can fail, is the replay-row equality directly above
    // (a committed counter that must be exactly unchanged by spending and
    // rolling back the whole budget) together with `distinct_transactions` and
    // `prior_proof_rejections`.

    // The budget was consumed by `into_attempts`. A fourth attempt would need a
    // NEW admission, which needs a NEW committed receipt — it cannot be minted
    // from the spent one, and the array pattern in the bridge cannot bind a
    // fourth element.
    // Split needle, for the same reason as in
    // `b_auth_get_own_devices_budget_mints_fixed_three_attempts`: an unsplit
    // literal occurs inside this assertion's own argument, because the file
    // includes itself.
    let ledger_destructuring = concat!("let [first, second, third] = ", "admission");
    assert_eq!(
        count_occurrences(B_AUTH_G7_SELF_SOURCE, ledger_destructuring),
        1,
        "the ledger binds exactly three array elements, in the bridge and \
         nowhere else"
    );

    pool.close().await;
    drop(guard);
    assert_executor_db_absent(&maintenance_url, &db_name).await;
}

// ---------------------------------------------------------------------------
// B-read: consuming read authority (Checkpoint B-read).
//
// The pure/source tests below run in the no-database gate. The database tests
// are `#[ignore]`d exactly like the B-auth cases and take their own private
// `chat_exec_*` executor database through the frozen `executor_seed` graph
// fixtures; every rollback first forces deferred constraints immediate
// (BREAD-07).
// ---------------------------------------------------------------------------

/// A committed, sealed admission for an exact fixture device row.
async fn fixture_read_admission(
    pool: &PgPool,
    endpoint: &str,
    did: &str,
    device_id: Uuid,
    dpop_jkt: &str,
) -> chat_protocol::dpop::VerifiedReadAdmission {
    let authority = repository::auth::authorize_unsigned_request(
        pool,
        chat_protocol::dpop::repository_test_evidence::ordinary_device_with_binding(
            Uuid::new_v4(),
            b_auth_proof_jti(),
            endpoint,
            B_AUTH_T,
            did,
            device_id,
            dpop_jkt,
        ),
    )
    .await
    .expect("the seeded fixture device authorizes an unsigned read");
    chat_protocol::dpop::seal_read_admission(authority)
        .expect("a committed existing-device receipt seals a read admission")
}

/// A fresh bare DID, distinct per call, over the valid `did:plc:[a-z2-7]{24}`
/// grammar.
fn b_read_fresh_did(seed_byte: u8) -> String {
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz234567";
    let suffix: String = (0..24)
        .map(|index| ALPHABET[usize::from(seed_byte.wrapping_add(index * 7) % 32)] as char)
        .collect();
    format!("did:plc:{suffix}")
}

/// Register one additional active device (with its immutable key) for `did`.
/// The signing key is derived per device so the active-JKT uniqueness
/// constraint never collides.
async fn register_read_device(pool: &PgPool, did: &str, device_id: Uuid) -> String {
    let mut seed = Sha256::new();
    seed.update(b"CATBIRD-CHAT-B-READ-TEST-DEVICE\0");
    seed.update(device_id.as_bytes());
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed.finalize().into());
    let public_key = signing_key.verifying_key().as_bytes().to_vec();
    let key_id = chat_protocol::validation::ed25519_key_id(&public_key)
        .expect("derive B-read test device key id")
        .as_str()
        .to_owned();
    sqlx::query(
        "INSERT INTO chat.principals(user_did, created_at) \
         VALUES($1,$2::timestamptz) ON CONFLICT DO NOTHING",
    )
    .bind(did)
    .bind(B_AUTH_T)
    .execute(pool)
    .await
    .expect("register the B-read test principal");
    sqlx::query(
        r#"
        INSERT INTO chat.devices (
            user_did, device_id, device_name, status, dpop_jkt,
            auth_generation, capabilities, created_at, updated_at
        ) VALUES ($1,$2,$3,'active',$4,1,chat.protocol_capabilities(),
                  $5::timestamptz,$5::timestamptz)
        "#,
    )
    .bind(did)
    .bind(device_id)
    .bind("b-read-test-device")
    .bind(&key_id)
    .bind(B_AUTH_T)
    .execute(pool)
    .await
    .expect("register the B-read test device row");
    sqlx::query(
        r#"
        INSERT INTO chat.device_keys (
            user_did, device_id, key_id, signing_public_key,
            enrollment_auth_generation, created_at
        ) VALUES ($1,$2,$3,$4,1,$5::timestamptz)
        "#,
    )
    .bind(did)
    .bind(device_id)
    .bind(&key_id)
    .bind(public_key)
    .bind(B_AUTH_T)
    .execute(pool)
    .await
    .expect("register the B-read test device key row");
    key_id
}

/// Seed the exact private retention fence for a fixture protocol instance
/// (floor zero) if it is absent.
async fn seed_private_retention_fence(pool: &PgPool, protocol_instance_id: Uuid) {
    sqlx::query(
        "INSERT INTO chat.event_retention(protocol_instance_id,retained_floor,updated_at) \
         VALUES($1,0,date_trunc('milliseconds',clock_timestamp())) ON CONFLICT DO NOTHING",
    )
    .bind(protocol_instance_id)
    .execute(pool)
    .await
    .expect("seed exact private G7 retention fence");
}

/// The fixture protocol instance's durable cursor key.
async fn fixture_cursor_key(pool: &PgPool, protocol_instance_id: Uuid) -> String {
    sqlx::query_scalar(
        "SELECT cursor_key_id FROM chat.protocol_instances WHERE protocol_instance_id=$1",
    )
    .bind(protocol_instance_id)
    .fetch_one(pool)
    .await
    .expect("read the fixture protocol instance cursor key")
}

/// Source input for the B-read source guards.
const B_READ_READ_AUTHORITY_SOURCE: &str = include_str!("../src/chat_protocol/read_authority.rs");

#[test]
fn read_admission_seal_consumes_repository_locked_generation() {
    // The seal takes exactly the committed request and nothing else: no
    // generation argument, no caller-selected coordinate.
    assert!(
        B_AUTH_DPOP_SOURCE.contains(
            "pub(crate) fn seal_read_admission(\n    request: VerifiedChatDeviceRequest,\n) -> \
             Result<VerifiedReadAdmission, ReadAdmissionBindingError> {"
        ),
        "the seal signature consumes only the committed request"
    );
    // The binding's locked generation is set from the receipt's locked
    // coordinates seam, never from a request field or caller argument.
    assert!(
        B_AUTH_DPOP_SOURCE.contains("let locked_auth_generation = coordinates.auth_generation;"),
        "the sealed binding generation comes from the repository-locked coordinates"
    );
    assert_eq!(
        count_occurrences(B_AUTH_DPOP_SOURCE, "fn locked_auth_generation("),
        0,
        "the mutation-path getter is not exposed on the read side"
    );
    // BREAD-08 / §3: the B-read seam methods and budgets expose no raw
    // generation getter or argument.
    assert_eq!(
        count_occurrences(&code_only(read_section_of_dpop()), "fn generation("),
        0,
        "no raw generation getter exists in the sealed read section"
    );
    assert_eq!(
        count_occurrences(&code_only(read_section_of_dpop()), "fn auth_generation("),
        0,
        "no raw auth-generation getter exists in the sealed read section"
    );
    assert_eq!(
        count_occurrences(B_READ_READ_AUTHORITY_SOURCE, "fn locked_auth_generation("),
        0,
        "read_authority.rs exposes no locked-generation getter"
    );
    for seam_body in ["into_single_read_attempt", "into_inventory_read_attempts"] {
        let start = B_AUTH_DPOP_SOURCE
            .find(&format!("fn {seam_body}("))
            .unwrap_or_else(|| panic!("the {seam_body} seam exists"));
        let end = start
            + B_AUTH_DPOP_SOURCE[start..]
                .find("\n    }\n")
                .expect("seam body terminates");
        let body = &B_AUTH_DPOP_SOURCE[start..end];
        assert_eq!(
            count_occurrences(body, "generation"),
            0,
            "the {seam_body} seam accepts and exposes no generation"
        );
        assert_eq!(
            count_occurrences(body, "jkt"),
            0,
            "the {seam_body} seam accepts and exposes no JKT"
        );
    }
    // The free conversions take the admission and the closed endpoint only.
    assert!(
        B_READ_READ_AUTHORITY_SOURCE.contains(
            "pub(in crate::chat_protocol) fn into_single_read_admission(\n    \
             admission: VerifiedReadAdmission,\n    endpoint: OrdinaryReadEndpoint,\n"
        ),
        "the ordinary conversion takes only the admission and the closed endpoint"
    );
    assert!(
        B_READ_READ_AUTHORITY_SOURCE.contains(
            "pub(in crate::chat_protocol) fn into_inventory_read_admission(\n    \
             admission: VerifiedReadAdmission,\n    endpoint: InventoryReadEndpoint,\n"
        ),
        "the inventory conversion takes only the admission and the closed endpoint"
    );
}

/// The sealed B-auth read-section window, reused by the pure B-read guards.
fn read_section_of_dpop() -> &'static str {
    let start = B_AUTH_DPOP_SOURCE
        .find("// Opaque existing-device read admission (Stage B).")
        .expect("the B-auth read section banner");
    let section = &B_AUTH_DPOP_SOURCE[start..];
    let end = section
        .find("#[derive(Debug, Deserialize)]")
        .expect("the read section ends before the pre-existing JWT types");
    &section[..end]
}

#[test]
fn read_admission_rejects_missing_nonpositive_and_invalid_receipt_binding() {
    // The REAL production structural constructor over synthetic shapes: the
    // missing/empty coordinate and nonpositive-generation negatives execute
    // here, in the no-database gate.
    let valid_jkt = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    let valid_sha = [0x5A_u8; 32];
    let outcome = |did: &str,
                   device_id: Uuid,
                   status: &str,
                   jkt: &str,
                   generation: i64,
                   key_id: &str,
                   sha: [u8; 32]| {
        chat_protocol::b_auth_bridge::structural_row_outcome(
            "1", did, device_id, status, jkt, generation, key_id, sha, None,
        )
    };
    // Missing coordinates.
    assert!(
        matches!(
            outcome("", Uuid::new_v4(), "active", valid_jkt, 1, "k", valid_sha),
            Err(chat_protocol::dpop::ReadAdmissionBindingError::LockedRowShape)
        ),
        "empty DID is rejected before verification"
    );
    assert!(
        matches!(
            outcome(
                "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa",
                Uuid::nil(),
                "active",
                valid_jkt,
                1,
                "k",
                valid_sha
            ),
            Err(chat_protocol::dpop::ReadAdmissionBindingError::LockedRowShape)
        ),
        "nil device is rejected before verification"
    );
    assert!(
        matches!(
            outcome(
                "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa",
                Uuid::new_v4(),
                "",
                valid_jkt,
                1,
                "k",
                valid_sha
            ),
            Err(chat_protocol::dpop::ReadAdmissionBindingError::LockedRowShape)
        ),
        "empty device status is rejected before verification"
    );
    assert!(
        matches!(
            outcome(
                "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa",
                Uuid::new_v4(),
                "active",
                valid_jkt,
                1,
                "",
                valid_sha
            ),
            Err(chat_protocol::dpop::ReadAdmissionBindingError::LockedRowShape)
        ),
        "empty key id is rejected before verification"
    );
    // Nonpositive generations.
    assert!(
        matches!(
            outcome(
                "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa",
                Uuid::new_v4(),
                "active",
                valid_jkt,
                0,
                "k",
                valid_sha
            ),
            Err(chat_protocol::dpop::ReadAdmissionBindingError::LockedRowShape)
        ),
        "zero generation is rejected before verification"
    );
    assert!(
        matches!(
            outcome(
                "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa",
                Uuid::new_v4(),
                "active",
                valid_jkt,
                -1,
                "k",
                valid_sha
            ),
            Err(chat_protocol::dpop::ReadAdmissionBindingError::LockedRowShape)
        ),
        "negative generation is rejected before verification"
    );
    // Invalid receipt bindings: noncanonical, non-32-byte, padded, or
    // non-base64url JKT, and a wrong-length signing-key digest.
    for bad_jkt in [
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", // 42 chars
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", // padded
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA!", // non-base64url
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB", // 43 chars, wrong value
        "",
    ] {
        assert!(
            matches!(
                outcome(
                    "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa",
                    Uuid::new_v4(),
                    "active",
                    bad_jkt,
                    1,
                    "k",
                    valid_sha
                ),
                Err(chat_protocol::dpop::ReadAdmissionBindingError::LockedRowShape)
            ),
            "malformed JKT {bad_jkt:?} is rejected before verification"
        );
    }
    // The defence-in-depth nonpositive branch stays in the seal itself.
    assert_eq!(
        count_occurrences(B_AUTH_DPOP_SOURCE, "auth_generation <= 0"),
        3,
        "the nonpositive branches remain at the seal, the structural \
         constructor, and the consuming verifier"
    );
}

#[test]
fn read_admission_exposes_no_generation_getter_or_raw_tuple_constructor() {
    let read_section = read_section_of_dpop();
    // No tuple constructor and no raw coordinate bundle anywhere in the read
    // section or the B-read module.
    for forbidden in [
        "struct ReadAdmissionBinding(",
        "struct VerifiedReadAdmission(",
        "struct ReadAdmissionAttempt(",
        "struct SingleReadAdmission(",
        "struct InventoryReadAdmission(",
    ] {
        assert_eq!(
            count_occurrences(B_AUTH_DPOP_SOURCE, forbidden)
                + count_occurrences(B_READ_READ_AUTHORITY_SOURCE, forbidden),
            0,
            "no raw tuple constructor may exist for `{forbidden}`"
        );
    }
    // No From/Into conversion into or out of any B-read budget or authority.
    for type_name in [
        "SingleReadAdmission",
        "InventoryReadAdmission",
        "LockedReadDeviceAuthority",
        "ConversationStateReadAuthority",
        "EntryReadAuthority",
        "VerifiedInventoryFence",
        "ConversationInventoryAuthority",
    ] {
        assert_eq!(
            count_occurrences(
                B_READ_READ_AUTHORITY_SOURCE,
                &format!("impl From<{type_name}>")
            ) + count_occurrences(
                B_READ_READ_AUTHORITY_SOURCE,
                &format!("> for {type_name} {{")
            ),
            0,
            "{type_name} must have no trait conversion"
        );
    }
    // No serde derive on the admission, budget, or authority types.
    for type_name in [
        "VerifiedReadAdmission",
        "ReadAdmissionBinding",
        "GetDevicesReadAdmission",
        "GetOwnDevicesReadAdmission",
        "ReadAdmissionAttempt",
        "SingleReadAdmission",
        "InventoryReadAdmission",
        "LockedReadDeviceAuthority",
        "VerifiedInventoryFence",
    ] {
        let mut from = 0_usize;
        while let Some(offset) = B_AUTH_DPOP_SOURCE[from..].find(type_name) {
            let index = from + offset;
            let before = &B_AUTH_DPOP_SOURCE[..index];
            if before.ends_with("struct ") || before.ends_with("pub(crate) struct ") {
                let declaration_start = before.rfind("#[derive(").map_or(index, |d| d);
                let declaration = &B_AUTH_DPOP_SOURCE[declaration_start..index + type_name.len()];
                assert!(
                    !declaration.contains("Serialize") && !declaration.contains("Deserialize"),
                    "{type_name} must not derive serde: {declaration}"
                );
            }
            from = index + type_name.len();
        }
    }
    let read_code = code_only(read_section);
    for forbidden in [
        "fn generation(",
        "fn auth_generation(&self)",
        "fn jkt(&self)",
        "fn key_id(&self)",
        "fn replay_ids(&self)",
        "fn trusted_instant(&self)",
        "fn transaction_id(&self)",
    ] {
        assert_eq!(
            count_occurrences(&read_code, forbidden),
            0,
            "the sealed read authority must expose no `{forbidden}`"
        );
    }
    // The B-read budgets are non-Clone/Copy/Debug: no derives and no manual
    // impls.
    for type_name in ["SingleReadAdmission", "InventoryReadAdmission"] {
        for forbidden in [
            format!("impl Clone for {type_name}"),
            format!("impl Copy for {type_name}"),
            format!("impl std::fmt::Debug for {type_name}"),
        ] {
            assert_eq!(
                count_occurrences(B_READ_READ_AUTHORITY_SOURCE, &forbidden),
                0,
                "{type_name} must not implement `{forbidden}`"
            );
        }
        // The declaration block (attribute lines through the struct line) must
        // carry no derive. Counted per-declaration, never as a whole-file
        // arithmetic, so derives on the endpoint/error enums cannot leak in.
        let declaration = declaration_with_attributes(
            B_READ_READ_AUTHORITY_SOURCE,
            &format!("struct {type_name}"),
        );
        assert!(
            !declaration.contains("#[derive"),
            "{type_name} must derive nothing, found: {declaration}"
        );
    }
}

#[tokio::test]
#[ignore = "requires the dedicated gate database seeded with the B-read fixture corpus"]
async fn read_admission_attempts_mint_only_three_fresh_transaction_guards() {
    let (pool, guard) = b_auth_pool().await;
    let db_name = guard.db_name.clone();
    let maintenance_url = guard.maintenance_url.clone();
    assert_private_executor_db_name(&db_name);

    let admission = real_read_admission(&pool, "blue.catbird.chat.getConversations").await;
    let ledger =
        chat_protocol::read_authority_bridge::inventory_fresh_guard_ledger(&pool, admission)
            .await
            .expect("the fixed three-attempt inventory budget spends against the seeded device");
    assert_eq!(
        ledger.verified, 3,
        "each of the three inventory attempts locked and verified exactly one row"
    );
    assert_eq!(
        ledger.distinct_transactions, 3,
        "every inventory attempt ran in its own fresh transaction"
    );
    assert_eq!(
        ledger.prior_refusals, 2,
        "the second and third attempts each refuse their predecessor's guard"
    );

    pool.close().await;
    drop(guard);
    assert_executor_db_absent(&maintenance_url, &db_name).await;
}

#[tokio::test]
#[ignore = "requires the dedicated gate database seeded with the B-read fixture corpus"]
async fn fourth_read_admission_attempt_fails_before_sql() {
    assert_attempt_minting_sites();

    let (pool, guard) = b_auth_pool().await;
    let db_name = guard.db_name.clone();
    let maintenance_url = guard.maintenance_url.clone();
    assert_private_executor_db_name(&db_name);

    let replay_rows_before = consumed_replay_rows(&pool).await;
    let admission = real_read_admission(&pool, "blue.catbird.chat.getConversations").await;
    let replay_rows_committed = consumed_replay_rows(&pool).await;
    assert!(
        replay_rows_committed > replay_rows_before,
        "the admission's authority transaction committed its replay set"
    );
    let ledger =
        chat_protocol::read_authority_bridge::inventory_fresh_guard_ledger(&pool, admission)
            .await
            .expect("the fixed three-attempt inventory budget spends against the seeded device");
    assert_eq!(ledger.verified, 3, "exactly three attempts exist to spend");
    // A fourth attempt is unrepresentable: the budget field is a fixed-size
    // [T; 3] array, the seam mints exactly three (assert_attempt_minting_sites
    // above), and the exact-length binding in the ledger compiles only for
    // three elements. The whole budget was consumed by value, so no attempt
    // survives to authorize any fourth lock.
    assert_eq!(
        consumed_replay_rows(&pool).await,
        replay_rows_committed,
        "spending the whole inventory budget — including every rollback — \
         changes no committed replay rows"
    );

    pool.close().await;
    drop(guard);
    assert_executor_db_absent(&maintenance_url, &db_name).await;
}

#[tokio::test]
#[ignore = "requires the dedicated gate database seeded with the B-read fixture corpus"]
async fn single_attempt_rejects_foreign_transaction_before_conversation_lookup() {
    let (pool, guard) = b_auth_pool().await;
    let db_name = guard.db_name.clone();
    let maintenance_url = guard.maintenance_url.clone();
    assert_private_executor_db_name(&db_name);

    let admission = real_read_admission(&pool, "blue.catbird.chat.getConversationState").await;
    let (locked_ok, transactions_differ, outcome) =
        chat_protocol::read_authority_bridge::single_foreign_transaction_outcome(&pool, admission)
            .await
            .expect("the attempt locks under its own transaction");
    assert!(
        locked_ok,
        "the single attempt locked and verified under transaction A"
    );
    assert!(
        transactions_differ,
        "the two sampled transaction identities really differ"
    );
    // The conversation id handed to the foreign transaction does not exist:
    // the refusal is the transaction-identity error, never
    // ConversationNotFound, so the same-transaction check demonstrably ran
    // before any conversation lookup.
    assert_eq!(
        outcome,
        chat_protocol::read_authority::ReadAuthorityError::Invariant,
        "a guard minted under transaction A fails under transaction B before a \
         protected lookup"
    );

    pool.close().await;
    drop(guard);
    assert_executor_db_absent(&maintenance_url, &db_name).await;
}

#[tokio::test]
#[ignore = "requires the dedicated gate database seeded with the B-read fixture corpus"]
async fn revocation_jkt_and_generation_drift_after_admission_fail_closed() {
    let (pool, guard) = b_auth_pool().await;
    let db_name = guard.db_name.clone();
    let maintenance_url = guard.maintenance_url.clone();
    assert_private_executor_db_name(&db_name);

    let did = B_AUTH_DID;
    let device_id = Uuid::parse_str(B_AUTH_DEVICE).expect("fixed device UUID");
    let alternate_jkt = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA";

    // Ruling-5 hunk: the drifted revocations need their FULL durable
    // provenance — `rollback_with_constraints` forces the deferred
    // `devices/device_keys` revocation FKs, `assert_device_revocation_mapping`
    // and the operation-claim mapping — so each case seeds the claim, receipt,
    // and `chat.device_revocations` parent first (the proven
    // `seed_revoked_device` shape, classifiable wrapper/transcript bytes),
    // then fabricates ONLY its own single-sided drift for the admission
    // assertion, and terminalizes the OTHER side of the device/key pair
    // afterwards so the forced constraints see the complete legal mapping.
    let seed_revocation_provenance = |tx_did: &'static str, tx_device: Uuid| {
        let pool = pool.clone();
        async move {
            let revocation_id = Uuid::new_v4();
            let mut tx = pool.begin().await.expect("begin revocation drift case");
            let accepted_at: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
                .fetch_one(&mut *tx)
                .await
                .expect("revocation instant");
            let (key_id, device_jkt): (String, String) = sqlx::query_as(
                "SELECT k.key_id, d.dpop_jkt FROM chat.device_keys k \
                 JOIN chat.devices d ON d.user_did = k.user_did AND d.device_id = k.device_id \
                 WHERE k.user_did = $1 AND k.device_id = $2",
            )
            .bind(tx_did)
            .bind(tx_device)
            .fetch_one(&mut *tx)
            .await
            .expect("the fixture device's key and jkt");
            let accepted_request_bytes =
                br#"{"body":{"$type":"blue.catbird.chat.defs#deviceRevocationBody"}}"#.to_vec();
            let mut signing_transcript_bytes = b"CATBIRD-CHAT-DEVICE-REVOKE\0".to_vec();
            signing_transcript_bytes.extend_from_slice(revocation_id.as_bytes());
            let request_digest: [u8; 32] = Sha256::digest(&signing_transcript_bytes).into();
            let accepted_request_sha256: [u8; 32] = Sha256::digest(&accepted_request_bytes).into();
            let signature = [7_u8; 64];
            let response = br#"{"revoked":true}"#;
            let response_sha256: [u8; 32] = Sha256::digest(response).into();
            sqlx::query(
                "INSERT INTO chat.operation_claims( \
                     operation_id, principal_did, endpoint_nsid, mutation_kind, \
                     request_digest, accepted_request_sha256, signature, claimed_at \
                 ) VALUES ($1,$2,'blue.catbird.chat.revokeDevice', \
                           'blue.catbird.chat.defs#deviceRevocationBody',$3,$4,$5,$6)",
            )
            .bind(revocation_id)
            .bind(tx_did)
            .bind(request_digest.as_slice())
            .bind(accepted_request_sha256.as_slice())
            .bind(signature.as_slice())
            .bind(accepted_at)
            .execute(&mut *tx)
            .await
            .expect("insert revokeDevice operation claim");
            sqlx::query(
                "INSERT INTO chat.idempotency_records( \
                     principal_did, endpoint_nsid, operation_id, request_digest, \
                     accepted_request_bytes, signing_transcript_bytes, signature, \
                     completed_status, response_bytes, response_sha256, \
                     historical_jkt, completed_at \
                 ) VALUES ($1,'blue.catbird.chat.revokeDevice',$2,$3,$4,$5,$6,200,$7,$8,$9,$10)",
            )
            .bind(tx_did)
            .bind(revocation_id)
            .bind(request_digest.as_slice())
            .bind(&accepted_request_bytes)
            .bind(&signing_transcript_bytes)
            .bind(signature.as_slice())
            .bind(response.as_slice())
            .bind(response_sha256.as_slice())
            .bind(&device_jkt)
            .bind(accepted_at)
            .execute(&mut *tx)
            .await
            .expect("insert revokeDevice receipt");
            sqlx::query(
                "INSERT INTO chat.device_revocations( \
                     revocation_id, actor_did, actor_device_id, actor_key_id, \
                     actor_auth_generation, target_did, target_device_id, \
                     target_auth_generation, accepted_request_bytes, \
                     signing_transcript_bytes, request_digest, signature, \
                     signed_at, accepted_at \
                 ) VALUES ($1,$2,$3,$4,1,$2,$3,1,$5,$6,$7,$8,$9,$9)",
            )
            .bind(revocation_id)
            .bind(tx_did)
            .bind(tx_device)
            .bind(&key_id)
            .bind(&accepted_request_bytes)
            .bind(&signing_transcript_bytes)
            .bind(request_digest.as_slice())
            .bind(signature.as_slice())
            .bind(accepted_at)
            .execute(&mut *tx)
            .await
            .expect("insert device revocation parent");
            (tx, revocation_id, accepted_at)
        }
    };

    // Case 1: device revocation after sealing. The admission's hidden binding
    // was captured against the active row; a revoked row fails closed.
    {
        let admission = real_read_admission(&pool, "blue.catbird.chat.getConversationState").await;
        let (mut tx, revocation_id, accepted_at) = seed_revocation_provenance(did, device_id).await;
        sqlx::query(
            "UPDATE chat.devices SET status='revoked', revoked_at=$3, updated_at=$3, \
             revocation_id=$4 WHERE user_did=$1 AND device_id=$2",
        )
        .bind(did)
        .bind(device_id)
        .bind(accepted_at)
        .bind(revocation_id)
        .execute(&mut *tx)
        .await
        .expect("revocation is a legal device lifecycle transition");
        let outcome = chat_protocol::read_authority_bridge::single_attempt_lock_in(
            &mut tx,
            admission,
            chat_protocol::read_authority_bridge::OrdinaryReadEndpoint::GetConversationState,
        )
        .await;
        assert!(
            matches!(
                outcome,
                Err(chat_protocol::read_authority::ReadAuthorityError::DeviceRevoked)
            ),
            "a revoked device registration fails closed after admission"
        );
        // Complete the legal mapping (the key side) before forcing constraints.
        sqlx::query(
            "UPDATE chat.device_keys SET revoked_at=$3, revocation_id=$4 \
             WHERE user_did=$1 AND device_id=$2",
        )
        .bind(did)
        .bind(device_id)
        .bind(accepted_at)
        .bind(revocation_id)
        .execute(&mut *tx)
        .await
        .expect("terminalize the device key for the forced mapping");
        rollback_with_constraints(tx).await;
    }

    // Case 2: key revocation after sealing. The KEY drift is fabricated first
    // and the admission asserted against it (the exact key-revocation arm);
    // the device side is terminalized only afterwards, for the forced mapping.
    {
        let admission = real_read_admission(&pool, "blue.catbird.chat.getConversationState").await;
        let (mut tx, revocation_id, accepted_at) = seed_revocation_provenance(did, device_id).await;
        sqlx::query(
            "UPDATE chat.device_keys SET revoked_at=$3, revocation_id=$4 \
             WHERE user_did=$1 AND device_id=$2",
        )
        .bind(did)
        .bind(device_id)
        .bind(accepted_at)
        .bind(revocation_id)
        .execute(&mut *tx)
        .await
        .expect("key revocation is a legal device-key lifecycle transition");
        let outcome = chat_protocol::read_authority_bridge::single_attempt_lock_in(
            &mut tx,
            admission,
            chat_protocol::read_authority_bridge::OrdinaryReadEndpoint::GetConversationState,
        )
        .await;
        assert!(
            matches!(
                outcome,
                Err(chat_protocol::read_authority::ReadAuthorityError::DeviceRevoked)
            ),
            "a revoked signing key fails closed after admission"
        );
        // Complete the legal mapping (the device side) before forcing
        // constraints.
        sqlx::query(
            "UPDATE chat.devices SET status='revoked', revoked_at=$3, updated_at=$3, \
             revocation_id=$4 WHERE user_did=$1 AND device_id=$2",
        )
        .bind(did)
        .bind(device_id)
        .bind(accepted_at)
        .bind(revocation_id)
        .execute(&mut *tx)
        .await
        .expect("terminalize the device for the forced mapping");
        rollback_with_constraints(tx).await;
    }

    // Case 3: JKT + generation drift after sealing, staged as the only legal
    // identity-change shape (rebind: jkt change with generation +1). The
    // hidden binding still names the sealed jkt/generation, so the locked row
    // drifts and fails before any protected read.
    {
        let admission = real_read_admission(&pool, "blue.catbird.chat.getConversationState").await;
        let mut tx = pool.begin().await.expect("begin revocation drift case");
        sqlx::query(
            "UPDATE chat.devices SET dpop_jkt=$3, auth_generation=2, \
             updated_at=clock_timestamp() WHERE user_did=$1 AND device_id=$2",
        )
        .bind(did)
        .bind(device_id)
        .bind(alternate_jkt)
        .execute(&mut *tx)
        .await
        .expect("the rebind shape is the only legal identity-change transition");
        let outcome = chat_protocol::read_authority_bridge::single_attempt_lock_in(
            &mut tx,
            admission,
            chat_protocol::read_authority_bridge::OrdinaryReadEndpoint::GetConversationState,
        )
        .await;
        assert!(
            matches!(
                outcome,
                Err(chat_protocol::read_authority::ReadAuthorityError::Invariant)
            ),
            "post-seal JKT/generation drift fails closed before any protected read"
        );
        rollback_with_constraints(tx).await;
    }

    pool.close().await;
    drop(guard);
    assert_executor_db_absent(&maintenance_url, &db_name).await;
}

#[tokio::test]
#[ignore = "requires the dedicated gate database seeded with the B-read fixture corpus"]
async fn group_pending_gets_state_and_direct_pending_is_not_entitled() {
    let fixture = executor_seed::private_genuine_group_pending_graph().await;
    let pool = fixture.pool.clone();
    let conversation_id = fixture.graph.conversation_id;

    // The creator keeps its open leaf: state authority with the open-leaf arm.
    let creator_admission = fixture_read_admission(
        &pool,
        "blue.catbird.chat.getConversationState",
        &fixture.graph.creator_did,
        fixture.graph.creator_device_id,
        &fixture.graph.creator_dpop_jkt,
    )
    .await;
    let (creator_guard, mut tx) = chat_protocol::read_authority_bridge::lock_single_attempt(
        &pool,
        creator_admission,
        chat_protocol::read_authority_bridge::OrdinaryReadEndpoint::GetConversationState,
    )
    .await
    .expect("creator single-attempt lock");
    let creator_state = chat_protocol::read_authority::authorize_conversation_state(
        &mut tx,
        creator_guard,
        conversation_id,
    )
    .await
    .expect("the creator's current open leaf authorizes state");
    let creator_view = chat_protocol::read_authority_bridge::state_authority_view(&creator_state);
    assert!(
        matches!(
            creator_view.relationship.arm,
            chat_protocol::read_authority_bridge::RelationshipArmView::OpenLeaf
        ),
        "the creator carries the current open-leaf witness"
    );
    assert_ne!(
        creator_view.graph_digest, [0_u8; 32],
        "the sealed aggregate carries a nonzero graph digest"
    );
    assert_ne!(
        creator_view.snapshot_digest, [0_u8; 32],
        "the sealed aggregate carries a nonzero snapshot digest"
    );
    rollback_with_constraints(tx).await;

    // The group-pending invitee authorizes current state only, with the
    // group-pending witness.
    let invitee_admission = fixture_read_admission(
        &pool,
        "blue.catbird.chat.getConversationState",
        &fixture.invitee.did,
        fixture.invitee.device_id,
        &fixture.invitee.dpop_jkt,
    )
    .await;
    let (invitee_guard, mut tx) = chat_protocol::read_authority_bridge::lock_single_attempt(
        &pool,
        invitee_admission,
        chat_protocol::read_authority_bridge::OrdinaryReadEndpoint::GetConversationState,
    )
    .await
    .expect("invitee single-attempt lock");
    let invitee_state = chat_protocol::read_authority::authorize_conversation_state(
        &mut tx,
        invitee_guard,
        conversation_id,
    )
    .await
    .expect("a group-pending participant authorizes current state");
    let invitee_view = chat_protocol::read_authority_bridge::state_authority_view(&invitee_state);
    assert!(
        matches!(
            invitee_view.relationship.arm,
            chat_protocol::read_authority_bridge::RelationshipArmView::GroupPendingParticipant
        ),
        "the group-pending invitee carries the group-pending witness"
    );
    assert_eq!(
        invitee_view.relationship.participant_period_id, fixture.invitee.participant_period_id,
        "the witness binds the durable participant period"
    );
    rollback_with_constraints(tx).await;
    // Entries require a current open leaf: the group-pending invitee is
    // denied application entries.
    let entry_outcome = {
        let admission = fixture_read_admission(
            &pool,
            "blue.catbird.chat.getEntries",
            &fixture.invitee.did,
            fixture.invitee.device_id,
            &fixture.invitee.dpop_jkt,
        )
        .await;
        let (guard, mut tx) = chat_protocol::read_authority_bridge::lock_single_attempt(
            &pool,
            admission,
            chat_protocol::read_authority_bridge::OrdinaryReadEndpoint::GetEntries,
        )
        .await
        .expect("invitee entry single-attempt lock");
        let outcome =
            chat_protocol::read_authority::authorize_entries(&mut tx, guard, conversation_id)
                .await
                .err()
                .expect("a group-pending participant has no entry authority");
        rollback_with_constraints(tx).await;
        outcome
    };
    assert_eq!(
        entry_outcome,
        chat_protocol::read_authority::ReadAuthorityError::NotEntitled,
        "group-pending authorizes state only, never application entries"
    );

    // A direct-pending invitee is NotEntitled to current state.
    let direct = executor_seed::private_genuine_direct_pending_graph().await;
    let direct_pool = direct.pool.clone();
    let direct_admission = fixture_read_admission(
        &direct_pool,
        "blue.catbird.chat.getConversationState",
        &direct.invitee.did,
        direct.invitee.device_id,
        &direct.invitee.dpop_jkt,
    )
    .await;
    let (direct_guard, mut tx) = chat_protocol::read_authority_bridge::lock_single_attempt(
        &direct_pool,
        direct_admission,
        chat_protocol::read_authority_bridge::OrdinaryReadEndpoint::GetConversationState,
    )
    .await
    .expect("direct invitee single-attempt lock");
    let direct_outcome = chat_protocol::read_authority::authorize_conversation_state(
        &mut tx,
        direct_guard,
        direct.graph.conversation_id,
    )
    .await
    .err()
    .expect("a direct-pending invitee is not entitled to state");
    assert_eq!(
        direct_outcome,
        chat_protocol::read_authority::ReadAuthorityError::NotEntitled,
        "direct-pending remains NotEntitled"
    );
    rollback_with_constraints(tx).await;
}

#[tokio::test]
#[ignore = "requires the dedicated gate database seeded with the B-read fixture corpus"]
async fn former_exact_device_gets_access_outside_membership_interval() {
    let fixture = executor_seed::private_genuine_removal_graph().await;
    let pool = fixture.pool.clone();
    let conversation_id = fixture.graph.conversation_id;
    let removed = &fixture.removed;

    let admission = fixture_read_admission(
        &pool,
        "blue.catbird.chat.getConversationState",
        &removed.did,
        removed.device_id,
        &removed.dpop_jkt,
    )
    .await;
    let (guard, mut tx) = chat_protocol::read_authority_bridge::lock_single_attempt(
        &pool,
        admission,
        chat_protocol::read_authority_bridge::OrdinaryReadEndpoint::GetConversationState,
    )
    .await
    .expect("single-attempt lock");
    let state_outcome = chat_protocol::read_authority::authorize_conversation_state(
        &mut tx,
        guard,
        conversation_id,
    )
    .await
    .err()
    .expect("the removed exact device has no current-state capability");
    assert_eq!(
        state_outcome,
        chat_protocol::read_authority::ReadAuthorityError::AccessOutsideMembershipInterval,
        "a removed exact leaf with a finite interval receives the outside-interval error"
    );
    rollback_with_constraints(tx).await;

    let admission = fixture_read_admission(
        &pool,
        "blue.catbird.chat.getEntries",
        &removed.did,
        removed.device_id,
        &removed.dpop_jkt,
    )
    .await;
    let (guard, mut tx) = chat_protocol::read_authority_bridge::lock_single_attempt(
        &pool,
        admission,
        chat_protocol::read_authority_bridge::OrdinaryReadEndpoint::GetEntries,
    )
    .await
    .expect("single-attempt lock");
    let entry_outcome =
        chat_protocol::read_authority::authorize_entries(&mut tx, guard, conversation_id)
            .await
            .err()
            .expect("a former exact device has no entry authority");
    assert_eq!(
        entry_outcome,
        chat_protocol::read_authority::ReadAuthorityError::AccessOutsideMembershipInterval,
        "the former-device interval denial is the outside-interval error, and G7 \
         never synthesizes current state from historical rows"
    );
    rollback_with_constraints(tx).await;
}

#[tokio::test]
#[ignore = "requires the dedicated gate database seeded with the B-read fixture corpus"]
async fn post_reset_old_exact_device_cannot_inherit_current_did_state() {
    let fixture = executor_seed::private_genuine_reset_graph().await;
    let pool = fixture.pool.clone();
    let conversation_id = fixture.graph.conversation_id;
    let old = &fixture.old;

    // BREAD-05 shape proof: the old exact device's DID is still a current
    // participant, and the old exact device has no current leaf — the exact
    // DID-level current-state inheritance trap the classification must refuse.
    let current_participant: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM chat.participants \
         WHERE conversation_id=$1 AND user_did=$2 AND current_membership",
    )
    .bind(conversation_id)
    .bind(&old.did)
    .fetch_one(&pool)
    .await
    .expect("count the old DID's current participant rows");
    assert_eq!(
        current_participant, 1,
        "the reset-retired DID remains a current participant (the BREAD-05 shape)"
    );
    let old_leaf: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM chat.member_devices \
         WHERE conversation_id=$1 AND user_did=$2 AND device_id=$3 AND active",
    )
    .bind(conversation_id)
    .bind(&old.did)
    .bind(old.device_id)
    .fetch_one(&pool)
    .await
    .expect("count the old exact device's active leaves");
    assert_eq!(old_leaf, 0, "the old exact device has no current leaf");

    let admission = fixture_read_admission(
        &pool,
        "blue.catbird.chat.getConversationState",
        &old.did,
        old.device_id,
        &old.dpop_jkt,
    )
    .await;
    let (guard, mut tx) = chat_protocol::read_authority_bridge::lock_single_attempt(
        &pool,
        admission,
        chat_protocol::read_authority_bridge::OrdinaryReadEndpoint::GetConversationState,
    )
    .await
    .expect("single-attempt lock");
    let state_outcome = chat_protocol::read_authority::authorize_conversation_state(
        &mut tx,
        guard,
        conversation_id,
    )
    .await
    .err()
    .expect("the post-reset old exact device must not inherit the DID's current state");
    assert_eq!(
        state_outcome,
        chat_protocol::read_authority::ReadAuthorityError::AccessOutsideMembershipInterval,
        "BREAD-05: the exact device's finite reset interval is classified before \
         the DID-only zero-leaf participant arm"
    );
    rollback_with_constraints(tx).await;
}

#[tokio::test]
#[ignore = "requires the dedicated gate database seeded with the B-read fixture corpus"]
async fn unrelated_terminal_requester_is_not_entitled() {
    let fixture = executor_seed::private_genuine_terminal_close_graph().await;
    let pool = fixture.pool.clone();
    let conversation_id = fixture.graph.conversation_id;

    let unrelated_did = b_read_fresh_did(0x0B);
    let unrelated_device = Uuid::new_v4();
    let unrelated_jkt = register_read_device(&pool, &unrelated_did, unrelated_device).await;

    let admission = fixture_read_admission(
        &pool,
        "blue.catbird.chat.getConversationState",
        &unrelated_did,
        unrelated_device,
        &unrelated_jkt,
    )
    .await;
    let (guard, mut tx) = chat_protocol::read_authority_bridge::lock_single_attempt(
        &pool,
        admission,
        chat_protocol::read_authority_bridge::OrdinaryReadEndpoint::GetConversationState,
    )
    .await
    .expect("single-attempt lock");
    let outcome = chat_protocol::read_authority::authorize_conversation_state(
        &mut tx,
        guard,
        conversation_id,
    )
    .await
    .err()
    .expect("an unrelated requester is not entitled to a terminal conversation");
    assert_eq!(
        outcome,
        chat_protocol::read_authority::ReadAuthorityError::NotEntitled,
        "BREAD-04: an unrelated terminal requester receives NotEntitled, never \
         AccessOutsideMembershipInterval"
    );
    rollback_with_constraints(tx).await;
}

#[tokio::test]
#[ignore = "requires the dedicated gate database seeded with the B-read fixture corpus"]
async fn terminal_proof_holder_gets_access_outside_membership_interval() {
    let fixture = executor_seed::private_genuine_terminal_close_graph().await;
    let pool = fixture.pool.clone();
    let conversation_id = fixture.graph.conversation_id;

    let admission = fixture_read_admission(
        &pool,
        "blue.catbird.chat.getConversationState",
        &fixture.graph.creator_did,
        fixture.graph.creator_device_id,
        &fixture.graph.creator_dpop_jkt,
    )
    .await;
    let (guard, mut tx) = chat_protocol::read_authority_bridge::lock_single_attempt(
        &pool,
        admission,
        chat_protocol::read_authority_bridge::OrdinaryReadEndpoint::GetConversationState,
    )
    .await
    .expect("single-attempt lock");
    let outcome = chat_protocol::read_authority::authorize_conversation_state(
        &mut tx,
        guard,
        conversation_id,
    )
    .await
    .err()
    .expect("an exact terminal schedule-proof holder has no current-state capability");
    assert_eq!(
        outcome,
        chat_protocol::read_authority::ReadAuthorityError::AccessOutsideMembershipInterval,
        "the exact schedule-proof holder receives AccessOutsideMembershipInterval"
    );
    rollback_with_constraints(tx).await;
}

#[tokio::test]
#[ignore = "requires the dedicated gate database seeded with the B-read fixture corpus"]
async fn entry_intervals_are_ordered_nonoverlapping_open_last_and_inclusive() {
    let fixture = executor_seed::private_genuine_removal_graph().await;
    let pool = fixture.pool.clone();
    let conversation_id = fixture.graph.conversation_id;
    let removed = &fixture.removed;

    // A removed exact device is a FORMER leaf, so the entry capability is
    // denied outright -- `authorize_entries` gates on a current open leaf.
    // This is the frozen B-read rule and it matches
    // `former_exact_device_gets_access_outside_membership_interval`, which
    // asserts the same denial on this same fixture and device. The interval
    // ordering / non-overlap / inclusive-terminal properties this test is named
    // for are exercised against the creator below and, at the validator itself,
    // by `interval_witness_boundary_tests`.
    let admission = fixture_read_admission(
        &pool,
        "blue.catbird.chat.getEntries",
        &removed.did,
        removed.device_id,
        &removed.dpop_jkt,
    )
    .await;
    let (guard, mut tx) = chat_protocol::read_authority_bridge::lock_single_attempt(
        &pool,
        admission,
        chat_protocol::read_authority_bridge::OrdinaryReadEndpoint::GetEntries,
    )
    .await
    .expect("single-attempt lock");
    let removed_outcome =
        chat_protocol::read_authority::authorize_entries(&mut tx, guard, conversation_id)
            .await
            .err()
            .expect("a removed exact device holds no entry authority");
    assert_eq!(
        removed_outcome,
        chat_protocol::read_authority::ReadAuthorityError::AccessOutsideMembershipInterval,
        "the former-device denial is the outside-interval error, never an interval union"
    );
    rollback_with_constraints(tx).await;

    // The creator's open interval is the last (only) interval and observes the
    // head.
    let creator_admission = fixture_read_admission(
        &pool,
        "blue.catbird.chat.getEntries",
        &fixture.graph.creator_did,
        fixture.graph.creator_device_id,
        &fixture.graph.creator_dpop_jkt,
    )
    .await;
    let (creator_guard, mut tx) = chat_protocol::read_authority_bridge::lock_single_attempt(
        &pool,
        creator_admission,
        chat_protocol::read_authority_bridge::OrdinaryReadEndpoint::GetEntries,
    )
    .await
    .expect("creator entry single-attempt lock");
    let creator_entries =
        chat_protocol::read_authority::authorize_entries(&mut tx, creator_guard, conversation_id)
            .await
            .expect("the creator's current open leaf authorizes entries");
    let creator_view = chat_protocol::read_authority_bridge::entry_authority_view(&creator_entries);
    assert_eq!(
        creator_view.ordered_intervals.len(),
        1,
        "the creator has exactly one open interval"
    );
    match &creator_view.ordered_intervals[0].terminal {
        chat_protocol::read_authority_bridge::IntervalTerminalView::Open {
            observed_head_seq,
            row_sha256,
        } => {
            assert!(
                *observed_head_seq >= creator_view.ordered_intervals[0].start_seq,
                "the observed head sequence covers the open interval's start"
            );
            assert_ne!(
                *row_sha256, [0_u8; 32],
                "the open row binding digest is nonzero"
            );
        }
        other => panic!("the creator interval must be open, found {other:?}"),
    }
    rollback_with_constraints(tx).await;

    // Source pins: the loader orders by (start_seq, membership_interval_id)
    // and the validator rejects overlaps and open-not-last intervals.
    assert!(
        B_READ_READ_AUTHORITY_SOURCE.contains("ORDER BY ai.start_seq, ai.membership_interval_id"),
        "the interval loader is deterministic in (start_seq, membership_interval_id) order"
    );
    // Re-pinned by Lane E finding 5a. The predicate was `start_seq <=
    // previous_terminal`, which also rejected the touching boundary that
    // `chat.assert_application_interval_schedule` MANDATES for replace->add and
    // reset->reset. Overlap is now strict, and the touch is admitted only for
    // the trigger's two legal kind pairs.
    assert!(
        B_READ_READ_AUTHORITY_SOURCE.contains("if start_seq < *terminal_seq"),
        "the validator rejects genuinely overlapping intervals"
    );
    assert!(
        B_READ_READ_AUTHORITY_SOURCE.contains(r#"("replace", "add") | ("reset", "reset")"#),
        "a touching boundary is admitted only for the schedule trigger's two legal kind pairs"
    );
    assert!(
        B_READ_READ_AUTHORITY_SOURCE.contains("An open interval must be last"),
        "the validator rejects an open interval that is not last"
    );
}

#[tokio::test]
#[ignore = "requires the dedicated gate database seeded with the B-read fixture corpus"]
async fn entry_intervals_preserve_readd_gaps_and_generation_boundaries() {
    let fixture = executor_seed::private_genuine_reset_graph().await;
    let pool = fixture.pool.clone();
    let conversation_id = fixture.graph.conversation_id;
    let old = &fixture.old;

    // Generation-bound proof: the old exact device's interval lives in the
    // superseded generation while the conversation is current at generation 1.
    let interval_generation: i64 = sqlx::query_scalar(
        "SELECT generation FROM chat.application_intervals WHERE membership_interval_id=$1",
    )
    .bind(old.membership_interval_id)
    .fetch_one(&pool)
    .await
    .expect("read the old interval's generation");
    assert_eq!(
        u64::try_from(interval_generation).expect("generation fits u64"),
        old.old_generation,
        "the retired interval is generation-bound to the old generation"
    );
    let current_generation: i64 = sqlx::query_scalar(
        "SELECT current_generation FROM chat.conversations WHERE conversation_id=$1",
    )
    .bind(conversation_id)
    .fetch_one(&pool)
    .await
    .expect("read the conversation's current generation");
    assert_eq!(current_generation, 1, "the reset successor is current");

    let admission = fixture_read_admission(
        &pool,
        "blue.catbird.chat.getEntries",
        &old.did,
        old.device_id,
        &old.dpop_jkt,
    )
    .await;
    let (guard, mut tx) = chat_protocol::read_authority_bridge::lock_single_attempt(
        &pool,
        admission,
        chat_protocol::read_authority_bridge::OrdinaryReadEndpoint::GetEntries,
    )
    .await
    .expect("single-attempt lock");
    // The post-reset OLD device is a former leaf: denied, not unioned. Its
    // generation binding is proved above, directly against the durable rows.
    let old_outcome =
        chat_protocol::read_authority::authorize_entries(&mut tx, guard, conversation_id)
            .await
            .err()
            .expect("the post-reset old exact device holds no entry authority");
    assert_eq!(
        old_outcome,
        chat_protocol::read_authority::ReadAuthorityError::AccessOutsideMembershipInterval,
        "the retired-generation denial is the outside-interval error"
    );
    rollback_with_constraints(tx).await;

    // The reset ACTIVATOR is the device whose intervals actually touch: its
    // retired interval closes `reset` at the activation sequence and its
    // successor opens `reset` at the SAME sequence, which
    // `chat.assert_application_interval_schedule` mandates. Reading as the
    // activator is the production-path regression lock for Lane E finding 5a --
    // before that fix this returned Invariant.
    let activator_admission = fixture_read_admission(
        &pool,
        "blue.catbird.chat.getEntries",
        &fixture.graph.creator_did,
        fixture.graph.creator_device_id,
        &fixture.graph.creator_dpop_jkt,
    )
    .await;
    let (activator_guard, mut tx) = chat_protocol::read_authority_bridge::lock_single_attempt(
        &pool,
        activator_admission,
        chat_protocol::read_authority_bridge::OrdinaryReadEndpoint::GetEntries,
    )
    .await
    .expect("activator entry single-attempt lock");
    let activator_entries =
        chat_protocol::read_authority::authorize_entries(&mut tx, activator_guard, conversation_id)
            .await
            .expect("the activator's mandated touching boundary is not an overlap");
    let activator_view =
        chat_protocol::read_authority_bridge::entry_authority_view(&activator_entries);
    assert!(
        matches!(
            activator_view
                .ordered_intervals
                .last()
                .expect("the activator holds at least one interval")
                .terminal,
            chat_protocol::read_authority_bridge::IntervalTerminalView::Open { .. }
        ),
        "the activator's current interval is open and last"
    );
    rollback_with_constraints(tx).await;
}

#[tokio::test]
#[ignore = "requires the dedicated gate database seeded with the B-read fixture corpus"]
async fn entry_authority_rejects_wrong_device_conversation_and_transaction() {
    let (pool, guard, graph) = private_genuine_graph().await;
    let maintenance_url = guard.maintenance_url.clone();
    let db_name = guard.db_name.clone();
    assert_private_executor_db_name(&db_name);
    let conversation_id = graph.conversation_id;

    // Wrong conversation: the conversation does not exist.
    {
        let admission = fixture_read_admission(
            &pool,
            "blue.catbird.chat.getEntries",
            &graph.creator_did,
            graph.creator_device_id,
            &graph.creator_dpop_jkt,
        )
        .await;
        let (device, mut tx) = chat_protocol::read_authority_bridge::lock_single_attempt(
            &pool,
            admission,
            chat_protocol::read_authority_bridge::OrdinaryReadEndpoint::GetEntries,
        )
        .await
        .expect("single-attempt lock");
        let outcome =
            chat_protocol::read_authority::authorize_entries(&mut tx, device, Uuid::new_v4())
                .await
                .err()
                .expect("a nonexistent conversation cannot authorize entries");
        assert_eq!(
            outcome,
            chat_protocol::read_authority::ReadAuthorityError::ConversationNotFound,
            "conversation absence remains ConversationNotFound"
        );
        rollback_with_constraints(tx).await;
    }

    // Wrong device: a registered but entirely unrelated device.
    {
        let unrelated_did = b_read_fresh_did(0x0C);
        let unrelated_device = Uuid::new_v4();
        let unrelated_jkt = register_read_device(&pool, &unrelated_did, unrelated_device).await;
        let admission = fixture_read_admission(
            &pool,
            "blue.catbird.chat.getEntries",
            &unrelated_did,
            unrelated_device,
            &unrelated_jkt,
        )
        .await;
        let (device, mut tx) = chat_protocol::read_authority_bridge::lock_single_attempt(
            &pool,
            admission,
            chat_protocol::read_authority_bridge::OrdinaryReadEndpoint::GetEntries,
        )
        .await
        .expect("single-attempt lock");
        let outcome =
            chat_protocol::read_authority::authorize_entries(&mut tx, device, conversation_id)
                .await
                .err()
                .expect("an unrelated device cannot authorize entries");
        assert_eq!(
            outcome,
            chat_protocol::read_authority::ReadAuthorityError::NotEntitled,
            "the unrelated requester receives NotEntitled"
        );
        rollback_with_constraints(tx).await;
    }

    // Wrong transaction: the guard was minted under transaction A and is
    // refused under transaction B before any protected lookup.
    {
        let admission = fixture_read_admission(
            &pool,
            "blue.catbird.chat.getEntries",
            &graph.creator_did,
            graph.creator_device_id,
            &graph.creator_dpop_jkt,
        )
        .await;
        let (device, mut tx_a) = chat_protocol::read_authority_bridge::lock_single_attempt(
            &pool,
            admission,
            chat_protocol::read_authority_bridge::OrdinaryReadEndpoint::GetEntries,
        )
        .await
        .expect("single-attempt lock under transaction A");
        rollback_with_constraints(tx_a).await;

        let mut tx_b = pool.begin().await.expect("begin foreign transaction");
        let outcome =
            chat_protocol::read_authority::authorize_entries(&mut tx_b, device, conversation_id)
                .await
                .err()
                .expect("the guard is terminal under a foreign transaction");
        assert_eq!(
            outcome,
            chat_protocol::read_authority::ReadAuthorityError::Invariant,
            "a guard minted under transaction A fails under transaction B before \
             a protected lookup"
        );
        rollback_with_constraints(tx_b).await;
    }

    pool.close().await;
    drop(guard);
    assert_executor_db_absent(&maintenance_url, &db_name).await;
}

/// Run one inventory scenario: seed the retention fence, mint the admission,
/// lock the device, build the exact fence record, and collect the authorities.
async fn inventory_run_for_fixture(
    pool: &PgPool,
    protocol_instance_id: Uuid,
    admission: chat_protocol::dpop::VerifiedReadAdmission,
) -> chat_protocol::read_authority_bridge::InventoryRunOutcome {
    seed_private_retention_fence(pool, protocol_instance_id).await;
    let cursor_key = fixture_cursor_key(pool, protocol_instance_id).await;
    chat_protocol::read_authority_bridge::inventory_run(
        pool,
        admission,
        protocol_instance_id,
        cursor_key,
        0,
        [0x11_u8; 32],
        0,
        Utc::now(),
    )
    .await
    .expect("the inventory run completes against the genuine fixture")
}

#[tokio::test]
#[ignore = "requires the dedicated gate database seeded with the B-read fixture corpus"]
async fn inventory_precedence_is_close_open_finite_participant_none() {
    // Close arm: terminal conversation plus exact schedule proof.
    let close_fixture = executor_seed::private_genuine_terminal_close_graph().await;
    let close_pool = close_fixture.pool.clone();
    let close_admission = fixture_read_admission(
        &close_pool,
        "blue.catbird.chat.getConversations",
        &close_fixture.graph.creator_did,
        close_fixture.graph.creator_device_id,
        &close_fixture.graph.creator_dpop_jkt,
    )
    .await;
    let close_run = inventory_run_for_fixture(
        &close_pool,
        close_fixture.graph.protocol_instance_id,
        close_admission,
    )
    .await;
    assert_eq!(
        close_run.authorities.len(),
        1,
        "the proof holder sees exactly its own terminal conversation"
    );
    let close_view = &close_run.authorities[0];
    assert_eq!(
        close_view.conversation_id,
        close_fixture.graph.conversation_id
    );
    match &close_view.arm {
        chat_protocol::read_authority_bridge::InventoryArmView::Close {
            terminal_seq,
            closing_transition_id,
            closing_outer_entry_fingerprint,
        } => {
            assert_eq!(*terminal_seq, close_fixture.terminal_seq);
            assert_eq!(
                *closing_transition_id, close_fixture.close_transition_id,
                "the close arm binds the exact closing transition"
            );
            assert_eq!(
                closing_outer_entry_fingerprint.as_slice(),
                close_fixture.closing_outer_entry_fingerprint.as_slice(),
                "the close arm binds the exact closing outer-entry fingerprint"
            );
        }
        other => panic!("the terminal proof holder must select the close arm, found {other:?}"),
    }
    assert_eq!(
        close_view.snapshot_digest, [0_u8; 32],
        "close tombstones carry no snapshot digest"
    );

    // Open arm: active conversation plus exact open membership interval.
    let (open_pool, _open_guard, open_graph) = private_genuine_graph().await;
    let open_admission = fixture_read_admission(
        &open_pool,
        "blue.catbird.chat.getConversations",
        &open_graph.creator_did,
        open_graph.creator_device_id,
        &open_graph.creator_dpop_jkt,
    )
    .await;
    let open_run =
        inventory_run_for_fixture(&open_pool, open_graph.protocol_instance_id, open_admission)
            .await;
    assert_eq!(
        open_run.authorities.len(),
        1,
        "the open-leaf requester sees its conversation"
    );
    let open_view = &open_run.authorities[0];
    assert_eq!(open_view.conversation_id, open_graph.conversation_id);
    match &open_view.arm {
        chat_protocol::read_authority_bridge::InventoryArmView::State {
            participant_period_id,
        } => {
            assert_ne!(
                *participant_period_id,
                Uuid::nil(),
                "the state arm binds the participant period"
            );
        }
        other => panic!("the exact open interval must select the state arm, found {other:?}"),
    }
    assert_eq!(open_view.txid, open_run.device_txid);
    assert_eq!(open_view.device_binding_sha256, open_run.device_binding);
    assert_eq!(
        open_view.fence.protocol_instance_id,
        open_graph.protocol_instance_id
    );
    assert_ne!(open_view.graph_digest, [0_u8; 32]);
    assert_ne!(open_view.snapshot_digest, [0_u8; 32]);

    // Finite arm: active conversation plus latest exact finite interval.
    let removal_fixture = executor_seed::private_genuine_removal_graph().await;
    let removal_pool = removal_fixture.pool.clone();
    let removal_admission = fixture_read_admission(
        &removal_pool,
        "blue.catbird.chat.getConversations",
        &removal_fixture.removed.did,
        removal_fixture.removed.device_id,
        &removal_fixture.removed.dpop_jkt,
    )
    .await;
    let removal_run = inventory_run_for_fixture(
        &removal_pool,
        removal_fixture.graph.protocol_instance_id,
        removal_admission,
    )
    .await;
    assert_eq!(
        removal_run.authorities.len(),
        1,
        "the removed device sees its conversation"
    );
    let removal_view = &removal_run.authorities[0];
    match &removal_view.arm {
        chat_protocol::read_authority_bridge::InventoryArmView::Removal {
            membership_interval_id,
            terminal_seq,
            closing_transition_id,
            closing_outer_entry_fingerprint,
            removed_at,
        } => {
            assert_eq!(
                *membership_interval_id,
                removal_fixture.removed.membership_interval_id
            );
            assert_eq!(*terminal_seq, removal_fixture.removed.terminal_seq);
            assert_eq!(
                *closing_transition_id,
                removal_fixture.removed.terminal_transition_id
            );
            assert_eq!(
                closing_outer_entry_fingerprint.as_slice(),
                removal_fixture
                    .removed
                    .terminal_outer_entry_fingerprint
                    .as_slice()
            );
            assert_eq!(
                *removed_at, removal_fixture.removed.removed_at,
                "the removal arm binds the durable removed-at instant"
            );
        }
        other => panic!("the finite exact interval must select the removal arm, found {other:?}"),
    }
    // The removal graph's creator (same corpus DID) also sees a state arm in
    // the same database.
    let creator_admission = fixture_read_admission(
        &removal_pool,
        "blue.catbird.chat.getConversations",
        &removal_fixture.graph.creator_did,
        removal_fixture.graph.creator_device_id,
        &removal_fixture.graph.creator_dpop_jkt,
    )
    .await;
    let creator_run = inventory_run_for_fixture(
        &removal_pool,
        removal_fixture.graph.protocol_instance_id,
        creator_admission,
    )
    .await;
    assert_eq!(creator_run.authorities.len(), 1);
    assert!(
        matches!(
            creator_run.authorities[0].arm,
            chat_protocol::read_authority_bridge::InventoryArmView::State { .. }
        ),
        "the removal graph's creator keeps its open-interval state arm"
    );

    // Participant arm: an eligible current participant with no exact-device
    // interval (a sibling device of the reset-retired DID).
    let reset_fixture = executor_seed::private_genuine_reset_graph().await;
    let reset_pool = reset_fixture.pool.clone();
    let sibling_device = Uuid::new_v4();
    let sibling_jkt =
        register_read_device(&reset_pool, &reset_fixture.old.did, sibling_device).await;
    let sibling_admission = fixture_read_admission(
        &reset_pool,
        "blue.catbird.chat.getConversations",
        &reset_fixture.old.did,
        sibling_device,
        &sibling_jkt,
    )
    .await;
    let sibling_run = inventory_run_for_fixture(
        &reset_pool,
        reset_fixture.graph.protocol_instance_id,
        sibling_admission,
    )
    .await;
    assert_eq!(
        sibling_run.authorities.len(),
        1,
        "the sibling sees the reset conversation once"
    );
    assert!(
        matches!(
            sibling_run.authorities[0].arm,
            chat_protocol::read_authority_bridge::InventoryArmView::State { .. }
        ),
        "a sibling with no former exact interval uses the DID-level participant arm"
    );
    // The old exact device in the same database selects the removal arm — the
    // finite interval beats the DID-level participant arm.
    let old_admission = fixture_read_admission(
        &reset_pool,
        "blue.catbird.chat.getConversations",
        &reset_fixture.old.did,
        reset_fixture.old.device_id,
        &reset_fixture.old.dpop_jkt,
    )
    .await;
    let old_run = inventory_run_for_fixture(
        &reset_pool,
        reset_fixture.graph.protocol_instance_id,
        old_admission,
    )
    .await;
    assert_eq!(old_run.authorities.len(), 1);
    assert!(
        matches!(
            old_run.authorities[0].arm,
            chat_protocol::read_authority_bridge::InventoryArmView::Removal { .. }
        ),
        "the reset-closed exact device selects the removal arm, not state"
    );

    // None arm: the direct-pending invitee is a candidate but yields no item.
    let direct_fixture = executor_seed::private_genuine_direct_pending_graph().await;
    let direct_pool = direct_fixture.pool.clone();
    let direct_candidate: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM chat.participants WHERE conversation_id=$1 AND user_did=$2",
    )
    .bind(direct_fixture.graph.conversation_id)
    .bind(&direct_fixture.invitee.did)
    .fetch_one(&direct_pool)
    .await
    .expect("count the direct-pending candidate rows");
    assert_eq!(
        direct_candidate, 1,
        "the direct-pending invitee IS a candidate (arm precedence excludes it, \
         not candidate discovery)"
    );
    let direct_admission = fixture_read_admission(
        &direct_pool,
        "blue.catbird.chat.getConversations",
        &direct_fixture.invitee.did,
        direct_fixture.invitee.device_id,
        &direct_fixture.invitee.dpop_jkt,
    )
    .await;
    let direct_run = inventory_run_for_fixture(
        &direct_pool,
        direct_fixture.graph.protocol_instance_id,
        direct_admission,
    )
    .await;
    assert_eq!(
        direct_run.authorities.len(),
        0,
        "direct-pending selects no inventory item"
    );

    // None: an unrelated requester is not even a candidate.
    let (unrelated_pool, _unrelated_guard, unrelated_graph) = private_genuine_graph().await;
    let unrelated_did = b_read_fresh_did(0x0D);
    let unrelated_device = Uuid::new_v4();
    let unrelated_jkt =
        register_read_device(&unrelated_pool, &unrelated_did, unrelated_device).await;
    let unrelated_admission = fixture_read_admission(
        &unrelated_pool,
        "blue.catbird.chat.getConversations",
        &unrelated_did,
        unrelated_device,
        &unrelated_jkt,
    )
    .await;
    let unrelated_run = inventory_run_for_fixture(
        &unrelated_pool,
        unrelated_graph.protocol_instance_id,
        unrelated_admission,
    )
    .await;
    assert_eq!(
        unrelated_run.authorities.len(),
        0,
        "an unrelated requester is not a candidate and sees no item"
    );
}

#[tokio::test]
#[ignore = "requires the dedicated gate database seeded with the B-read fixture corpus"]
async fn inventory_fence_rejects_cursor_digest_session_device_and_protocol_splicing() {
    let (pool, guard, graph) = private_genuine_graph().await;
    let maintenance_url = guard.maintenance_url.clone();
    let db_name = guard.db_name.clone();
    assert_private_executor_db_name(&db_name);
    seed_private_retention_fence(&pool, graph.protocol_instance_id).await;
    let cursor_key = fixture_cursor_key(&pool, graph.protocol_instance_id).await;

    // (a) A zero cursor digest is rejected by the validating constructor.
    let zero_digest = chat_protocol::read_authority_bridge::fence_material_rejected(
        graph.protocol_instance_id,
        cursor_key.clone(),
        0,
        [0_u8; 32],
        0,
        Utc::now(),
    );
    assert_eq!(
        zero_digest,
        Some(chat_protocol::read_authority::ReadAuthorityError::Invariant),
        "a bare zero digest is never proof"
    );

    // (b) Protocol splicing: a record built against a foreign protocol
    // instance.
    let admission = fixture_read_admission(
        &pool,
        "blue.catbird.chat.getConversations",
        &graph.creator_did,
        graph.creator_device_id,
        &graph.creator_dpop_jkt,
    )
    .await;
    let (device, mut tx) =
        chat_protocol::read_authority_bridge::lock_inventory_attempt(&pool, admission)
            .await
            .expect("inventory-attempt lock");
    let foreign_instance = Uuid::new_v4();
    let outcome = chat_protocol::read_authority_bridge::verify_fence_material(
        &mut tx,
        device,
        foreign_instance,
        cursor_key.clone(),
        0,
        [0x22_u8; 32],
        0,
        Utc::now(),
    )
    .await;
    assert!(
        matches!(
            outcome,
            Err(chat_protocol::read_authority::ReadAuthorityError::Invariant)
        ),
        "a fence record from a foreign protocol instance is spliced and fails"
    );
    rollback_with_constraints(tx).await;

    // (c) Key splicing: the live instance with a drifted cursor key.
    let admission = fixture_read_admission(
        &pool,
        "blue.catbird.chat.getConversations",
        &graph.creator_did,
        graph.creator_device_id,
        &graph.creator_dpop_jkt,
    )
    .await;
    let (device, mut tx) =
        chat_protocol::read_authority_bridge::lock_inventory_attempt(&pool, admission)
            .await
            .expect("inventory-attempt lock");
    let drifted_key = "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC";
    let outcome = chat_protocol::read_authority_bridge::verify_fence_material(
        &mut tx,
        device,
        graph.protocol_instance_id,
        drifted_key.to_owned(),
        0,
        [0x33_u8; 32],
        0,
        Utc::now(),
    )
    .await;
    assert!(
        matches!(
            outcome,
            Err(chat_protocol::read_authority::ReadAuthorityError::Invariant)
        ),
        "a fence record bound to a drifted cursor key fails"
    );
    rollback_with_constraints(tx).await;

    // (d) Device/session splicing: the device was locked under transaction A
    // but the fence is verified under transaction B.
    let admission = fixture_read_admission(
        &pool,
        "blue.catbird.chat.getConversations",
        &graph.creator_did,
        graph.creator_device_id,
        &graph.creator_dpop_jkt,
    )
    .await;
    let (device, mut tx_a) =
        chat_protocol::read_authority_bridge::lock_inventory_attempt(&pool, admission)
            .await
            .expect("inventory-attempt lock under transaction A");
    let mut tx_b = pool.begin().await.expect("begin foreign transaction B");
    let outcome = chat_protocol::read_authority_bridge::verify_fence_material(
        &mut tx_b,
        device,
        graph.protocol_instance_id,
        cursor_key.clone(),
        0,
        [0x44_u8; 32],
        0,
        Utc::now(),
    )
    .await;
    assert!(
        matches!(
            outcome,
            Err(chat_protocol::read_authority::ReadAuthorityError::Invariant)
        ),
        "a fence verified outside the device lock's transaction is spliced and fails"
    );
    rollback_with_constraints(tx_b).await;
    rollback_with_constraints(tx_a).await;

    // (e) Positive control: the same transaction, exact instance and key.
    let admission = fixture_read_admission(
        &pool,
        "blue.catbird.chat.getConversations",
        &graph.creator_did,
        graph.creator_device_id,
        &graph.creator_dpop_jkt,
    )
    .await;
    let run = inventory_run_for_fixture(&pool, graph.protocol_instance_id, admission).await;
    assert_eq!(
        run.authorities.len(),
        1,
        "the exact fence verifies and the open-leaf conversation yields one item"
    );
    assert_eq!(
        run.authorities[0].fence.event_cursor_sha256, [0x11_u8; 32],
        "the authority binds the exact cursor digest from the verified fence"
    );

    pool.close().await;
    drop(guard);
    assert_executor_db_absent(&maintenance_url, &db_name).await;
}

#[tokio::test]
#[ignore = "requires the dedicated gate database seeded with the B-read fixture corpus"]
async fn inventory_fence_rejects_key_floor_head_and_expiry_drift() {
    let (pool, guard, graph) = private_genuine_graph().await;
    let maintenance_url = guard.maintenance_url.clone();
    let db_name = guard.db_name.clone();
    assert_private_executor_db_name(&db_name);
    seed_private_retention_fence(&pool, graph.protocol_instance_id).await;
    let cursor_key = fixture_cursor_key(&pool, graph.protocol_instance_id).await;

    // (b) Expiry drift: a fence captured in the future, or beyond the session
    // expiry horizon.
    for (label, captured_at) in [
        ("future", Utc::now() + chrono::Duration::minutes(1)),
        ("stale", Utc::now() - chrono::Duration::minutes(30)),
    ] {
        let admission = fixture_read_admission(
            &pool,
            "blue.catbird.chat.getConversations",
            &graph.creator_did,
            graph.creator_device_id,
            &graph.creator_dpop_jkt,
        )
        .await;
        let (device, mut tx) =
            chat_protocol::read_authority_bridge::lock_inventory_attempt(&pool, admission)
                .await
                .expect("inventory-attempt lock");
        let outcome = chat_protocol::read_authority_bridge::verify_fence_material(
            &mut tx,
            device,
            graph.protocol_instance_id,
            cursor_key.clone(),
            0,
            [0x77_u8; 32],
            0,
            captured_at,
        )
        .await;
        assert!(
            matches!(
                outcome,
                Err(chat_protocol::read_authority::ReadAuthorityError::Invariant)
            ),
            "a {label} fence capture is temporal drift"
        );
        rollback_with_constraints(tx).await;
    }

    // (c) Head drift: the fence claims a snapshot event position beyond the
    // protocol's maximum event position.
    let admission = fixture_read_admission(
        &pool,
        "blue.catbird.chat.getConversations",
        &graph.creator_did,
        graph.creator_device_id,
        &graph.creator_dpop_jkt,
    )
    .await;
    let (device, mut tx) =
        chat_protocol::read_authority_bridge::lock_inventory_attempt(&pool, admission)
            .await
            .expect("inventory-attempt lock");
    let fence = chat_protocol::read_authority_bridge::verify_fence_material(
        &mut tx,
        device,
        graph.protocol_instance_id,
        cursor_key.clone(),
        1,
        [0x88_u8; 32],
        0,
        Utc::now(),
    )
    .await
    .expect("the fence verifies: position 1 is floor-consistent and fresh");
    let outcome = chat_protocol::read_authority::inventory_authorities(&mut tx, fence)
        .await
        .err()
        .expect("the head revalidation refuses a snapshot beyond the event stream");
    assert_eq!(
        outcome,
        chat_protocol::read_authority::ReadAuthorityError::Invariant,
        "a fence snapshot position beyond the head is drift"
    );
    rollback_with_constraints(tx).await;

    // (d) Key drift through the deterministic FOR UPDATE barrier: a writer
    // holds an uncommitted retention-floor raise; the final revalidation
    // blocks on the row lock, the writer commits, and the committed drift is
    // then refused. No sleeps: the barrier is the lock itself.
    let mut tx_writer = pool.begin().await.expect("begin the barrier writer");
    sqlx::query(
        "UPDATE chat.event_retention SET retained_floor=7, \
         updated_at=clock_timestamp() WHERE protocol_instance_id=$1",
    )
    .bind(graph.protocol_instance_id)
    .execute(&mut *tx_writer)
    .await
    .expect("the writer holds the retention row lock uncommitted");

    let admission = fixture_read_admission(
        &pool,
        "blue.catbird.chat.getConversations",
        &graph.creator_did,
        graph.creator_device_id,
        &graph.creator_dpop_jkt,
    )
    .await;
    let (device, mut tx) =
        chat_protocol::read_authority_bridge::lock_inventory_attempt(&pool, admission)
            .await
            .expect("inventory-attempt lock");
    // Verification reads the committed floor (0) — the writer's raise is not
    // visible yet.
    let fence = chat_protocol::read_authority_bridge::verify_fence_material(
        &mut tx,
        device,
        graph.protocol_instance_id,
        cursor_key.clone(),
        0,
        [0x99_u8; 32],
        0,
        Utc::now(),
    )
    .await
    .expect("the fence verifies against the committed floor");
    // The writer MUST commit before the final revalidation runs: the
    // revalidation takes FOR UPDATE on the retention row the writer holds,
    // and awaiting it to completion first would deadlock this single task
    // against its own uncommitted writer (client-side; invisible to
    // Postgres). The drift is still committed BETWEEN fence verification
    // (which read the old floor) and the final revalidation, which must then
    // refuse it.
    tx_writer
        .commit()
        .await
        .expect("the barrier writer commits its drift");
    let outcome = chat_protocol::read_authority::inventory_authorities(&mut tx, fence)
        .await
        .err()
        .expect("the committed floor drift is refused by the final revalidation");
    assert_eq!(
        outcome,
        chat_protocol::read_authority::ReadAuthorityError::Invariant,
        "key/floor drift committed between fence verification and final \
         revalidation fails the whole attempt"
    );
    rollback_with_constraints(tx).await;

    // (a) Floor drift, run LAST: the schema's floor monotonicity
    // (`event retention floor cannot move backward`) forbids restoring a
    // raised floor, so the durable raise must be the test's final act. A
    // record whose retained floor sits above its event position is rejected
    // structurally, and a live floor above the snapshot position fails
    // verification. The raise targets 8 — strictly above arm (d)'s committed
    // floor 7 — keeping the monotonic invariant.
    let floor_record = chat_protocol::read_authority_bridge::fence_material_rejected(
        graph.protocol_instance_id,
        cursor_key.clone(),
        0,
        [0x55_u8; 32],
        5,
        Utc::now(),
    );
    assert_eq!(
        floor_record,
        Some(chat_protocol::read_authority::ReadAuthorityError::Invariant),
        "a retained floor above the event position is not a valid fence"
    );
    sqlx::query(
        "UPDATE chat.event_retention SET retained_floor=8, \
         updated_at=clock_timestamp() WHERE protocol_instance_id=$1",
    )
    .bind(graph.protocol_instance_id)
    .execute(&pool)
    .await
    .expect("raise the live retention floor");
    let admission = fixture_read_admission(
        &pool,
        "blue.catbird.chat.getConversations",
        &graph.creator_did,
        graph.creator_device_id,
        &graph.creator_dpop_jkt,
    )
    .await;
    let (device, mut tx) =
        chat_protocol::read_authority_bridge::lock_inventory_attempt(&pool, admission)
            .await
            .expect("inventory-attempt lock");
    let outcome = chat_protocol::read_authority_bridge::verify_fence_material(
        &mut tx,
        device,
        graph.protocol_instance_id,
        cursor_key.clone(),
        0,
        [0x66_u8; 32],
        0,
        Utc::now(),
    )
    .await;
    assert!(
        matches!(
            outcome,
            Err(chat_protocol::read_authority::ReadAuthorityError::Invariant)
        ),
        "a live retention floor above the snapshot event position is drift"
    );
    rollback_with_constraints(tx).await;

    pool.close().await;
    drop(guard);
    assert_executor_db_absent(&maintenance_url, &db_name).await;
}

// ============================================================================
// C1-1: canonical-JSON v1 encoder — pure fixture-driven tests (no database).
//
// Drives the production `read_projection` canonical encoder through the
// frozen `encode_canonical_generated_chat_json_v1` entry point. The fixture
// (`server/tests/fixtures/chat_protocol_g7_canonical_json_v1.json`) was
// written fixture-first and its canonical hex/SHA-256 values were derived by
// an INDEPENDENT Python JCS reference (RFC 8785) kept at
// /private/tmp/c1-jcs-reference/ — never from the Rust encoder.
// ============================================================================

const CANONICAL_JSON_FIXTURE: &str =
    include_str!("fixtures/chat_protocol_g7_canonical_json_v1.json");

use catbird_atproto::generated::blue_catbird::chat as chat_dto;
use jacquard_common::DefaultStr;

fn canonical_json_fixture() -> serde_json::Value {
    serde_json::from_str(CANONICAL_JSON_FIXTURE).expect("C1-1 fixture parses as JSON")
}

fn hex_lowercase(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// The frozen encoder entry takes `&'static str` definition ids; the fixture's
/// ids are compile-time literals, so a static lookup keeps the fixture
/// authoritative while satisfying the signature.
fn static_definition_id(fixture_id: &str) -> &'static str {
    match fixture_id {
        "blue.catbird.chat.defs#conversationState" => "blue.catbird.chat.defs#conversationState",
        "blue.catbird.chat.defs#conversationRemovalTombstone" => {
            "blue.catbird.chat.defs#conversationRemovalTombstone"
        }
        "blue.catbird.chat.defs#conversationCloseTombstone" => {
            "blue.catbird.chat.defs#conversationCloseTombstone"
        }
        "blue.catbird.chat.defs#conversationInventoryItem" => {
            "blue.catbird.chat.defs#conversationInventoryItem"
        }
        "blue.catbird.chat.defs#welcomeView" => "blue.catbird.chat.defs#welcomeView",
        "blue.catbird.chat.defs#leafRecoveryView" => "blue.catbird.chat.defs#leafRecoveryView",
        "blue.catbird.chat.defs#recoveryWorkView" => "blue.catbird.chat.defs#recoveryWorkView",
        "blue.catbird.chat.defs#recoveryWorkPendingView" => {
            "blue.catbird.chat.defs#recoveryWorkPendingView"
        }
        "blue.catbird.chat.defs#leafRecoveryInboxItem" => {
            "blue.catbird.chat.defs#leafRecoveryInboxItem"
        }
        "blue.catbird.chat.defs#metadataContentProjection" => {
            "blue.catbird.chat.defs#metadataContentProjection"
        }
        _ => panic!("fixture definition id is not mapped to a static literal: {fixture_id}"),
    }
}

/// `extra_data` injection: generated DTOs carry the flattened
/// `Option<BTreeMap<SmolStr, Data>>` member, so invalid vectors record the
/// poison as `extraData` and the harness injects it into the DTO before the
/// encoder serializes it.
trait CanonicalExtraDataInjection {
    fn inject_canonical_extra_data(&mut self, extra: &serde_json::Value) -> Result<(), String>;
}

macro_rules! impl_extra_data_injection {
    ($($ty:ty),+ $(,)?) => {
        $(
            impl CanonicalExtraDataInjection for $ty {
                fn inject_canonical_extra_data(
                    &mut self,
                    extra: &serde_json::Value,
                ) -> Result<(), String> {
                    let map: std::collections::BTreeMap<
                        jacquard_common::deps::smol_str::SmolStr,
                        jacquard_common::types::value::Data<DefaultStr>,
                    > = serde_json::from_value(extra.clone())
                        .map_err(|error| format!("extra_data decode: {error}"))?;
                    self.extra_data = Some(map);
                    Ok(())
                }
            }
        )+
    };
}

impl_extra_data_injection!(
    chat_dto::ConversationState<DefaultStr>,
    chat_dto::ConversationRemovalTombstone<DefaultStr>,
    chat_dto::ConversationCloseTombstone<DefaultStr>,
    chat_dto::WelcomeView<DefaultStr>,
    chat_dto::LeafRecoveryView<DefaultStr>,
    chat_dto::MetadataContentProjection<DefaultStr>,
);

/// Decodes the fixture's typed value into the generated DTO named by the
/// fixture's `dto` field and encodes it through the frozen entry point. The
/// fixture value is exactly the generated serializer's JSON shape (camelCase,
/// `$bytes` objects, bare byte arrays), so this is a genuine generated-DTO
/// round trip. The DTO is decoded from the re-serialized JSON text because
/// the generated `serde_bytes_helper` visitors require borrowed string keys
/// (they do not deserialize from an owned `serde_json::Value`).
fn encode_fixture_vector(
    vector: &serde_json::Value,
) -> Result<
    chat_protocol::read_projection::CanonicalChatJsonV1,
    chat_protocol::read_projection::ProjectionError,
> {
    let fixture_id = vector["definitionId"].as_str().expect("definitionId");
    let definition_id = static_definition_id(fixture_id);
    let dto_kind = vector["dto"].as_str().expect("dto");
    let value = &vector["value"];
    let value_text = serde_json::to_string(value).expect("fixture value re-serializes");
    let extra_data = vector.get("extraData");
    match dto_kind {
        "ConversationState" => {
            let mut dto: chat_dto::ConversationState<DefaultStr> =
                serde_json::from_str(&value_text).expect("fixture DTO decodes");
            if let Some(extra) = extra_data {
                dto.inject_canonical_extra_data(extra)
                    .expect("extra_data injects");
            }
            chat_protocol::read_projection::encode_canonical_generated_chat_json_v1(
                &dto,
                definition_id,
            )
        }
        "ConversationRemovalTombstone" => {
            let mut dto: chat_dto::ConversationRemovalTombstone<DefaultStr> =
                serde_json::from_str(&value_text).expect("fixture DTO decodes");
            if let Some(extra) = extra_data {
                dto.inject_canonical_extra_data(extra)
                    .expect("extra_data injects");
            }
            chat_protocol::read_projection::encode_canonical_generated_chat_json_v1(
                &dto,
                definition_id,
            )
        }
        "ConversationCloseTombstone" => {
            let mut dto: chat_dto::ConversationCloseTombstone<DefaultStr> =
                serde_json::from_str(&value_text).expect("fixture DTO decodes");
            if let Some(extra) = extra_data {
                dto.inject_canonical_extra_data(extra)
                    .expect("extra_data injects");
            }
            chat_protocol::read_projection::encode_canonical_generated_chat_json_v1(
                &dto,
                definition_id,
            )
        }
        "ConversationInventoryItem" => {
            let dto: chat_dto::ConversationInventoryItem<DefaultStr> =
                serde_json::from_str(&value_text).expect("fixture DTO decodes");
            chat_protocol::read_projection::encode_canonical_generated_chat_json_v1(
                &dto,
                definition_id,
            )
        }
        "WelcomeView" => {
            let mut dto: chat_dto::WelcomeView<DefaultStr> =
                serde_json::from_str(&value_text).expect("fixture DTO decodes");
            if let Some(extra) = extra_data {
                dto.inject_canonical_extra_data(extra)
                    .expect("extra_data injects");
            }
            chat_protocol::read_projection::encode_canonical_generated_chat_json_v1(
                &dto,
                definition_id,
            )
        }
        "LeafRecoveryView" => {
            let mut dto: chat_dto::LeafRecoveryView<DefaultStr> =
                serde_json::from_str(&value_text).expect("fixture DTO decodes");
            if let Some(extra) = extra_data {
                dto.inject_canonical_extra_data(extra)
                    .expect("extra_data injects");
            }
            chat_protocol::read_projection::encode_canonical_generated_chat_json_v1(
                &dto,
                definition_id,
            )
        }
        "RecoveryWorkView" => {
            let dto: chat_dto::RecoveryWorkView<DefaultStr> =
                serde_json::from_str(&value_text).expect("fixture DTO decodes");
            chat_protocol::read_projection::encode_canonical_generated_chat_json_v1(
                &dto,
                definition_id,
            )
        }
        "LeafRecoveryInboxItem" => {
            let dto: chat_dto::LeafRecoveryInboxItem<DefaultStr> =
                serde_json::from_str(&value_text).expect("fixture DTO decodes");
            chat_protocol::read_projection::encode_canonical_generated_chat_json_v1(
                &dto,
                definition_id,
            )
        }
        "MetadataContentProjection" => {
            let mut dto: chat_dto::MetadataContentProjection<DefaultStr> =
                serde_json::from_str(&value_text).expect("fixture DTO decodes");
            if let Some(extra) = extra_data {
                dto.inject_canonical_extra_data(extra)
                    .expect("extra_data injects");
            }
            chat_protocol::read_projection::encode_canonical_generated_chat_json_v1(
                &dto,
                definition_id,
            )
        }
        other => panic!("fixture dto kind is not dispatched: {other}"),
    }
}

/// Payload probes for the redaction guarantee: every string value longer than
/// six characters and every large/float number in the fixture vector must not
/// appear in the redacted error text. Shorter values are single enum tokens
/// (e.g. "member", "active") that also appear inside static reason text and
/// member names, so they cannot distinguish a leaked value from structural
/// text; the payload material that matters (identifiers, base64, datetimes,
/// unsafe numbers) is always longer. Member names (paths) and static reason
/// text are structural and are expected to appear, so any probe that is a
/// substring of a member key is dropped as well.
fn redaction_probes(vector: &serde_json::Value) -> Vec<String> {
    let mut probes = Vec::new();
    let mut keys = Vec::new();
    fn collect(value: &serde_json::Value, out: &mut Vec<String>, keys: &mut Vec<String>) {
        match value {
            serde_json::Value::String(text) => {
                if text.len() > 6 {
                    out.push(text.clone());
                }
            }
            serde_json::Value::Number(number) => {
                if let Some(float) = number.as_f64() {
                    if float.fract() != 0.0 {
                        out.push(number.to_string());
                    }
                } else if number.as_i64().is_some_and(|value| value.abs() > 999) {
                    out.push(number.to_string());
                }
            }
            serde_json::Value::Array(items) => {
                for item in items {
                    collect(item, out, keys);
                }
            }
            serde_json::Value::Object(map) => {
                for (key, item) in map {
                    keys.push(key.clone());
                    collect(item, out, keys);
                }
            }
            serde_json::Value::Null | serde_json::Value::Bool(_) => {}
        }
    }
    collect(&vector["value"], &mut probes, &mut keys);
    if let Some(extra) = vector.get("extraData") {
        collect(extra, &mut probes, &mut keys);
    }
    probes.retain(|probe| !keys.iter().any(|key| key.contains(probe)));
    probes
}

#[test]
fn c1_canonical_json_fixture_valid_vectors_encode_to_exact_hex_and_sha256() {
    let fixture = canonical_json_fixture();
    let vectors = fixture["vectors"].as_array().expect("fixture vectors");
    let mut checked = 0;
    for vector in vectors {
        if vector.get("failure").is_some() {
            continue;
        }
        let name = vector["name"].as_str().expect("vector name");
        let encoded = encode_fixture_vector(vector)
            .unwrap_or_else(|error| panic!("{name} must encode: {error}"));
        let actual_hex = hex_lowercase(encoded.bytes());
        assert_eq!(
            actual_hex,
            vector["canonicalUtf8Hex"]
                .as_str()
                .expect("canonicalUtf8Hex"),
            "{name} must encode to the fixture's exact canonical UTF-8 hex"
        );
        assert_eq!(
            encoded.sha256_hex(),
            vector["sha256"].as_str().expect("sha256"),
            "{name} must match the fixture's exact SHA-256"
        );
        checked += 1;
    }
    assert_eq!(checked, 18, "every valid fixture vector was checked");
}

#[test]
fn c1_canonical_json_fixture_invalid_vectors_fail_redacted_before_bytes() {
    let fixture = canonical_json_fixture();
    let vectors = fixture["vectors"].as_array().expect("fixture vectors");
    let mut checked = 0;
    for vector in vectors {
        let Some(failure) = vector.get("failure") else {
            continue;
        };
        let name = vector["name"].as_str().expect("vector name");
        let expected_kind = failure["kind"].as_str().expect("failure kind");
        let error = encode_fixture_vector(vector)
            .err()
            .unwrap_or_else(|| panic!("{name} must fail before producing canonical bytes"));
        let kind_name = format!("{:?}", error.kind());
        assert_eq!(
            kind_name, expected_kind,
            "{name} must fail with the fixture's exact failure kind"
        );
        let display = error.to_string();
        assert!(
            display.contains(&kind_name),
            "{name} error must name its redacted kind"
        );
        for probe in redaction_probes(vector) {
            assert!(
                !display.contains(&probe),
                "{name} redacted error must not leak payload value {probe:?}"
            );
        }
        checked += 1;
    }
    assert_eq!(checked, 9, "every invalid fixture vector was checked");
}

// ============================================================================
// C1-2: checked projection source types and the six projection functions —
// pure tests (no database).
//
// Drives the production `read_projection` checked sources and projection
// functions. Complete generated DTOs are produced from typed sources for the
// full frozen case list; constructor negatives prove the checked guards fail
// BEFORE any DTO materializes; the source guards pin the corrected Step-5
// text (canonical bytes only from the local canonical writer; the single
// `serde_json::to_vec` serialize-once step at read_projection.rs:982 is
// allowed and present; `extra_data` can never be non-empty in produced
// canonical bytes).
// ============================================================================

const C1_2_CONVERSATION_ID: &str = "123e4567-e89b-12d3-a456-426614174000";
const C1_2_DEVICE_ID_A: &str = "123e4567-e89b-12d3-a456-426614174001";
const C1_2_DEVICE_ID_B: &str = "123e4567-e89b-12d3-a456-426614174002";
const C1_2_RECOVERY_REQUEST_ID: &str = "123e4567-e89b-12d3-a456-426614174003";
const C1_2_WELCOME_ID: &str = "123e4567-e89b-12d3-a456-426614174004";
const C1_2_TRANSITION_ID_1: &str = "123e4567-e89b-12d3-a456-426614174005";
const C1_2_TRANSITION_ID_2: &str = "123e4567-e89b-12d3-a456-426614174006";
const C1_2_REVOCATION_ID: &str = "123e4567-e89b-12d3-a456-426614174007";
const C1_2_DID_A: &str = "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa";
const C1_2_DID_B: &str = "did:plc:bbbbbbbbbbbbbbbbbbbbbbbb";
const C1_2_KEY_ID: &str = "kJ2O8X9rQmzNpY3fA7sD5gH1vL0cE4uW6tR8bB2nM4q";
const C1_2_CIPHER_SUITE: &str = "MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519";
const C1_2_REQUESTED_AT: &str = "2026-08-03T04:05:06.789Z";
const C1_2_EXPIRES_AT: &str = "2026-08-05T23:59:59.000Z";
const C1_2_REMOVED_AT: &str = "2026-07-30T12:00:00.000Z";
const C1_2_CLOSED_AT: &str = "2026-07-31T23:59:59.999Z";
const C1_2_CREATED_AT: &str = "2026-08-04T10:00:00.000Z";
const C1_2_TERMINAL_AT_1: &str = "2026-08-04T11:00:00.000Z";
const C1_2_TERMINAL_AT_2: &str = "2026-08-04T12:00:00.000Z";
const C1_2_TERMINAL_AT_3: &str = "2026-08-04T13:00:00.000Z";

use chat_protocol::read_projection::{
    conversation_inventory_item, conversation_state_view, leaf_recovery_inbox_item,
    leaf_recovery_view, recovery_work, welcome_view,
};
use chat_protocol::read_projection::{
    CheckedConversationCoordinates, CheckedDeviceLeafView, CheckedInvitationProvenance,
    CheckedKeyPackageArtifact, CheckedLeafRecoveryReservation, CheckedMetadataAuthorProof,
    CheckedMetadataAvatarBinding, CheckedMetadataCryptoContext, CheckedMetadataSnapshot,
    CheckedParticipantView, CheckedWelcomeProvenance, ConversationProjectionSource,
    LeafRecoveryInboxInput, ProjectionErrorKind, RetainedLeafRecoveryProjectionSource,
    RetainedRecoveryWorkProjectionSource, RetainedRecoveryWorkTerminal,
    RetainedWelcomeProjectionSource,
};
use jacquard_common::deps::bytes::Bytes;
use jacquard_common::deps::smol_str::SmolStr;

fn c1_2_bytes_0_to_32() -> Vec<u8> {
    (0..32).collect()
}

fn c1_2_bytes_32_to_64() -> Vec<u8> {
    (32..64).collect()
}

fn c1_2_bytes_64_to_96() -> Vec<u8> {
    (64..96).collect()
}

fn c1_2_bytes_0_to_16() -> Vec<u8> {
    (0..16).collect()
}

fn c1_2_bytes_0_to_64() -> Vec<u8> {
    (0..64).collect()
}

fn c1_2_nonce_12() -> Vec<u8> {
    (0..12).collect()
}

fn c1_2_welcome_bytes() -> Vec<u8> {
    (128..160).collect()
}

fn c1_2_coordinates() -> CheckedConversationCoordinates {
    CheckedConversationCoordinates::new(
        C1_2_CONVERSATION_ID,
        0,
        3,
        &c1_2_bytes_0_to_32(),
        1,
        &c1_2_bytes_32_to_64(),
        &c1_2_bytes_64_to_96(),
        "active",
    )
    .expect("fixture coordinates are checked")
}

fn c1_2_metadata_crypto_context() -> CheckedMetadataCryptoContext {
    CheckedMetadataCryptoContext::new(
        &c1_2_bytes_0_to_16(),
        0,
        &c1_2_bytes_0_to_32(),
        1,
        &c1_2_bytes_32_to_64(),
        &c1_2_bytes_64_to_96(),
    )
    .expect("fixture metadata crypto context is checked")
}

fn c1_2_metadata_author_proof() -> CheckedMetadataAuthorProof {
    CheckedMetadataAuthorProof::new(
        C1_2_DID_A,
        C1_2_DEVICE_ID_A,
        C1_2_KEY_ID,
        &c1_2_bytes_32_to_64(),
        1,
        C1_2_TRANSITION_ID_1,
        1,
        "admin",
        "active",
    )
    .expect("fixture author proof is checked")
}

fn c1_2_metadata_snapshot() -> CheckedMetadataSnapshot {
    CheckedMetadataSnapshot::new(
        c1_2_metadata_crypto_context(),
        C1_2_TRANSITION_ID_1,
        1,
        &c1_2_nonce_12(),
        &c1_2_bytes_0_to_64(),
        &c1_2_bytes_0_to_32(),
        64,
        c1_2_metadata_author_proof(),
        None,
    )
    .expect("fixture metadata snapshot is checked")
}

fn c1_2_leaf_a() -> CheckedDeviceLeafView {
    CheckedDeviceLeafView::new(
        C1_2_DID_A,
        C1_2_DEVICE_ID_A,
        "genesis",
        C1_2_KEY_ID,
        "active",
        None,
    )
    .expect("fixture leaf A is checked")
}

fn c1_2_leaf_b() -> CheckedDeviceLeafView {
    CheckedDeviceLeafView::new(
        C1_2_DID_B,
        C1_2_DEVICE_ID_B,
        "keyPackage",
        C1_2_KEY_ID,
        "active",
        Some(&c1_2_bytes_32_to_64()),
    )
    .expect("fixture leaf B is checked")
}

fn c1_2_participant_a() -> CheckedParticipantView {
    CheckedParticipantView::new(C1_2_DID_A, "admin", "active", 1, None)
        .expect("fixture participant A is checked")
}

fn c1_2_participant_b_pending() -> CheckedParticipantView {
    let provenance =
        CheckedInvitationProvenance::new(C1_2_TRANSITION_ID_1, C1_2_DID_A, C1_2_DEVICE_ID_A)
            .expect("fixture invitation provenance is checked");
    CheckedParticipantView::new(C1_2_DID_B, "member", "pending", 0, Some(provenance))
        .expect("fixture pending participant is checked")
}

fn c1_2_key_package_artifact() -> CheckedKeyPackageArtifact {
    CheckedKeyPackageArtifact::new(
        "mlsMessage",
        "keyPackage",
        &c1_2_bytes_0_to_32(),
        &c1_2_bytes_32_to_64(),
        &c1_2_bytes_64_to_96(),
    )
    .expect("fixture key package artifact is checked")
}

fn c1_2_reservation(status: &str) -> CheckedLeafRecoveryReservation {
    CheckedLeafRecoveryReservation::new(
        C1_2_RECOVERY_REQUEST_ID,
        C1_2_CONVERSATION_ID,
        c1_2_coordinates(),
        C1_2_DID_A,
        C1_2_DEVICE_ID_A,
        C1_2_KEY_ID,
        1,
        &c1_2_bytes_64_to_96(),
        C1_2_CIPHER_SUITE,
        "leafRecovery",
        status,
        C1_2_EXPIRES_AT,
        c1_2_key_package_artifact(),
    )
    .expect("fixture reservation is checked")
}

fn c1_2_reservation_status_for(view_status: &str) -> &'static str {
    match view_status {
        "open" => "active",
        "fulfilled" => "consumed",
        "cancelled" => "released",
        "expired" => "expired",
        "superseded" => "released",
        other => panic!("unexpected retained leaf-recovery status {other}"),
    }
}

fn c1_2_leaf_recovery_source(view_status: &str) -> RetainedLeafRecoveryProjectionSource {
    let reservation = c1_2_reservation(c1_2_reservation_status_for(view_status));
    RetainedLeafRecoveryProjectionSource::new(
        C1_2_RECOVERY_REQUEST_ID,
        C1_2_CONVERSATION_ID,
        C1_2_DID_A,
        C1_2_DEVICE_ID_A,
        "add",
        c1_2_coordinates(),
        view_status,
        C1_2_REQUESTED_AT,
        C1_2_EXPIRES_AT,
        reservation,
    )
    .expect("fixture leaf-recovery source is checked")
}

fn c1_2_work_source(
    terminal: RetainedRecoveryWorkTerminal,
) -> RetainedRecoveryWorkProjectionSource {
    RetainedRecoveryWorkProjectionSource::new(
        C1_2_WELCOME_ID,
        C1_2_CONVERSATION_ID,
        C1_2_DID_A,
        C1_2_DEVICE_ID_A,
        "welcomeExpired",
        C1_2_WELCOME_ID,
        c1_2_coordinates(),
        C1_2_CREATED_AT,
        terminal,
    )
    .expect("fixture recovery-work source is checked")
}

fn c1_2_welcome_source(status: &str) -> RetainedWelcomeProjectionSource {
    let provenance =
        CheckedWelcomeProvenance::new(C1_2_RECOVERY_REQUEST_ID, &c1_2_bytes_64_to_96())
            .expect("fixture welcome provenance is checked");
    RetainedWelcomeProjectionSource::new(
        C1_2_WELCOME_ID,
        C1_2_CONVERSATION_ID,
        2,
        c1_2_coordinates(),
        status,
        &c1_2_welcome_bytes(),
        &c1_2_bytes_0_to_32(),
        C1_2_DID_A,
        C1_2_DEVICE_ID_A,
        provenance,
        C1_2_EXPIRES_AT,
    )
    .expect("fixture welcome source is checked")
}

fn c1_2_contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

#[test]
fn c1_2_active_conversation_state_projects_complete_dto() {
    let source = ConversationProjectionSource::state(
        C1_2_CIPHER_SUITE,
        "group",
        c1_2_coordinates(),
        vec![c1_2_leaf_a()],
        c1_2_metadata_snapshot(),
        vec![c1_2_participant_a()],
        42,
    )
    .expect("active checked state source");
    let dto = conversation_state_view(&source).expect("active state projects");
    assert_eq!(dto.cipher_suite.as_str(), C1_2_CIPHER_SUITE);
    assert_eq!(dto.conversation_kind.as_str(), "group");
    assert_eq!(
        dto.coordinates.conversation_id.as_str(),
        C1_2_CONVERSATION_ID
    );
    assert_eq!(dto.coordinates.generation, 0);
    assert_eq!(dto.coordinates.state_version, 3);
    assert_eq!(dto.coordinates.group_id, Bytes::from(c1_2_bytes_0_to_32()));
    assert_eq!(dto.coordinates.epoch, 1);
    assert_eq!(
        dto.coordinates.group_context_hash,
        Bytes::from(c1_2_bytes_32_to_64())
    );
    assert_eq!(
        dto.coordinates.confirmation_tag,
        Bytes::from(c1_2_bytes_64_to_96())
    );
    assert_eq!(dto.coordinates.lifecycle.as_str(), "active");
    assert_eq!(dto.leaves.len(), 1);
    assert_eq!(dto.leaves[0].user_did.as_str(), C1_2_DID_A);
    assert_eq!(dto.leaves[0].device_id.as_str(), C1_2_DEVICE_ID_A);
    assert_eq!(dto.leaves[0].leaf_origin.as_str(), "genesis");
    assert_eq!(dto.leaves[0].key_id.as_str(), C1_2_KEY_ID);
    assert_eq!(dto.leaves[0].device_status.as_str(), "active");
    assert!(dto.leaves[0].join_key_package_ref.is_none());
    let snapshot = &dto.metadata_snapshot;
    assert_eq!(
        snapshot.coordinate.conversation_id,
        Bytes::from(c1_2_bytes_0_to_16())
    );
    assert_eq!(snapshot.coordinate.generation, 0);
    assert_eq!(
        snapshot.coordinate.group_id,
        Bytes::from(c1_2_bytes_0_to_32())
    );
    assert_eq!(snapshot.coordinate.epoch, 1);
    assert_eq!(
        snapshot.coordinate.group_context_hash,
        Bytes::from(c1_2_bytes_32_to_64())
    );
    assert_eq!(
        snapshot.coordinate.confirmation_tag,
        Bytes::from(c1_2_bytes_64_to_96())
    );
    assert_eq!(snapshot.origin_transition_id.as_str(), C1_2_TRANSITION_ID_1);
    assert_eq!(snapshot.metadata_version, 1);
    assert_eq!(snapshot.nonce, Bytes::from(c1_2_nonce_12()));
    assert_eq!(snapshot.ciphertext, Bytes::from(c1_2_bytes_0_to_64()));
    assert_eq!(
        snapshot.ciphertext_sha256,
        Bytes::from(c1_2_bytes_0_to_32())
    );
    assert_eq!(snapshot.ciphertext_size, 64);
    assert_eq!(snapshot.author_proof.author_did.as_str(), C1_2_DID_A);
    assert_eq!(
        snapshot.author_proof.author_device_id.as_str(),
        C1_2_DEVICE_ID_A
    );
    assert_eq!(snapshot.author_proof.author_key_id.as_str(), C1_2_KEY_ID);
    assert_eq!(
        snapshot.author_proof.signature_public_key,
        Bytes::from(c1_2_bytes_32_to_64())
    );
    assert_eq!(snapshot.author_proof.auth_generation_at_origin, 1);
    assert_eq!(
        snapshot.author_proof.origin_transition_id.as_str(),
        C1_2_TRANSITION_ID_1
    );
    assert_eq!(snapshot.author_proof.origin_seq, 1);
    assert_eq!(snapshot.author_proof.role_at_origin.as_str(), "admin");
    assert_eq!(
        snapshot.author_proof.device_status_at_origin.as_str(),
        "active"
    );
    assert!(snapshot.avatar_binding.is_none());
    assert_eq!(dto.participants.len(), 1);
    assert_eq!(dto.participants[0].user_did.as_str(), C1_2_DID_A);
    assert_eq!(dto.participants[0].role.as_str(), "admin");
    assert_eq!(dto.participants[0].status.as_str(), "active");
    assert_eq!(dto.participants[0].leaf_count, 1);
    assert!(dto.participants[0].invitation_provenance.is_none());
    assert_eq!(dto.snapshot_seq, 42);
    assert!(dto.extra_data.is_none());
}

#[test]
fn c1_2_group_pending_and_zero_leaf_states_project_complete_dtos() {
    let group_pending = ConversationProjectionSource::state(
        C1_2_CIPHER_SUITE,
        "group",
        c1_2_coordinates(),
        vec![c1_2_leaf_a()],
        c1_2_metadata_snapshot(),
        vec![c1_2_participant_a(), c1_2_participant_b_pending()],
        5,
    )
    .expect("group-pending checked state source");
    let dto = conversation_state_view(&group_pending).expect("group-pending state projects");
    assert_eq!(dto.leaves.len(), 1);
    assert_eq!(dto.participants.len(), 2);
    assert_eq!(dto.participants[1].user_did.as_str(), C1_2_DID_B);
    assert_eq!(dto.participants[1].role.as_str(), "member");
    assert_eq!(dto.participants[1].status.as_str(), "pending");
    assert_eq!(dto.participants[1].leaf_count, 0);
    let provenance = dto.participants[1]
        .invitation_provenance
        .as_ref()
        .expect("pending participant carries immutable invitation provenance");
    assert_eq!(
        provenance.invitation_transition_id.as_str(),
        C1_2_TRANSITION_ID_1
    );
    assert_eq!(provenance.invited_by_did.as_str(), C1_2_DID_A);
    assert_eq!(provenance.invited_by_device_id.as_str(), C1_2_DEVICE_ID_A);
    assert_eq!(dto.participants[0].leaf_count, 1);
    assert_eq!(dto.snapshot_seq, 5);
    assert!(dto.extra_data.is_none());

    let zero_leaf = ConversationProjectionSource::state(
        C1_2_CIPHER_SUITE,
        "group",
        c1_2_coordinates(),
        vec![],
        c1_2_metadata_snapshot(),
        vec![
            CheckedParticipantView::new(C1_2_DID_A, "admin", "active", 0, None)
                .expect("active zero-leaf participant is checked"),
        ],
        0,
    )
    .expect("zero-leaf checked state source");
    let dto = conversation_state_view(&zero_leaf).expect("zero-leaf state projects");
    assert!(
        dto.leaves.is_empty(),
        "no leaf is invented for a zero-leaf state"
    );
    assert_eq!(dto.participants.len(), 1);
    assert_eq!(dto.participants[0].leaf_count, 0);
    assert_eq!(dto.snapshot_seq, 0);
    assert!(dto.extra_data.is_none());
}

#[test]
fn c1_2_removal_tombstone_projects_and_state_view_refuses() {
    let source = ConversationProjectionSource::removal(
        C1_2_CONVERSATION_ID,
        C1_2_DID_A,
        C1_2_DEVICE_ID_A,
        C1_2_TRANSITION_ID_1,
        C1_2_REMOVED_AT,
        7,
    )
    .expect("removal checked source");
    let item = conversation_inventory_item(&source).expect("removal arm projects a tombstone");
    let chat_dto::ConversationInventoryItem::ConversationRemovalTombstone(tombstone) = &item else {
        panic!("the removal arm materializes exactly the removal tombstone");
    };
    assert_eq!(tombstone.conversation_id.as_str(), C1_2_CONVERSATION_ID);
    assert_eq!(tombstone.user_did.as_str(), C1_2_DID_A);
    assert_eq!(tombstone.device_id.as_str(), C1_2_DEVICE_ID_A);
    assert_eq!(
        tombstone.membership_interval_id.as_str(),
        C1_2_TRANSITION_ID_1
    );
    assert_eq!(tombstone.removed_at.as_str(), C1_2_REMOVED_AT);
    assert_eq!(tombstone.terminal_seq, 7);
    assert!(tombstone.extra_data.is_none());
    let error = conversation_state_view(&source)
        .expect_err("a removed interval has no historical conversationState projection");
    assert_eq!(
        error.kind(),
        ProjectionErrorKind::NoConversationStateProjection,
        "the removal arm yields AccessOutsideMembershipInterval-shaped tombstone semantics only"
    );
}

#[test]
fn c1_2_post_reset_removal_tombstone_has_no_historical_state_projection() {
    let reset_activation_id = C1_2_TRANSITION_ID_2;
    let source = ConversationProjectionSource::removal(
        C1_2_CONVERSATION_ID,
        C1_2_DID_A,
        C1_2_DEVICE_ID_A,
        reset_activation_id,
        C1_2_REMOVED_AT,
        4,
    )
    .expect("post-reset removal checked source");
    let item =
        conversation_inventory_item(&source).expect("post-reset removal projects a tombstone");
    let chat_dto::ConversationInventoryItem::ConversationRemovalTombstone(tombstone) = &item else {
        panic!("the post-reset removal arm materializes exactly the removal tombstone");
    };
    assert_eq!(
        tombstone.membership_interval_id.as_str(),
        reset_activation_id,
        "the interval is opened by the exact reset activation transition"
    );
    assert_eq!(tombstone.terminal_seq, 4);
    assert_eq!(tombstone.conversation_id.as_str(), C1_2_CONVERSATION_ID);
    assert_eq!(tombstone.user_did.as_str(), C1_2_DID_A);
    assert_eq!(tombstone.device_id.as_str(), C1_2_DEVICE_ID_A);
    assert_eq!(tombstone.removed_at.as_str(), C1_2_REMOVED_AT);
    assert!(tombstone.extra_data.is_none());
    let error = conversation_state_view(&source)
        .expect_err("a post-reset old exact device has no historical conversationState projection");
    assert_eq!(
        error.kind(),
        ProjectionErrorKind::NoConversationStateProjection
    );
}

#[test]
fn c1_2_close_tombstone_projects_and_state_view_refuses() {
    let source = ConversationProjectionSource::close(
        C1_2_CLOSED_AT,
        C1_2_DID_B,
        C1_2_DEVICE_ID_B,
        C1_2_CONVERSATION_ID,
        "direct",
        c1_2_coordinates(),
        9,
    )
    .expect("close checked source");
    let item = conversation_inventory_item(&source).expect("close arm projects a tombstone");
    let chat_dto::ConversationInventoryItem::ConversationCloseTombstone(tombstone) = &item else {
        panic!("the close arm materializes exactly the close tombstone");
    };
    assert_eq!(tombstone.closed_at.as_str(), C1_2_CLOSED_AT);
    assert_eq!(tombstone.closed_by_did.as_str(), C1_2_DID_B);
    assert_eq!(tombstone.closed_by_device_id.as_str(), C1_2_DEVICE_ID_B);
    assert_eq!(tombstone.conversation_id.as_str(), C1_2_CONVERSATION_ID);
    assert_eq!(tombstone.conversation_kind.as_str(), "direct");
    assert_eq!(
        tombstone.retired.conversation_id.as_str(),
        C1_2_CONVERSATION_ID
    );
    assert_eq!(tombstone.retired.generation, 0);
    assert_eq!(tombstone.retired.state_version, 3);
    assert_eq!(
        tombstone.retired.group_id,
        Bytes::from(c1_2_bytes_0_to_32())
    );
    assert_eq!(tombstone.retired.epoch, 1);
    assert_eq!(
        tombstone.retired.group_context_hash,
        Bytes::from(c1_2_bytes_32_to_64())
    );
    assert_eq!(
        tombstone.retired.confirmation_tag,
        Bytes::from(c1_2_bytes_64_to_96())
    );
    assert_eq!(tombstone.retired.lifecycle.as_str(), "active");
    assert_eq!(tombstone.terminal_seq, 9);
    assert!(tombstone.extra_data.is_none());
    let error = conversation_state_view(&source)
        .expect_err("a closed conversation has no conversationState projection");
    assert_eq!(
        error.kind(),
        ProjectionErrorKind::NoConversationStateProjection
    );
}

#[test]
fn c1_2_pending_welcome_projects_complete_dto() {
    let source = c1_2_welcome_source("pending");
    let dto = welcome_view(&source).expect("pending Welcome projects");
    assert_eq!(dto.welcome_id.as_str(), C1_2_WELCOME_ID);
    assert_eq!(dto.conversation_id.as_str(), C1_2_CONVERSATION_ID);
    assert_eq!(dto.transition_seq, 2);
    assert_eq!(
        dto.coordinates.conversation_id.as_str(),
        C1_2_CONVERSATION_ID
    );
    assert_eq!(dto.coordinates.generation, 0);
    assert_eq!(dto.coordinates.state_version, 3);
    assert_eq!(dto.coordinates.group_id, Bytes::from(c1_2_bytes_0_to_32()));
    assert_eq!(dto.coordinates.epoch, 1);
    assert_eq!(
        dto.coordinates.group_context_hash,
        Bytes::from(c1_2_bytes_32_to_64())
    );
    assert_eq!(
        dto.coordinates.confirmation_tag,
        Bytes::from(c1_2_bytes_64_to_96())
    );
    assert_eq!(dto.coordinates.lifecycle.as_str(), "active");
    assert_eq!(dto.status.as_str(), "pending");
    assert_eq!(dto.opaque_welcome, Bytes::from(c1_2_welcome_bytes()));
    assert_eq!(dto.sha256, Bytes::from(c1_2_bytes_0_to_32()));
    assert_eq!(dto.recipient_did.as_str(), C1_2_DID_A);
    assert_eq!(dto.recipient_device_id.as_str(), C1_2_DEVICE_ID_A);
    assert_eq!(
        dto.provenance.recovery_request_id.as_str(),
        C1_2_RECOVERY_REQUEST_ID
    );
    assert_eq!(
        dto.provenance.key_package_ref,
        Bytes::from(c1_2_bytes_64_to_96())
    );
    assert_eq!(dto.expires_at.as_str(), C1_2_EXPIRES_AT);
    assert!(dto.extra_data.is_none());
}

#[test]
fn c1_2_every_retained_leaf_recovery_status_projects_complete_view() {
    for view_status in ["open", "fulfilled", "cancelled", "expired", "superseded"] {
        let source = c1_2_leaf_recovery_source(view_status);
        let dto = leaf_recovery_view(&source)
            .unwrap_or_else(|error| panic!("{view_status} leaf recovery projects: {error}"));
        assert_eq!(dto.status.as_str(), view_status);
        assert_eq!(
            dto.reservation.status.as_str(),
            c1_2_reservation_status_for(view_status),
            "the reservation status is consistent with the retained {view_status} status"
        );
        assert_eq!(dto.recovery_request_id.as_str(), C1_2_RECOVERY_REQUEST_ID);
        assert_eq!(dto.conversation_id.as_str(), C1_2_CONVERSATION_ID);
        assert_eq!(dto.requester_did.as_str(), C1_2_DID_A);
        assert_eq!(dto.requester_device_id.as_str(), C1_2_DEVICE_ID_A);
        assert_eq!(dto.recovery_kind.as_str(), "add");
        assert_eq!(
            dto.bound_coordinate.conversation_id.as_str(),
            C1_2_CONVERSATION_ID
        );
        assert_eq!(dto.requested_at.as_str(), C1_2_REQUESTED_AT);
        assert_eq!(dto.expires_at.as_str(), C1_2_EXPIRES_AT);
        let reservation = &dto.reservation;
        assert_eq!(
            reservation.recovery_request_id.as_str(),
            C1_2_RECOVERY_REQUEST_ID
        );
        assert_eq!(reservation.conversation_id.as_str(), C1_2_CONVERSATION_ID);
        assert_eq!(reservation.requester_did.as_str(), C1_2_DID_A);
        assert_eq!(reservation.requester_device_id.as_str(), C1_2_DEVICE_ID_A);
        assert_eq!(reservation.requester_key_id.as_str(), C1_2_KEY_ID);
        assert_eq!(reservation.requester_auth_generation, 1);
        assert_eq!(
            reservation.key_package_ref,
            Bytes::from(c1_2_bytes_64_to_96())
        );
        assert_eq!(reservation.cipher_suite.as_str(), C1_2_CIPHER_SUITE);
        assert_eq!(reservation.purpose.as_str(), "leafRecovery");
        assert_eq!(reservation.expires_at.as_str(), C1_2_EXPIRES_AT);
        assert_eq!(
            reservation.bound_coordinate.conversation_id.as_str(),
            C1_2_CONVERSATION_ID
        );
        assert_eq!(reservation.key_package.framing.as_str(), "mlsMessage");
        assert_eq!(reservation.key_package.content_type.as_str(), "keyPackage");
        assert_eq!(
            reservation.key_package.bytes,
            Bytes::from(c1_2_bytes_0_to_32())
        );
        assert_eq!(
            reservation.key_package.sha256,
            Bytes::from(c1_2_bytes_32_to_64())
        );
        assert_eq!(
            reservation.key_package.key_package_ref,
            Bytes::from(c1_2_bytes_64_to_96())
        );
        assert!(reservation.extra_data.is_none());
        assert!(dto.extra_data.is_none());
    }
}

#[test]
fn c1_2_all_recovery_work_variants_project_with_consistent_status() {
    let pending = c1_2_work_source(RetainedRecoveryWorkTerminal::Pending);
    let dto = recovery_work(&pending).expect("pending work projects");
    let chat_dto::RecoveryWorkView::RecoveryWorkPendingView(pending_view) = &dto else {
        panic!("pending terminal arm projects the pending view");
    };
    assert_eq!(pending_view.status.as_str(), "pending");
    assert_eq!(pending_view.recovery_work_id.as_str(), C1_2_WELCOME_ID);
    assert_eq!(pending_view.conversation_id.as_str(), C1_2_CONVERSATION_ID);
    assert_eq!(pending_view.recipient_did.as_str(), C1_2_DID_A);
    assert_eq!(pending_view.recipient_device_id.as_str(), C1_2_DEVICE_ID_A);
    assert_eq!(pending_view.source_kind.as_str(), "welcomeExpired");
    assert_eq!(pending_view.source_id.as_str(), C1_2_WELCOME_ID);
    assert_eq!(
        pending_view.source_coordinate.conversation_id.as_str(),
        C1_2_CONVERSATION_ID
    );
    assert_eq!(pending_view.created_at.as_str(), C1_2_CREATED_AT);
    assert!(pending_view.extra_data.is_none());

    let completed = c1_2_work_source(RetainedRecoveryWorkTerminal::CompletedByTransition {
        terminal_transition_id: SmolStr::from(C1_2_TRANSITION_ID_1),
        terminal_at: SmolStr::from(C1_2_TERMINAL_AT_1),
    });
    let dto = recovery_work(&completed).expect("completed work projects");
    let chat_dto::RecoveryWorkView::RecoveryWorkCompletedByTransitionView(completed_view) = &dto
    else {
        panic!("completed terminal arm projects the completed view");
    };
    assert_eq!(completed_view.status.as_str(), "completed");
    assert_eq!(
        completed_view.terminal_transition_id.as_str(),
        C1_2_TRANSITION_ID_1
    );
    assert_eq!(completed_view.terminal_at.as_str(), C1_2_TERMINAL_AT_1);
    assert!(completed_view.extra_data.is_none());

    let superseded_by_transition =
        c1_2_work_source(RetainedRecoveryWorkTerminal::SupersededByTransition {
            terminal_transition_id: SmolStr::from(C1_2_TRANSITION_ID_2),
            terminal_at: SmolStr::from(C1_2_TERMINAL_AT_2),
        });
    let dto = recovery_work(&superseded_by_transition).expect("superseded-by-transition projects");
    let chat_dto::RecoveryWorkView::RecoveryWorkSupersededByTransitionView(superseded_view) = &dto
    else {
        panic!("superseded-by-transition arm projects its own view");
    };
    assert_eq!(superseded_view.status.as_str(), "superseded");
    assert_eq!(
        superseded_view.terminal_transition_id.as_str(),
        C1_2_TRANSITION_ID_2
    );
    assert_eq!(superseded_view.terminal_at.as_str(), C1_2_TERMINAL_AT_2);
    assert!(superseded_view.extra_data.is_none());

    let superseded_by_revocation =
        c1_2_work_source(RetainedRecoveryWorkTerminal::SupersededByRevocation {
            terminal_revocation_id: SmolStr::from(C1_2_REVOCATION_ID),
            terminal_at: SmolStr::from(C1_2_TERMINAL_AT_3),
        });
    let dto = recovery_work(&superseded_by_revocation).expect("superseded-by-revocation projects");
    let chat_dto::RecoveryWorkView::RecoveryWorkSupersededByRevocationView(superseded_view) = &dto
    else {
        panic!("superseded-by-revocation arm projects its own view");
    };
    assert_eq!(superseded_view.status.as_str(), "superseded");
    assert_eq!(
        superseded_view.terminal_revocation_id.as_str(),
        C1_2_REVOCATION_ID
    );
    assert_eq!(superseded_view.terminal_at.as_str(), C1_2_TERMINAL_AT_3);
    assert!(superseded_view.extra_data.is_none());
}

#[test]
fn c1_2_leaf_recovery_inbox_input_covers_exactly_five_variants() {
    let inputs = [
        LeafRecoveryInboxInput::leaf_recovery(c1_2_leaf_recovery_source("open")),
        LeafRecoveryInboxInput::recovery_work_pending(c1_2_work_source(
            RetainedRecoveryWorkTerminal::Pending,
        ))
        .expect("pending work inbox input"),
        LeafRecoveryInboxInput::recovery_work_completed_by_transition(c1_2_work_source(
            RetainedRecoveryWorkTerminal::CompletedByTransition {
                terminal_transition_id: SmolStr::from(C1_2_TRANSITION_ID_1),
                terminal_at: SmolStr::from(C1_2_TERMINAL_AT_1),
            },
        ))
        .expect("completed work inbox input"),
        LeafRecoveryInboxInput::recovery_work_superseded_by_transition(c1_2_work_source(
            RetainedRecoveryWorkTerminal::SupersededByTransition {
                terminal_transition_id: SmolStr::from(C1_2_TRANSITION_ID_2),
                terminal_at: SmolStr::from(C1_2_TERMINAL_AT_2),
            },
        ))
        .expect("superseded-by-transition work inbox input"),
        LeafRecoveryInboxInput::recovery_work_superseded_by_revocation(c1_2_work_source(
            RetainedRecoveryWorkTerminal::SupersededByRevocation {
                terminal_revocation_id: SmolStr::from(C1_2_REVOCATION_ID),
                terminal_at: SmolStr::from(C1_2_TERMINAL_AT_3),
            },
        ))
        .expect("superseded-by-revocation work inbox input"),
    ];
    let expected_tags = [
        "leafRecoveryView",
        "recoveryWorkPendingView",
        "recoveryWorkCompletedByTransitionView",
        "recoveryWorkSupersededByTransitionView",
        "recoveryWorkSupersededByRevocationView",
    ];
    for (input, expected_tag) in inputs.into_iter().zip(expected_tags) {
        // Exhaustive closure proof over the input union: a sixth variant
        // would fail this match at compile time.
        let input_tag = match &input {
            LeafRecoveryInboxInput::LeafRecoveryView(_) => "leafRecoveryView",
            LeafRecoveryInboxInput::RecoveryWorkPendingView(_) => "recoveryWorkPendingView",
            LeafRecoveryInboxInput::RecoveryWorkCompletedByTransitionView(_) => {
                "recoveryWorkCompletedByTransitionView"
            }
            LeafRecoveryInboxInput::RecoveryWorkSupersededByTransitionView(_) => {
                "recoveryWorkSupersededByTransitionView"
            }
            LeafRecoveryInboxInput::RecoveryWorkSupersededByRevocationView(_) => {
                "recoveryWorkSupersededByRevocationView"
            }
        };
        assert_eq!(input_tag, expected_tag);
        let item = leaf_recovery_inbox_item(input).expect("the closed inbox input projects");
        let item_tag = match &item {
            chat_dto::LeafRecoveryInboxItem::LeafRecoveryView(_) => "leafRecoveryView",
            chat_dto::LeafRecoveryInboxItem::RecoveryWorkPendingView(_) => {
                "recoveryWorkPendingView"
            }
            chat_dto::LeafRecoveryInboxItem::RecoveryWorkCompletedByTransitionView(_) => {
                "recoveryWorkCompletedByTransitionView"
            }
            chat_dto::LeafRecoveryInboxItem::RecoveryWorkSupersededByTransitionView(_) => {
                "recoveryWorkSupersededByTransitionView"
            }
            chat_dto::LeafRecoveryInboxItem::RecoveryWorkSupersededByRevocationView(_) => {
                "recoveryWorkSupersededByRevocationView"
            }
        };
        assert_eq!(item_tag, expected_tag);
        assert!(
            item_has_no_extra_data(&item),
            "{expected_tag} must materialize with no extra_data"
        );
    }
}

fn item_has_no_extra_data(item: &chat_dto::LeafRecoveryInboxItem<DefaultStr>) -> bool {
    match item {
        chat_dto::LeafRecoveryInboxItem::LeafRecoveryView(view) => view.extra_data.is_none(),
        chat_dto::LeafRecoveryInboxItem::RecoveryWorkPendingView(view) => view.extra_data.is_none(),
        chat_dto::LeafRecoveryInboxItem::RecoveryWorkCompletedByTransitionView(view) => {
            view.extra_data.is_none()
        }
        chat_dto::LeafRecoveryInboxItem::RecoveryWorkSupersededByTransitionView(view) => {
            view.extra_data.is_none()
        }
        chat_dto::LeafRecoveryInboxItem::RecoveryWorkSupersededByRevocationView(view) => {
            view.extra_data.is_none()
        }
    }
}

#[test]
fn c1_2_inbox_rejects_wrong_terminal_shape_before_materialization() {
    let completed_source = c1_2_work_source(RetainedRecoveryWorkTerminal::CompletedByTransition {
        terminal_transition_id: SmolStr::from(C1_2_TRANSITION_ID_1),
        terminal_at: SmolStr::from(C1_2_TERMINAL_AT_1),
    });
    let error = LeafRecoveryInboxInput::recovery_work_pending(completed_source)
        .err()
        .expect("a pending inbox variant cannot carry a completed terminal");
    assert_eq!(error.kind(), ProjectionErrorKind::WrongTerminalShape);

    let pending_source = c1_2_work_source(RetainedRecoveryWorkTerminal::Pending);
    let error = LeafRecoveryInboxInput::recovery_work_completed_by_transition(pending_source)
        .err()
        .expect("a completed inbox variant cannot carry a pending terminal");
    assert_eq!(error.kind(), ProjectionErrorKind::WrongTerminalShape);

    let revocation_source =
        c1_2_work_source(RetainedRecoveryWorkTerminal::SupersededByRevocation {
            terminal_revocation_id: SmolStr::from(C1_2_REVOCATION_ID),
            terminal_at: SmolStr::from(C1_2_TERMINAL_AT_3),
        });
    let error = LeafRecoveryInboxInput::recovery_work_superseded_by_transition(revocation_source)
        .err()
        .expect("a superseded-by-transition inbox variant cannot carry a revocation terminal");
    assert_eq!(error.kind(), ProjectionErrorKind::WrongTerminalShape);

    // Direct variant construction bypasses the checked constructor; the
    // projection's own re-check still fails before materialization.
    let completed_source = c1_2_work_source(RetainedRecoveryWorkTerminal::CompletedByTransition {
        terminal_transition_id: SmolStr::from(C1_2_TRANSITION_ID_1),
        terminal_at: SmolStr::from(C1_2_TERMINAL_AT_1),
    });
    let input = LeafRecoveryInboxInput::RecoveryWorkPendingView(completed_source);
    let error = leaf_recovery_inbox_item(input)
        .expect_err("the projection re-checks the variant/terminal pair");
    assert_eq!(error.kind(), ProjectionErrorKind::WrongTerminalShape);
}

#[test]
fn c1_2_checked_constructors_reject_invalid_values_before_materialization() {
    // Closed enum vocabulary.
    let error = ConversationProjectionSource::state(
        "bogus-suite",
        "group",
        c1_2_coordinates(),
        vec![],
        c1_2_metadata_snapshot(),
        vec![],
        0,
    )
    .err()
    .expect("checked-source failure");
    assert_eq!(error.kind(), ProjectionErrorKind::StringEnumViolation);
    let error = ConversationProjectionSource::state(
        C1_2_CIPHER_SUITE,
        "bogus-kind",
        c1_2_coordinates(),
        vec![],
        c1_2_metadata_snapshot(),
        vec![],
        0,
    )
    .err()
    .expect("checked-source failure");
    assert_eq!(error.kind(), ProjectionErrorKind::StringEnumViolation);
    let error =
        CheckedConversationCoordinates::new(C1_2_CONVERSATION_ID, 0, 0, &[], 0, &[], &[], "bogus")
            .err()
            .expect("checked-source failure");
    assert_eq!(error.kind(), ProjectionErrorKind::StringEnumViolation);
    let error = CheckedDeviceLeafView::new(
        C1_2_DID_A,
        C1_2_DEVICE_ID_A,
        "bogus",
        C1_2_KEY_ID,
        "active",
        None,
    )
    .err()
    .expect("checked-source failure");
    assert_eq!(error.kind(), ProjectionErrorKind::StringEnumViolation);
    let error = CheckedParticipantView::new(C1_2_DID_A, "bogus", "active", 1, None)
        .err()
        .expect("checked-source failure");
    assert_eq!(error.kind(), ProjectionErrorKind::StringEnumViolation);

    // Negative and zero-bound sequences.
    let error = ConversationProjectionSource::state(
        C1_2_CIPHER_SUITE,
        "group",
        c1_2_coordinates(),
        vec![],
        c1_2_metadata_snapshot(),
        vec![],
        -1,
    )
    .err()
    .expect("checked-source failure");
    assert_eq!(error.kind(), ProjectionErrorKind::IntegerOutOfRange);
    let error = ConversationProjectionSource::removal(
        C1_2_CONVERSATION_ID,
        C1_2_DID_A,
        C1_2_DEVICE_ID_A,
        C1_2_TRANSITION_ID_1,
        C1_2_REMOVED_AT,
        0,
    )
    .err()
    .expect("checked-source failure");
    assert_eq!(error.kind(), ProjectionErrorKind::IntegerOutOfRange);

    // Noncanonical datetime.
    let error = ConversationProjectionSource::removal(
        C1_2_CONVERSATION_ID,
        C1_2_DID_A,
        C1_2_DEVICE_ID_A,
        C1_2_TRANSITION_ID_1,
        "2026-07-30T12:00:00Z",
        7,
    )
    .err()
    .expect("checked-source failure");
    assert_eq!(error.kind(), ProjectionErrorKind::InvalidDatetime);

    // Invalid DID.
    let error = CheckedDeviceLeafView::new(
        "not-a-did",
        C1_2_DEVICE_ID_A,
        "genesis",
        C1_2_KEY_ID,
        "active",
        None,
    )
    .err()
    .expect("checked-source failure");
    assert_eq!(error.kind(), ProjectionErrorKind::InvalidDid);

    // Exact byte lengths.
    let error = c1_2_welcome_source_sha256_short()
        .err()
        .expect("checked-source failure");
    assert_eq!(error.kind(), ProjectionErrorKind::InvalidByteLength);
    let error = CheckedMetadataCryptoContext::new(
        &c1_2_bytes_0_to_15(),
        0,
        &c1_2_bytes_0_to_32(),
        1,
        &c1_2_bytes_32_to_64(),
        &c1_2_bytes_64_to_96(),
    )
    .err()
    .expect("checked-source failure");
    assert_eq!(error.kind(), ProjectionErrorKind::InvalidByteLength);

    // Strict ordering is rejected rather than sorted.
    let error = ConversationProjectionSource::state(
        C1_2_CIPHER_SUITE,
        "group",
        c1_2_coordinates(),
        vec![c1_2_leaf_a()],
        c1_2_metadata_snapshot(),
        vec![c1_2_participant_b_pending(), c1_2_participant_a()],
        1,
    )
    .err()
    .expect("checked-source failure");
    assert_eq!(error.kind(), ProjectionErrorKind::InconsistentSourceFields);
    let error = ConversationProjectionSource::state(
        C1_2_CIPHER_SUITE,
        "group",
        c1_2_coordinates(),
        vec![c1_2_leaf_a(), c1_2_leaf_a()],
        c1_2_metadata_snapshot(),
        vec![c1_2_participant_a()],
        1,
    )
    .err()
    .expect("checked-source failure");
    assert_eq!(error.kind(), ProjectionErrorKind::InconsistentSourceFields);
    let error = ConversationProjectionSource::state(
        C1_2_CIPHER_SUITE,
        "group",
        c1_2_coordinates(),
        vec![c1_2_leaf_b(), c1_2_leaf_a()],
        c1_2_metadata_snapshot(),
        vec![c1_2_participant_a()],
        1,
    )
    .err()
    .expect("checked-source failure");
    assert_eq!(error.kind(), ProjectionErrorKind::InconsistentSourceFields);

    // Cross-field consistency.
    let error = CheckedDeviceLeafView::new(
        C1_2_DID_A,
        C1_2_DEVICE_ID_A,
        "genesis",
        C1_2_KEY_ID,
        "active",
        Some(&c1_2_bytes_32_to_64()),
    )
    .err()
    .expect("checked-source failure");
    assert_eq!(error.kind(), ProjectionErrorKind::InconsistentSourceFields);
    let error = CheckedParticipantView::new(C1_2_DID_B, "member", "pending", 1, None)
        .err()
        .expect("checked-source failure");
    assert_eq!(error.kind(), ProjectionErrorKind::InconsistentSourceFields);
    let error = CheckedParticipantView::new(C1_2_DID_B, "member", "pending", 0, None)
        .err()
        .expect("checked-source failure");
    assert_eq!(error.kind(), ProjectionErrorKind::InconsistentSourceFields);
    let error = ConversationProjectionSource::close(
        C1_2_CLOSED_AT,
        C1_2_DID_B,
        C1_2_DEVICE_ID_B,
        C1_2_CONVERSATION_ID,
        "direct",
        CheckedConversationCoordinates::new(
            C1_2_TRANSITION_ID_1,
            0,
            3,
            &c1_2_bytes_0_to_32(),
            1,
            &c1_2_bytes_32_to_64(),
            &c1_2_bytes_64_to_96(),
            "active",
        )
        .expect("retired coordinates for the negative close case"),
        9,
    )
    .err()
    .expect("checked-source failure");
    assert_eq!(error.kind(), ProjectionErrorKind::InconsistentSourceFields);
    let error = RetainedLeafRecoveryProjectionSource::new(
        C1_2_RECOVERY_REQUEST_ID,
        C1_2_CONVERSATION_ID,
        C1_2_DID_A,
        C1_2_DEVICE_ID_A,
        "add",
        c1_2_coordinates(),
        "open",
        C1_2_REQUESTED_AT,
        C1_2_EXPIRES_AT,
        c1_2_reservation("consumed"),
    )
    .err()
    .expect("checked-source failure");
    assert_eq!(error.kind(), ProjectionErrorKind::InconsistentSourceFields);
    let error = RetainedRecoveryWorkProjectionSource::new(
        C1_2_WELCOME_ID,
        C1_2_CONVERSATION_ID,
        C1_2_DID_A,
        C1_2_DEVICE_ID_A,
        "welcomeExpired",
        C1_2_WELCOME_ID,
        c1_2_coordinates(),
        C1_2_CREATED_AT,
        RetainedRecoveryWorkTerminal::SupersededByRevocation {
            terminal_revocation_id: SmolStr::from(C1_2_REVOCATION_ID),
            terminal_at: SmolStr::from("2026-08-04T13:00:00Z"),
        },
    )
    .err()
    .expect("checked-source failure");
    assert_eq!(error.kind(), ProjectionErrorKind::InvalidDatetime);
}

fn c1_2_welcome_source_sha256_short(
) -> Result<RetainedWelcomeProjectionSource, chat_protocol::read_projection::ProjectionError> {
    let provenance =
        CheckedWelcomeProvenance::new(C1_2_RECOVERY_REQUEST_ID, &c1_2_bytes_64_to_96())
            .expect("fixture welcome provenance is checked");
    RetainedWelcomeProjectionSource::new(
        C1_2_WELCOME_ID,
        C1_2_CONVERSATION_ID,
        2,
        c1_2_coordinates(),
        "pending",
        &c1_2_welcome_bytes(),
        &c1_2_bytes_0_to_16(),
        C1_2_DID_A,
        C1_2_DEVICE_ID_A,
        provenance,
        C1_2_EXPIRES_AT,
    )
}

fn c1_2_bytes_0_to_15() -> Vec<u8> {
    (0..15).collect()
}

/// Concrete, dyn-compatible canonical-encode probe (generated `Serialize`
/// is generic, so a bare `&dyn serde::Serialize` cannot exist).
trait C1_2CanonicalProbe {
    fn c1_2_encode(
        &self,
    ) -> Result<
        chat_protocol::read_projection::CanonicalChatJsonV1,
        chat_protocol::read_projection::ProjectionError,
    >;
}

macro_rules! impl_c1_2_canonical_probe {
    ($($ty:ty => $def:expr),+ $(,)?) => {
        $(
            impl C1_2CanonicalProbe for $ty {
                fn c1_2_encode(
                    &self,
                ) -> Result<
                    chat_protocol::read_projection::CanonicalChatJsonV1,
                    chat_protocol::read_projection::ProjectionError,
                > {
                    chat_protocol::read_projection::encode_canonical_generated_chat_json_v1(
                        self, $def,
                    )
                }
            }
        )+
    };
}

impl_c1_2_canonical_probe!(
    chat_dto::ConversationState<DefaultStr> => "blue.catbird.chat.defs#conversationState",
    chat_dto::ConversationInventoryItem<DefaultStr> => "blue.catbird.chat.defs#conversationInventoryItem",
    chat_dto::WelcomeView<DefaultStr> => "blue.catbird.chat.defs#welcomeView",
    chat_dto::LeafRecoveryView<DefaultStr> => "blue.catbird.chat.defs#leafRecoveryView",
    chat_dto::RecoveryWorkView<DefaultStr> => "blue.catbird.chat.defs#recoveryWorkView",
    chat_dto::LeafRecoveryInboxItem<DefaultStr> => "blue.catbird.chat.defs#leafRecoveryInboxItem",
);

#[test]
fn c1_2_projected_dtos_encode_canonically_without_extra_data() {
    let state = conversation_state_view(
        &ConversationProjectionSource::state(
            C1_2_CIPHER_SUITE,
            "group",
            c1_2_coordinates(),
            vec![c1_2_leaf_a()],
            c1_2_metadata_snapshot(),
            vec![c1_2_participant_a()],
            42,
        )
        .expect("active checked state source"),
    )
    .expect("active state projects");
    let removal = conversation_inventory_item(
        &ConversationProjectionSource::removal(
            C1_2_CONVERSATION_ID,
            C1_2_DID_A,
            C1_2_DEVICE_ID_A,
            C1_2_TRANSITION_ID_1,
            C1_2_REMOVED_AT,
            7,
        )
        .expect("removal checked source"),
    )
    .expect("removal tombstone projects");
    let close = conversation_inventory_item(
        &ConversationProjectionSource::close(
            C1_2_CLOSED_AT,
            C1_2_DID_B,
            C1_2_DEVICE_ID_B,
            C1_2_CONVERSATION_ID,
            "direct",
            c1_2_coordinates(),
            9,
        )
        .expect("close checked source"),
    )
    .expect("close tombstone projects");
    let welcome = welcome_view(&c1_2_welcome_source("pending")).expect("welcome projects");
    let leaf_recovery =
        leaf_recovery_view(&c1_2_leaf_recovery_source("open")).expect("leaf recovery projects");
    let work = recovery_work(&c1_2_work_source(RetainedRecoveryWorkTerminal::Pending))
        .expect("recovery work projects");
    let inbox = leaf_recovery_inbox_item(LeafRecoveryInboxInput::leaf_recovery(
        c1_2_leaf_recovery_source("open"),
    ))
    .expect("inbox item projects");
    let cases: Vec<(&dyn C1_2CanonicalProbe, &'static str)> = vec![
        (&state, "conversationState"),
        (&removal, "conversationInventoryItem (removal)"),
        (&close, "conversationInventoryItem (close)"),
        (&welcome, "welcomeView"),
        (&leaf_recovery, "leafRecoveryView"),
        (&work, "recoveryWorkView"),
        (&inbox, "leafRecoveryInboxItem"),
    ];
    for (dto, label) in cases {
        let encoded = dto
            .c1_2_encode()
            .unwrap_or_else(|error| panic!("{label} encodes canonically: {error}"));
        assert!(
            !c1_2_contains_bytes(encoded.bytes(), b"extraData"),
            "{label} canonical bytes never contain a non-empty extraData member"
        );
        assert_eq!(
            encoded.sha256(),
            <[u8; 32]>::from(sha2::Sha256::digest(encoded.bytes())),
            "{label} SHA-256 is the digest of the returned canonical bytes"
        );
        let re_encoded = dto
            .c1_2_encode()
            .expect("{label} encodes deterministically");
        assert_eq!(
            re_encoded.bytes(),
            encoded.bytes(),
            "{label} canonical bytes are deterministic"
        );
    }
}
// ----------------------------------------------------------------------------
// C1-2 source guards (brief Step 5, corrected text).
// ----------------------------------------------------------------------------

const C1_2_READ_PROJECTION_SOURCE: &str = include_str!("../src/chat_protocol/read_projection.rs");
const C1_2_ENTITLEMENT_SOURCE: &str = include_str!("chat_protocol_g7_entitlement.rs");

fn c1_2_assert_no_forbidden_derive(source: &str, declaration: &str) {
    let start = source
        .find(declaration)
        .unwrap_or_else(|| panic!("{declaration} must exist in read_projection.rs"));
    let preceding = &source[..start];
    let Some(derive_start) = preceding.rfind("#[derive(") else {
        return;
    };
    let attribute = &preceding[derive_start..start];
    for token in ["Clone", "Debug", "Serialize", "Deserialize"] {
        assert!(
            !attribute.contains(token),
            "{declaration} must not derive {token}"
        );
    }
}

#[test]
fn c1_2_source_guards_pin_checked_surface_and_encoder_byte_flow() {
    let source = C1_2_READ_PROJECTION_SOURCE;
    // The corrected Step-5 text: canonical bytes come ONLY from the local
    // canonical writer; the single `serde_json::to_vec` serialize-once step
    // at read_projection.rs:982 is allowed and present. No path returns or
    // stores serde's output as canonical bytes.
    assert_eq!(
        count_occurrences(source, "serde_json::to_vec("),
        1,
        "the encoder serializes the generated DTO exactly once"
    );
    assert_eq!(
        count_occurrences(source, "Ok(CanonicalChatJsonV1 {"),
        1,
        "exactly one canonical-result construction exists"
    );
    assert!(source.contains("let mut canonical = Vec::with_capacity"));
    assert!(source.contains("bytes: canonical,"));
    // No test-only constructor: the file's only `#[cfg(test)]` region is the
    // encoder's unit-test module, and it never names the checked sources.
    assert_eq!(
        count_occurrences(source, "#[cfg(test)]"),
        1,
        "no checked-source constructor is test-only"
    );
    let test_region = source
        .split("#[cfg(test)]")
        .nth(1)
        .expect("the single test region");
    for type_name in [
        "ConversationProjectionSource",
        "RetainedWelcomeProjectionSource",
        "RetainedLeafRecoveryProjectionSource",
        "RetainedRecoveryWorkProjectionSource",
        "RetainedRecoveryWorkTerminal",
        "LeafRecoveryInboxInput",
        "CheckedConversationCoordinates",
    ] {
        assert!(
            !test_region.contains(type_name),
            "the checked source {type_name} must not be constructed in a test-only region"
        );
    }
    // The six frozen projection signatures exist verbatim.
    for signature in [
        "pub(crate) fn conversation_state_view(",
        "pub(crate) fn conversation_inventory_item(",
        "pub(crate) fn welcome_view(",
        "pub(crate) fn leaf_recovery_view(",
        "pub(crate) fn recovery_work(",
        "pub(crate) fn leaf_recovery_inbox_item(",
    ] {
        assert!(source.contains(signature), "{signature} must be pinned");
    }
    // No Clone/Debug/serde derives on the checked source types.
    for declaration in [
        "pub(crate) enum ConversationProjectionSource {",
        "pub(crate) struct RetainedWelcomeProjectionSource {",
        "pub(crate) struct RetainedLeafRecoveryProjectionSource {",
        "pub(crate) struct RetainedRecoveryWorkProjectionSource {",
        "pub(crate) enum RetainedRecoveryWorkTerminal {",
        "pub(crate) enum LeafRecoveryInboxInput {",
        "pub(crate) struct CheckedConversationCoordinates {",
    ] {
        c1_2_assert_no_forbidden_derive(source, declaration);
    }
    // `extra_data` can never be non-empty in produced canonical bytes: the
    // encoder's unknown-field branch rejects any non-empty `extra_data`
    // map, and the C1-2 section never sets a non-None `extra_data`.
    assert!(source.contains("a non-empty extra_data map can never smuggle one"));
    let c1_2_section = source
        .split("// C1-2: checked projection source types and the six projection functions.")
        .nth(1)
        .expect("the C1-2 section banner");
    assert_eq!(
        count_occurrences(c1_2_section, "extra_data: Some("),
        0,
        "the projections never populate extra_data"
    );
    // Every projection function is pure-test-covered in this file.
    for function in [
        "conversation_state_view",
        "conversation_inventory_item",
        "welcome_view",
        "leaf_recovery_view",
        "recovery_work",
        "leaf_recovery_inbox_item",
    ] {
        assert!(
            count_occurrences(C1_2_ENTITLEMENT_SOURCE, function) >= 3,
            "{function} must be pure-test-covered in the entitlement suite"
        );
    }
    // The guarded fixtures' byte helpers are all exercised by the tests.
    assert!(C1_2_ENTITLEMENT_SOURCE.contains("c1_2_contains_bytes"));
}
