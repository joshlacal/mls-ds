//! Real MLS engine backed by `catbird_mls::MLSContext`.
//!
//! Each [`MlsEngine`] wraps a per-user `MLSContext` with in-memory keychain
//! and a temporary SQLite database. Produces real OpenMLS key packages,
//! creates real MLS groups, and encrypts/decrypts real ciphertexts.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use catbird_mls::orchestrator::{
    direct_request_bootstrap::{
        DirectRequestBootstrapInput, DirectRequestIntroductionResult, DirectRequestWelcomeInput,
    },
    direct_request_journal::DirectRequestJournal,
    MlsCryptoContext,
};
use catbird_mls::{EpochSecretStorage, KeychainAccess, MLSContext, MLSError};

// ── In-memory keychain (no iOS Keychain in tests) ────────────────────────

#[derive(Clone)]
struct InMemoryKeychain {
    store: Arc<Mutex<HashMap<String, Vec<u8>>>>,
}

impl InMemoryKeychain {
    fn new() -> Self {
        Self {
            store: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

#[async_trait::async_trait]
impl KeychainAccess for InMemoryKeychain {
    async fn read(&self, key: String) -> std::result::Result<Option<Vec<u8>>, MLSError> {
        Ok(self.store.lock().unwrap().get(&key).cloned())
    }

    async fn write(&self, key: String, value: Vec<u8>) -> std::result::Result<(), MLSError> {
        self.store.lock().unwrap().insert(key, value);
        Ok(())
    }

    async fn delete(&self, key: String) -> std::result::Result<(), MLSError> {
        self.store.lock().unwrap().remove(&key);
        Ok(())
    }
}

// ── MlsEngine ────────────────────────────────────────────────────────────

/// Per-user MLS engine backed by a real `MLSContext`.
#[derive(Default)]
struct InMemoryEpochSecretStorage {
    secrets: Mutex<HashMap<(String, u64), Vec<u8>>>,
}

#[async_trait::async_trait]
impl EpochSecretStorage for InMemoryEpochSecretStorage {
    async fn store_epoch_secret(
        &self,
        conversation_id: String,
        epoch: u64,
        secret_data: Vec<u8>,
    ) -> bool {
        self.secrets
            .lock()
            .unwrap()
            .insert((conversation_id, epoch), secret_data);
        true
    }

    async fn get_epoch_secret(&self, conversation_id: String, epoch: u64) -> Option<Vec<u8>> {
        self.secrets
            .lock()
            .unwrap()
            .get(&(conversation_id, epoch))
            .cloned()
    }

    async fn delete_epoch_secret(&self, conversation_id: String, epoch: u64) -> bool {
        self.secrets
            .lock()
            .unwrap()
            .remove(&(conversation_id, epoch));
        true
    }

    async fn delete_epochs_before(&self, conversation_id: String, cutoff_epoch: u64) -> u32 {
        let mut secrets = self.secrets.lock().unwrap();
        let before = secrets.len();
        secrets.retain(|(stored_conversation, epoch), _| {
            stored_conversation != &conversation_id || *epoch >= cutoff_epoch
        });
        u32::try_from(before.saturating_sub(secrets.len())).unwrap_or(u32::MAX)
    }
}

pub struct MlsEngine {
    ctx: Arc<MLSContext>,
    _temp_dir: PathBuf,
    db_key: String,
    keychain: InMemoryKeychain,
}

impl Drop for MlsEngine {
    fn drop(&mut self) {
        let _ = self.ctx.flush_and_prepare_close();
        let _ = std::fs::remove_dir_all(&self._temp_dir);
    }
}

impl MlsEngine {
    /// Create a new engine with a temporary SQLite database.
    pub fn new(user_label: &str) -> Result<Self> {
        let temp_dir = std::env::temp_dir().join(format!(
            "mls-e2e-{}-{}-{}",
            user_label,
            std::process::id(),
            uuid::Uuid::new_v4().simple()
        ));
        std::fs::create_dir_all(&temp_dir)
            .with_context(|| format!("create temp dir {:?}", temp_dir))?;

        let db_path = temp_dir.join("mls.db");
        let keychain = InMemoryKeychain::new();
        let db_key = format!("test-key-{}", user_label);
        let ctx = MLSContext::new(
            db_path.to_string_lossy().to_string(),
            db_key.clone(),
            Box::new(keychain.clone()),
        )
        .map_err(|e| anyhow::anyhow!("MLSContext::new failed: {e}"))?;

        ctx.set_epoch_secret_storage(Box::new(InMemoryEpochSecretStorage::default()))
            .map_err(|e| anyhow::anyhow!("set_epoch_secret_storage failed: {e}"))?;

        Ok(Self {
            ctx,
            _temp_dir: temp_dir,
            db_key,
            keychain,
        })
    }

    /// The device's live native context, for driving a real orchestrator over
    /// this exact store.
    pub fn context(&self) -> Arc<MLSContext> {
        self.ctx.clone()
    }

    /// Flush and drop the actual native context while retaining its exact store.
    pub fn close_for_offline(mut self) -> Result<ClosedMlsEngine> {
        self.ctx
            .flush_and_prepare_close()
            .map_err(|e| anyhow::anyhow!("close native context: {e}"))?;
        let retained = ClosedMlsEngine {
            path: std::mem::take(&mut self._temp_dir),
            db_key: self.db_key.clone(),
            keychain: self.keychain.clone(),
        };
        drop(self);
        Ok(retained)
    }

    pub fn persist_request_publication(&self, request_id: &str, exact: &[u8]) -> Result<()> {
        self.ctx
            .persist_direct_request_publish(request_id, exact)
            .map_err(|e| anyhow::anyhow!("persist request publication: {e}"))
    }

    pub fn confirm_request_publication(
        &self,
        request_id: &str,
        receipt: &[u8],
        authority_key: &[u8],
    ) -> Result<()> {
        self.ctx
            .confirm_published_bootstrap(request_id, receipt, authority_key)
            .map(|_| ())
            .map_err(|e| anyhow::anyhow!("confirm published request: {e}"))
    }

    /// Generate a real MLS key package for the given identity.
    /// Returns `(key_package_bytes, hash_ref_bytes)`.
    pub fn create_key_package(&self, identity: &str) -> Result<(Vec<u8>, Vec<u8>)> {
        let result = self
            .ctx
            .create_key_package(identity.as_bytes().to_vec())
            .map_err(|e| anyhow::anyhow!("create_key_package: {e}"))?;
        Ok((result.key_package_data, result.hash_ref))
    }

    pub fn identity_public_key(&self, identity: &str) -> Result<Vec<u8>> {
        self.ctx
            .identity_public_key(identity.to_owned())
            .map_err(|error| anyhow::anyhow!("identity_public_key: {error}"))
    }

    pub fn sign_identity(&self, identity: &str, transcript: Vec<u8>) -> Result<Vec<u8>> {
        self.ctx
            .sign_with_identity_key(identity.to_owned(), transcript)
            .map_err(|error| anyhow::anyhow!("sign_with_identity_key: {error}"))
    }

    pub fn prepare_direct_request(
        &self,
        input: &DirectRequestBootstrapInput,
    ) -> Result<DirectRequestJournal> {
        self.ctx
            .prepare_direct_request_bootstrap(input)
            .map_err(|error| anyhow::anyhow!("prepare_direct_request_bootstrap: {error}"))
    }

    pub fn process_direct_request(&self, input: &DirectRequestWelcomeInput) -> Result<Vec<u8>> {
        self.ctx
            .process_direct_request_welcome(input)
            .map(|welcome| welcome.group_id)
            .map_err(|error| anyhow::anyhow!("process_direct_request_welcome: {error}"))
    }

    pub fn decrypt_direct_request(
        &self,
        input: &DirectRequestWelcomeInput,
    ) -> Result<DirectRequestIntroductionResult> {
        self.ctx
            .decrypt_direct_request_introduction(input)
            .map_err(|error| anyhow::anyhow!("decrypt_direct_request_introduction: {error}"))
    }

    /// Create a real MLS group. Returns binary group_id.
    pub fn create_group(&self, identity: &str) -> Result<Vec<u8>> {
        let result = self
            .ctx
            .create_group(identity.as_bytes().to_vec(), None)
            .map_err(|e| anyhow::anyhow!("create_group: {e}"))?;
        Ok(result.group_id)
    }

    /// Add members to a group. Returns `(commit_data, welcome_data)`.
    pub fn add_members(
        &self,
        group_id: &[u8],
        key_packages: Vec<Vec<u8>>,
    ) -> Result<(Vec<u8>, Vec<u8>)> {
        let kps = key_packages
            .into_iter()
            .map(|data| catbird_mls::KeyPackageData { data })
            .collect();
        let result = self
            .ctx
            .add_members(group_id.to_vec(), kps)
            .map_err(|e| anyhow::anyhow!("add_members: {e}"))?;
        Ok((result.commit_data, result.welcome_data))
    }

    /// Process a welcome message to join a group. Returns binary group_id.
    pub fn process_welcome(&self, welcome_bytes: &[u8], identity: &str) -> Result<Vec<u8>> {
        let result = self
            .ctx
            .process_welcome(welcome_bytes.to_vec(), identity.as_bytes().to_vec(), None)
            .map_err(|e| anyhow::anyhow!("process_welcome: {e}"))?;
        Ok(result.group_id)
    }

    /// Delegate to the shipping canonical-AAD encryption path, not a test bypass.
    pub fn encrypt_canonical(
        &self,
        group_id: &[u8],
        plaintext: &[u8],
        aad: Vec<u8>,
        expected_epoch: u64,
    ) -> Result<Vec<u8>> {
        self.ctx
            .encrypt_message_with_aad(group_id.to_vec(), plaintext.to_vec(), aad, expected_epoch)
            .map(|result| result.ciphertext)
            .map_err(|e| anyhow::anyhow!("canonical encryption: {e}"))
    }

    pub fn decrypt_authenticated(
        &self,
        group_id: &[u8],
        ciphertext: &[u8],
    ) -> Result<catbird_mls::DecryptResult> {
        self.ctx
            .decrypt_message(group_id.to_vec(), ciphertext.to_vec())
            .map_err(|e| anyhow::anyhow!("authenticated decryption: {e}"))
    }

    pub fn epoch(&self, group_id: &[u8]) -> Result<u64> {
        self.ctx
            .get_epoch(group_id.to_vec())
            .map_err(|e| anyhow::anyhow!("native epoch: {e}"))
    }

    /// Encrypt a plaintext message. Returns `(padded_ciphertext, padded_size)`.
    pub fn encrypt(&self, group_id: &[u8], plaintext: &[u8]) -> Result<(Vec<u8>, u32)> {
        let result = self
            .ctx
            .encrypt_message(group_id.to_vec(), plaintext.to_vec())
            .map_err(|e| anyhow::anyhow!("encrypt_message: {e}"))?;
        Ok((result.ciphertext, result.padded_size))
    }

    /// Decrypt a ciphertext. Returns plaintext bytes.
    pub fn decrypt(&self, group_id: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
        let result = self
            .ctx
            .decrypt_message(group_id.to_vec(), ciphertext.to_vec())
            .map_err(|e| anyhow::anyhow!("decrypt_message: {e}"))?;
        Ok(result.plaintext)
    }

    /// Process an incoming MLS message (commit, proposal, application message).
    pub fn process_message(
        &self,
        group_id: &[u8],
        message_data: &[u8],
    ) -> Result<catbird_mls::ProcessedContent> {
        self.ctx
            .process_message(group_id.to_vec(), message_data.to_vec())
            .map_err(|e| anyhow::anyhow!("process_message: {e}"))
    }

    /// Extract the identity (DID) from a key package.
    pub fn extract_key_package_identity(kp_bytes: &[u8]) -> Result<String> {
        catbird_mls::mls_extract_key_package_identity(kp_bytes.to_vec())
            .map_err(|e| anyhow::anyhow!("extract_kp_identity: {e}"))
    }

    /// Extract the signature public key from a key package.
    pub fn extract_key_package_sig_key(kp_bytes: &[u8]) -> Result<Vec<u8>> {
        catbird_mls::mls_extract_key_package_signature_public_key(kp_bytes.to_vec())
            .map_err(|e| anyhow::anyhow!("extract_kp_sig_key: {e}"))
    }

    // ---- merged from main (b7838df3): clean-v2 federation helpers ----
    pub fn sign_with_identity_key(&self, identity: &str, payload: &[u8]) -> Result<Vec<u8>> {
        self.ctx
            .sign_with_identity_key(identity.to_string(), payload.to_vec())
            .map_err(|e| anyhow::anyhow!("sign_with_identity_key: {e}"))
    }

    /// Export a real ratchet-tree GroupInfo for the current group state.
    pub fn export_group_info(&self, group_id: &[u8], identity: &str) -> Result<Vec<u8>> {
        self.ctx
            .export_group_info(group_id.to_vec(), identity.as_bytes().to_vec())
            .map_err(|e| anyhow::anyhow!("export_group_info: {e}"))
    }

    pub fn group_context_hash(&self, group_id: &[u8]) -> Result<Vec<u8>> {
        self.ctx
            .get_group_context_hash(group_id.to_vec())
            .map_err(|e| anyhow::anyhow!("get_group_context_hash: {e}"))
    }

    pub fn confirmation_tag(&self, group_id: &[u8]) -> Result<Vec<u8>> {
        self.ctx
            .get_confirmation_tag(group_id.to_vec())
            .map_err(|e| anyhow::anyhow!("get_confirmation_tag: {e}"))
    }

    /// Stage a real MLS self-update commit.
    pub fn self_update(&self, group_id: &[u8]) -> Result<Vec<u8>> {
        self.ctx
            .self_update(group_id.to_vec())
            .map(|result| result.commit_data)
            .map_err(|e| anyhow::anyhow!("self_update: {e}"))
    }

    pub fn self_update_with_aad(&self, group_id: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        self.ctx
            .self_update_with_aad_for_test(group_id.to_vec(), aad.to_vec())
            .map(|result| result.commit_data)
            .map_err(|e| anyhow::anyhow!("self_update_with_aad: {e}"))
    }

    pub fn add_members_with_aad(
        &self,
        group_id: &[u8],
        key_packages: Vec<Vec<u8>>,
        aad: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>)> {
        let key_packages = key_packages
            .into_iter()
            .map(|data| catbird_mls::KeyPackageData { data })
            .collect();
        let result = self
            .ctx
            .add_members_with_aad(group_id.to_vec(), key_packages, Some(aad.to_vec()))
            .map_err(|e| anyhow::anyhow!("add_members_with_aad: {e}"))?;
        Ok((
            result.commit_data,
            result.welcome_data,
            result
                .next_group_context_hash
                .context("add_members_with_aad omitted next GroupContext hash")?,
            result
                .next_confirmation_tag
                .context("add_members_with_aad omitted next confirmation tag")?,
        ))
    }

    /// Merge pending commit locally to advance epoch after server ACK.
    pub fn merge_pending_commit(&self, group_id: &[u8]) -> Result<u64> {
        let result = self
            .ctx
            .merge_pending_commit(group_id.to_vec())
            .map_err(|e| anyhow::anyhow!("merge_pending_commit: {e}"))?;
        Ok(result.new_epoch)
    }

    pub fn encrypt_with_aad(
        &self,
        group_id: &[u8],
        plaintext: &[u8],
        aad: &[u8],
    ) -> Result<(Vec<u8>, u32)> {
        let result = self
            .ctx
            .encrypt_message_with_aad_for_test(
                group_id.to_vec(),
                plaintext.to_vec(),
                aad.to_vec(),
            )
            .map_err(|e| anyhow::anyhow!("encrypt_message_with_aad: {e}"))?;
        Ok((result.ciphertext, result.padded_size))
    }

    /// Merge an incoming commit staged by [`Self::process_message`].
    pub fn merge_incoming_commit(&self, group_id: &[u8], target_epoch: u64) -> Result<u64> {
        self.ctx
            .merge_incoming_commit(group_id.to_vec(), target_epoch)
            .map_err(|e| anyhow::anyhow!("merge_incoming_commit: {e}"))
    }
}

/// Offline state contains custody, not a running MLS context or network client.
pub struct ClosedMlsEngine {
    path: PathBuf,
    db_key: String,
    keychain: InMemoryKeychain,
}
impl ClosedMlsEngine {
    pub fn reopen(self) -> Result<MlsEngine> {
        let ctx = MLSContext::new(
            self.path.join("mls.db").to_string_lossy().into_owned(),
            self.db_key.clone(),
            Box::new(self.keychain.clone()),
        )
        .map_err(|e| anyhow::anyhow!("reopen captured native store: {e}"))?;
        Ok(MlsEngine {
            ctx,
            _temp_dir: self.path,
            db_key: self.db_key,
            keychain: self.keychain,
        })
    }
}
