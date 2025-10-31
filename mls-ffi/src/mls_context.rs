use std::collections::HashMap;
use openmls::prelude::*;
use openmls::group::PURE_CIPHERTEXT_WIRE_FORMAT_POLICY;
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;

use crate::error::MLSError;

pub struct GroupState {
    pub group: MlsGroup,
    pub signer_public_key: Vec<u8>,
}

pub struct MLSContextInner {
    provider: OpenMlsRustCrypto,
    groups: HashMap<Vec<u8>, GroupState>,
    signers_by_identity: HashMap<Vec<u8>, Vec<u8>>, // identity -> public key bytes
    staged_welcomes: HashMap<String, StagedWelcome>,
    staged_commits: HashMap<String, Box<StagedCommit>>,
}

impl MLSContextInner {
    pub fn new() -> Self {
        Self {
            provider: OpenMlsRustCrypto::default(),
            groups: HashMap::new(),
            signers_by_identity: HashMap::new(),
            staged_welcomes: HashMap::new(),
            staged_commits: HashMap::new(),
        }
    }

    pub fn provider(&self) -> &OpenMlsRustCrypto {
        &self.provider
    }

    pub fn create_group(&mut self, identity: &str, config: crate::types::GroupConfig) -> Result<Vec<u8>, MLSError> {
        eprintln!("[MLS-CONTEXT] create_group: Starting for identity '{}'", identity);
        
        let credential = Credential::new(
            CredentialType::Basic,
            identity.as_bytes().to_vec()
        );
        eprintln!("[MLS-CONTEXT] Credential created");
        
        eprintln!("[MLS-CONTEXT] Generating signature keys...");
        let signature_keys = SignatureKeyPair::new(SignatureScheme::ED25519)
            .map_err(|e| {
                eprintln!("[MLS-CONTEXT] ERROR: Failed to create signature keys: {:?}", e);
                MLSError::OpenMLSError
            })?;
        eprintln!("[MLS-CONTEXT] Signature keys generated");

        eprintln!("[MLS-CONTEXT] Storing signature keys...");
        signature_keys.store(self.provider.storage())
            .map_err(|e| {
                eprintln!("[MLS-CONTEXT] ERROR: Failed to store signature keys: {:?}", e);
                MLSError::OpenMLSError
            })?;
        eprintln!("[MLS-CONTEXT] Signature keys stored");

        // Build group config with forward secrecy settings
        eprintln!("[MLS-CONTEXT] Building group config...");
        let group_config = MlsGroupCreateConfig::builder()
            .max_past_epochs(config.max_past_epochs as usize)
            .sender_ratchet_configuration(SenderRatchetConfiguration::new(
                config.out_of_order_tolerance,
                config.maximum_forward_distance,
            ))
            .wire_format_policy(PURE_CIPHERTEXT_WIRE_FORMAT_POLICY)
            .build();
        eprintln!("[MLS-CONTEXT] Group config built");

        eprintln!("[MLS-CONTEXT] Creating MLS group...");
        let group = MlsGroup::new(
            &self.provider,
            &signature_keys,
            &group_config,
            CredentialWithKey {
                credential,
                signature_key: signature_keys.public().into(),
            },
        )
        .map_err(|e| {
            eprintln!("[MLS-CONTEXT] ERROR: Failed to create MLS group: {:?}", e);
            MLSError::OpenMLSError
        })?;
        eprintln!("[MLS-CONTEXT] MLS group created successfully");

        let group_id = group.group_id().as_slice().to_vec();
        eprintln!("[MLS-CONTEXT] Group ID: {}", hex::encode(&group_id));

        self.groups.insert(group_id.clone(), GroupState {
            group,
            signer_public_key: signature_keys.public().to_vec(),
        });
        eprintln!("[MLS-CONTEXT] Group state stored");

        self.signers_by_identity.insert(identity.as_bytes().to_vec(), signature_keys.public().to_vec());
        eprintln!("[MLS-CONTEXT] Signer mapped to identity");

        eprintln!("[MLS-CONTEXT] create_group: Completed successfully");
        Ok(group_id)
    }

    pub fn add_group(&mut self, group: MlsGroup, identity: &str) -> Result<(), MLSError> {
        let signer_pk = self.signers_by_identity
            .get(identity.as_bytes())
            .ok_or_else(|| MLSError::group_not_found(format!("No signer for identity: {}", identity)))?
            .clone();
        
        let group_id = group.group_id().as_slice().to_vec();
        self.groups.insert(group_id, GroupState { 
            group, 
            signer_public_key: signer_pk 
        });
        Ok(())
    }

    pub fn signer_for_group(&self, group_id: &GroupId) -> Result<SignatureKeyPair, MLSError> {
        let state = self.groups
            .get(group_id.as_slice())
            .ok_or_else(|| MLSError::group_not_found(hex::encode(group_id.as_slice())))?;
        
        // Load signer from storage using public key
        SignatureKeyPair::read(
            self.provider.storage(), 
            &state.signer_public_key,
            SignatureScheme::ED25519
        )
            .ok_or_else(|| MLSError::OpenMLSError)
    }

    pub fn with_group<T, F: FnOnce(&mut MlsGroup, &OpenMlsRustCrypto, &SignatureKeyPair) -> Result<T, MLSError>>(
        &mut self,
        group_id: &GroupId,
        f: F,
    ) -> Result<T, MLSError> {
        eprintln!("[MLS-CONTEXT] with_group: Looking up group {}", hex::encode(group_id.as_slice()));
        
        // Check if group exists first (before mutable borrow)
        if !self.groups.contains_key(group_id.as_slice()) {
            eprintln!("[MLS-CONTEXT] ERROR: Group not found: {}", hex::encode(group_id.as_slice()));
            let available: Vec<String> = self.groups.keys().map(|k| hex::encode(k)).collect();
            eprintln!("[MLS-CONTEXT] Available groups: {:?}", available);
            return Err(MLSError::group_not_found(hex::encode(group_id.as_slice())));
        }
        
        // Now safe to get mutable reference
        let state = match self.groups.get_mut(group_id.as_slice()) {
            Some(s) => s,
            None => return Err(MLSError::group_not_found(hex::encode(group_id.as_slice()))),
        };
        eprintln!("[MLS-CONTEXT] Group found");
        
        // Load signer from storage
        eprintln!("[MLS-CONTEXT] Loading signer from storage...");
        let signer = SignatureKeyPair::read(
            self.provider.storage(), 
            &state.signer_public_key,
            SignatureScheme::ED25519
        )
            .ok_or_else(|| {
                eprintln!("[MLS-CONTEXT] ERROR: Failed to load signer from storage");
                MLSError::OpenMLSError
            })?;
        eprintln!("[MLS-CONTEXT] Signer loaded successfully");
        
        f(&mut state.group, &self.provider, &signer)
    }

    pub fn with_group_ref<T, F: FnOnce(&MlsGroup, &OpenMlsRustCrypto) -> Result<T, MLSError>>(
        &self,
        group_id: &GroupId,
        f: F,
    ) -> Result<T, MLSError> {
        let state = self.groups
            .get(group_id.as_slice())
            .ok_or_else(|| MLSError::group_not_found(hex::encode(group_id.as_slice())))?;
        f(&state.group, &self.provider)
    }

    pub fn store_staged_welcome(&mut self, id: String, staged: StagedWelcome) {
        self.staged_welcomes.insert(id, staged);
    }

    pub fn take_staged_welcome(&mut self, id: &str) -> Result<StagedWelcome, MLSError> {
        self.staged_welcomes.remove(id)
            .ok_or_else(|| MLSError::invalid_input("Staged welcome not found"))
    }

    pub fn store_staged_commit(&mut self, id: String, staged: Box<StagedCommit>) {
        self.staged_commits.insert(id, staged);
    }

    pub fn take_staged_commit(&mut self, id: &str) -> Result<Box<StagedCommit>, MLSError> {
        self.staged_commits.remove(id)
            .ok_or_else(|| MLSError::invalid_input("Staged commit not found"))
    }

    /// Check if a group exists in the context
    pub fn has_group(&self, group_id: &[u8]) -> bool {
        self.groups.contains_key(group_id)
    }
}
