use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use crate::error::{MLSError, Result};

// Placeholder for OpenMLS provider
pub struct MLSProvider;

pub struct MLSContext {
    groups: Arc<Mutex<HashMap<Vec<u8>, Vec<u8>>>>, // group_id -> serialized state
}

impl MLSContext {
    pub fn new() -> Self {
        Self {
            groups: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn add_group(&self, group_id: Vec<u8>, state: Vec<u8>) -> Result<()> {
        let mut groups = self.groups.lock()
            .map_err(|e| MLSError::ThreadSafety(e.to_string()))?;
        groups.insert(group_id, state);
        Ok(())
    }

    pub fn get_group(&self, group_id: &[u8]) -> Result<Vec<u8>> {
        let groups = self.groups.lock()
            .map_err(|e| MLSError::ThreadSafety(e.to_string()))?;
        groups.get(group_id)
            .cloned()
            .ok_or_else(|| MLSError::GroupNotFound(hex::encode(group_id)))
    }

    pub fn remove_group(&self, group_id: &[u8]) -> Result<()> {
        let mut groups = self.groups.lock()
            .map_err(|e| MLSError::ThreadSafety(e.to_string()))?;
        groups.remove(group_id);
        Ok(())
    }
}

impl Default for MLSContext {
    fn default() -> Self {
        Self::new()
    }
}

unsafe impl Send for MLSContext {}
unsafe impl Sync for MLSContext {}
