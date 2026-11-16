//! One-time provisioning for a new, separately mounted recovery erasure log.
//!
//! The server itself only opens an existing journal and fails closed if the
//! file is missing. This command uses create_new, so it cannot overwrite a
//! journal with prior deletions.

use catbird_server::labyrinth::{
    recovery_crypto::RecoveryCrypto, recovery_tombstones::RecoveryTombstones,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let crypto = RecoveryCrypto::from_env()?
        .ok_or("set LABYRINTH_RECOVERY_SHARE_KEK_FILE and LABYRINTH_RECOVERY_SHARE_KEK_ID")?;
    let path = std::env::var("LABYRINTH_RECOVERY_SHARE_TOMBSTONE_FILE")?;
    RecoveryTombstones::provision_new(path, crypto.journal_key())?;
    println!("Recovery-share erasure journal provisioned");
    Ok(())
}
