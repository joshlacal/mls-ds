//! Durable erasure authority outside PostgreSQL backups.
//!
//! A share deletion is appended and synced here before its database row is
//! cleared. Startup must open the existing, separately mounted journal and
//! replay it before any HTTP route is served. The OS file lock deliberately
//! permits only one writer process for this journal. A missing, malformed, or
//! locked journal fails startup closed.

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::sync::Mutex;

use chrono::{DateTime, SecondsFormat, Utc};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use sqlx::PgPool;

use super::error::{LabyrinthError, LabyrinthResult};

const HEADER: &str = "catbird-labyrinth-recovery-tombstones-v1";
const MAC_DOMAIN: &[u8] = b"catbird-labyrinth-recovery-tombstone-mac-v1\0";
const MAX_FILE_BYTES: u64 = 256 * 1024 * 1024;
type HmacSha256 = Hmac<Sha256>;
type Key = (String, [u8; 16]);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Delete,
    Purge,
}

impl Kind {
    fn as_str(self) -> &'static str {
        match self {
            Kind::Delete => "delete",
            Kind::Purge => "purge",
        }
    }

    fn parse(value: &str) -> Result<Self, String> {
        match value {
            "delete" => Ok(Self::Delete),
            "purge" => Ok(Self::Purge),
            _ => Err("unknown recovery tombstone kind".into()),
        }
    }
}

#[derive(Clone)]
struct Tombstone {
    did: String,
    vid: [u8; 16],
    at: DateTime<Utc>,
    kind: Kind,
}

struct JournalState {
    file: File,
    tombstones: HashMap<Key, Tombstone>,
    failed: bool,
}

/// Process-local index over a durable, exclusively locked journal.
pub struct RecoveryTombstones {
    state: Mutex<JournalState>,
    mac_key: [u8; 32],
}

impl RecoveryTombstones {
    /// Provision a *new* journal. Production startup calls `open_existing`;
    /// this explicit provisioning path is useful for a new volume or a test.
    pub fn provision_new(path: impl AsRef<Path>, key: [u8; 32]) -> Result<Self, String> {
        let path = path.as_ref();
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options
            .open(path)
            .map_err(|error| format!("provision recovery tombstone journal: {error}"))?;
        file.write_all(header_line(&key).as_bytes())
            .map_err(|error| format!("write recovery tombstone header: {error}"))?;
        file.sync_all()
            .map_err(|error| format!("sync recovery tombstone header: {error}"))?;
        drop(file);
        if let Some(parent) = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            File::open(parent)
                .and_then(|directory| directory.sync_all())
                .map_err(|error| format!("sync recovery tombstone directory: {error}"))?;
        }
        Self::open_existing(path, key)
    }

    /// Open and validate a journal supplied by a separate persistent mount.
    /// Never creates or repairs a missing/partial file at serving startup.
    pub fn open_existing(path: impl AsRef<Path>, key: [u8; 32]) -> Result<Self, String> {
        let path = path.as_ref();
        let metadata = std::fs::symlink_metadata(path)
            .map_err(|error| format!("recovery tombstone journal is missing: {error}"))?;
        if !metadata.file_type().is_file() {
            return Err("recovery tombstone journal must be a regular, non-symlink file".into());
        }
        if metadata.len() > MAX_FILE_BYTES {
            return Err("recovery tombstone journal exceeds maximum size".into());
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if metadata.permissions().mode() & 0o077 != 0 {
                return Err("recovery tombstone journal must be private (mode 0600)".into());
            }
        }
        let mut file = OpenOptions::new()
            .read(true)
            .append(true)
            .open(path)
            .map_err(|error| format!("open recovery tombstone journal: {error}"))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let opened = file
                .metadata()
                .map_err(|error| format!("stat recovery tombstone journal: {error}"))?;
            if (opened.dev(), opened.ino()) != (metadata.dev(), metadata.ino()) {
                return Err("recovery tombstone journal changed while opening".into());
            }
        }
        file.try_lock()
            .map_err(|error| format!("recovery tombstone journal is already in use: {error}"))?;
        let mut reader_file = &mut file;
        if metadata.len() == 0 {
            return Err("recovery tombstone journal header is missing".into());
        }
        reader_file
            .seek(SeekFrom::End(-1))
            .map_err(|error| format!("seek recovery tombstone journal: {error}"))?;
        let mut final_byte = [0_u8; 1];
        reader_file
            .read_exact(&mut final_byte)
            .map_err(|error| format!("read recovery tombstone journal end: {error}"))?;
        if final_byte != [b'\n'] {
            return Err("recovery tombstone journal has a truncated final record".into());
        }
        reader_file
            .seek(SeekFrom::Start(0))
            .map_err(|error| format!("seek recovery tombstone journal: {error}"))?;
        let mut lines = BufReader::new(reader_file).lines();
        let expected_header = header_line(&key);
        if lines
            .next()
            .transpose()
            .map_err(|error| error.to_string())?
            .as_deref()
            != Some(expected_header.trim_end_matches('\n'))
        {
            return Err("recovery tombstone journal header is missing or invalid".into());
        }
        let mut tombstones = HashMap::new();
        for line in lines {
            let line = line.map_err(|error| format!("read recovery tombstone journal: {error}"))?;
            if line.len() > 1024 {
                return Err("recovery tombstone journal record is too long".into());
            }
            let item = decode_record(&line, &key)?;
            tombstones
                .entry((item.did.clone(), item.vid))
                .or_insert(item);
        }
        Ok(Self {
            state: Mutex::new(JournalState {
                file,
                tombstones,
                failed: false,
            }),
            mac_key: key,
        })
    }

    pub fn contains(&self, did: &str, vid: &[u8; 16]) -> bool {
        let state = self
            .state
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        state.failed || state.tombstones.contains_key(&(did.to_owned(), *vid))
    }

    pub fn deleted_at(&self, did: &str, vid: &[u8; 16]) -> Option<DateTime<Utc>> {
        self.state
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .tombstones
            .get(&(did.to_owned(), *vid))
            .map(|item| item.at)
    }

    pub fn append_delete(
        &self,
        did: &str,
        vid: &[u8; 16],
        at: DateTime<Utc>,
    ) -> Result<(), String> {
        self.append(did, vid, at, Kind::Delete)
    }

    pub fn append_purge(&self, did: &str, vid: &[u8; 16], at: DateTime<Utc>) -> Result<(), String> {
        self.append(did, vid, at, Kind::Purge)
    }

    fn append(
        &self,
        did: &str,
        vid: &[u8; 16],
        at: DateTime<Utc>,
        kind: Kind,
    ) -> Result<(), String> {
        if crate::labyrinth::wire::bytes::check_did("did", did).is_err() {
            return Err("recovery tombstone DID is invalid".into());
        }
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        if state.failed {
            return Err("recovery tombstone journal was previously lost".into());
        }
        if state.tombstones.contains_key(&(did.to_owned(), *vid)) {
            return Ok(());
        }
        let item = Tombstone {
            did: did.to_owned(),
            vid: *vid,
            at,
            kind,
        };
        let line = encode_record(&item, &self.mac_key);
        if let Err(error) = state.file.write_all(line.as_bytes()) {
            state.failed = true;
            return Err(format!("append recovery tombstone: {error}"));
        }
        if let Err(error) = state.file.sync_all() {
            state.failed = true;
            return Err(format!("sync recovery tombstone: {error}"));
        }
        state.tombstones.insert((did.to_owned(), *vid), item);
        Ok(())
    }

    /// Replay all durable erasures into a freshly restored database before
    /// serving requests. A replayed deletion also restores the audit event.
    pub async fn replay(&self, pool: &PgPool) -> LabyrinthResult<usize> {
        let items: Vec<Tombstone> = {
            let state = self
                .state
                .lock()
                .unwrap_or_else(|poison| poison.into_inner());
            if state.failed {
                return Err(LabyrinthError::internal());
            }
            state.tombstones.values().cloned().collect()
        };
        let recorded: std::collections::HashSet<Key> = items
            .iter()
            .map(|item| (item.did.clone(), item.vid))
            .collect();
        let mut tx = pool.begin().await?;
        let database_tombstones: Vec<(String, Vec<u8>)> = sqlx::query_as(
            "SELECT owner_did,vdevice_id FROM labyrinth.recovery_shares \
             WHERE deleted_at IS NOT NULL",
        )
        .fetch_all(&mut *tx)
        .await?;
        for (did, vid) in database_tombstones {
            let vid: [u8; 16] = vid.try_into().map_err(|_| LabyrinthError::internal())?;
            if !recorded.contains(&(did, vid)) {
                tracing::error!("recovery tombstone journal omits a database tombstone");
                return Err(LabyrinthError::internal());
            }
        }
        let mut erased = 0;
        for item in items {
            let changed = sqlx::query(
                "UPDATE labyrinth.recovery_shares SET encrypted_share=NULL, nonce=NULL, \
                 kek_key_id=NULL, fetch_verifier=NULL, deleted_at=$3 \
                 WHERE owner_did=$1 AND vdevice_id=$2 AND deleted_at IS NULL",
            )
            .bind(&item.did)
            .bind(item.vid.as_slice())
            .bind(item.at)
            .execute(&mut *tx)
            .await?
            .rows_affected();
            if changed != 0 {
                erased += changed as usize;
                sqlx::query(
                    "INSERT INTO labyrinth.recovery_share_events \
                     (owner_did,vdevice_id,kind,actor_device_id,at) VALUES($1,$2,$3,NULL,$4)",
                )
                .bind(&item.did)
                .bind(item.vid.as_slice())
                .bind(item.kind.as_str())
                .bind(item.at)
                .execute(&mut *tx)
                .await?;
            }
        }
        tx.commit().await?;
        Ok(erased)
    }
}

fn encode_record(item: &Tombstone, key: &[u8; 32]) -> String {
    let body = format!(
        "v1\t{}\t{}\t{}\t{}",
        item.did,
        hex::encode(item.vid),
        item.at.to_rfc3339_opts(SecondsFormat::Millis, true),
        item.kind.as_str()
    );
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts 32-byte keys");
    mac.update(MAC_DOMAIN);
    mac.update(body.as_bytes());
    format!("{body}\t{}\n", hex::encode(mac.finalize().into_bytes()))
}

fn header_line(key: &[u8; 32]) -> String {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts 32-byte keys");
    mac.update(MAC_DOMAIN);
    mac.update(b"header\0");
    mac.update(HEADER.as_bytes());
    format!("{HEADER}\t{}\n", hex::encode(mac.finalize().into_bytes()))
}

fn decode_record(line: &str, key: &[u8; 32]) -> Result<Tombstone, String> {
    let (body, tag) = line
        .rsplit_once('\t')
        .ok_or_else(|| "recovery tombstone journal record has no MAC".to_owned())?;
    let tag = hex::decode(tag).map_err(|_| "recovery tombstone MAC is not hex".to_owned())?;
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts 32-byte keys");
    mac.update(MAC_DOMAIN);
    mac.update(body.as_bytes());
    mac.verify_slice(&tag)
        .map_err(|_| "recovery tombstone journal MAC mismatch".to_owned())?;
    let fields: Vec<&str> = body.split('\t').collect();
    let ["v1", did, vid_hex, at_text, kind_text] = fields.as_slice() else {
        return Err("recovery tombstone journal record shape is invalid".into());
    };
    if crate::labyrinth::wire::bytes::check_did("did", did).is_err() {
        return Err("recovery tombstone journal DID is invalid".into());
    }
    let vid: [u8; 16] = hex::decode(vid_hex)
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or_else(|| "recovery tombstone journal vdeviceId is invalid".to_owned())?;
    let at = DateTime::parse_from_rfc3339(at_text)
        .map_err(|_| "recovery tombstone journal time is invalid".to_owned())?
        .with_timezone(&Utc);
    Ok(Tombstone {
        did: (*did).to_owned(),
        vid,
        at,
        kind: Kind::parse(kind_text)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn journal_mac_rejects_changed_identity_and_key() {
        let key = [0x42; 32];
        let item = Tombstone {
            did: "did:plc:abcdefghijklmnopqrstuvwx".into(),
            vid: [0x11; 16],
            at: DateTime::parse_from_rfc3339("2026-11-16T12:00:00Z")
                .unwrap()
                .with_timezone(&Utc),
            kind: Kind::Delete,
        };
        let line = encode_record(&item, &key);
        assert!(decode_record(line.trim_end(), &key).is_ok());
        assert!(decode_record(line.trim_end(), &[0x43; 32]).is_err());
        let changed = line.replace("abcdefghijklmnopqrstuvwx", "abcdefghijklmnopqrstuvwy");
        assert!(decode_record(changed.trim_end(), &key).is_err());
        assert_ne!(header_line(&key), header_line(&[0x43; 32]));
    }
}
