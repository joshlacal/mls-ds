//! Durable erasure authority outside PostgreSQL backups.
//!
//! A share deletion is appended and synced here before its database row is
//! cleared. Startup must open the existing, separately mounted journal and
//! replay it before any HTTP route is served. The OS file lock deliberately
//! permits only one writer process for this journal. A missing, malformed, or
//! locked journal fails startup closed.

use std::collections::{HashMap, HashSet};
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use chrono::{DateTime, SecondsFormat, Utc};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use sqlx::PgPool;

use super::error::{LabyrinthError, LabyrinthResult};

const HEADER: &str = "catbird-labyrinth-recovery-tombstones-v1";
const MAC_DOMAIN: &[u8] = b"catbird-labyrinth-recovery-tombstone-mac-v1\0";
const SEGMENT_BYTES: u64 = 256 * 1024 * 1024;
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
    _root_lock: File,
    file: File,
    active_id: Option<uuid::Uuid>,
    bytes: u64,
    tombstones: HashMap<Key, Tombstone>,
    failed: bool,
}

/// Process-local index over a durable, exclusively locked journal.
pub struct RecoveryTombstones {
    state: Mutex<JournalState>,
    path: PathBuf,
    segment_bytes: u64,
    mac_key: [u8; 32],
}

impl RecoveryTombstones {
    /// Provision a *new* journal. Production startup calls `open_existing`;
    /// this explicit provisioning path is useful for a new volume or a test.
    pub fn provision_new(path: impl AsRef<Path>, key: [u8; 32]) -> Result<Self, String> {
        let path = path.as_ref();
        create_segment(path, &header_line(&key))?;
        Self::open_existing(path, key)
    }

    /// Open the v1 base and every linked segment. The base inode lock is
    /// retained for the lifetime of the writer even after a rollover.
    pub fn open_existing(path: impl AsRef<Path>, key: [u8; 32]) -> Result<Self, String> {
        let path = path.as_ref().to_path_buf();
        let root = open_segment(&path)?;
        root.try_lock()
            .map_err(|e| format!("recovery tombstone journal is already in use: {e}"))?;
        let mut file = root.try_clone().map_err(|e| e.to_string())?;
        let mut active_id = None;
        let mut expected = header_line(&key);
        let mut visited = HashSet::new();
        let mut tombstones = HashMap::new();
        loop {
            file.seek(SeekFrom::Start(0)).map_err(|e| e.to_string())?;
            let mut reader = BufReader::new(&file);
            let mut line = String::new();
            if !read_line(&mut reader, &mut line)? || line != expected {
                return Err("recovery tombstone journal header is missing or invalid".into());
            }
            let mut successor = None;
            while read_line(&mut reader, &mut line)? {
                if successor.is_some() {
                    return Err("records after recovery tombstone segment seal".into());
                }
                if line.starts_with("next-v2\t") {
                    let body = verified_control(&line, &key)?;
                    let fields: Vec<_> = body.split('\t').collect();
                    let ["next-v2", previous, next] = fields.as_slice() else {
                        return Err("invalid recovery tombstone segment link".into());
                    };
                    let id = uuid::Uuid::parse_str(next).map_err(|e| e.to_string())?;
                    if *previous != segment_label(active_id) || !visited.insert(id) {
                        return Err("invalid recovery tombstone segment chain".into());
                    }
                    successor = Some(id);
                } else {
                    let item = decode_record(line.trim_end_matches('\n'), &key)?;
                    tombstones
                        .entry((item.did.clone(), item.vid))
                        .or_insert(item);
                }
            }
            let Some(id) = successor else { break };
            expected = segment_header(&key, active_id, id);
            file = open_segment(&segment_path(&path, id))?;
            active_id = Some(id);
        }
        let bytes = file.metadata().map_err(|e| e.to_string())?.len();
        Ok(Self {
            state: Mutex::new(JournalState {
                _root_lock: root,
                file,
                bytes,
                active_id,
                tombstones,
                failed: false,
            }),
            path,
            segment_bytes: SEGMENT_BYTES,
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
        // The old writer allowed valid v1 files above 256 MiB. Stream them on
        // startup and roll forward on their next append; never rewrite the base.
        if state.bytes.saturating_add(line.len() as u64) > self.segment_bytes {
            let id = uuid::Uuid::new_v4();
            let header = segment_header(&self.mac_key, state.active_id, id);
            let file = create_segment(&segment_path(&self.path, id), &header)?;
            let seal = control_line(
                &format!("next-v2\t{}\t{id}", segment_label(state.active_id)),
                &self.mac_key,
            );
            // The successor and directory entry are durable before its link.
            // An interrupted pre-link creation leaves an unreferenced file.
            state.append_synced(&seal)?;
            state.file = file;
            state.active_id = Some(id);
            state.bytes = header.len() as u64;
        }
        state.append_synced(&line)?;
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

impl JournalState {
    fn append_synced(&mut self, line: &str) -> Result<(), String> {
        if let Err(error) = self
            .file
            .write_all(line.as_bytes())
            .and_then(|_| self.file.sync_all())
        {
            self.failed = true;
            return Err(format!(
                "persist recovery tombstone journal record: {error}"
            ));
        }
        self.bytes += line.len() as u64;
        Ok(())
    }
}

fn open_segment(path: &Path) -> Result<File, String> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|e| format!("missing recovery tombstone journal {}: {e}", path.display()))?;
    if !metadata.is_file() {
        return Err("recovery tombstone journal must be a regular, non-symlink file".into());
    }
    let file = OpenOptions::new()
        .read(true)
        .append(true)
        .open(path)
        .map_err(|e| format!("open recovery tombstone journal: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let opened = file.metadata().map_err(|e| e.to_string())?;
        if opened.dev() != metadata.dev()
            || opened.ino() != metadata.ino()
            || opened.mode() & 0o077 != 0
        {
            return Err("recovery tombstone journal is not the expected private file".into());
        }
    }
    Ok(file)
}

fn create_segment(path: &Path, header: &str) -> Result<File, String> {
    let mut options = OpenOptions::new();
    options.read(true).append(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .map_err(|e| format!("create recovery tombstone journal: {e}"))?;
    file.write_all(header.as_bytes())
        .and_then(|_| file.sync_all())
        .map_err(|e| format!("persist recovery tombstone journal header: {e}"))?;
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    File::open(parent)
        .and_then(|f| f.sync_all())
        .map_err(|e| format!("sync recovery tombstone directory: {e}"))?;
    Ok(file)
}

fn segment_path(base: &Path, id: uuid::Uuid) -> PathBuf {
    let mut name = base.as_os_str().to_owned();
    name.push(format!(".segment.{id}"));
    PathBuf::from(name)
}

fn segment_label(id: Option<uuid::Uuid>) -> String {
    id.map_or_else(|| "root".into(), |id| id.to_string())
}

fn segment_header(key: &[u8; 32], previous: Option<uuid::Uuid>, next: uuid::Uuid) -> String {
    control_line(
        &format!("segment-v2\t{}\t{next}", segment_label(previous)),
        key,
    )
}

fn control_mac(body: &str, key: &[u8; 32]) -> HmacSha256 {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts 32-byte keys");
    mac.update(b"catbird-labyrinth-recovery-tombstone-segment-v2\0");
    mac.update(body.as_bytes());
    mac
}

fn control_line(body: &str, key: &[u8; 32]) -> String {
    let tag = control_mac(body, key).finalize().into_bytes();
    format!("{body}\t{}\n", hex::encode(tag))
}

fn verified_control<'a>(line: &'a str, key: &[u8; 32]) -> Result<&'a str, String> {
    let (body, tag) = line
        .trim_end_matches('\n')
        .rsplit_once('\t')
        .ok_or("invalid recovery tombstone control record")?;
    let tag = hex::decode(tag).map_err(|e| e.to_string())?;
    control_mac(body, key)
        .verify_slice(&tag)
        .map_err(|_| "recovery tombstone segment MAC mismatch")?;
    Ok(body)
}

fn read_line(reader: &mut impl BufRead, line: &mut String) -> Result<bool, String> {
    line.clear();
    let count = reader
        .take(1026)
        .read_line(line)
        .map_err(|e| e.to_string())?;
    if count == 0 {
        return Ok(false);
    }
    if count > 1025 || !line.ends_with('\n') {
        return Err("overlong or truncated recovery tombstone journal record".into());
    }
    Ok(true)
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

    #[test]
    fn rotation_reopens_every_legacy_and_linked_erasure() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("erasures");
        let did = "did:plc:abcdefghijklmnopqrstuvwx";
        let key = [0x44; 32];
        let at = Utc::now();
        // Start with bytes emitted by the old writer, then simulate a smaller
        // rollover threshold. Existing oversized segments are read in place.
        let mut base = create_segment(&path, &header_line(&key)).unwrap();
        let legacy = Tombstone {
            did: did.into(),
            vid: [0; 16],
            at,
            kind: Kind::Delete,
        };
        base.write_all(encode_record(&legacy, &key).as_bytes())
            .unwrap();
        base.sync_all().unwrap();
        drop(base);
        let mut journal = RecoveryTombstones::open_existing(&path, key).unwrap();
        journal.segment_bytes = 1;
        journal.append_delete(did, &[1; 16], at).unwrap();
        journal.append_purge(did, &[2; 16], at).unwrap();
        journal.append_delete(did, &[1; 16], at).unwrap();
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 3);
        assert!(
            RecoveryTombstones::open_existing(&path, key).is_err(),
            "root retains the writer lease"
        );
        drop(journal);
        let journal = RecoveryTombstones::open_existing(&path, key).unwrap();
        for i in 0..3 {
            assert!(journal.contains(did, &[i; 16]));
        }
        assert!(!journal.contains(did, &[3; 16]));
        assert_eq!(
            journal.state.lock().unwrap().tombstones[&(did.into(), [2; 16])].kind,
            Kind::Purge
        );
    }

    #[test]
    fn missing_substituted_and_truncated_linked_segments_fail_closed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("erasures");
        let key = [0x45; 32];
        let mut journal = RecoveryTombstones::provision_new(&path, key).unwrap();
        journal.segment_bytes = 1;
        journal
            .append_delete("did:plc:abcdefghijklmnopqrstuvwx", &[1; 16], Utc::now())
            .unwrap();
        let id = journal.state.lock().unwrap().active_id.unwrap();
        drop(journal);
        let linked = segment_path(&path, id);
        let original = dir.path().join("original");
        std::fs::rename(&linked, &original).unwrap();
        assert!(RecoveryTombstones::open_existing(&path, key).is_err());
        let substituted =
            create_segment(&linked, &segment_header(&key, None, uuid::Uuid::new_v4())).unwrap();
        drop(substituted);
        assert!(RecoveryTombstones::open_existing(&path, key).is_err());
        std::fs::rename(original, &linked).unwrap();
        let file = OpenOptions::new().write(true).open(linked).unwrap();
        file.set_len(file.metadata().unwrap().len() - 1).unwrap();
        assert!(RecoveryTombstones::open_existing(&path, key).is_err());
    }
}
