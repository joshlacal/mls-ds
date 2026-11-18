//! A device's home erased its account-wide membership index. The sequencer
//! can still attest individual new entries for a surviving recovered leaf.
//! An attestation never reinstalls membership, a grant, or an erased payload.
use super::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct PageRequest {
    pub(crate) after: u64,
    pub(crate) limit: i64,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Page {
    query: PageRequest,
    cut: Cut,
    allowed: Vec<Grant>,
    has_more: bool,
}

#[derive(Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Cut {
    last_seq: i64,
    last_time: DateTime<Utc>,
    digest: [u8; 32],
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Grant {
    seq: i64,
    id: Uuid,
    pruned: bool,
    // A deletion control is bound by the complete matching erasure inventory.
    receipt: Option<[u8; 32]>,
    signed_request: Option<[u8; 32]>,
    control_digest: Option<[u8; 32]>,
}

type Failure = EntryReadFacadeError;

async fn deletion_cut(
    tx: &mut Transaction<'_, Postgres>,
    cid: Uuid,
    did: &str,
    device: Uuid,
) -> Result<(Cut, Vec<(i64, Uuid)>), Failure> {
    let mut after = Some(0);
    let mut controls = Vec::new();
    let mut time = None;
    let mut hash = Sha256::new();
    while let Some(cursor) = after {
        let (page, next) =
            super::super::conversation::load_account_deletion_page(tx, cid, Some(cursor))
                .await
                .map_err(|_| Failure::Storage)?;
        for marker in page.into_iter().filter(|m| m.deleted_did.as_str() == did) {
            let wire = marker
                .actor_write
                .as_ref()
                .filter(|w| w.payload_bytes.is_some())
                .ok_or(Failure::NotEntitled)?;
            if marker.key_proof.is_none() || marker.revocation_proof.is_none() {
                return Err(Failure::NotEntitled);
            }
            let proof: crate::labyrinth::auth::WriteBodyWire =
                serde_json::from_slice(&wire.write_body).map_err(|_| Failure::NotEntitled)?;
            if proof.endpoint_nsid != "blue.catbird.labyrinth.deleteAccountData"
                || Uuid::parse_str(&proof.actor_device_id).map_err(|_| Failure::NotEntitled)?
                    == device
            {
                return Err(Failure::NotEntitled);
            }
            let at = DateTime::parse_from_rfc3339(&proof.signed_at)
                .map_err(|_| Failure::NotEntitled)?
                .with_timezone(&Utc);
            time = Some(time.map_or(at, |previous: DateTime<Utc>| previous.max(at)));
            let id = Uuid::parse_str(marker.entry_id.as_str()).map_err(|_| Failure::Invariant)?;
            controls.push((marker.seq, id));
            // Fixed-size per-marker digests bind the complete verified signed
            // wire evidence on both sides, including multiple erasure operations.
            hash.update(Sha256::digest(
                serde_json::to_vec(&marker).map_err(|_| Failure::Invariant)?,
            ));
        }
        after = next;
    }
    Ok((
        Cut {
            last_seq: controls.last().ok_or(Failure::NotEntitled)?.0,
            last_time: time.ok_or(Failure::NotEntitled)?,
            digest: hash.finalize().into(),
        },
        controls,
    ))
}

fn receipt_digest(value: &Value) -> Result<[u8; 32], Failure> {
    let canonical =
        encode_canonical_generated_chat_json_v1(value, "blue.catbird.chat.defs#sequencerReceipt")
            .map_err(|_| Failure::Invariant)?;
    Ok(Sha256::digest(canonical.bytes()).into())
}

fn request_digest(entry: &Value) -> Result<[u8; 32], Failure> {
    let mut signed = entry["signedRequest"].clone();
    if !signed.is_object() {
        return Err(Failure::Invariant);
    }
    // Source and transport both normalize wire bytes before this comparison.
    signed.sort_all_objects();
    Ok(Sha256::digest(serde_json::to_vec(&signed).map_err(|_| Failure::Invariant)?).into())
}

pub(super) async fn authorize(
    tx: &mut Transaction<'_, Postgres>,
    window: &RecoveryReadWindow,
    query: PageRequest,
) -> Result<Page, Failure> {
    if !(1..=100).contains(&query.limit)
        || query.after > crate::chat_protocol::validation::MAX_SAFE_INTEGER as u64
    {
        return Err(Failure::InvalidRequest);
    }
    let (cut, markers) = deletion_cut(tx, window.conversation, &window.did, window.device).await?;
    let ids: Vec<i64> = markers
        .iter()
        .filter(|(seq, _)| *seq >= window.first_seq && *seq > query.after as i64)
        .map(|(seq, _)| *seq)
        .collect();
    let controls:Vec<(i64,Uuid)>=sqlx::query_as(
        "SELECT e.seq,e.entry_id FROM chat.entry_recipients r JOIN chat.entries e USING(conversation_id,seq) \
         WHERE r.conversation_id=$1 AND r.user_did=$2 AND r.device_id=$3 AND r.seq=ANY($4) ORDER BY e.seq LIMIT $5"
    ).bind(window.conversation).bind(&window.did).bind(window.device).bind(&ids).bind(query.limit+1)
      .fetch_all(&mut **tx).await.map_err(|_|Failure::Storage)?;
    let mut allowed = Vec::new();
    for (seq, id) in controls {
        allowed.push(Grant {
            seq,
            id,
            pruned: false,
            receipt: None,
            signed_request: None,
            control_digest: None,
        });
    }
    let mut cursor = query
        .after
        .max(cut.last_seq as u64)
        .max((window.first_seq - 1) as u64);
    while allowed.len() <= query.limit as usize && cursor < window.last_seq as u64 {
        let page = delivery::get_entries_with_terminal_control_interval(
            tx,
            window.conversation,
            &window.did,
            window.device,
            cursor,
            query.limit + 1,
            None,
        )
        .await
        .map_err(map_delivery_error)?;
        for row in page.entries {
            if row.seq > window.last_seq || row.received_at <= cut.last_time {
                continue;
            }
            if row.entry_kind == "blue.catbird.chat.defs#accountDeletedEntry" {
                let mut entry = entry_json(&row)?;
                entry.sort_all_objects();
                allowed.push(Grant {
                    seq: row.seq,
                    id: row.entry_id,
                    pruned: false,
                    receipt: None,
                    signed_request: None,
                    control_digest: Some(
                        Sha256::digest(serde_json::to_vec(&entry).map_err(|_| Failure::Invariant)?)
                            .into(),
                    ),
                });
                if allowed.len() > query.limit as usize {
                    break;
                }
                continue;
            }
            let receipt_bytes = row
                .sequencer_receipt_bytes
                .as_ref()
                .ok_or(Failure::NotEntitled)?;
            let receipt = serde_json::from_slice(receipt_bytes).map_err(|_| Failure::Invariant)?;
            let value = entry_json(&row)?;
            let pruned = value["payloadPruned"].as_bool() == Some(true);
            allowed.push(Grant {
                seq: row.seq,
                id: row.entry_id,
                pruned,
                receipt: Some(receipt_digest(&receipt)?),
                control_digest: None,
                signed_request: if pruned {
                    None
                } else {
                    Some(request_digest(&value)?)
                },
            });
            if allowed.len() > query.limit as usize {
                break;
            }
        }
        if !page.has_more {
            break;
        }
        if page.next_after_seq <= cursor {
            return Err(Failure::Invariant);
        }
        cursor = page.next_after_seq;
    }
    let has_more = allowed.len() > query.limit as usize;
    allowed.truncate(query.limit as usize);
    Ok(Page {
        query,
        cut,
        allowed,
        has_more,
    })
}

pub(super) async fn matches_cut(
    tx: &mut Transaction<'_, Postgres>,
    window: &RecoveryReadWindow,
    page: &Page,
) -> Result<(), Failure> {
    if deletion_cut(tx, window.conversation, &window.did, window.device)
        .await?
        .0
        != page.cut
    {
        return Err(Failure::NotEntitled);
    }
    Ok(())
}

impl Page {
    pub(super) async fn local_rows(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        window: &RecoveryReadWindow,
        query: PageRequest,
    ) -> Result<(Vec<(i64, Vec<u8>)>, bool), Failure> {
        if self.query != query || self.allowed.len() > query.limit as usize {
            return Err(Failure::NotEntitled);
        }
        let seqs: Vec<_> = self.allowed.iter().map(|g| g.seq).collect();
        let rows:Vec<(i64,Uuid,Vec<u8>,Option<Vec<u8>>)>=sqlx::query_as(
            "SELECT seq,entry_id,entry_bytes,pruned_entry_bytes FROM chat.direct_request_transport_entries \
             WHERE conversation_id=$1 AND seq=ANY($2) ORDER BY seq"
        ).bind(window.conversation).bind(&seqs).fetch_all(&mut **tx).await.map_err(|_|Failure::Storage)?;
        if rows.len() != self.allowed.len() {
            return Err(Failure::Storage);
        }
        let mut output = Vec::with_capacity(rows.len());
        let mut previous = query.after as i64;
        for ((seq, id, bytes, pruned_bytes), grant) in rows.into_iter().zip(&self.allowed) {
            if seq != grant.seq
                || id != grant.id
                || seq <= previous
                || seq < window.first_seq
                || seq > window.last_seq
            {
                return Err(Failure::NotEntitled);
            }
            previous = seq;
            let entry = present_transport_entry(&bytes)?;
            if let Some(digest) = &grant.receipt {
                if seq <= self.cut.last_seq
                    || receipt_digest(&entry["sequencerReceipt"])? != *digest
                {
                    return Err(Failure::NotEntitled);
                }
                if entry["payloadPruned"].as_bool() != Some(true) {
                    if grant.pruned {
                        output.push((seq, pruned_bytes.ok_or(Failure::NotEntitled)?));
                        continue;
                    }
                    if Some(request_digest(&entry)?) != grant.signed_request {
                        return Err(Failure::NotEntitled);
                    }
                }
            } else {
                if entry["$type"] != "blue.catbird.chat.defs#accountDeletedEntry" {
                    return Err(Failure::NotEntitled);
                }
                if let Some(expected) = grant.control_digest {
                    let mut presented = entry;
                    presented.sort_all_objects();
                    if seq <= self.cut.last_seq
                        || <[u8; 32]>::from(Sha256::digest(
                            serde_json::to_vec(&presented).map_err(|_| Failure::Invariant)?,
                        )) != expected
                    {
                        return Err(Failure::NotEntitled);
                    }
                } else if seq > self.cut.last_seq || entry["deletedDid"] != window.did {
                    return Err(Failure::NotEntitled);
                }
            }
            output.push((seq, bytes));
        }
        Ok((output, self.has_more))
    }
}
