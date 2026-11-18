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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chat_protocol::test_support::seed_clean_slate_application_fixture;
    use crate::common::{fresh_db::fresh_fully_migrated_db, http_acceptance as http};
    use crate::federation::{
        receipt::I13ReceiptSigner, space_read_relay::test_car_builder::deletion_evidence,
    };
    use crate::labyrinth::repo::retention::sequence_account_deleted_entry;

    #[tokio::test]
    async fn surviving_device_pages_only_its_erasure_controls_and_new_signed_entries() {
        let source = fresh_fully_migrated_db("chat_fed_relay_").await;
        let source_pool = source.connect(4).await;
        http::ensure_fence(&source_pool).await;
        let mirror = fresh_fully_migrated_db("chat_fed_relay_").await;
        let mirror_pool = mirror.connect(3).await;
        let ds = crate::identity::service_did_base();
        let signer = I13ReceiptSigner::new(http::random_p256(), ds.clone());
        let router =
            http::router_for_authenticated_acceptance_with(source_pool.clone(), |runtime| {
                runtime.with_i13_receipt_signer(signer.clone())
            })
            .await;
        let room = seed_clean_slate_application_fixture(&source_pool, false, &ds, Some([0x57; 32]))
            .await
            .unwrap();
        let cid = room.conversation_id;
        let live_device = room.sender_device_id;
        let original = Uuid::new_v4();
        let signing = http::random_p256();
        let jwk = http::public_jwk(&signing);
        let reader = http::Device {
            did: room.sender_did.clone(),
            device_id: live_device,
            signing,
            jkt: http::jwk_thumbprint(&jwk),
            jwk,
        };
        http::cache_device_did(&reader).await;
        let send = |signed: &Value| {
            let request = http::unsigned_json_request(
                &reader,
                "blue.catbird.chat.sendMessage",
                serde_json::to_vec(&json!({"signedRequest":signed})).unwrap(),
            );
            http::send(router.clone(), request)
        };
        let (status, sent) = send(&room.signed_request).await;
        assert_eq!(status, axum::http::StatusCode::OK, "{sent}");
        let old_seq = sent["entry"]["seq"].as_i64().unwrap();
        let at = Utc::now();
        let proof = deletion_evidence(&room.sender_did, original, [0x41; 16], at);
        let mut tx = source_pool.begin().await.unwrap();
        let marker = sequence_account_deleted_entry(
            &mut tx,
            cid,
            &room.sender_did,
            at,
            at,
            Some(&signer),
            Some(&proof),
        )
        .await
        .unwrap()
        .unwrap();
        tx.commit().await.unwrap();
        let cut = marker["seq"].as_i64().unwrap();
        assert_eq!(cut, old_seq + 1);
        let (status, newer) = send(&room.next_sender_signed_request()).await;
        assert_eq!(status, axum::http::StatusCode::OK, "{newer}");
        let latest = newer["entry"]["seq"].as_i64().unwrap();
        assert_eq!(latest, cut + 1);
        // Both stores get the same sequencer-signed data through their own
        // ordinary persistence functions. The old transport payload still exists.
        let mut mirror_tx = mirror_pool.begin().await.unwrap();
        for seq in [old_seq, cut, latest] {
            let entry = super::super::entry_json_for_test(&source_pool, cid, seq)
                .await
                .unwrap();
            delivery::insert_transport_entry(
                &mut mirror_tx,
                cid,
                seq,
                entry["entryId"].as_str().unwrap().parse().unwrap(),
                &serde_json::to_vec(&entry).unwrap(),
                at,
            )
            .await
            .unwrap();
        }
        mirror_tx.commit().await.unwrap();
        let mut window = RecoveryReadWindow {
            conversation: cid,
            did: room.sender_did,
            device: live_device,
            key_id: room.sender_key_id,
            auth_generation: 1,
            welcome: Uuid::new_v4(),
            generation: 0,
            first_seq: 1,
            last_seq: latest,
            post_erasure: None,
        };
        let mut source_tx = source_pool.begin().await.unwrap();
        let mut mirror_tx = mirror_pool.begin().await.unwrap();
        for (after, limit, expected, more) in [
            (0, 100, vec![cut, latest], false),
            (0, 1, vec![cut], true),
            (cut as u64, 100, vec![latest], false),
            (latest as u64, 100, vec![], false),
        ] {
            let query = PageRequest { after, limit };
            let page = authorize(&mut source_tx, &window, query).await.unwrap();
            matches_cut(&mut mirror_tx, &window, &page).await.unwrap();
            let (rows, has_more) = page
                .local_rows(&mut mirror_tx, &window, query)
                .await
                .unwrap();
            assert_eq!(has_more, more);
            assert_eq!(
                rows.iter().map(|(seq, _)| *seq).collect::<Vec<_>>(),
                expected
            );
            for (seq, bytes) in rows {
                let presented: Value = serde_json::from_slice(&bytes).unwrap();
                assert_eq!(presented["seq"], seq);
                if seq == cut {
                    assert_eq!(presented["deletedDid"], reader.did);
                } else {
                    assert_eq!(presented["entryId"], newer["entry"]["entryId"]);
                }
            }
        }
        // An unlisted sibling receives no marker control. The deleting enrollment is denied.
        window.device = Uuid::new_v4();
        let query = PageRequest {
            after: 0,
            limit: 100,
        };
        assert!(authorize(&mut source_tx, &window, query)
            .await
            .unwrap()
            .allowed
            .is_empty());
        window.device = original;
        assert!(matches!(
            authorize(&mut source_tx, &window, query).await,
            Err(Failure::NotEntitled)
        ));
    }
}
