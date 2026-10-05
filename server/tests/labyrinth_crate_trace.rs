//! Cross-check against the labyrinth crate (design §6 "Tests"): replay the
//! exact XRPC request sequence the crate's own client made against its
//! memory-backed reference server (`MemoryXrpcServer`) through the real
//! mls-ds handlers, and require the same outcome for every call.
//!
//! The fixture `tests/fixtures/labyrinth_crate_xrpc_trace.json` (180 calls)
//! was recorded by the crate's own `tests/xrpc_trace.rs` (bookmark
//! `labyrinth-1.1`): three accounts (four physical devices) initialize
//! Labyrinth with mls-ds mailboxes and exchange messages in one
//! conversation, then exercise attachments, redaction, the lookup endpoints,
//! virtual devices, revocation and account deletion. Each physical device
//! sends its own signed `chatBinding` (keyed by the seeded chat key) before
//! its genesis epoch, so the calls replay verbatim. mls-ds takes no
//! dependency on the (private) crate; the recorded payloads are the crate's
//! own wire bytes, so this proves mls-ds accepts exactly what the crate
//! sends and answers in the shapes it reads.
//!
//! Values that legitimately differ between the two servers are compared by
//! presence and JSON type only: `epochId` (mls-ds: bigserial, reference:
//! padded seq), `receivedAt`, `lastUsedAt`, `redactedAt`, chat `keyId`s,
//! chat-key `createdAt`, and server-assigned TID `rkey`s.

mod common;

#[path = "common/labyrinth_harness.rs"]
mod harness;

use harness::*;
use serde_json::Value;
use uuid::Uuid;

const VOLATILE: &[&str] = &["epochId", "receivedAt", "lastUsedAt", "redactedAt", "keyId"];

fn is_tid(v: &Value) -> bool {
    v.as_str()
        .is_some_and(|s| s.len() == 13 && s.bytes().all(|b| matches!(b, b'2'..=b'7' | b'a'..=b'z')))
}

fn same_type(a: &Value, b: &Value) -> bool {
    std::mem::discriminant(a) == std::mem::discriminant(b)
}

/// Compare `got` (mls-ds) with `want` (reference) at `path`.
fn compare(path: &str, got: &Value, want: &Value, diffs: &mut Vec<String>) {
    match (got, want) {
        (Value::Object(g), Value::Object(w)) => {
            let mut keys: Vec<&String> = g.keys().chain(w.keys()).collect();
            keys.sort();
            keys.dedup();
            let chat_key_view = w.contains_key("signingPublicKey");
            for k in keys {
                let p = format!("{path}/{k}");
                match (g.get(k), w.get(k)) {
                    (Some(gv), Some(wv)) => {
                        let volatile = VOLATILE.contains(&k.as_str())
                            || (k == "createdAt" && chat_key_view)
                            || (k == "rkey" && is_tid(gv) && is_tid(wv));
                        if volatile {
                            if !same_type(gv, wv) {
                                diffs.push(format!("{p}: type {gv} vs {wv}"));
                            }
                        } else {
                            compare(&p, gv, wv, diffs);
                        }
                    }
                    (gv, wv) => diffs.push(format!("{p}: mls-ds {gv:?} vs reference {wv:?}")),
                }
            }
        }
        (Value::Array(g), Value::Array(w)) => {
            if g.len() != w.len() {
                diffs.push(format!("{path}: {} items vs {}", g.len(), w.len()));
                return;
            }
            for (i, (gv, wv)) in g.iter().zip(w).enumerate() {
                compare(&format!("{path}/{i}"), gv, wv, diffs);
            }
        }
        _ => {
            if got != want {
                diffs.push(format!("{path}: mls-ds {got} vs reference {want}"));
            }
        }
    }
}

async fn send(device: &Device, name: &str, call: &Value) -> Reply {
    if call["kind"] == "query" {
        let params: Vec<(&str, String)> = call["params"]
            .as_array()
            .unwrap()
            .iter()
            .map(|p| (p[0].as_str().unwrap(), p[1].as_str().unwrap().to_owned()))
            .collect();
        device.query(name, &params).await
    } else {
        let op: [u8; 16] = hex::decode(call["operationId"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        device.call_op(name, &call["payload"], op).await
    }
}

#[tokio::test]
async fn crate_client_trace_replays_identically_against_mls_ds() {
    let trace: Value =
        serde_json::from_str(include_str!("fixtures/labyrinth_crate_xrpc_trace.json")).unwrap();
    let env = Env::new().await;
    let mut devices = Vec::new();
    for m in trace["members"].as_array().unwrap() {
        let did = m[0].as_str().unwrap();
        let seed = m[1].as_u64().unwrap() as u8;
        devices.push((did.to_owned(), seed, env.device_for(did, [seed; 32]).await));
    }
    let leaves: Vec<Leaf> = trace["members"]
        .as_array()
        .unwrap()
        .iter()
        .zip(&devices)
        .map(|(m, (_, _, device))| Leaf {
            device,
            joined_seq: m[2].as_i64().unwrap(),
            removed_seq: None,
        })
        .collect();
    let thread = Uuid::parse_str(trace["thread"].as_str().unwrap()).unwrap();
    seed_conversation_with_id(
        &env,
        thread,
        &leaves,
        trace["nextEntrySeq"].as_i64().unwrap(),
    )
    .await;

    let calls = trace["calls"].as_array().unwrap();
    assert!(calls.len() >= 180, "the trace covers the full client flow");
    let mut replayed = std::collections::BTreeSet::new();
    let mut failures = Vec::new();
    for (i, call) in calls.iter().enumerate() {
        let nsid = call["nsid"].as_str().unwrap();
        let Some(name) = nsid.strip_prefix(PREFIX) else {
            continue;
        };
        let did = call["did"].as_str().unwrap();
        let seed = call["seed"].as_u64().unwrap() as u8;
        let (_, _, device) = devices
            .iter()
            .find(|(d, s, _)| d == did && *s == seed)
            .expect("caller is a seeded device");
        // The process-wide per-DID service-auth limiter throttles the
        // trace's bursts; a throttled call is resent after Retry-After like
        // any client would (it never reached the handler).
        let mut attempts = 0;
        let reply = loop {
            let reply = send(device, name, call).await;
            if reply.status != axum::http::StatusCode::TOO_MANY_REQUESTS || attempts == 10 {
                break reply;
            }
            attempts += 1;
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        };
        replayed.insert(name.to_owned());
        let want_status = call["status"].as_u64().unwrap() as u16;
        if reply.status.as_u16() != want_status
            || (want_status != 200 && Some(reply.error()) != call["error"].as_str())
        {
            failures.push(format!(
                "#{i} {name}: mls-ds {} {} vs reference {want_status} {}",
                reply.status, reply.json, call["error"]
            ));
            continue;
        }
        if want_status == 200 {
            let (mut got, mut want) = (reply.json.clone(), call["response"].clone());
            if name == "getChatDeviceKeys" {
                // The lexicon fixes no order for a DID's chat keys (mls-ds
                // pages by key id, the reference by registration), so the
                // page is compared as a set.
                for v in [&mut got, &mut want] {
                    if let Some(items) = v["items"].as_array_mut() {
                        items.sort_by_key(|k| k["signingPublicKey"]["$bytes"].to_string());
                    }
                }
            }
            let mut diffs = Vec::new();
            compare("", &got, &want, &mut diffs);
            for d in diffs {
                failures.push(format!("#{i} {name}: {d}"));
            }
        }
    }
    assert!(failures.is_empty(), "divergences:\n{}", failures.join("\n"));
    for name in [
        "createDevice",
        "createEpoch",
        "registerOrfState",
        "publishEpochHead",
        "getEpochHead",
        "getChatDeviceKeys",
        "getMemberDevices",
        "createMek",
        "appendBatch",
        "findMeks",
        "listBatches",
        "getVirtualDevice",
        "touchVirtualDevice",
        "redactMessage",
        "putAttachmentRef",
        "getMessages",
        "listThreads",
        "listOwnerThreads",
        "deleteAccountData",
        "purgeMailbox",
    ] {
        assert!(replayed.contains(name), "trace exercised {name}");
    }
}
