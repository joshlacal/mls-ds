//! Opt-in cross-process smoke fixture. Normal DS auth and device proofs;
//! synthetic SQL chat membership, actual local-PLC DID signing documents.
mod common;
#[path = "common/labyrinth_harness.rs"]
mod harness;
use harness::*;
use serde_json::{json, Value};
use std::{io::Write, os::unix::fs::OpenOptionsExt, path::Path};
use uuid::Uuid;

fn private_write(path: &Path, bytes: &[u8]) {
    let mut f = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    f.write_all(bytes).unwrap();
    f.sync_all().unwrap();
}
async fn refresh_docs(plc: &str, dids: &[&str]) {
    for did in dids {
        let document: catbird_server::auth::DidDocument = reqwest::get(format!("{plc}/{did}"))
            .await
            .unwrap()
            .error_for_status()
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(document.id, *did);
        catbird_server::auth::cache_test_did_document(document).await;
    }
}
#[tokio::test]
#[ignore = "explicit disposable local host integration; no production identities"]
async fn conversation_storage_smoke_fixture() {
    let config_path = std::env::var("CONVERSATION_SMOKE_CONFIG").expect("explicit lab config");
    let c: Value = serde_json::from_slice(&std::fs::read(config_path).unwrap()).unwrap();
    let dir = Path::new(c["outputDir"].as_str().unwrap());
    std::fs::create_dir_all(dir.join("requests")).unwrap();
    std::fs::create_dir_all(dir.join("responses")).unwrap();
    let plc = c["plcOrigin"].as_str().unwrap();
    assert!(plc.starts_with("http://localhost:") || plc.starts_with("http://127.0.0.1:"));
    let authority = c["authorityDID"].as_str().unwrap();
    let env = Env::new().await;
    let sender = env
        .device_for(c["senderDID"].as_str().unwrap(), random_seed())
        .await;
    let reader = env
        .device_for(c["readerDID"].as_str().unwrap(), random_seed())
        .await;
    let revoked_sibling = env.device_for(&reader.did, random_seed()).await;
    let leaves = [
        Leaf {
            device: &sender,
            joined_seq: 1,
            removed_seq: None,
        },
        Leaf {
            device: &reader,
            joined_seq: 1,
            removed_seq: None,
        },
        Leaf {
            device: &revoked_sibling,
            joined_seq: 1,
            removed_seq: Some(2),
        },
    ];
    let thread =
        seed_conversation_with_storage(&env, Uuid::new_v4(), &leaves, 3, Some(authority)).await;
    env.revoke(&revoked_sibling).await;
    refresh_docs(plc, &[authority, &sender.did, &reader.did]).await;
    private_write(
        &dir.join("sender-chat-key.raw"),
        &sender.chat_key.to_bytes(),
    );
    private_write(
        &dir.join("reader-chat-key.raw"),
        &reader.chat_key.to_bytes(),
    );
    let bind_port = c["bindPort"].as_u64().unwrap_or(0);
    assert!(bind_port <= 65535);
    let listener = tokio::net::TcpListener::bind(format!("127.0.0.1:{bind_port}"))
        .await
        .unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let router = env.router.clone();
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
    let server = tokio::spawn(async move {
        axum::serve(listener, router)
            .with_graceful_shutdown(async {
                let _ = stop_rx.await;
            })
            .await
            .unwrap();
    });
    std::fs::write(dir.join("ready.json"),serde_json::to_vec_pretty(&json!({"origin":origin,"audience":catbird_server::auth::expected_mls_service_ref(),"threadId":thread,"authorityDID":authority,"senderDID":sender.did,"readerDID":reader.did,"senderDeviceId":sender.device_id,"readerDeviceId":reader.device_id,"revokedSiblingDeviceId":revoked_sibling.device_id,"senderChatSecretPath":dir.join("sender-chat-key.raw"),"authBoundary":"actual local PLC signing documents and caller-supplied PDS service-auth tokens; fresh seeded chat device/leaf state"})).unwrap()).unwrap();
    println!(
        "conversation storage fixture ready: {}",
        dir.join("ready.json").display()
    );
    let http = reqwest::Client::new();
    for tick in 0..36000 {
        if dir.join("stop").exists() {
            break;
        }
        if tick % 600 == 0 {
            refresh_docs(plc, &[authority, &sender.did, &reader.did]).await;
        }
        for entry in std::fs::read_dir(dir.join("requests")).unwrap() {
            let entry = entry.unwrap();
            let filename = entry.file_name();
            if entry.path().extension().and_then(|s| s.to_str()) != Some("json")
                || dir.join("responses").join(&filename).exists()
            {
                continue;
            }
            let command: Value =
                serde_json::from_slice(&std::fs::read(entry.path()).unwrap()).unwrap();
            let reply = if command["control"] == "inspectStorage" {
                let rows: Vec<(Value, String, Uuid, i64, i64, Uuid)> = sqlx::query_as("SELECT record, source_cid, space_generation, seq, chat_seq, writer_device_id FROM labyrinth.batches WHERE conversation_id=$1")
                    .bind(thread).fetch_all(&env.pool).await.unwrap();
                let summaries: Vec<_> = rows.iter().map(|(record,cid,generation,seq,chat_seq,device)| {
                    let has_ciphertext=record["items"].as_array().unwrap().iter().any(|item| !item["signedEncMessage"]["$bytes"].as_str().unwrap().is_empty());
                    json!({"cid":cid,"generation":generation,"seq":seq,"chatSeq":chat_seq,"writerDeviceId":device,"hasCiphertext":has_ciphertext})
                }).collect();
                json!({"status":200,"body":{"rows":summaries}})
            } else if command["control"] == "removeReader" {
                remove_member(&env, thread, &reader, 3).await;
                json!({"status":200,"body":{"removed":true}})
            } else {
                let actor = match command["actor"].as_str().unwrap() {
                    "sender" => &sender,
                    "reader" => &reader,
                    "revokedSibling" => &revoked_sibling,
                    _ => panic!("unknown actor"),
                };
                let nsid = command["nsid"].as_str().unwrap();
                assert!(nsid.starts_with(PREFIX));
                let token = command["token"].as_str().unwrap();
                let response = if command["method"] == "POST" {
                    let body = serde_json::to_vec(&command["body"]).unwrap();
                    let (proof, sig) = actor.write_headers(nsid, &body, *Uuid::new_v4().as_bytes());
                    http.post(format!("{origin}/xrpc/{nsid}"))
                        .bearer_auth(token)
                        .header("content-type", "application/json")
                        .header("catbird-labyrinth-write", proof)
                        .header("catbird-labyrinth-write-signature", sig)
                        .body(body)
                        .send()
                        .await
                        .unwrap()
                } else {
                    let mut query = url::form_urlencoded::Serializer::new(String::new());
                    query.append_pair("actorDeviceId", &actor.device_id.to_string());
                    for (key, value) in command["query"].as_object().unwrap() {
                        query.append_pair(key, value.as_str().unwrap());
                    }
                    let query = query.finish();
                    let (proof, sig) = actor.read_headers(nsid, &query);
                    http.get(format!("{origin}/xrpc/{nsid}?{query}"))
                        .bearer_auth(token)
                        .header("catbird-labyrinth-read", proof)
                        .header("catbird-labyrinth-read-signature", sig)
                        .send()
                        .await
                        .unwrap()
                };
                let status = response.status().as_u16();
                let text = response.text().await.unwrap();
                json!({"status":status,"body":serde_json::from_str::<Value>(&text).unwrap_or(json!({"text":text}))})
            };
            std::fs::write(
                dir.join("responses").join(filename),
                serde_json::to_vec_pretty(&reply).unwrap(),
            )
            .unwrap();
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    let _ = stop_tx.send(());
    server.await.unwrap();
}
