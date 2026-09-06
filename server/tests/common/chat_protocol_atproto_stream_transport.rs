//! Strict wire regression over the real service-auth inventory/ticket/router
//! journeys. Mount as a child of the frozen inventory generation proof module.
//! That parent supplies only guarded initial-state and HTTP fixture helpers.
//! The frozen former Text-frame tests are deliberately not edited.
#![cfg(all(test, feature = "test-support"))]

use super::*;
use crate::chat_protocol::validation::{CanonicalTimestamp, CanonicalUuidV4};
use catbird_atproto::generated::blue_catbird::chat::SubscriptionMessage;
use tower_util::ServiceExt as _;

const ENVELOPE_TYPE: &str = "blue.catbird.chat.defs#eventEnvelope";
const TYPING_TYPE: &str = "blue.catbird.chat.defs#typingEvent";

struct DecodedFrame {
    binary: Vec<u8>,
    value: Value,
    logical_json: Vec<u8>,
}

fn exact_keys(value: &Value, expected: &[&str]) -> bool {
    let Some(object) = value.as_object() else {
        return false;
    };
    object.len() == expected.len() && expected.iter().all(|key| object.contains_key(*key))
}

fn canonical_date(value: &Value) -> bool {
    value
        .as_str()
        .is_some_and(|text| CanonicalTimestamp::parse(text).is_ok())
}

fn canonical_uuid(value: &Value) -> bool {
    value
        .as_str()
        .is_some_and(|text| CanonicalUuidV4::parse(text).is_ok())
}

/// Strictly checks the emitted representation independently of the generated
/// DTO's permissive timestamp and extra-data decoding. Diagnostic errors never
/// contain opaque cursors or event body bytes.
fn decode_binary(binary: Vec<u8>, expected_type: &str) -> Result<DecodedFrame, &'static str> {
    let mut input = std::io::Cursor::new(binary.as_slice());
    let header: Value =
        serde_ipld_dagcbor::de::from_reader_once(&mut input).map_err(|_| "invalid CBOR header")?;
    let mut body: Value =
        serde_ipld_dagcbor::de::from_reader_once(&mut input).map_err(|_| "invalid CBOR body")?;
    if input.position() as usize != binary.len() {
        return Err("trailing CBOR object or bytes");
    }
    if !exact_keys(&header, &["op", "t"]) || header["op"] != 1 || header["t"] != expected_type {
        return Err("incorrect operation or full external type reference");
    }
    // The root union tag lives exclusively in the header. Nested union tags
    // remain data: messageAvailable is a nested closed-union discriminator.
    if body.get("$type").is_some() {
        return Err("outer type must be absent from CBOR body");
    }
    let mut reencoded =
        serde_ipld_dagcbor::to_vec(&header).map_err(|_| "invalid header encoding")?;
    reencoded.extend(serde_ipld_dagcbor::to_vec(&body).map_err(|_| "invalid body encoding")?);
    if reencoded != binary {
        return Err("noncanonical or duplicate CBOR map encoding");
    }
    match expected_type {
        ENVELOPE_TYPE => {
            if !exact_keys(&body, &["createdAt", "cursor", "payload", "previousCursor"]) {
                return Err("incorrect envelope fields");
            }
            if !canonical_date(&body["createdAt"]) {
                return Err("noncanonical envelope timestamp");
            }
            for key in ["cursor", "previousCursor"] {
                if !body[key]
                    .as_str()
                    .is_some_and(|s| !s.is_empty() && s.len() <= 512)
                {
                    return Err("invalid cursor spelling");
                }
            }
            let payload = &body["payload"];
            if !exact_keys(payload, &["$type", "conversationId", "seq"])
                || payload["$type"] != "blue.catbird.chat.defs#messageAvailableEvent"
                || !canonical_uuid(&payload["conversationId"])
                || !payload["seq"]
                    .as_u64()
                    .is_some_and(|seq| (1..=9_007_199_254_740_991).contains(&seq))
            {
                return Err("incorrect messageAvailable payload");
            }
        }
        TYPING_TYPE => {
            if !exact_keys(
                &body,
                &[
                    "typingId",
                    "conversationId",
                    "actorDid",
                    "actorDeviceId",
                    "isTyping",
                    "expiresAt",
                ],
            ) || !canonical_uuid(&body["typingId"])
                || !canonical_uuid(&body["conversationId"])
                || !canonical_uuid(&body["actorDeviceId"])
                || !canonical_date(&body["expiresAt"])
                || !body["isTyping"].is_boolean()
            {
                return Err("incorrect typing fields or timestamp");
            }
            if crate::chat_protocol::validation::BareDid::parse(
                body["actorDid"].as_str().ok_or("missing typing actor")?,
            )
            .is_err()
            {
                return Err("invalid typing actor");
            }
        }
        _ => return Err("unexpected subscription type"),
    }
    body["$type"] = json!(expected_type);
    let message: SubscriptionMessage = serde_json::from_value(body.clone())
        .map_err(|_| "generated DTO cannot decode validated body")?;
    let logical_json =
        serde_json::to_vec(&message).map_err(|_| "generated DTO serialization failed")?;
    Ok(DecodedFrame {
        binary,
        value: body,
        logical_json,
    })
}

async fn next_binary(socket: &mut ClientSocket, expected_type: &str) -> DecodedFrame {
    timeout(StdDuration::from_secs(5), async {
        loop {
            match socket.next().await {
                Some(Ok(Message::Ping(payload))) => {
                    socket.send(Message::Pong(payload)).await.unwrap()
                }
                Some(Ok(Message::Pong(_))) => {}
                Some(Ok(Message::Binary(bytes))) => {
                    return decode_binary(bytes.to_vec(), expected_type)
                        .expect("strict actual binary subscription frame")
                }
                Some(Ok(Message::Text(_))) => {
                    panic!("expected binary ATProto frame; received legacy Text frame")
                }
                _ => panic!("original upgraded stream ended before its addressed frame"),
            }
        }
    })
    .await
    .expect("addressed binary frame arrives within five seconds")
}

async fn next_envelope(socket: &mut ClientSocket, _anchor_retained: bool) -> DecodedFrame {
    next_binary(socket, ENVELOPE_TYPE).await
}

async fn send_with_headers(
    router: axum::Router,
    request: axum::http::Request<axum::body::Body>,
) -> (axum::http::StatusCode, axum::http::HeaderMap, Value) {
    let response = router.oneshot(request).await.unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    (status, headers, serde_json::from_slice(&bytes).unwrap())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn binary_streams_preserve_two_original_sockets_across_inventory_generations() {
    let _serial = SERIAL.lock().await;
    let pool = owned_database().await;
    let (mut group_a, device_a) = ready_group(&pool).await;
    let router = http::router_for_authenticated_acceptance(pool.clone()).await;
    let initial = inventory_roundtrip(&pool, &router, &device_a).await;
    let (address, server) = serve_router(router.clone()).await;
    let mut first = upgrade(&router, &device_a, &initial, address).await;
    let mut second = upgrade(&router, &device_a, &initial, address).await;
    let anchor = receipt(&pool, &initial.cursor)
        .await
        .expect("both upgrades share the committed initial receipt");
    let ticket_count: i64 = sqlx::query_scalar("SELECT count(*) FROM chat.subscription_tickets WHERE inventory_session_id=$1 AND consumed_at IS NOT NULL")
        .bind(initial.session_id).fetch_one(&pool).await.unwrap();
    assert_eq!(
        ticket_count, 2,
        "two independent one-use tickets, one original fence"
    );
    let mut previous_cursor = initial.cursor.clone();
    let mut prior_inventory = initial.session_row.clone();
    let mut prior_capability = initial.capability.clone();
    let mut retained_receipts = vec![(initial.cursor.clone(), anchor)];

    for _rotation in 0..2 {
        // Only B's authentic operations advance the global log while A is
        // quiet. A is never an audience member for B's group or application.
        advance_unrelated_global_event(&pool, &router).await;
        tokio::join!(assert_quiet(&mut first), assert_quiet(&mut second));
        let refreshed = inventory_roundtrip(&pool, &router, &device_a).await;
        assert_ne!(
            refreshed.capability, prior_capability,
            "actual inventory refresh observes the newer global event fence"
        );
        assert!(
            refreshed.session_row["snapshot_event_position"]
                .as_i64()
                .unwrap()
                > prior_inventory["snapshot_event_position"].as_i64().unwrap()
        );
        let anchor_retained = receipt(&pool, &initial.cursor).await.is_some();
        // Do not stop at the missing-anchor diagnostic on RED: actually send
        // the next addressed message and require delivery on both original101s.
        let (message_id, seq) =
            send_ready_application(&pool, &router, &device_a, &mut group_a).await;
        let (first_frame, second_frame) = tokio::join!(
            next_envelope(&mut first, anchor_retained),
            next_envelope(&mut second, anchor_retained)
        );
        assert!(
            first_frame.binary == second_frame.binary,
            "same-fence streams emit byte-identical binary frames"
        );
        assert!(
            first_frame.logical_json == second_frame.logical_json,
            "same-fence streams reconstruct identical logical envelopes"
        );
        let envelope = first_frame.value;
        assert_eq!(envelope["previousCursor"], previous_cursor);
        assert_eq!(
            envelope["payload"]["$type"],
            "blue.catbird.chat.defs#messageAvailableEvent"
        );
        assert_eq!(
            envelope["payload"]["conversationId"],
            group_a.conversation_id.to_string()
        );
        assert_eq!(envelope["payload"]["seq"], seq);
        let cursor = envelope["cursor"].as_str().unwrap().to_owned();
        let successor = receipt(&pool, &cursor)
            .await
            .expect("receipt commits before the frame");
        assert_eq!(
            successor["inventory_session_id"],
            initial.session_id.to_string()
        );
        assert_eq!(
            successor["expires_at"], initial.session_row["expires_at"],
            "refresh does not renew old stream authority"
        );
        assert_eq!(
            successor["predecessor_cursor_hash"],
            format!("\\x{}", hex::encode(capability_hash(&previous_cursor)))
        );
        assert_eq!(
            successor["canonical_envelope_sha256"],
            format!(
                "\\x{}",
                hex::encode(Sha256::digest(&first_frame.logical_json))
            )
        );
        assert_ne!(
            refreshed.session_id, initial.session_id,
            "old and new inventory bindings are distinct"
        );
        assert!(
            row_by_session(&pool, initial.session_id).await.as_ref() == Some(&initial.session_row),
            "original parent remains byte-equivalent"
        );
        for (old_cursor, old_row) in &retained_receipts {
            assert!(
                receipt(&pool, old_cursor).await.as_ref() == Some(old_row),
                "existing cursor receipts remain immutable"
            );
        }
        let entries: Vec<i64> = sqlx::query_scalar(
            "SELECT seq FROM chat.entries WHERE conversation_id=$1 AND message_id=$2",
        )
        .bind(group_a.conversation_id)
        .bind(message_id)
        .fetch_all(&pool)
        .await
        .unwrap();
        assert_eq!(entries, vec![i64::try_from(seq).unwrap()]);
        let events: Vec<i64> = sqlx::query_scalar("SELECT event_position FROM chat.events WHERE event_kind='messageAvailable' AND convert_from(payload_bytes,'UTF8')::jsonb->>'conversationId'=$1 AND (convert_from(payload_bytes,'UTF8')::jsonb->>'seq')::bigint=$2")
            .bind(group_a.conversation_id.to_string()).bind(i64::try_from(seq).unwrap()).fetch_all(&pool).await.unwrap();
        assert_eq!(
            events.len(),
            1,
            "one durable event for one accepted application"
        );
        let recipients: Vec<(String,Uuid)> = sqlx::query_as("SELECT user_did,device_id FROM chat.event_recipients WHERE event_position=$1 ORDER BY user_did,device_id")
            .bind(events[0]).fetch_all(&pool).await.unwrap();
        let mut expected_recipients = vec![
            (device_a.did.clone(), device_a.device_id),
            (group_a.fulfiller.did.clone(), group_a.fulfiller.device_id),
        ];
        expected_recipients.sort();
        assert_eq!(
            recipients, expected_recipients,
            "exact two-member frozen event audience"
        );
        let receipt_count: i64 = sqlx::query_scalar("SELECT count(*) FROM chat.event_cursor_receipts WHERE inventory_session_id=$1 AND device_id=$2 AND event_position=$3")
            .bind(initial.session_id).bind(device_a.device_id).bind(events[0]).fetch_one(&pool).await.unwrap();
        assert_eq!(
            receipt_count, 1,
            "two live sockets share one successor receipt"
        );
        // Probe lookup by the ORIGINAL capability only after both original
        // sockets delivered. Leave the new ticket unused: it must not hide a
        // broken original connection by reconnecting around the failure.
        let _unused_original_ticket = mint_existing_ticket(&router, &device_a, &initial).await;
        retained_receipts.push((cursor.clone(), successor));
        previous_cursor = cursor;
        prior_inventory = refreshed.session_row;
        prior_capability = refreshed.capability;
        tokio::join!(assert_quiet(&mut first), assert_quiet(&mut second));
    }
    first.close(None).await.unwrap();
    second.close(None).await.unwrap();
    drop(first);
    drop(second);
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn binary_stream_at_mixed_capacity_keeps_old_pages_and_advertises_original_expiry() {
    let _serial = SERIAL.lock().await;
    let pool = owned_database().await;
    let (mut group_a, device_a) = ready_group(&pool).await;
    let router = http::router_for_authenticated_acceptance(pool.clone()).await;
    advance_unrelated_global_event(&pool, &router).await;
    let own_query = format!("?actorDeviceId={}", device_a.device_id);
    let (status, _) = http::send(
        router.clone(),
        http::unsigned_request(
            &device_a,
            "blue.catbird.chat.getOwnDevices",
            "GET",
            &own_query,
        ),
    )
    .await;
    assert_eq!(
        status,
        axum::http::StatusCode::OK,
        "real own-device inventory consumes one shared capacity slot"
    );
    assert_eq!(active_session_count(&pool, &device_a).await, 1);
    let initial = inventory_roundtrip(&pool, &router, &device_a).await;
    let (address, server) = serve_router(router.clone()).await;
    let mut socket = upgrade(&router, &device_a, &initial, address).await;
    let mut sessions = vec![initial.session_id];
    // Six new shared generations plus the initial shared generation and one
    // actual own-device snapshot reach the unchanged combined cap of eight.
    for expected_count in 3..=8 {
        advance_unrelated_global_event(&pool, &router).await;
        let next = inventory_roundtrip(&pool, &router, &device_a).await;
        assert!(
            !sessions.contains(&next.session_id),
            "each advanced fence has a distinct retained parent"
        );
        sessions.push(next.session_id);
        assert_eq!(active_session_count(&pool, &device_a).await, expected_count);
    }
    advance_unrelated_global_event(&pool, &router).await;
    assert_quiet(&mut socket).await;
    let before = inventory_rows(&pool).await;
    let earliest: DateTime<Utc> = sqlx::query_scalar(
        "SELECT min(expires_at) FROM (SELECT expires_at FROM chat.inventory_sessions WHERE user_did=$1 AND device_id=$2 AND expires_at>clock_timestamp() UNION ALL SELECT expires_at FROM chat.device_inventory_sessions WHERE user_did=$1 AND device_id=$2 AND expires_at>clock_timestamp()) live"
    ).bind(&device_a.did).bind(device_a.device_id).fetch_one(&pool).await.unwrap();
    let before_request = clock_now(&pool).await;
    let (status, headers, body) = send_with_headers(
        router.clone(),
        http::unsigned_request(
            &device_a,
            "blue.catbird.chat.getConversations",
            "GET",
            &format!("?actorDeviceId={}&limit=100", device_a.device_id),
        ),
    )
    .await;
    assert_eq!(
        status,
        axum::http::StatusCode::TOO_MANY_REQUESTS,
        "a fresh ninth inventory cannot evict live retained parents"
    );
    assert_eq!(body["error"], "RateLimited");
    let after_request = clock_now(&pool).await;
    let retry_after: i64 = headers
        .get(axum::http::header::RETRY_AFTER)
        .expect("capacity rejection includes Retry-After from retained expiry")
        .to_str()
        .unwrap()
        .parse()
        .unwrap();
    let ceil_remaining = |observed: DateTime<Utc>| {
        (((earliest - observed).num_microseconds().unwrap() as f64 / 1_000_000.0).ceil() as i64)
            .max(1)
    };
    assert!(
        retry_after >= ceil_remaining(after_request)
            && retry_after <= ceil_remaining(before_request),
        "Retry-After is bounded by PostgreSQL observations around the earliest original expiry"
    );
    let after = inventory_rows(&pool).await;
    for (table, old_rows) in &before {
        assert!(
            after.get(table) == Some(old_rows),
            "capacity rejection mutated chat.{table}"
        );
    }
    assert_eq!(active_session_count(&pool, &device_a).await, 8);
    // The own-device response is a complete single page with no retained
    // capability. Its internal snapshot may be replaced at mixed capacity;
    // every shared parent and stream chain must remain immutable.
    let before_own_rows = inventory_rows(&pool).await;
    let own_rows_for_device = |rows: &BTreeMap<&str, Value>| -> Vec<Value> {
        rows["device_inventory_sessions"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|row| {
                row["user_did"] == device_a.did
                    && row["device_id"] == device_a.device_id.to_string()
            })
            .cloned()
            .collect()
    };
    let old_own = own_rows_for_device(&before_own_rows);
    assert_eq!(old_own.len(), 1);
    assert_eq!(sessions.len(), 7);
    let (own_status, _, own_body) = send_with_headers(
        router.clone(),
        http::unsigned_request(
            &device_a,
            "blue.catbird.chat.getOwnDevices",
            "GET",
            &own_query,
        ),
    )
    .await;
    assert_eq!(
        own_status,
        axum::http::StatusCode::OK,
        "a complete own-device snapshot replaces its one internal predecessor"
    );
    assert_eq!(own_body["hasMore"], false);
    assert!(own_body["items"].is_array() && own_body.get("nextPageCursor").is_none());
    let after_own_rows = inventory_rows(&pool).await;
    for (table, retained) in &before_own_rows {
        if !matches!(
            *table,
            "device_inventory_sessions" | "device_inventory_items"
        ) {
            assert!(
                after_own_rows.get(table) == Some(retained),
                "own snapshot replacement must preserve shared chat.{table}"
            );
        }
    }
    let new_own = own_rows_for_device(&after_own_rows);
    assert_eq!(new_own.len(), 1);
    let old_id = &old_own[0]["device_inventory_session_id"];
    let new_id = &new_own[0]["device_inventory_session_id"];
    assert!(
        new_id != old_id,
        "the internal own-device snapshot is actually replaced"
    );
    // Targeted replacement must not touch another device's internal snapshot.
    for table in ["device_inventory_sessions", "device_inventory_items"] {
        let unaffected_before: Vec<_> = before_own_rows[table]
            .as_array()
            .unwrap()
            .iter()
            .filter(|row| row["device_inventory_session_id"] != *old_id)
            .collect();
        let unaffected_after: Vec<_> = after_own_rows[table]
            .as_array()
            .unwrap()
            .iter()
            .filter(|row| row["device_inventory_session_id"] != *new_id)
            .collect();
        assert!(
            unaffected_after == unaffected_before,
            "own replacement is confined to the exact device's prior snapshot"
        );
    }
    assert_eq!(active_session_count(&pool, &device_a).await, 8);
    for nsid in [
        "blue.catbird.chat.getPendingWelcomes",
        "blue.catbird.chat.getLeafRecoveryInbox",
    ] {
        let query = format!(
            "?actorDeviceId={}&inventorySessionId={}&limit=100",
            device_a.device_id, initial.capability
        );
        let (status, page) = http::send(
            router.clone(),
            http::unsigned_request(&device_a, nsid, "GET", &query),
        )
        .await;
        assert_eq!(
            status,
            axum::http::StatusCode::OK,
            "explicit original inventory page remains usable at capacity"
        );
        assert_eq!(page["inventorySessionId"], initial.capability);
        assert_eq!(page["hasMore"], false);
    }
    let (_, seq) = send_ready_application(&pool, &router, &device_a, &mut group_a).await;
    let frame = next_envelope(&mut socket, receipt(&pool, &initial.cursor).await.is_some()).await;
    let envelope = frame.value;
    assert_eq!(envelope["previousCursor"], initial.cursor);
    assert_eq!(
        envelope["payload"]["conversationId"],
        group_a.conversation_id.to_string()
    );
    assert_eq!(envelope["payload"]["seq"], seq);
    let successor = receipt(&pool, envelope["cursor"].as_str().unwrap())
        .await
        .unwrap();
    assert_eq!(
        successor["inventory_session_id"],
        initial.session_id.to_string()
    );
    assert_eq!(successor["expires_at"], initial.session_row["expires_at"]);
    assert!(row_by_session(&pool, initial.session_id).await.as_ref() == Some(&initial.session_row));
    socket.close(None).await.unwrap();
    drop(socket);
    server.stop().await;
}

/// A real signed ephemeral request crosses the same authority/readiness checks
/// as applications. Its typed binary frame must not mint a durable cursor.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn signed_typing_is_binary_canonical_and_does_not_advance_the_durable_cursor() {
    let _serial = SERIAL.lock().await;
    let pool = owned_database().await;
    let (mut group, device) = ready_group(&pool).await;
    let router = http::router_for_authenticated_acceptance(pool.clone()).await;
    let initial = inventory_roundtrip(&pool, &router, &device).await;
    let (address, server) = serve_router(router.clone()).await;
    let mut socket = upgrade(&router, &device, &initial, address).await;
    // Allow the actual handler to register its exact-conversation receiver.
    assert_quiet(&mut socket).await;
    seed_traffic_projection(&pool, &group).await;
    let before_inventory = inventory_rows(&pool).await;
    let count_durable = || async {
        let entries: i64 =
            sqlx::query_scalar("SELECT count(*) FROM chat.entries WHERE conversation_id=$1")
                .bind(group.conversation_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        let recipients: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM chat.event_recipients WHERE user_did=$1 AND device_id=$2",
        )
        .bind(&device.did)
        .bind(device.device_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        (entries, recipients)
    };
    let before_durable = count_durable().await;
    let typing_id = Uuid::new_v4();
    let body = json!({
        "$type":"blue.catbird.chat.defs#typingBody", "signatureDomain":"CATBIRD-CHAT-TYPING\u{0000}",
        "typingId":typing_id,"actorDid":group.requester.did,"actorDeviceId":group.requester.device_id,
        "keyId":group.requester.key_id,"authGeneration":1,"coordinates":coordinate_json(&group.prior),
        "isTyping":true,"signedAt":Utc::now().to_rfc3339_opts(SecondsFormat::Millis,true)
    });
    let mut wrapper = json!({"body":body,"signature":STANDARD.encode([0_u8;64])});
    let unsigned = serde_json::to_vec(&wrapper).unwrap();
    let canonical = decode_canonical_signed_mutation(&unsigned).unwrap();
    wrapper["signature"] = json!(STANDARD.encode(
        group
            .requester
            .signing_key
            .sign(canonical.transcript_bytes())
            .to_bytes()
    ));
    let response = signed_post(&router, &device, "blue.catbird.chat.publishTyping", wrapper).await;
    assert!(
        canonical_date(&response["typing"]["expiresAt"]),
        "actual publishTyping response uses canonical millisecond expiry"
    );
    let frame = next_binary(&mut socket, TYPING_TYPE).await;
    let typing = frame.value;
    assert_eq!(typing["typingId"], typing_id.to_string());
    assert_eq!(typing["conversationId"], group.conversation_id.to_string());
    assert_eq!(typing["actorDid"], device.did);
    assert_eq!(typing["actorDeviceId"], device.device_id.to_string());
    assert_eq!(typing["isTyping"], true);
    assert_eq!(typing["expiresAt"], response["typing"]["expiresAt"]);
    assert!(typing.get("cursor").is_none() && typing.get("previousCursor").is_none());
    assert!(
        inventory_rows(&pool).await == before_inventory,
        "typing leaves inventory, tickets, and cursor receipts immutable"
    );
    assert_eq!(
        count_durable().await,
        before_durable,
        "typing creates neither conversation entries nor durable event recipients"
    );
    let (_, seq) = send_ready_application(&pool, &router, &device, &mut group).await;
    let application = next_binary(&mut socket, ENVELOPE_TYPE).await;
    assert!(
        application.value["previousCursor"] == initial.cursor,
        "the next durable event continues the original cursor after typing"
    );
    assert_eq!(application.value["payload"]["seq"], seq);
    socket.close(None).await.unwrap();
    drop(socket);
    server.stop().await;
}

fn synthetic_binary(created_at: &str) -> Vec<u8> {
    let header = json!({"op":1,"t":ENVELOPE_TYPE});
    let body = json!({
        "createdAt":created_at,"cursor":"synthetic-current-cursor",
        "previousCursor":"synthetic-previous-cursor",
        "payload":{"$type":"blue.catbird.chat.defs#messageAvailableEvent",
            "conversationId":"11111111-1111-4111-8111-111111111111","seq":4}
    });
    let mut bytes = serde_ipld_dagcbor::to_vec(&header).unwrap();
    bytes.extend(serde_ipld_dagcbor::to_vec(&body).unwrap());
    bytes
}

#[test]
fn strict_binary_boundary_rejects_trailing_objects_and_noncanonical_timestamp_spellings() {
    let valid = synthetic_binary("2026-09-05T19:36:21.676Z");
    assert!(decode_binary(valid.clone(), ENVELOPE_TYPE).is_ok());
    for date in [
        "2026-09-05T19:36:21.676000Z",
        "2026-09-05T19:36:21.676000000Z",
        "2026-09-05T19:36:21.676+00:00",
    ] {
        assert_eq!(
            decode_binary(synthetic_binary(date), ENVELOPE_TYPE).err(),
            Some("noncanonical envelope timestamp")
        );
    }
    let mut trailing = valid.clone();
    trailing.extend(serde_ipld_dagcbor::to_vec(&json!({})).unwrap());
    assert_eq!(
        decode_binary(trailing, ENVELOPE_TYPE).err(),
        Some("trailing CBOR object or bytes")
    );
    assert_eq!(
        decode_binary(valid, "#eventEnvelope").err(),
        Some("incorrect operation or full external type reference")
    );
}

/// With no replaceable own snapshot, eight live shared parents occupy every
/// slot. This is the actual own-device facade's capacity/Retry-After branch.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn eight_shared_sessions_reject_fresh_own_snapshot_with_original_expiry_retry_after() {
    let _serial = SERIAL.lock().await;
    let pool = owned_database().await;
    let (_group, device) = ready_group(&pool).await;
    let router = http::router_for_authenticated_acceptance(pool.clone()).await;
    let first = inventory_roundtrip(&pool, &router, &device).await;
    let mut sessions = vec![first.session_id];
    for expected in 2..=8 {
        advance_unrelated_global_event(&pool, &router).await;
        let next = inventory_roundtrip(&pool, &router, &device).await;
        assert!(
            !sessions.contains(&next.session_id),
            "each real global fence creates one shared parent"
        );
        sessions.push(next.session_id);
        assert_eq!(active_session_count(&pool, &device).await, expected);
    }
    let own_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM chat.device_inventory_sessions WHERE user_did=$1 AND device_id=$2",
    )
    .bind(&device.did)
    .bind(device.device_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(own_count, 0, "there is no own snapshot to replace");
    let earliest: DateTime<Utc> = sqlx::query_scalar("SELECT min(expires_at) FROM chat.inventory_sessions WHERE user_did=$1 AND device_id=$2 AND expires_at>clock_timestamp()")
        .bind(&device.did).bind(device.device_id).fetch_one(&pool).await.unwrap();
    let before = inventory_rows(&pool).await;
    let before_request = clock_now(&pool).await;
    let (status, headers, body) = send_with_headers(
        router.clone(),
        http::unsigned_request(
            &device,
            "blue.catbird.chat.getOwnDevices",
            "GET",
            &format!("?actorDeviceId={}", device.device_id),
        ),
    )
    .await;
    let after_request = clock_now(&pool).await;
    assert_eq!(
        status,
        axum::http::StatusCode::TOO_MANY_REQUESTS,
        "eight retained shared parents prevent a fresh own-device ninth slot"
    );
    assert_eq!(body["error"], "RateLimited");
    let retry_after: i64 = headers
        .get(axum::http::header::RETRY_AFTER)
        .expect("own-device facade exposes Retry-After for the earliest original expiry")
        .to_str()
        .unwrap()
        .parse()
        .unwrap();
    let ceil_remaining = |observed: DateTime<Utc>| {
        (((earliest - observed).num_microseconds().unwrap() as f64 / 1_000_000.0).ceil() as i64)
            .max(1)
    };
    assert!(
        retry_after >= ceil_remaining(after_request)
            && retry_after <= ceil_remaining(before_request),
        "own-device Retry-After is bounded by exact PostgreSQL observations"
    );
    assert!(
        inventory_rows(&pool).await == before,
        "rejected own-device admission preserves every retained row and creates no own snapshot"
    );
    assert_eq!(active_session_count(&pool, &device).await, 8);
    assert!(
        row_by_session(&pool, first.session_id).await.as_ref() == Some(&first.session_row),
        "the earliest original shared parent remains byte-identical"
    );
}
