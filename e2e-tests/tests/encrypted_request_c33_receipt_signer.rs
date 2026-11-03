#![allow(dead_code)]
#[path = "support/encrypted_requests.rs"]
mod encrypted_requests;
#[path = "support/staged_direct_request.rs"]
mod staged;

use anyhow::Context as _;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use encrypted_requests::{request_database_url, DeterministicFaultTransport};
use serde_json::Value;

async fn publication_graph(
    database: &tokio_postgres::Client,
    fixture: &staged::StagedRequest,
) -> anyhow::Result<Value> {
    let row = database
        .query_one(
            "SELECT jsonb_build_object(\
             'attempt',(SELECT to_jsonb(a) FROM chat.direct_request_attempts a WHERE request_id=$1),\
             'packages',(SELECT jsonb_agg(jsonb_build_object('ref',encode(k.key_package_ref,'hex'),'status',k.status,'terminalTransitionId',k.terminal_transition_id) ORDER BY k.key_package_ref) FROM chat.key_packages k JOIN chat.direct_request_selected_devices d USING(key_package_ref) WHERE d.request_id=$1),\
             'conversation',(SELECT count(*) FROM chat.conversations WHERE conversation_id=$2),\
             'participants',(SELECT count(*) FROM chat.participants WHERE conversation_id=$2),\
             'publication',(SELECT count(*) FROM chat.direct_request_publications WHERE request_id=$1),\
             'welcomeDeliveries',(SELECT count(*) FROM chat.direct_request_device_deliveries WHERE request_id=$1),\
             'intervals',(SELECT count(*) FROM chat.application_intervals WHERE conversation_id=$2),\
             'leaves',(SELECT count(*) FROM chat.member_devices WHERE conversation_id=$2),\
             'entries',(SELECT count(*) FROM chat.entries WHERE conversation_id=$2),\
             'transitions',(SELECT count(*) FROM chat.transitions WHERE conversation_id=$2),\
             'pushEvents',(SELECT count(*) FROM chat.direct_request_push_events WHERE request_id=$1),\
             'pushRecipients',(SELECT count(*) FROM chat.direct_request_push_event_recipients WHERE request_id=$1),\
             'lifecycleReserve',(SELECT count(*) FROM chat.direct_request_lifecycle_reserves WHERE request_id=$1),\
             'events',(SELECT count(*) FROM chat.events WHERE position(convert_to(($2::uuid)::text,'UTF8') in payload_bytes)>0)\
             )",
            &[&fixture.request_id, &fixture.conversation_id],
        )
        .await?;
    Ok(row.get(0))
}

#[tokio::test(flavor = "multi_thread")]
async fn c33_initial_publication_without_i13_signer_refuses_before_canonical_effects(
) -> anyhow::Result<()> {
    let fixture = staged::stage_request_without_sequencer_receipts("c33-no-i13-signer").await?;
    assert_ne!(
        fixture.server.receipt_public_key, fixture.server.sequencer_receipt_public_key,
        "the genuine outcome signer is not an I13 fallback"
    );
    assert_eq!(
        STANDARD
            .decode(
                fixture.publication["body"]["archiveCommitment"]
                    .as_str()
                    .context("archiveCommitment")?
            )?
            .len(),
        32,
        "the rejected publication must carry the real bootstrap commitment"
    );
    let (database, connection) =
        tokio_postgres::connect(request_database_url(), tokio_postgres::NoTls).await?;
    let connection_task = tokio::spawn(connection);
    let before = publication_graph(&database, &fixture).await?;
    for field in [
        "conversation",
        "participants",
        "publication",
        "welcomeDeliveries",
        "intervals",
        "leaves",
        "entries",
        "transitions",
        "pushEvents",
        "pushRecipients",
        "lifecycleReserve",
        "events",
    ] {
        assert_eq!(before[field], 0, "initial publication already has {field}");
    }

    let (status, body) = fixture
        .post_publication(&mut DeterministicFaultTransport::default())
        .await?;
    let error: Value = serde_json::from_slice(&body)?;
    assert_eq!(status, reqwest::StatusCode::BAD_REQUEST, "{error}");
    assert_eq!(error["error"], "CutoverRequired", "{error}");
    assert_eq!(
        publication_graph(&database, &fixture).await?,
        before,
        "missing I13 signer changed the canonical graph, attempt or reserved packages"
    );
    connection_task.abort();
    Ok(())
}
