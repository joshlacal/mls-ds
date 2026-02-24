use anyhow::Context;
use async_trait::async_trait;
use futures::future::join_all;
use ractor::{Actor, ActorProcessingErr, ActorRef, RpcReplyPort};
use sqlx::PgPool;
use std::sync::Arc;
use tracing::{debug, error};

pub enum BroadcasterMessage {
    WriteEnvelopes(
        String,
        String,
        Vec<String>,
        Option<String>,
        RpcReplyPort<anyhow::Result<usize>>,
    ),
}

pub struct BroadcasterActor;

pub struct BroadcasterArgs {
    pub db_pool: PgPool,
    pub worker_id: usize,
}

pub struct BroadcasterState {
    db_pool: PgPool,
    worker_id: usize,
}

#[derive(Clone)]
pub struct BroadcasterPool {
    workers: Arc<Vec<ActorRef<BroadcasterMessage>>>,
    chunk_size: usize,
}

impl BroadcasterPool {
    pub async fn spawn(
        db_pool: PgPool,
        worker_count: usize,
        chunk_size: usize,
    ) -> anyhow::Result<Self> {
        let worker_count = worker_count.max(1);
        let chunk_size = chunk_size.max(1);
        let mut workers = Vec::with_capacity(worker_count);

        for worker_id in 0..worker_count {
            let (worker_ref, _handle) = ractor::Actor::spawn(
                None,
                BroadcasterActor,
                BroadcasterArgs {
                    db_pool: db_pool.clone(),
                    worker_id,
                },
            )
            .await
            .map_err(|e| {
                anyhow::anyhow!("Failed to spawn broadcaster worker {}: {}", worker_id, e)
            })?;

            workers.push(worker_ref);
        }

        Ok(Self {
            workers: Arc::new(workers),
            chunk_size,
        })
    }

    pub async fn fanout_envelopes(
        &self,
        convo_id: &str,
        msg_id: &str,
        recipients: Vec<String>,
        skip_did: Option<&str>,
    ) -> anyhow::Result<usize> {
        if recipients.is_empty() {
            return Ok(0);
        }

        let mut calls = Vec::new();
        let skip_did = skip_did.map(str::to_string);

        for (idx, chunk) in recipients.chunks(self.chunk_size).enumerate() {
            let worker = self.workers[idx % self.workers.len()].clone();
            let chunk_recipients = chunk.to_vec();
            let convo_id = convo_id.to_string();
            let msg_id = msg_id.to_string();
            let skip_did = skip_did.clone();

            calls.push(async move {
                ractor::call!(
                    worker,
                    BroadcasterMessage::WriteEnvelopes,
                    convo_id,
                    msg_id,
                    chunk_recipients,
                    skip_did
                )
                .map_err(|e| anyhow::anyhow!("Failed broadcaster RPC: {}", e))?
            });
        }

        let mut total_inserted = 0usize;
        for result in join_all(calls).await {
            total_inserted += result?;
        }

        Ok(total_inserted)
    }

    pub fn shutdown(&self) {
        for worker in self.workers.iter() {
            worker.stop(None);
        }
    }
}

#[async_trait]
impl Actor for BroadcasterActor {
    type Msg = BroadcasterMessage;
    type State = BroadcasterState;
    type Arguments = BroadcasterArgs;

    async fn pre_start(
        &self,
        _myself: ActorRef<Self::Msg>,
        args: Self::Arguments,
    ) -> Result<Self::State, ActorProcessingErr> {
        Ok(BroadcasterState {
            db_pool: args.db_pool,
            worker_id: args.worker_id,
        })
    }

    async fn handle(
        &self,
        _myself: ActorRef<Self::Msg>,
        message: Self::Msg,
        state: &mut Self::State,
    ) -> Result<(), ActorProcessingErr> {
        match message {
            BroadcasterMessage::WriteEnvelopes(convo_id, msg_id, recipients, skip_did, reply) => {
                let mut inserted = 0usize;
                let write_result: anyhow::Result<usize> = async {
                    for recipient_did in recipients {
                        if skip_did.as_deref() == Some(recipient_did.as_str()) {
                            continue;
                        }

                        let envelope_id = uuid::Uuid::new_v4().to_string();
                        let query_result = sqlx::query(
                            r#"
                            INSERT INTO envelopes (id, convo_id, recipient_did, message_id, created_at)
                            VALUES ($1, $2, $3, $4, NOW())
                            ON CONFLICT (recipient_did, message_id) DO NOTHING
                            "#,
                        )
                        .bind(&envelope_id)
                        .bind(&convo_id)
                        .bind(&recipient_did)
                        .bind(&msg_id)
                        .execute(&state.db_pool)
                        .await
                        .context("Failed to insert envelope")?;

                        inserted += query_result.rows_affected() as usize;
                    }

                    Ok(inserted)
                }
                .await;

                let write_status = write_result.as_ref().map(|_| ()).map_err(|e| e.to_string());

                if !reply.is_closed() {
                    let _ = reply.send(write_result);
                }

                if let Err(e) = write_status {
                    error!(
                        "Broadcaster worker {} failed fanout for convo {}: {}",
                        state.worker_id, convo_id, e
                    );
                } else {
                    debug!(
                        "Broadcaster worker {} processed fanout for convo {}",
                        state.worker_id, convo_id
                    );
                }
            }
        }

        Ok(())
    }
}
