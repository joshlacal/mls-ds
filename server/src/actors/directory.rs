use async_trait::async_trait;
use ractor::{Actor, ActorProcessingErr, ActorRef, RpcReplyPort, SupervisionEvent};
use sqlx::PgPool;
use std::collections::HashMap;
use tracing::{debug, error, info, warn};

/// Key-package lookup result returned by directory workers.
#[derive(Debug, Clone)]
pub struct DirectoryKeyPackage {
    pub key_package: Vec<u8>,
    pub key_package_hash: String,
}

/// Message protocol for directory workers.
pub enum DirectoryActorMessage {
    /// Fetch the newest available key package for a member DID.
    FetchKeyPackage(
        String,
        RpcReplyPort<anyhow::Result<Option<DirectoryKeyPackage>>>,
    ),
}

/// Message protocol for directory supervisor.
pub enum DirectorySupervisorMessage {
    /// Dispatch key-package lookup to worker pool.
    FetchKeyPackage(
        String,
        RpcReplyPort<anyhow::Result<Option<DirectoryKeyPackage>>>,
    ),
}

pub struct DirectoryActor;
pub struct DirectorySupervisor;

pub struct DirectoryActorArgs {
    pub db_pool: PgPool,
    pub worker_index: usize,
}

pub struct DirectorySupervisorArgs {
    pub db_pool: PgPool,
    pub worker_count: usize,
}

pub struct DirectoryActorState {
    db_pool: PgPool,
    worker_index: usize,
}

pub struct DirectorySupervisorState {
    db_pool: PgPool,
    workers: Vec<ActorRef<DirectoryActorMessage>>,
    worker_index_by_pid: HashMap<u64, usize>,
    next_worker: usize,
}

#[async_trait]
impl Actor for DirectoryActor {
    type Msg = DirectoryActorMessage;
    type State = DirectoryActorState;
    type Arguments = DirectoryActorArgs;

    async fn pre_start(
        &self,
        _myself: ActorRef<Self::Msg>,
        args: Self::Arguments,
    ) -> Result<Self::State, ActorProcessingErr> {
        Ok(DirectoryActorState {
            db_pool: args.db_pool,
            worker_index: args.worker_index,
        })
    }

    async fn handle(
        &self,
        _myself: ActorRef<Self::Msg>,
        message: Self::Msg,
        state: &mut Self::State,
    ) -> Result<(), ActorProcessingErr> {
        match message {
            DirectoryActorMessage::FetchKeyPackage(recipient_did, reply) => {
                let lookup_result = sqlx::query_as::<_, (Vec<u8>, String)>(
                    "SELECT key_package, key_package_hash \
                     FROM key_packages \
                     WHERE owner_did = $1 \
                       AND consumed_at IS NULL \
                       AND expires_at > NOW() \
                     ORDER BY created_at DESC \
                     LIMIT 1",
                )
                .bind(&recipient_did)
                .fetch_optional(&state.db_pool)
                .await
                .map(|row| {
                    row.map(|(key_package, key_package_hash)| DirectoryKeyPackage {
                        key_package,
                        key_package_hash,
                    })
                })
                .map_err(|e| anyhow::anyhow!("Directory lookup failed: {}", e));

                if !reply.is_closed() {
                    let _ = reply.send(lookup_result);
                } else {
                    debug!(
                        "Directory worker {} reply channel closed for {}",
                        state.worker_index, recipient_did
                    );
                }
            }
        }

        Ok(())
    }
}

#[async_trait]
impl Actor for DirectorySupervisor {
    type Msg = DirectorySupervisorMessage;
    type State = DirectorySupervisorState;
    type Arguments = DirectorySupervisorArgs;

    async fn pre_start(
        &self,
        myself: ActorRef<Self::Msg>,
        args: Self::Arguments,
    ) -> Result<Self::State, ActorProcessingErr> {
        let worker_count = args.worker_count.max(1);
        let mut workers = Vec::with_capacity(worker_count);
        let mut worker_index_by_pid = HashMap::new();

        for worker_index in 0..worker_count {
            let worker = spawn_directory_worker(&myself, &args.db_pool, worker_index)
                .await
                .map_err(|e| format!("Failed to spawn directory worker {}: {}", worker_index, e))?;

            worker_index_by_pid.insert(worker.get_id().pid(), worker_index);
            workers.push(worker);
        }

        info!("DirectorySupervisor started with {} workers", worker_count);

        Ok(DirectorySupervisorState {
            db_pool: args.db_pool,
            workers,
            worker_index_by_pid,
            next_worker: 0,
        })
    }

    async fn handle(
        &self,
        _myself: ActorRef<Self::Msg>,
        message: Self::Msg,
        state: &mut Self::State,
    ) -> Result<(), ActorProcessingErr> {
        match message {
            DirectorySupervisorMessage::FetchKeyPackage(recipient_did, reply) => {
                if state.workers.is_empty() {
                    if !reply.is_closed() {
                        let _ = reply.send(Err(anyhow::anyhow!(
                            "Directory worker pool is not available"
                        )));
                    }
                    return Ok(());
                }

                let worker_index = state.next_worker % state.workers.len();
                state.next_worker = (state.next_worker + 1) % state.workers.len();
                let worker = state.workers[worker_index].clone();

                let result = ractor::call!(
                    worker,
                    DirectoryActorMessage::FetchKeyPackage,
                    recipient_did
                )
                .map_err(|e| anyhow::anyhow!("Directory worker RPC failed: {}", e))?;

                if !reply.is_closed() {
                    let _ = reply.send(result);
                }
            }
        }

        Ok(())
    }

    async fn handle_supervisor_evt(
        &self,
        myself: ActorRef<Self::Msg>,
        message: SupervisionEvent,
        state: &mut Self::State,
    ) -> Result<(), ActorProcessingErr> {
        match message {
            SupervisionEvent::ActorFailed(actor, err) => {
                restart_failed_worker(state, &myself, &actor, Some(err.to_string())).await;
            }
            SupervisionEvent::ActorTerminated(actor, _, reason) => {
                restart_failed_worker(state, &myself, &actor, reason).await;
            }
            _ => {}
        }

        Ok(())
    }
}

async fn restart_failed_worker(
    state: &mut DirectorySupervisorState,
    supervisor: &ActorRef<DirectorySupervisorMessage>,
    actor: &ractor::ActorCell,
    reason: Option<String>,
) {
    let worker_pid = actor.get_id().pid();
    let Some(worker_index) = state.worker_index_by_pid.remove(&worker_pid) else {
        return;
    };

    warn!(
        "Directory worker {} (pid {}) exited: {:?}; restarting",
        worker_index, worker_pid, reason
    );

    match spawn_directory_worker(supervisor, &state.db_pool, worker_index).await {
        Ok(worker_ref) => {
            state
                .worker_index_by_pid
                .insert(worker_ref.get_id().pid(), worker_index);
            if worker_index < state.workers.len() {
                state.workers[worker_index] = worker_ref;
            } else {
                state.workers.push(worker_ref);
            }
            info!("Directory worker {} restarted", worker_index);
        }
        Err(e) => {
            error!(
                "Failed to restart directory worker {} after failure: {}",
                worker_index, e
            );
        }
    }
}

async fn spawn_directory_worker(
    supervisor: &ActorRef<DirectorySupervisorMessage>,
    db_pool: &PgPool,
    worker_index: usize,
) -> anyhow::Result<ActorRef<DirectoryActorMessage>> {
    let (worker_ref, _handle) = ractor::Actor::spawn_linked(
        None,
        DirectoryActor,
        DirectoryActorArgs {
            db_pool: db_pool.clone(),
            worker_index,
        },
        supervisor.get_cell(),
    )
    .await
    .map_err(|e| anyhow::anyhow!("Failed spawning directory worker {}: {}", worker_index, e))?;

    Ok(worker_ref)
}
