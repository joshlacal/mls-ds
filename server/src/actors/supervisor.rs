use async_trait::async_trait;
use ractor::{Actor, ActorProcessingErr, ActorRef, RpcReplyPort, SupervisionEvent};
use std::{collections::HashMap, time::Duration};
use tracing::{debug, error, info, warn};

use super::conversation::{ConversationActor, ConvoActorArgs};
use super::messages::ConvoMessage;

const MAX_RESTART_ATTEMPTS: u32 = 5;
const INITIAL_RESTART_BACKOFF_MS: u64 = 250;
const MAX_RESTART_BACKOFF_MS: u64 = 5_000;

/// Supervisor message protocol for conversation actor lifecycle.
pub enum GroupSupervisorMessage {
    /// Get an existing conversation actor or spawn a new linked child.
    GetOrSpawnConversation(
        String,
        ConvoActorArgs,
        RpcReplyPort<anyhow::Result<ActorRef<ConvoMessage>>>,
    ),
    /// Remove cached conversation metadata.
    RemoveConversation(String),
}

/// Supervisor responsible for all [`ConversationActor`] children.
pub struct GroupSupervisor;

pub struct GroupSupervisorState {
    conversations: HashMap<String, ActorRef<ConvoMessage>>,
    spawn_args: HashMap<String, ConvoActorArgs>,
    restart_attempts: HashMap<String, u32>,
}

#[async_trait]
impl Actor for GroupSupervisor {
    type Msg = GroupSupervisorMessage;
    type State = GroupSupervisorState;
    type Arguments = ();

    async fn pre_start(
        &self,
        _myself: ActorRef<Self::Msg>,
        _args: Self::Arguments,
    ) -> Result<Self::State, ActorProcessingErr> {
        info!("GroupSupervisor started");
        Ok(GroupSupervisorState {
            conversations: HashMap::new(),
            spawn_args: HashMap::new(),
            restart_attempts: HashMap::new(),
        })
    }

    async fn handle(
        &self,
        myself: ActorRef<Self::Msg>,
        message: Self::Msg,
        state: &mut Self::State,
    ) -> Result<(), ActorProcessingErr> {
        match message {
            GroupSupervisorMessage::GetOrSpawnConversation(convo_id, args, reply) => {
                if let Some(actor_ref) = state.conversations.get(&convo_id) {
                    // N32: reuse any actor in an active lifecycle state.
                    // `Running`-only treated a freshly spawned (`Starting`)
                    // child as dead and spawned a duplicate ConversationActor
                    // for the same convo (duplicate seq assignment).
                    if super::registry::actor_status_is_alive(actor_ref.get_status()) {
                        let _ = reply.send(Ok(actor_ref.clone()));
                        return Ok(());
                    }
                }

                state.conversations.remove(&convo_id);
                let spawn_args = args.clone();

                let spawn_result = spawn_conversation(&myself, &convo_id, spawn_args).await;
                match spawn_result {
                    Ok(actor_ref) => {
                        state
                            .conversations
                            .insert(convo_id.clone(), actor_ref.clone());
                        state.spawn_args.insert(convo_id.clone(), args);
                        state.restart_attempts.insert(convo_id.clone(), 0);
                        info!("Spawned linked ConversationActor for {}", convo_id);
                        let _ = reply.send(Ok(actor_ref));
                    }
                    Err(e) => {
                        error!("Failed to spawn ConversationActor for {}: {}", convo_id, e);
                        let _ = reply.send(Err(e));
                    }
                }
            }
            GroupSupervisorMessage::RemoveConversation(convo_id) => {
                state.conversations.remove(&convo_id);
                state.spawn_args.remove(&convo_id);
                state.restart_attempts.remove(&convo_id);
                debug!(
                    "Removed conversation {} from GroupSupervisor cache",
                    convo_id
                );
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
            SupervisionEvent::ActorStarted(actor) => {
                debug!("Child actor started: {:?}", actor.get_id());
            }
            SupervisionEvent::ActorTerminated(actor, _, reason) => {
                if let Some(convo_id) = find_conversation_id(state, &actor) {
                    state.conversations.remove(&convo_id);
                    state.spawn_args.remove(&convo_id);
                    state.restart_attempts.remove(&convo_id);
                    info!(
                        "ConversationActor {} terminated cleanly ({:?})",
                        convo_id, reason
                    );
                }
            }
            SupervisionEvent::ActorFailed(actor, failure) => {
                if let Some(convo_id) = find_conversation_id(state, &actor) {
                    state.conversations.remove(&convo_id);

                    let attempt_count = {
                        let attempts = state.restart_attempts.entry(convo_id.clone()).or_insert(0);
                        *attempts += 1;
                        *attempts
                    };

                    if attempt_count > MAX_RESTART_ATTEMPTS {
                        warn!(
                            "ConversationActor {} exceeded restart limit after failure: {}",
                            convo_id, failure
                        );
                        state.spawn_args.remove(&convo_id);
                        state.restart_attempts.remove(&convo_id);
                        return Ok(());
                    }

                    if let Some(args) = state.spawn_args.get(&convo_id).cloned() {
                        let backoff = restart_backoff(attempt_count);
                        warn!(
                            "ConversationActor {} failed (attempt {}), restarting in {:?}: {}",
                            convo_id, attempt_count, backoff, failure
                        );
                        tokio::time::sleep(backoff).await;

                        match spawn_conversation(&myself, &convo_id, args).await {
                            Ok(new_actor_ref) => {
                                state.conversations.insert(convo_id.clone(), new_actor_ref);
                                info!(
                                    "ConversationActor {} restarted successfully (attempt {})",
                                    convo_id, attempt_count
                                );
                            }
                            Err(err) => {
                                error!(
                                    "Failed to restart ConversationActor {} after failure: {}",
                                    convo_id, err
                                );
                            }
                        }
                    }
                }
            }
            _ => {}
        }

        Ok(())
    }
}

fn find_conversation_id(state: &GroupSupervisorState, actor: &ractor::ActorCell) -> Option<String> {
    state
        .conversations
        .iter()
        .find_map(|(convo_id, actor_ref)| {
            (actor_ref.get_id() == actor.get_id()).then(|| convo_id.clone())
        })
}

fn restart_backoff(attempt: u32) -> Duration {
    let exponent = attempt.saturating_sub(1).min(10);
    let multiplier = 2u64.pow(exponent);
    Duration::from_millis((INITIAL_RESTART_BACKOFF_MS * multiplier).min(MAX_RESTART_BACKOFF_MS))
}

async fn spawn_conversation(
    supervisor: &ActorRef<GroupSupervisorMessage>,
    convo_id: &str,
    args: ConvoActorArgs,
) -> anyhow::Result<ActorRef<ConvoMessage>> {
    let (actor_ref, _handle) =
        ractor::Actor::spawn_linked(None, ConversationActor, args, supervisor.get_cell())
            .await
            .map_err(|e| anyhow::anyhow!("failed to spawn linked ConversationActor: {}", e))?;

    debug!("Linked ConversationActor started for {}", convo_id);
    Ok(actor_ref)
}
