use dashmap::DashMap;
use ractor::{ActorRef, ActorStatus};
use sqlx::PgPool;
use std::sync::{Arc, RwLock};
use tracing::{debug, info, warn};

use super::conversation::ConvoActorArgs;
use super::directory::{
    DirectoryKeyPackage, DirectorySupervisor, DirectorySupervisorArgs, DirectorySupervisorMessage,
};
use super::messages::ConvoMessage;
use super::supervisor::{GroupSupervisor, GroupSupervisorMessage};
use crate::config::QuorumConfig;
use crate::realtime::SseState;

pub struct ActorRegistry {
    actors: Arc<DashMap<String, ActorRef<ConvoMessage>>>,
    group_supervisor: Arc<RwLock<Option<ActorRef<GroupSupervisorMessage>>>>,
    directory_supervisor: Arc<RwLock<Option<ActorRef<DirectorySupervisorMessage>>>>,
    db_pool: PgPool,
    sse_state: Arc<SseState>,
    notification_service: Option<Arc<crate::notifications::NotificationService>>,
    /// ADR-008 D1 (Phase 2): per-process quorum knobs, snapshotted from env at
    /// startup. Each spawned `ConversationActor` receives a clone via
    /// `ConvoActorArgs::quorum_config`.
    quorum_config: QuorumConfig,
}

impl ActorRegistry {
    pub fn new(
        db_pool: PgPool,
        sse_state: Arc<SseState>,
        notification_service: Option<Arc<crate::notifications::NotificationService>>,
    ) -> Self {
        info!("Initializing ActorRegistry");
        Self {
            actors: Arc::new(DashMap::new()),
            group_supervisor: Arc::new(RwLock::new(None)),
            directory_supervisor: Arc::new(RwLock::new(None)),
            db_pool,
            sse_state,
            notification_service,
            quorum_config: QuorumConfig::from_env(),
        }
    }

    pub async fn get_or_spawn(&self, convo_id: &str) -> anyhow::Result<ActorRef<ConvoMessage>> {
        if let Some(actor_ref) = self.actors.get(convo_id) {
            if actor_ref.get_status() == ActorStatus::Running {
                debug!("Using existing actor for conversation");
                return Ok(actor_ref.clone());
            }

            self.actors.remove(convo_id);
        }

        let supervisor = self.get_or_spawn_group_supervisor().await?;
        let args = ConvoActorArgs {
            convo_id: convo_id.to_string(),
            db_pool: self.db_pool.clone(),
            sse_state: self.sse_state.clone(),
            notification_service: self.notification_service.clone(),
            quorum_config: self.quorum_config.clone(),
        };

        let actor_ref = ractor::call!(
            supervisor,
            GroupSupervisorMessage::GetOrSpawnConversation,
            convo_id.to_string(),
            args
        )
        .map_err(|e| anyhow::anyhow!("Failed GroupSupervisor call: {}", e))??;

        self.actors.insert(convo_id.to_string(), actor_ref.clone());

        info!(
            "Actor available for conversation {}. Total actors: {}",
            convo_id,
            self.actor_count()
        );

        Ok(actor_ref)
    }

    pub fn actor_count(&self) -> usize {
        self.actors.len()
    }

    pub async fn fetch_key_package_for_member(
        &self,
        member_did: &str,
    ) -> anyhow::Result<Option<DirectoryKeyPackage>> {
        let supervisor = self.get_or_spawn_directory_supervisor().await?;
        ractor::call!(
            supervisor,
            DirectorySupervisorMessage::FetchKeyPackage,
            member_did.to_string()
        )
        .map_err(|e| anyhow::anyhow!("Failed DirectorySupervisor call: {}", e))?
    }

    pub fn remove_actor(&self, convo_id: &str) {
        if let Some(supervisor) = self
            .group_supervisor
            .read()
            .expect("group_supervisor read lock")
            .as_ref()
            .cloned()
        {
            let _ = supervisor.cast(GroupSupervisorMessage::RemoveConversation(
                convo_id.to_string(),
            ));
        }

        if self.actors.remove(convo_id).is_some() {
            info!(
                "Removed actor for conversation {}. Remaining actors: {}",
                convo_id,
                self.actor_count()
            );
        } else {
            warn!(
                "Attempted to remove non-existent actor for conversation {}",
                convo_id
            );
        }
    }

    pub async fn shutdown_all(&self) {
        info!("Shutting down all {} actors", self.actor_count());

        for entry in self.actors.iter() {
            let actor_ref = entry.value();
            debug!("Sending shutdown to actor");
            let _ = actor_ref.cast(ConvoMessage::Shutdown);
        }

        if let Some(supervisor) = self
            .group_supervisor
            .read()
            .expect("group_supervisor read lock")
            .as_ref()
            .cloned()
        {
            supervisor.stop(None);
        }

        if let Ok(mut guard) = self.group_supervisor.write() {
            *guard = None;
        }

        if let Some(supervisor) = self
            .directory_supervisor
            .read()
            .expect("directory_supervisor read lock")
            .as_ref()
            .cloned()
        {
            supervisor.stop(None);
        }

        if let Ok(mut guard) = self.directory_supervisor.write() {
            *guard = None;
        }

        self.actors.clear();
        info!("All actors shut down");
    }

    async fn get_or_spawn_group_supervisor(
        &self,
    ) -> anyhow::Result<ActorRef<GroupSupervisorMessage>> {
        {
            let guard = self
                .group_supervisor
                .read()
                .expect("group_supervisor read lock");
            if let Some(supervisor) = guard.as_ref() {
                if supervisor.get_status() == ActorStatus::Running {
                    return Ok(supervisor.clone());
                }
            }
        }

        {
            let guard = self
                .group_supervisor
                .write()
                .expect("group_supervisor write lock");
            if let Some(supervisor) = guard.as_ref() {
                if supervisor.get_status() == ActorStatus::Running {
                    return Ok(supervisor.clone());
                }
            }
        }

        let (supervisor_ref, _handle) = ractor::Actor::spawn(None, GroupSupervisor, ())
            .await
            .map_err(|e| anyhow::anyhow!("Failed to spawn GroupSupervisor: {}", e))?;

        let mut guard = self
            .group_supervisor
            .write()
            .expect("group_supervisor write lock");
        if let Some(supervisor) = guard.as_ref() {
            if supervisor.get_status() == ActorStatus::Running {
                return Ok(supervisor.clone());
            }
        }
        *guard = Some(supervisor_ref.clone());
        info!("GroupSupervisor spawned");

        Ok(supervisor_ref)
    }

    async fn get_or_spawn_directory_supervisor(
        &self,
    ) -> anyhow::Result<ActorRef<DirectorySupervisorMessage>> {
        {
            let guard = self
                .directory_supervisor
                .read()
                .expect("directory_supervisor read lock");
            if let Some(supervisor) = guard.as_ref() {
                if supervisor.get_status() == ActorStatus::Running {
                    return Ok(supervisor.clone());
                }
            }
        }

        {
            let guard = self
                .directory_supervisor
                .write()
                .expect("directory_supervisor write lock");
            if let Some(supervisor) = guard.as_ref() {
                if supervisor.get_status() == ActorStatus::Running {
                    return Ok(supervisor.clone());
                }
            }
        }

        let worker_count = std::env::var("DIRECTORY_ACTOR_POOL_SIZE")
            .ok()
            .and_then(|value| value.parse::<usize>().ok())
            .filter(|value| *value > 0)
            .unwrap_or(4);

        let (supervisor_ref, _handle) = ractor::Actor::spawn(
            None,
            DirectorySupervisor,
            DirectorySupervisorArgs {
                db_pool: self.db_pool.clone(),
                worker_count,
            },
        )
        .await
        .map_err(|e| anyhow::anyhow!("Failed to spawn DirectorySupervisor: {}", e))?;

        let mut guard = self
            .directory_supervisor
            .write()
            .expect("directory_supervisor write lock");
        if let Some(supervisor) = guard.as_ref() {
            if supervisor.get_status() == ActorStatus::Running {
                return Ok(supervisor.clone());
            }
        }
        *guard = Some(supervisor_ref.clone());
        info!("DirectorySupervisor spawned with {} workers", worker_count);

        Ok(supervisor_ref)
    }
}

impl Clone for ActorRegistry {
    fn clone(&self) -> Self {
        Self {
            actors: Arc::clone(&self.actors),
            group_supervisor: Arc::clone(&self.group_supervisor),
            directory_supervisor: Arc::clone(&self.directory_supervisor),
            db_pool: self.db_pool.clone(),
            sse_state: self.sse_state.clone(),
            notification_service: self.notification_service.clone(),
            quorum_config: self.quorum_config.clone(),
        }
    }
}
