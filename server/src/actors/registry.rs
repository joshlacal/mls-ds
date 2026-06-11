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
    /// N32: single-flight guards for supervisor spawning. Exactly one caller
    /// may run the spawn-and-cache critical section at a time; everyone else
    /// waits on the lock and re-checks the cache. A `tokio::sync::Mutex` is
    /// required (not `std`) because the guard is held across the spawn
    /// `.await`. Held only on the cold path — once a supervisor is cached
    /// and alive, callers return from the read-lock fast path.
    group_supervisor_spawn_lock: Arc<tokio::sync::Mutex<()>>,
    directory_supervisor_spawn_lock: Arc<tokio::sync::Mutex<()>>,
    db_pool: PgPool,
    sse_state: Arc<SseState>,
    notification_service: Option<Arc<crate::notifications::NotificationService>>,
    /// ADR-008 D1 (Phase 2): per-process quorum knobs, snapshotted from env at
    /// startup. Each spawned `ConversationActor` receives a clone via
    /// `ConvoActorArgs::quorum_config`.
    quorum_config: QuorumConfig,
}

/// N32: an actor is usable if it is anywhere in its active lifecycle, not
/// only `Running`. A freshly spawned actor reports `Starting` until
/// `pre_start` completes; treating `Starting` as dead made every concurrent
/// first-touch caller conclude the cached supervisor was unusable and spawn
/// its own — N callers got N `GroupSupervisor`s, each spawning its own
/// `ConversationActor` for the same convo (duplicate seq assignment;
/// `messages_convo_seq_unique` violations). Messages sent to a `Starting`
/// actor are queued in its mailbox and processed once it is `Running`.
pub(super) fn actor_status_is_alive(status: ActorStatus) -> bool {
    matches!(
        status,
        ActorStatus::Starting | ActorStatus::Running | ActorStatus::Upgrading
    )
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
            group_supervisor_spawn_lock: Arc::new(tokio::sync::Mutex::new(())),
            directory_supervisor_spawn_lock: Arc::new(tokio::sync::Mutex::new(())),
            db_pool,
            sse_state,
            notification_service,
            quorum_config: QuorumConfig::from_env(),
        }
    }

    pub async fn get_or_spawn(&self, convo_id: &str) -> anyhow::Result<ActorRef<ConvoMessage>> {
        if let Some(actor_ref) = self.actors.get(convo_id) {
            if actor_status_is_alive(actor_ref.get_status()) {
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

    /// Return the cached supervisor if it is still in an active lifecycle
    /// state, clearing only the registry's cache slot otherwise.
    fn cached_alive_supervisor<M>(slot: &RwLock<Option<ActorRef<M>>>) -> Option<ActorRef<M>> {
        let guard = slot.read().expect("supervisor read lock");
        guard
            .as_ref()
            .filter(|supervisor| actor_status_is_alive(supervisor.get_status()))
            .cloned()
    }

    /// N32: single-flight supervisor spawn.
    ///
    /// Pre-fix, this was double-checked locking with two bugs: (1) the
    /// `Running`-only liveness check treated a freshly spawned (`Starting`)
    /// supervisor as dead, and (2) no lock was held across the spawn
    /// `.await`, so every concurrent first-touch caller spawned its own
    /// supervisor and overwrote the cache. Documented as the known-RED
    /// `test_message_sequence_numbers_sequential` race (duplicate
    /// `ConversationActor`s -> duplicate seq).
    ///
    /// Now: fast-path read; otherwise acquire the spawn mutex, re-check the
    /// cache under exclusivity, and spawn at most once. Per-conversation
    /// spawn single-flight then falls out of the actor model for free: the
    /// one `GroupSupervisor` serializes `GetOrSpawnConversation` through its
    /// mailbox.
    async fn get_or_spawn_group_supervisor(
        &self,
    ) -> anyhow::Result<ActorRef<GroupSupervisorMessage>> {
        if let Some(supervisor) = Self::cached_alive_supervisor(&self.group_supervisor) {
            return Ok(supervisor);
        }

        let _spawn_guard = self.group_supervisor_spawn_lock.lock().await;
        // Re-check under spawn exclusivity: a racing caller may have spawned
        // and cached while we waited on the lock.
        if let Some(supervisor) = Self::cached_alive_supervisor(&self.group_supervisor) {
            return Ok(supervisor);
        }

        let (supervisor_ref, _handle) = ractor::Actor::spawn(None, GroupSupervisor, ())
            .await
            .map_err(|e| anyhow::anyhow!("Failed to spawn GroupSupervisor: {}", e))?;

        *self
            .group_supervisor
            .write()
            .expect("group_supervisor write lock") = Some(supervisor_ref.clone());
        info!("GroupSupervisor spawned");

        Ok(supervisor_ref)
    }

    async fn get_or_spawn_directory_supervisor(
        &self,
    ) -> anyhow::Result<ActorRef<DirectorySupervisorMessage>> {
        if let Some(supervisor) = Self::cached_alive_supervisor(&self.directory_supervisor) {
            return Ok(supervisor);
        }

        let _spawn_guard = self.directory_supervisor_spawn_lock.lock().await;
        if let Some(supervisor) = Self::cached_alive_supervisor(&self.directory_supervisor) {
            return Ok(supervisor);
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

        *self
            .directory_supervisor
            .write()
            .expect("directory_supervisor write lock") = Some(supervisor_ref.clone());
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
            group_supervisor_spawn_lock: Arc::clone(&self.group_supervisor_spawn_lock),
            directory_supervisor_spawn_lock: Arc::clone(&self.directory_supervisor_spawn_lock),
            db_pool: self.db_pool.clone(),
            sse_state: self.sse_state.clone(),
            notification_service: self.notification_service.clone(),
            quorum_config: self.quorum_config.clone(),
        }
    }
}
