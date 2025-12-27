use dashmap::DashMap;
use ractor::ActorRef;
use sqlx::PgPool;
use std::sync::Arc;
use tracing::{debug, info, warn};

use super::conversation::{ConversationActor, ConvoActorArgs};
use super::messages::ConvoMessage;
use crate::realtime::SseState;

/// Central registry for managing conversation actor lifecycle.
///
/// The `ActorRegistry` is responsible for:
/// - Spawning new conversation actors on-demand
/// - Caching actor references for reuse
/// - Tracking the count of active actors
/// - Coordinating graceful shutdown of all actors
///
/// # Thread Safety
///
/// This registry uses [`DashMap`] internally for lock-free concurrent access,
/// allowing multiple threads to spawn and retrieve actors simultaneously without
/// contention. The registry itself is cheaply clonable via [`Arc`].
///
/// # Actor Lifecycle
///
/// 1. **Spawn**: Actors are created lazily when first accessed via [`get_or_spawn`]
/// 2. **Reuse**: Subsequent requests for the same conversation reuse the existing actor
/// 3. **Removal**: Actors can be manually removed via [`remove_actor`]
/// 4. **Shutdown**: All actors can be stopped gracefully via [`shutdown_all`]
///
/// # Examples
///
/// ```no_run
/// use sqlx::PgPool;
///
/// # async fn example(db_pool: PgPool) -> anyhow::Result<()> {
/// let registry = ActorRegistry::new(db_pool);
///
/// // Get or spawn an actor for a conversation
/// let actor_ref = registry.get_or_spawn("conv_123").await?;
///
/// // Check how many actors are active
/// let count = registry.actor_count();
/// println!("Active actors: {}", count);
///
/// // Shutdown all actors when done
/// registry.shutdown_all().await;
/// # Ok(())
/// # }
/// ```
///
/// [`get_or_spawn`]: ActorRegistry::get_or_spawn
/// [`remove_actor`]: ActorRegistry::remove_actor
/// [`shutdown_all`]: ActorRegistry::shutdown_all
pub struct ActorRegistry {
    actors: Arc<DashMap<String, ActorRef<ConvoMessage>>>,
    db_pool: PgPool,
    sse_state: Arc<SseState>,
    notification_service: Option<Arc<crate::notifications::NotificationService>>,
}

impl ActorRegistry {
    /// Creates a new actor registry with the given database connection pool and SSE state.
    ///
    /// # Arguments
    ///
    /// - `db_pool`: PostgreSQL connection pool used by spawned actors
    /// - `sse_state`: SSE state for real-time event broadcasting
    ///
    /// # Returns
    ///
    /// A new `ActorRegistry` instance ready to spawn actors.
    pub fn new(
        db_pool: PgPool, 
        sse_state: Arc<SseState>,
        notification_service: Option<Arc<crate::notifications::NotificationService>>,
    ) -> Self {
        info!("Initializing ActorRegistry");
        Self {
            actors: Arc::new(DashMap::new()),
            db_pool,
            sse_state,
            notification_service,
        }
    }

    /// Retrieves an existing actor or spawns a new one for the given conversation.
    ///
    /// This method implements the "get-or-create" pattern:
    /// - If an actor already exists for `convo_id`, returns the cached reference
    /// - If no actor exists, spawns a new one and caches it for future use
    ///
    /// # Arguments
    ///
    /// - `convo_id`: Unique identifier for the conversation
    ///
    /// # Returns
    ///
    /// An [`ActorRef`] that can be used to send messages to the conversation actor.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Actor spawning fails
    /// - Database connection fails during actor initialization
    ///
    /// # Concurrency
    ///
    /// Multiple concurrent calls with the same `convo_id` may result in multiple
    /// actors being spawned temporarily, but only one will be retained in the registry.
    /// This is acceptable as the actor system will clean up unused actors.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # async fn example(registry: &ActorRegistry) -> anyhow::Result<()> {
    /// let actor = registry.get_or_spawn("conv_abc123").await?;
    /// // Use actor to send messages...
    /// # Ok(())
    /// # }
    /// ```
    pub async fn get_or_spawn(&self, convo_id: &str) -> anyhow::Result<ActorRef<ConvoMessage>> {
        // Check if actor already exists
        if let Some(actor_ref) = self.actors.get(convo_id) {
            debug!("Using existing actor for conversation");
            return Ok(actor_ref.clone());
        }

        debug!("Spawning new actor for conversation");

        // Spawn new actor
        let args = ConvoActorArgs {
            convo_id: convo_id.to_string(),
            db_pool: self.db_pool.clone(),
            sse_state: self.sse_state.clone(),
            notification_service: self.notification_service.clone(),
        };

        let (actor_ref, _handle) = ractor::Actor::spawn(None, ConversationActor, args)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to spawn actor: {}", e))?;

        // Store in registry
        self.actors.insert(convo_id.to_string(), actor_ref.clone());

        info!(
            "Actor spawned successfully for conversation {}. Total actors: {}",
            convo_id,
            self.actor_count()
        );

        Ok(actor_ref)
    }

    /// Returns the number of currently active actors in the registry.
    ///
    /// This is useful for monitoring and metrics purposes.
    ///
    /// # Returns
    ///
    /// The count of active conversation actors.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # fn example(registry: &ActorRegistry) {
    /// let count = registry.actor_count();
    /// println!("Currently tracking {} conversations", count);
    /// # }
    /// ```
    pub fn actor_count(&self) -> usize {
        self.actors.len()
    }

    /// Removes an actor from the registry.
    ///
    /// This is typically called when an actor stops or needs to be cleaned up.
    /// The actor reference is removed from the cache, and subsequent calls to
    /// [`get_or_spawn`] for the same conversation will create a new actor.
    ///
    /// # Arguments
    ///
    /// - `convo_id`: Unique identifier for the conversation
    ///
    /// # Notes
    ///
    /// This method logs a warning if attempting to remove a non-existent actor.
    ///
    /// [`get_or_spawn`]: ActorRegistry::get_or_spawn
    pub fn remove_actor(&self, convo_id: &str) {
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

    /// Gracefully shuts down all active actors.
    ///
    /// This method:
    /// 1. Sends a [`ConvoMessage::Shutdown`] to each active actor
    /// 2. Clears the actor registry
    ///
    /// Actors will complete any in-flight operations before stopping.
    /// This is typically called during application shutdown.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # async fn example(registry: ActorRegistry) {
    /// // At application shutdown
    /// registry.shutdown_all().await;
    /// # }
    /// ```
    ///
    /// [`ConvoMessage::Shutdown`]: super::messages::ConvoMessage::Shutdown
    pub async fn shutdown_all(&self) {
        info!("Shutting down all {} actors", self.actor_count());

        // Send shutdown message to all actors
        for entry in self.actors.iter() {
            let convo_id = entry.key();
            let actor_ref = entry.value();

            debug!("Sending shutdown to actor");
            let _ = actor_ref.cast(ConvoMessage::Shutdown);
        }

        // Clear the registry
        self.actors.clear();
        info!("All actors shut down");
    }
}

impl Clone for ActorRegistry {
    fn clone(&self) -> Self {
        Self {
            actors: Arc::clone(&self.actors),
            db_pool: self.db_pool.clone(),
            sse_state: self.sse_state.clone(),
            notification_service: self.notification_service.clone(),
        }
    }
}
