use anyhow::Result;
use sqlx::PgPool;

// Re-export from db module
pub use crate::db::{init_db, init_db_default, DbConfig, DbPool};

// Legacy compatibility function
pub async fn init_db_legacy(database_url: &str) -> Result<PgPool> {
    let config = DbConfig {
        database_url: database_url.to_string(),
        ..Default::default()
    };
    init_db(config).await
}

// Keep backward compatibility functions
pub async fn is_member(pool: &DbPool, did: &str, convo_id: &str) -> Result<bool> {
    crate::db::is_member(pool, did, convo_id).await
}

pub async fn get_current_epoch(pool: &DbPool, convo_id: &str) -> Result<i32> {
    crate::db::get_current_epoch(pool, convo_id).await
}
