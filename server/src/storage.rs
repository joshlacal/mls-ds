use anyhow::Result;
use sqlx::PgPool;

// Re-export from db module
pub use crate::db::{init_db, DbConfig, DbPool};

pub async fn init_db_legacy(database_url: &str) -> Result<PgPool> {
    let config = DbConfig {
        database_url: database_url.to_string(),
        ..Default::default()
    };
    init_db(config).await
}
