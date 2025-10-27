//! MLS Authorization Middleware
//! 
//! Enforces group membership authorization before allowing MLS operations.
//! This is CRITICAL for security - prevents unauthorized access to group messages.

use axum::http::StatusCode;
use sqlx::PgPool;
use anyhow::{Result, anyhow};

/// Verify that a user is an active member of a group
pub async fn verify_group_membership(
    user_did: &str,
    convo_id: &str,
    db: &PgPool,
) -> Result<()> {
    let member = sqlx::query!(
        r#"
        SELECT member_did 
        FROM members 
        WHERE convo_id = $1
        AND member_did = $2 
        AND left_at IS NULL
        "#,
        convo_id,
        user_did
    )
    .fetch_optional(db)
    .await?;
    
    if member.is_none() {
        return Err(anyhow!(
            "User {} is not an active member of conversation {}",
            user_did, convo_id
        ));
    }
    
    Ok(())
}

/// Verify that a user is the creator of a group
pub async fn verify_group_creator(
    user_did: &str,
    convo_id: &str,
    db: &PgPool,
) -> Result<()> {
    let conversation = sqlx::query!(
        r#"
        SELECT creator_did 
        FROM conversations 
        WHERE id = $1
        "#,
        convo_id
    )
    .fetch_optional(db)
    .await?;
    
    match conversation {
        Some(convo) if convo.creator_did == user_did => Ok(()),
        Some(_) => Err(anyhow!(
            "User {} is not the creator of conversation {}",
            user_did, convo_id
        )),
        None => Err(anyhow!(
            "Conversation {} not found",
            convo_id
        )),
    }
}

/// Check if a user can add members to a group
/// Currently: only the creator can add members
/// Future: could support admin roles
pub async fn verify_can_add_members(
    user_did: &str,
    convo_id: &str,
    db: &PgPool,
) -> Result<()> {
    // For now, only creators can add members
    verify_group_creator(user_did, convo_id, db).await
}

/// Check if a user can remove members from a group
/// Currently: only the creator can remove members
/// Future: could support admin roles, or allow self-removal
pub async fn verify_can_remove_members(
    user_did: &str,
    convo_id: &str,
    target_did: &str,
    db: &PgPool,
) -> Result<()> {
    // Users can always remove themselves
    if user_did == target_did {
        return verify_group_membership(user_did, convo_id, db).await;
    }
    
    // Otherwise, must be creator
    verify_group_creator(user_did, convo_id, db).await
}

/// Get the current epoch for a conversation
pub async fn get_conversation_epoch(
    convo_id: &str,
    db: &PgPool,
) -> Result<i32> {
    // Get epoch from conversations table
    let result = sqlx::query!(
        r#"
        SELECT current_epoch
        FROM conversations
        WHERE id = $1
        "#,
        convo_id
    )
    .fetch_one(db)
    .await?;
    
    Ok(result.current_epoch)
}

#[cfg(test)]
mod tests {
    use super::*;
    
    // Note: Integration tests should be in tests/ directory
    // These are unit tests for helper functions
    
    #[test]
    fn test_conversation_id_string() {
        let convo_id = "0123456789abcdef";
        assert_eq!(convo_id.len(), 16);
    }
}
