use axum::{extract::State, http::StatusCode, Json};
use jacquard_axum::ExtractXrpc;
use tracing::info;

use crate::{
    auth::AuthUser,
    generated::blue_catbird::mlsChat::get_subscription_ticket::{
        GetSubscriptionTicketOutput, GetSubscriptionTicketRequest,
    },
    sqlx_jacquard::chrono_to_datetime,
    storage::DbPool,
};

const NSID: &str = "blue.catbird.mlsChat.getSubscriptionTicket";

/// v2 subscription ticket endpoint.
/// Delegates to the existing v1 handler logic for ticket generation.
/// TODO: Return proper typed error variants instead of bare StatusCode.
#[tracing::instrument(skip(pool, auth_user))]
pub async fn get_subscription_ticket(
    State(pool): State<DbPool>,
    auth_user: AuthUser,
    ExtractXrpc(params): ExtractXrpc<GetSubscriptionTicketRequest>,
) -> Result<Json<GetSubscriptionTicketOutput<'static>>, StatusCode> {
    if let Err(_e) = crate::auth::enforce_standard(&auth_user.claims, NSID) {
        return Err(StatusCode::UNAUTHORIZED);
    }

    // Delegate to existing v1 ticket generation logic
    let input = crate::handlers::subscription_ticket::GetSubscriptionTicketInput {
        convo_id: params
            .convo_ids
            .as_ref()
            .and_then(|ids| ids.first().map(|id| id.to_string())),
    };

    let v1_result = crate::handlers::subscription_ticket::get_subscription_ticket(
        State(pool),
        auth_user,
        Json(input),
    )
    .await?;

    let v1_output = v1_result.0;

    info!("✅ [v2.getSubscriptionTicket] Issued ticket for user");

    // Parse the v1 expires_at string back to chrono then to jacquard Datetime
    let expires_at = v1_output
        .expires_at
        .parse::<chrono::DateTime<chrono::Utc>>()
        .map(chrono_to_datetime)
        .unwrap_or_else(|_| chrono_to_datetime(chrono::Utc::now()));

    let endpoint = jacquard_common::types::string::Uri::new_owned(&v1_output.endpoint)
        .ok()
        .map(Into::into);

    Ok(Json(GetSubscriptionTicketOutput {
        ticket: v1_output.ticket.into(),
        endpoint,
        expires_at,
        extra_data: Default::default(),
    }))
}
