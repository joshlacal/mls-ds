use axum::{http::StatusCode, Json};
use serde::Deserialize;
use serde_json::json;

use crate::{
    auth::{enforce_standard, AuthUser},
    federation::FederationMode,
};

const GET_MODE_NSID: &str = "blue.catbird.mls.admin.getFederationMode";
const SET_MODE_NSID: &str = "blue.catbird.mls.admin.setFederationMode";

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SetFederationModeInput {
    pub mode: String,
}

pub async fn get_federation_mode(
    auth_user: AuthUser,
) -> Result<Json<serde_json::Value>, StatusCode> {
    enforce_standard(&auth_user.claims, GET_MODE_NSID).map_err(|_| StatusCode::UNAUTHORIZED)?;
    super::federation_peers_admin::require_federation_admin(&auth_user)?;

    Ok(Json(json!({
        "effectiveMode": FederationMode::effective().as_str(),
        "overrideMode": FederationMode::runtime_override().map(FederationMode::as_str),
        "envMode": FederationMode::from_env().as_str(),
    })))
}

pub async fn set_federation_mode(
    auth_user: AuthUser,
    Json(input): Json<SetFederationModeInput>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    enforce_standard(&auth_user.claims, SET_MODE_NSID).map_err(|_| StatusCode::UNAUTHORIZED)?;
    super::federation_peers_admin::require_federation_admin(&auth_user)?;

    let mode = FederationMode::try_from_str(&input.mode).ok_or(StatusCode::BAD_REQUEST)?;
    FederationMode::set_runtime_override(Some(mode));

    Ok(Json(json!({
        "updated": true,
        "effectiveMode": FederationMode::effective().as_str(),
        "overrideMode": FederationMode::runtime_override().map(FederationMode::as_str),
        "envMode": FederationMode::from_env().as_str(),
    })))
}
