use std::sync::Arc;

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    routing::{get, post},
    Json, Router,
};
use log::*;
use ofapi::{tokens::TokenCapability, util};
use serde::{Deserialize, Serialize};

use crate::{auth, database, AppState};

#[derive(Deserialize, Clone)]
pub(crate) struct ModerationConfig {
    namereq_route: String,
}

pub(crate) fn register(
    routes: Router<Arc<AppState>>,
    config: &ModerationConfig,
) -> Router<Arc<AppState>> {
    info!("Registering moderation routes");
    let namereq_route = &config.namereq_route;
    info!("\tName request route @ {}", namereq_route);
    routes
        .route(namereq_route, get(get_outstanding_requests))
        .route(namereq_route, post(name_request))
}

#[derive(Debug, Serialize)]
struct NameRequest {
    player_uid: u64,
    requested_name: String,
}

#[derive(Debug)]
pub(crate) enum NameCheckStatus {
    Pending,
    Approved,
    Denied,
}
impl NameCheckStatus {
    pub(crate) fn from_str(s: &str) -> Option<Self> {
        match s {
            "pending" => Some(Self::Pending),
            "approved" => Some(Self::Approved),
            "denied" => Some(Self::Denied),
            _ => None,
        }
    }
}

#[derive(Debug, Deserialize)]
struct NameRequestDecision {
    player_uid: u64,
    requested_name: String,
    decision: String,
    by: String,
}

async fn get_outstanding_requests(
    State(app): State<Arc<AppState>>,
    headers: HeaderMap,
) -> (StatusCode, Json<Vec<NameRequest>>) {
    assert!(app.is_tls);

    let Some(key) = auth::SECRET_KEY.get() else {
        warn!("Authed route used without auth module init");
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(vec![]));
    };

    if util::validate_authed_request(key, &headers, vec![TokenCapability::ApproveNames]).is_err() {
        return (StatusCode::UNAUTHORIZED, Json(vec![]));
    }

    let db = app.db.lock().await;
    let requests = database::get_outstanding_namereqs(&db)
        .into_iter()
        .map(|(uid, name)| NameRequest {
            player_uid: uid as u64,
            requested_name: name,
        })
        .collect::<Vec<_>>();
    (StatusCode::OK, Json(requests))
}

async fn name_request(
    State(app): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<NameRequestDecision>,
) -> (StatusCode, String) {
    assert!(app.is_tls);

    let Some(key) = auth::SECRET_KEY.get() else {
        warn!("Authed route used without auth module init");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Server error".to_string(),
        );
    };

    if util::validate_authed_request(key, &headers, vec![TokenCapability::ApproveNames]).is_err() {
        return (StatusCode::UNAUTHORIZED, "Unauthorized".to_string());
    }

    let Some(new_status) = NameCheckStatus::from_str(&req.decision) else {
        return (
            StatusCode::BAD_REQUEST,
            "Invalid decision; must be either approved, denied, or pending".to_string(),
        );
    };

    info!(
        "Name request: {} -> {} [{} by {}]",
        req.player_uid, req.requested_name, req.decision, req.by
    );

    let db = app.db.lock().await;
    match database::get_namecheck_for_player(&db, req.player_uid as i64) {
        Err(e) => {
            warn!(
                "Failed to get name check flag for player {}: {}",
                req.player_uid, e
            );
            // if this happens, the player doesn't exist. it was probably deleted.
            // just void the request.
            return (
                StatusCode::ALREADY_REPORTED,
                format!("Player {} does not exist", req.player_uid),
            );
        }
        Ok(0) => {}
        _ => {
            info!(
                "Name request already processed for player {}",
                req.player_uid
            );
            return (
                StatusCode::ALREADY_REPORTED,
                format!("No name check pending for player {}", req.player_uid),
            );
        }
    }

    if let Err(e) = database::set_namecheck_for_player(&db, req.player_uid as i64, new_status) {
        warn!(
            "Failed to update name check flag for player {}: {}",
            req.player_uid, e
        );
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Server error".to_string(),
        );
    }

    (StatusCode::OK, req.decision)
}
