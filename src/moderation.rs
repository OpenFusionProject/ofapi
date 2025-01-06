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

#[derive(Debug, Deserialize)]
struct NameRequestDecision {
    player_uid: u64,
    requested_name: String,
    decision: String,
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

    info!(
        "Name request: {} -> {} [{}]",
        req.player_uid, req.requested_name, req.decision
    );
    (StatusCode::OK, req.decision)
}
