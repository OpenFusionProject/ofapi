use std::sync::Arc;

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    routing::post,
    Json, Router,
};
use log::*;
use ofapi::{tokens::TokenCapability, util};
use serde::Deserialize;

use crate::{auth, AppState};

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
    routes.route(namereq_route, post(name_request))
}

#[derive(Debug, Deserialize)]
struct NameRequestDecision {
    player_uid: u64,
    requested_name: String,
    decision: String,
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
