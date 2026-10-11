use std::sync::Arc;

use axum::{
    extract::State,
    response::IntoResponse,
    routing::{get, Router},
};
use log::info;
use ofapi::util;
use serde::Deserialize;

use crate::AppState;

#[derive(Deserialize, Clone)]
pub(crate) struct LauncherConfig {
    route: String,
    add_subroute: String,
}

pub(crate) fn register(
    routes: Router<Arc<AppState>>,
    config: &LauncherConfig,
) -> Router<Arc<AppState>> {
    let route = &config.route;
    info!("Registering launcher routes @ {}", route);
    let add_route = util::get_subroute(route, &config.add_subroute);
    info!("\tAdd route @ {}", add_route);
    routes.route(&add_route, get(redirect_server))
}

async fn redirect_server(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let endpoint = &state.config.core.public_url;
    let mut new_uri = format!("ofl://server?endpoint={}", endpoint);
    let description = &state.config.core.server_name;
    if !description.is_empty() {
        new_uri.push_str(&format!("&description={}", description));
    }

    axum::response::Redirect::temporary(&new_uri)
}
