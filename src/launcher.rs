use axum::{
    extract::State,
    response::IntoResponse,
    routing::{get, Router},
};
use log::info;
use serde::Deserialize;
use std::sync::Arc;

use crate::{util, AppState};

#[derive(Deserialize, Clone)]
pub(crate) struct LauncherConfig {
    route: String,
}

pub(crate) fn register(
    routes: Router<Arc<AppState>>,
    config: &LauncherConfig,
) -> Router<Arc<AppState>> {
    let route = &config.route;
    info!("Registering launcher route @ {}", route);
    let routes = routes.route(route, get(redirect_server));

    // Some browsers automatically add a trailing slash, so register that as well
    if let Some(alternate_route) = util::get_trailing_slash_route(route) {
        info!("Registering launcher alt route @ {}", alternate_route);
        routes.route(&alternate_route, get(redirect_server))
    } else {
        routes
    }
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
