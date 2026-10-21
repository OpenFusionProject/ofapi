use axum::{
    extract::State,
    response::IntoResponse,
    routing::{get, Router},
};
use log::info;
use serde::Deserialize;
use std::{collections::HashMap, sync::Arc};

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
    let routes = routes.route(route, get(trampoline));

    // Some browsers automatically add a trailing slash, so register that as well
    if let Some(alternate_route) = util::get_trailing_slash_route(route) {
        info!("Registering launcher alt route @ {}", alternate_route);
        routes.route(&alternate_route, get(trampoline))
    } else {
        routes
    }
}

async fn trampoline(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let endpoint = &state.config.core.public_url;
    let mut new_uri = format!("ofl://server?endpoint={}", endpoint);
    let description = &state.config.core.server_name;
    if !description.is_empty() {
        new_uri.push_str(&format!("&description={}", description));
    }

    // Generate the page content
    let app = &state;
    let public_url = &app.config.core.public_url;
    let mut vars = HashMap::new();
    vars.insert(
        "LAUNCH_URI".to_string(),
        new_uri,
    );
    vars.insert(
        "SERVER_NAME".to_string(),
        app.config.core.server_name.clone(),
    );
    vars.insert(
        "LOGO_URL".to_string(),
        format!("http://{}/launcher/logo.png", public_url),
    );
    vars.insert(
        "BANNER_URL".to_string(),
        format!("http://{}/launcher/background.png", public_url),
    );
    vars.insert(
        "PRIVACY_POLICY_URL".to_string(),
        format!("http://{}/privacy", public_url),
    );

    let Ok(content_html) = util::gen_content_from_template(
        &app.config.core.template_dir,
        "launcher_trampoline.html",
        &vars,
    ) else {
        return Err(axum::http::StatusCode::INTERNAL_SERVER_ERROR.into_response());
    };

    Ok(axum::response::Html(content_html))
}
