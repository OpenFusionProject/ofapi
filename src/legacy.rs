use std::{
    fs,
    sync::{Arc, OnceLock},
};

use axum::{
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    routing::{get, Router},
};
use log::{info, warn};
use ofapi::util;
use serde::Deserialize;

use crate::AppState;

#[derive(Deserialize, Clone)]
pub(crate) struct LegacyConfig {
    assetinfo_route: String,
    logininfo_route: String,
    local_route: String,
    local_num: i32,
}

#[derive(Debug, Deserialize)]
struct MinimalVersionManifest {
    uuid: String,
    asset_url: String,
}

static ASSET_URL: OnceLock<String> = OnceLock::new();
static LOGIN_ADDRESS: OnceLock<String> = OnceLock::new();

pub(crate) fn register(
    routes: Router<Arc<AppState>>,
    config: &LegacyConfig,
    uuid: Option<&String>,
) -> Router<Arc<AppState>> {
    let assetinfo_route = &config.assetinfo_route;
    let logininfo_route = &config.logininfo_route;
    let local_route = &config.local_route;

    if let Some(uuid) = uuid {
        if set_asset_url(uuid).is_err() {
            warn!("Skipping legacy route as version could not be found.");
            return routes;
        }
    } else {
        warn!("Skipping legacy routes as no versions are specified.");
        return routes;
    }

    info!("Registering legacy routes");
    info!("\tAsset info route @ {}", assetinfo_route);
    info!("\tLogin info route @ {}", logininfo_route);
    info!("\tLocal route @ {}", local_route);

    routes
        .route(assetinfo_route, get(get_assetinfo))
        .route(logininfo_route, get(get_logininfo))
        .route(local_route, get(get_local))
}

fn set_asset_url(uuid: &str) -> Result<(), Box<dyn std::error::Error>> {
    let file_name = format!("static/versions/{}.json", uuid);
    let contents = fs::read(file_name)?;
    let contents = String::from_utf8(contents)?;
    let manifest: MinimalVersionManifest = serde_json::from_str(&contents)?;

    if manifest.uuid != uuid {
        return Err("UUID of version in config does not match manifest.".into());
    };

    ASSET_URL.set(manifest.asset_url)?;
    Ok(())
}

async fn get_assetinfo() -> impl IntoResponse {
    ASSET_URL.get().unwrap().clone()
}

async fn get_logininfo(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    if LOGIN_ADDRESS.get().is_none() {
        let resolved = util::resolve_server_addr(&state.config.game.login_address);
        if resolved.is_none() {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                "Could not resolve server address.",
            );
        }
        LOGIN_ADDRESS.set(resolved.unwrap()).unwrap();
    }
    (StatusCode::OK, LOGIN_ADDRESS.get().unwrap())
}

async fn get_local(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    format!("Local:{}", state.config.legacy.as_ref().unwrap().local_num)
}
