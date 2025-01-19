use std::{
    collections::HashMap,
    fs,
    sync::{Arc, OnceLock},
};

use axum::{
    extract::State,
    http::StatusCode,
    response::{Html, IntoResponse},
    routing::{get, Router},
};
use log::{info, warn};
use ofapi::util;
use serde::Deserialize;

use crate::AppState;

#[derive(Deserialize, Clone)]
pub(crate) struct LegacyConfig {
    index_route: String,
    assetinfo_route: String,
    logininfo_route: String,
}

#[derive(Debug, Deserialize)]
struct MinimalVersionManifest {
    uuid: String,
    asset_url: String,
    main_file_url: String,
}

static INDEX_PAGE: OnceLock<String> = OnceLock::new();
static VERSION_MANIFEST: OnceLock<MinimalVersionManifest> = OnceLock::new();
static LOGIN_ADDRESS: OnceLock<String> = OnceLock::new();

pub(crate) fn register(
    routes: Router<Arc<AppState>>,
    config: &LegacyConfig,
    uuid: Option<&String>,
    template_dir: &str,
) -> Router<Arc<AppState>> {
    let index_route = &config.index_route;
    let assetinfo_route = &config.assetinfo_route;
    let logininfo_route = &config.logininfo_route;

    if let Some(uuid) = uuid {
        if init_version_manifest(uuid).is_err() {
            warn!("Skipping legacy routes as version could not be found.");
            return routes;
        }
    } else {
        warn!("Skipping legacy routes as no versions are specified.");
        return routes;
    }
    if generate_index_page(template_dir).is_err() {
        warn!("Skipping legacy routes since we couldn't generate legacy index page.")
    }

    info!("Registering legacy routes");
    info!("\tIndex route @ {}", index_route);
    info!("\tAsset info route @ {}", assetinfo_route);
    info!("\tLogin info route @ {}", logininfo_route);

    routes
        .route(index_route, get(get_index))
        .route(assetinfo_route, get(get_assetinfo))
        .route(logininfo_route, get(get_logininfo))
}

fn init_version_manifest(uuid: &str) -> Result<(), Box<dyn std::error::Error>> {
    let file_name = format!("static/versions/{}.json", uuid);
    let contents = fs::read(file_name)?;
    let contents = String::from_utf8(contents)?;
    let mut manifest: MinimalVersionManifest = serde_json::from_str(&contents)?;

    if manifest.uuid != uuid {
        return Err("UUID of version in config does not match manifest.".into());
    };

    // Legacy client needs trailing slash, so we add it here
    manifest.asset_url += "/";
    VERSION_MANIFEST.set(manifest).unwrap();
    Ok(())
}

fn generate_index_page(template_dir: &str) -> Result<(), Box<dyn std::error::Error>> {
    let mut vars = HashMap::new();
    vars.insert(
        "UNITY_MAIN_FILE".to_string(),
        VERSION_MANIFEST.get().unwrap().main_file_url.clone(),
    );
    let content = util::gen_content_from_template(template_dir, "legacy_index.html", &vars)?;
    INDEX_PAGE.set(content)?;
    Ok(())
}

async fn get_index() -> impl IntoResponse {
    Html(INDEX_PAGE.get().unwrap().clone())
}

async fn get_assetinfo() -> impl IntoResponse {
    VERSION_MANIFEST.get().unwrap().asset_url.clone()
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
