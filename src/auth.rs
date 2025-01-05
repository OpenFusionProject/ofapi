use std::sync::{Arc, OnceLock};

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    routing::post,
    Json, Router,
};
use log::{info, warn};
use ofapi::tokens::{self, TokenCapabilities, TokenCapability, TokenLifetime};
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};

use crate::{database, util, AppState};

#[derive(Deserialize, Clone)]
pub(crate) struct AuthConfig {
    route: String,
    refresh_subroute: String,
    secret_path: String,
    valid_secs_refresh: u64,
    valid_secs_session: u64,
}

#[derive(Deserialize)]
pub(crate) struct AuthRequest {
    username: String,
    password: String,
}

pub(crate) static SECRET_KEY: OnceLock<Vec<u8>> = OnceLock::new();

fn check_secret(path: &str, rng: &SystemRandom) {
    const SECRET_LENGTH: usize = 32;
    // try to open the secret file first
    if let Ok(secret) = std::fs::read(path) {
        if secret.len() == SECRET_LENGTH {
            info!("\tUsing existing secret key @ {}", path);
            SECRET_KEY.set(secret).unwrap();
            return;
        }
    }

    // generate a new secret
    warn!("\tGenerating new secret key => {}", path);
    let mut secret = vec![0; SECRET_LENGTH];
    rng.fill(&mut secret).unwrap();
    std::fs::write(path, &secret).unwrap();
    SECRET_KEY.set(secret).unwrap();
}

pub(crate) fn register(
    routes: Router<Arc<AppState>>,
    config: &AuthConfig,
    rng: &SystemRandom,
) -> Router<Arc<AppState>> {
    let route = &config.route;
    let refresh_route = util::get_subroute(route, &config.refresh_subroute);
    info!("Registering auth route @ {}", route);
    info!("\tRefresh route @ {}", refresh_route);
    check_secret(&config.secret_path, rng);
    routes
        .route(route, post(do_auth))
        .route(&refresh_route, post(do_refresh))
}

async fn do_auth(
    State(app): State<Arc<AppState>>,
    Json(req): Json<AuthRequest>,
) -> Result<String, (StatusCode, String)> {
    assert!(app.is_tls);

    let key = SECRET_KEY.get().unwrap();
    let valid_secs = app.config.auth.as_ref().unwrap().valid_secs_refresh;

    let db = app.db.lock().await;
    let account_id =
        database::check_credentials(&db, &req.username, &req.password).map_err(|e| {
            warn!("Auth error: {}", e);
            (StatusCode::UNAUTHORIZED, "Invalid credentials".to_string())
        })?;
    match tokens::gen_jwt(
        key,
        account_id.to_string(),
        TokenCapabilities::new().with(TokenCapability::Refresh),
        TokenLifetime::Temporary(valid_secs),
    ) {
        Ok(jwt) => Ok(jwt),
        Err(e) => {
            warn!("Auth error: {}", e);
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                "Server error".to_string(),
            ))
        }
    }
}

#[derive(Debug, Serialize)]
pub(crate) struct RefreshResponse {
    username: String,
    session_token: String,
}

async fn do_refresh(
    State(app): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<RefreshResponse>, (StatusCode, String)> {
    assert!(app.is_tls);

    let key = SECRET_KEY.get().unwrap();

    let account_id =
        match util::validate_authed_request(key, &headers, vec![TokenCapability::Refresh]) {
            Ok(id) => id,
            Err(e) => return Err((StatusCode::UNAUTHORIZED, e)),
        };

    let db = app.db.lock().await;
    let username = match database::find_account(&db, account_id) {
        Some(a) => a.login,
        None => {
            warn!("Account not found: {} (refresh)", account_id);
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                "Server error".to_string(),
            ));
        }
    };
    // TODO validate the refresh token against the last password reset timestamp

    let caps = TokenCapabilities::new()
        .with(TokenCapability::ManageOwnAccount)
        .with(TokenCapability::GetCookie);

    let valid_secs = app.config.auth.as_ref().unwrap().valid_secs_session;

    match tokens::gen_jwt(
        key,
        account_id.to_string(),
        caps,
        TokenLifetime::Temporary(valid_secs),
    ) {
        Ok(jwt) => Ok(Json(RefreshResponse {
            username,
            session_token: jwt,
        })),
        Err(e) => {
            warn!("Refresh error: {}", e);
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                "Server error".to_string(),
            ))
        }
    }
}
