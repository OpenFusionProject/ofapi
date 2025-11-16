use std::sync::Arc;

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    routing::post,
    Json, Router,
};
use base64::{prelude::BASE64_STANDARD, Engine};
use log::*;
use ofapi::tokens::TokenCapability;
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};

use crate::{auth, database, util, AppState};

#[derive(Deserialize, Clone)]
pub(crate) struct CookieConfig {
    route: String,
    valid_secs: u64,
}

#[derive(Serialize)]
pub(crate) struct CookieResponse {
    username: String,
    cookie: String,
    expires: u64,
}

pub(crate) fn register(
    routes: Router<Arc<AppState>>,
    config: &CookieConfig,
) -> Router<Arc<AppState>> {
    let route = &config.route;
    info!("Registering cookie route @ {}", route);
    routes.route(route, post(get_cookie))
}

fn gen_cookie(rng: &SystemRandom) -> String {
    const COOKIE_LENGTH: usize = 64;
    const COOKIE_BYTES: usize = COOKIE_LENGTH * 3 / 4;
    let mut cookie_bytes = [0; COOKIE_BYTES];
    rng.fill(&mut cookie_bytes).unwrap();
    let cookie = BASE64_STANDARD.encode(cookie_bytes);
    assert!(cookie.len() == COOKIE_LENGTH);
    cookie
}

async fn get_cookie(
    State(app): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<CookieResponse>, (StatusCode, String)> {
    assert!(app.is_tls);

    // since we aren't in the auth module, the secret key is not guaranteed to be set
    let Some(key) = auth::SECRET_KEY.get() else {
        warn!("Cookie route used, but auth module not initialized");
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            "Server error".to_string(),
        ));
    };

    let account_id =
        match util::validate_authed_request(key, &headers, vec![TokenCapability::GetCookie]) {
            Ok(id) => id.parse::<i64>(),
            Err(e) => return Err((StatusCode::UNAUTHORIZED, e)),
        };
    let account_id = match account_id {
        Ok(id) => id,
        Err(_) => return Err((StatusCode::UNAUTHORIZED, "Bad token".to_string())),
    };

    let cookie = gen_cookie(&app.rng);
    let valid_secs = app.config.cookie.as_ref().unwrap().valid_secs;

    let db = app.db.lock().await;
    let username = match database::find_account(&db, account_id) {
        Some(a) => a.login,
        None => {
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                "Server error".to_string(),
            ))
        }
    };

    let expires = database::set_cookie(&db, account_id, &cookie, valid_secs).map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Server error".to_string(),
        )
    })?;

    Ok(Json(CookieResponse {
        username,
        cookie,
        expires,
    }))
}
