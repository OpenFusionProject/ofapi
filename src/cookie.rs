use std::{
    sync::Arc,
    time::{Duration, SystemTime},
};

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    routing::post,
    Json, Router,
};
use base64::{prelude::BASE64_STANDARD, Engine};
use log::info;
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use sqlite::Connection;

use crate::{util, AppState};

#[derive(Deserialize, Clone)]
pub struct CookieConfig {
    route: String,
    valid_secs: u64,
}

#[derive(Serialize)]
pub struct CookieResponse {
    cookie: String,
    expires: u64,
}

pub fn register(routes: Router<Arc<AppState>>, config: &CookieConfig) -> Router<Arc<AppState>> {
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

fn set_cookie(
    db: &Connection,
    account_id: i64,
    cookie: &str,
    valid_secs: u64,
) -> Result<u64, sqlite::Error> {
    const QUERY: &str =
        "INSERT OR REPLACE INTO Auth (AccountID, Cookie, Expires) VALUES (?, ?, ?);";

    let valid_for = Duration::from_secs(valid_secs);
    let expires = SystemTime::now() + valid_for;
    let expires_timestamp = util::as_timestamp(expires);

    let mut stmt = db.prepare(QUERY)?;
    stmt.bind((1, account_id)).unwrap();
    stmt.bind((2, cookie)).unwrap();
    stmt.bind((3, expires_timestamp as i64)).unwrap();
    stmt.next()?;
    Ok(expires_timestamp)
}

async fn get_cookie(
    State(app): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<CookieResponse>, (StatusCode, String)> {
    let db = app.db.lock().await;
    let account_id = match util::validate_authed_request(&headers) {
        Ok(id) => id,
        Err(e) => return Err((StatusCode::UNAUTHORIZED, e)),
    };

    let cookie = gen_cookie(&app.rng);
    let valid_secs = app.config.cookie.as_ref().unwrap().valid_secs;
    let expires = set_cookie(&db, account_id, &cookie, valid_secs).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("DB error: {}", e),
        )
    })?;
    Ok(Json(CookieResponse { cookie, expires }))
}
