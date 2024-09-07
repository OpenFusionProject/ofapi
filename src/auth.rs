use std::{
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use axum::{extract::State, http::StatusCode, routing::post, Json, Router};
use base64::{prelude::BASE64_STANDARD, Engine};
use log::info;
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use sqlite::Connection;

use crate::AppState;

#[derive(Deserialize, Clone)]
pub struct AuthConfig {
    route: String,
}

#[derive(Deserialize)]
pub struct AuthRequest {
    username: String,
    password: String,
}

#[derive(Serialize)]
pub struct AuthResponse {
    cookie: String,
    expires: u64,
}

pub fn register(routes: Router<Arc<AppState>>, config: &AuthConfig) -> Router<Arc<AppState>> {
    let route = &config.route;
    info!("Registering auth route @ {}", route);
    routes.route(route, post(do_auth))
}

fn check_credentials(
    db: &Connection,
    username: &str,
    password: &str,
) -> Result<i64, (StatusCode, String)> {
    const QUERY: &str = "
        SELECT AccountID, Password
        FROM Accounts
        WHERE Login = ?
        LIMIT 1;
        ";
    let mut stmt = db.prepare(QUERY).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("DB error: {}", e),
        )
    })?;
    stmt.bind((1, username)).unwrap();
    if let Ok(sqlite::State::Row) = stmt.next() {
        let account_id: i64 = stmt.read(0).unwrap();
        let hashed_password: String = stmt.read(1).unwrap();
        match bcrypt::verify(password, &hashed_password) {
            Ok(true) => Ok(account_id),
            Ok(false) => Err((StatusCode::UNAUTHORIZED, "Invalid password".to_string())),
            Err(e) => Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("bcrypt error: {}", e),
            )),
        }
    } else {
        Err((
            StatusCode::NOT_FOUND,
            format!("User {} not found", username),
        ))
    }
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

fn set_cookie(db: &Connection, account_id: i64, cookie: &str) -> Result<u64, sqlite::Error> {
    const QUERY: &str =
        "INSERT OR REPLACE INTO Auth (AccountID, Cookie, Expires) VALUES (?, ?, ?);";
    const VALID_FOR: Duration = Duration::from_secs(60);

    let expires = SystemTime::now() + VALID_FOR;
    let expires_timestamp = expires
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let mut stmt = db.prepare(QUERY)?;
    stmt.bind((1, account_id)).unwrap();
    stmt.bind((2, cookie)).unwrap();
    stmt.bind((3, expires_timestamp as i64)).unwrap();
    stmt.next()?;
    Ok(expires_timestamp)
}

async fn do_auth(
    State(app): State<Arc<AppState>>,
    Json(req): Json<AuthRequest>,
) -> Result<Json<AuthResponse>, (StatusCode, String)> {
    assert!(app.is_tls);

    let db = app.db.lock().await;
    let account_id = check_credentials(&db, &req.username, &req.password)?;

    let cookie = gen_cookie(&app.rng);
    let expires = set_cookie(&db, account_id, &cookie).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("DB error: {}", e),
        )
    })?;
    Ok(Json(AuthResponse { cookie, expires }))
}
