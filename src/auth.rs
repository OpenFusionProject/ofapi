use std::sync::{Arc, OnceLock};

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    routing::post,
    Json, Router,
};
use jsonwebtoken::{get_current_timestamp, DecodingKey, EncodingKey, Validation};
use log::{info, warn};
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use sqlite::Connection;

use crate::{util, AppState};

#[derive(Deserialize, Clone)]
pub struct AuthConfig {
    route: String,
    secret_path: String,
    valid_secs: u64,
}

#[derive(Deserialize)]
pub struct AuthRequest {
    username: String,
    password: String,
}

#[derive(Deserialize, Serialize)]
pub struct Claims {
    sub: String, // account id as a string
    exp: u64,    // expiration timestamp in UTC
}

static SECRET_KEY: OnceLock<Vec<u8>> = OnceLock::new();

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

pub fn register(
    routes: Router<Arc<AppState>>,
    config: &AuthConfig,
    rng: &SystemRandom,
) -> Router<Arc<AppState>> {
    const CHECK_ROUTE: &str = "/check";
    let route = &config.route;
    let check_route = format!("{}{}", route, CHECK_ROUTE);
    info!("Registering auth route @ {}", route);
    info!("Registering auth check route @ {}", check_route);
    check_secret(&config.secret_path, rng);
    routes
        .route(route, post(do_auth))
        .route(&check_route, post(do_check))
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

fn gen_jwt(account_id: i64, valid_secs: u64) -> Result<String, String> {
    let secret = SECRET_KEY.get().unwrap();
    let key = EncodingKey::from_secret(secret);
    let exp = get_current_timestamp() + valid_secs;
    let claims = Claims {
        sub: account_id.to_string(),
        exp,
    };
    jsonwebtoken::encode(&jsonwebtoken::Header::default(), &claims, &key)
        .map_err(|e| format!("JWT error: {}", e))
}

fn get_validator(account_id: Option<i64>) -> Validation {
    let mut validation = Validation::default();
    // required claims
    validation.required_spec_claims.insert("exp".to_string());
    validation.required_spec_claims.insert("sub".to_string());
    // ensure account ID matches if passed in
    validation.sub = account_id.map(|id| id.to_string());
    validation
}

pub fn validate_jwt(jwt: &str) -> Result<i64, String> {
    let Some(secret) = SECRET_KEY.get() else {
        return Err("Auth module not initialized".to_string());
    };
    let key = DecodingKey::from_secret(secret);
    let validation = get_validator(None);
    let Ok(token) = jsonwebtoken::decode::<Claims>(jwt, &key, &validation) else {
        return Err("Bad JWT".to_string());
    };
    match token.claims.sub.parse() {
        Ok(id) => Ok(id),
        Err(e) => Err(format!("Bad account ID: {}", e)),
    }
}

async fn do_auth(
    State(app): State<Arc<AppState>>,
    Json(req): Json<AuthRequest>,
) -> Result<String, (StatusCode, String)> {
    assert!(app.is_tls);
    let db = app.db.lock().await;
    let account_id = check_credentials(&db, &req.username, &req.password)?;
    let valid_secs = app.config.auth.as_ref().unwrap().valid_secs;
    match gen_jwt(account_id, valid_secs) {
        Ok(jwt) => Ok(jwt),
        Err(e) => Err((StatusCode::INTERNAL_SERVER_ERROR, e)),
    }
}

fn get_username_from_id(db: &Connection, account_id: i64) -> Result<String, (StatusCode, String)> {
    const QUERY: &str = "
        SELECT Login
        FROM Accounts
        WHERE AccountID = ?
        LIMIT 1;
        ";
    let mut stmt = db.prepare(QUERY).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("DB error: {}", e),
        )
    })?;
    stmt.bind((1, account_id)).unwrap();
    if let Ok(sqlite::State::Row) = stmt.next() {
        let username: String = stmt.read(0).unwrap();
        Ok(username)
    } else {
        Err((
            StatusCode::NOT_FOUND,
            format!("Account ID {} not found", account_id),
        ))
    }
}

async fn do_check(
    State(app): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<String, (StatusCode, String)> {
    assert!(app.is_tls);
    let Ok(account_id) = util::validate_authed_request(&headers) else {
        return Err((StatusCode::UNAUTHORIZED, "Bad token".to_string()));
    };
    let db = app.db.lock().await;
    get_username_from_id(&db, account_id)
}
