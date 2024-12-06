use std::sync::{Arc, OnceLock};

use axum::{extract::State, http::StatusCode, routing::post, Json, Router};
use jsonwebtoken::{get_current_timestamp, DecodingKey, EncodingKey, Validation};
use log::{info, warn};
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};

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
    crt: u64,    // creation timestamp in UTC
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
    let route = &config.route;
    info!("Registering auth route @ {}", route);
    check_secret(&config.secret_path, rng);
    routes.route(route, post(do_auth))
}

fn gen_jwt(account_id: i64, valid_secs: u64) -> Result<String, String> {
    let secret = SECRET_KEY.get().unwrap();
    let key = EncodingKey::from_secret(secret);
    let crt = get_current_timestamp();
    let exp = crt + valid_secs;
    let claims = Claims {
        sub: account_id.to_string(),
        crt,
        exp,
    };
    jsonwebtoken::encode(&jsonwebtoken::Header::default(), &claims, &key)
        .map_err(|e| format!("JWT error: {}", e))
}

fn get_validator(account_id: Option<i64>) -> Validation {
    let mut validation = Validation::default();
    // required claims
    validation.required_spec_claims.insert("crt".to_string());
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

    // I don't 100% trust this crate to validate the expiration timestamp, so do it manually
    let now = get_current_timestamp();
    if token.claims.exp < now {
        return Err("Expired JWT".to_string());
    }

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
    let account_id = util::check_credentials(&db, &req.username, &req.password).map_err(|e| {
        warn!("Auth error: {}", e);
        (StatusCode::UNAUTHORIZED, "Invalid credentials".to_string())
    })?;
    let valid_secs = app.config.auth.as_ref().unwrap().valid_secs;
    match gen_jwt(account_id, valid_secs) {
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
