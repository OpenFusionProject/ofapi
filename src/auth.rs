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
use serde_repr::{Deserialize_repr, Serialize_repr};

use crate::{database, util, AppState};

#[derive(Deserialize, Clone)]
pub struct AuthConfig {
    route: String,
    refresh_subroute: String,
    secret_path: String,
    valid_secs_refresh: u64,
    valid_secs_session: u64,
}

#[derive(Deserialize)]
pub struct AuthRequest {
    username: String,
    password: String,
}

#[repr(u8)]
#[derive(Deserialize_repr, Serialize_repr, PartialEq, Eq)]
pub enum TokenKind {
    Refresh = 0,
    Session = 1,
}

#[derive(Deserialize, Serialize)]
pub struct Claims {
    sub: String,     // account id as a string
    crt: u64,        // creation timestamp in UTC
    exp: u64,        // expiration timestamp in UTC
    kind: TokenKind, // kind of token
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
    let refresh_route = util::get_subroute(route, &config.refresh_subroute);
    info!("Registering auth route @ {}", route);
    info!("\tRefresh route @ {}", refresh_route);
    check_secret(&config.secret_path, rng);
    routes
        .route(route, post(do_auth))
        .route(&refresh_route, post(do_refresh))
}

fn gen_jwt(auth_config: &AuthConfig, account_id: i64, kind: TokenKind) -> Result<String, String> {
    let secret = SECRET_KEY.get().unwrap();
    let key = EncodingKey::from_secret(secret);

    let valid_secs = match kind {
        TokenKind::Refresh => auth_config.valid_secs_refresh,
        TokenKind::Session => auth_config.valid_secs_session,
    };

    let crt = get_current_timestamp();
    let exp = crt + valid_secs;
    let claims = Claims {
        sub: account_id.to_string(),
        crt,
        exp,
        kind,
    };

    jsonwebtoken::encode(&jsonwebtoken::Header::default(), &claims, &key)
        .map_err(|e| format!("JWT error: {}", e))
}

fn get_validator(account_id: Option<i64>) -> Validation {
    let mut validation = Validation::default();
    // required claims
    validation.required_spec_claims.insert("sub".to_string());
    validation.required_spec_claims.insert("exp".to_string());
    // ensure account ID matches if passed in
    validation.sub = account_id.map(|id| id.to_string());
    validation
}

pub fn validate_jwt(jwt: &str, kind: TokenKind) -> Result<i64, String> {
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

    if token.claims.kind != kind {
        return Err("Bad token kind".to_string());
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
    let account_id =
        database::check_credentials(&db, &req.username, &req.password).map_err(|e| {
            warn!("Auth error: {}", e);
            (StatusCode::UNAUTHORIZED, "Invalid credentials".to_string())
        })?;
    match gen_jwt(
        app.config.auth.as_ref().unwrap(),
        account_id,
        TokenKind::Refresh,
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
pub struct RefreshResponse {
    username: String,
    session_token: String,
}

async fn do_refresh(
    State(app): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<RefreshResponse>, (StatusCode, String)> {
    assert!(app.is_tls);
    let account_id = match util::validate_authed_request(&headers, TokenKind::Refresh) {
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

    match gen_jwt(
        app.config.auth.as_ref().unwrap(),
        account_id,
        TokenKind::Session,
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
