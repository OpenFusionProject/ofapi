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

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum TokenLifetime {
    ShortTerm,   // e.g. session tokens
    LongTerm,    // e.g. refresh tokens
    Permanent,   // e.g. API keys (use with caution)
    Custom(u64), // duration in secs
}

#[repr(u64)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TokenCapability {
    // lower privileges
    Refresh = (1 << 0),
    ManageOwnAccount = (1 << 1),
    GetCookie = (1 << 2),
    // higher privileges (dangerous)
    ApproveNames = (1 << 20),
    // highest privileges (very dangerous)
    ManageAllAccounts = (1 << 40),
}

pub(crate) struct TokenCapabilities {
    capabilities: u64,
}
impl TokenCapabilities {
    pub(crate) fn new() -> Self {
        Self { capabilities: 0 }
    }

    pub(crate) fn load(capabilities: u64) -> Self {
        Self { capabilities }
    }

    pub(crate) fn with(self, capability: TokenCapability) -> Self {
        Self {
            capabilities: self.capabilities | (1 << capability as u64),
        }
    }

    pub(crate) fn check(&self, capability: TokenCapability) -> bool {
        (self.capabilities & (1 << capability as u64)) != 0
    }
}

#[derive(Deserialize, Serialize)]
pub(crate) struct Claims {
    sub: String, // account id as a string
    crt: u64,    // creation timestamp in UTC
    exp: u64,    // expiration timestamp in UTC
    caps: u64,   // token capabilities
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

fn gen_jwt(
    auth_config: &AuthConfig,
    subject: String,
    caps: TokenCapabilities,
    lifetime: TokenLifetime,
) -> Result<String, String> {
    let secret = SECRET_KEY.get().unwrap();
    let key = EncodingKey::from_secret(secret);

    let crt = get_current_timestamp();
    let exp = match lifetime {
        TokenLifetime::ShortTerm => crt + auth_config.valid_secs_session,
        TokenLifetime::LongTerm => crt + auth_config.valid_secs_refresh,
        TokenLifetime::Permanent => u64::MAX,
        TokenLifetime::Custom(duration_secs) => crt + duration_secs,
    };

    let claims = Claims {
        sub: subject,
        crt,
        exp,
        caps: caps.capabilities,
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

pub(crate) fn validate_jwt(jwt: &str, caps: Vec<TokenCapability>) -> Result<i64, String> {
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

    let token_caps = TokenCapabilities::load(token.claims.caps);
    for cap in &caps {
        if !token_caps.check(*cap) {
            return Err(format!("Missing capability: {:?}", cap));
        }
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
        account_id.to_string(),
        TokenCapabilities::new().with(TokenCapability::Refresh),
        TokenLifetime::LongTerm,
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
    let account_id = match util::validate_authed_request(&headers, vec![TokenCapability::Refresh]) {
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

    match gen_jwt(
        app.config.auth.as_ref().unwrap(),
        account_id.to_string(),
        caps,
        TokenLifetime::ShortTerm,
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
