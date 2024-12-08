use std::sync::{Arc, LazyLock};

use axum::{
    extract::{Query, State},
    http::StatusCode,
    routing::post,
    Json, Router,
};
use jsonwebtoken::get_current_timestamp;
use log::*;
use regex::Regex;
use serde::Deserialize;

use crate::{
    database,
    email::{self, EmailVerificationKind},
    util, AppState,
};

// From OpenFusion:
// Login has to be 4 - 32 characters long and can't contain
// special characters other than dash and underscore
// const regex = /^[a-zA-Z0-9_-]{4,32}$/;
const USERNAME_REGEX_SPEC: &str = r"^[a-zA-Z0-9_-]{4,32}$";
static USERNAME_REGEX: LazyLock<Regex> = LazyLock::new(|| Regex::new(USERNAME_REGEX_SPEC).unwrap());

// From OpenFusion:
// Password has to be 8 - 32 characters long
// const regex = /^.{8,32}$/;
const PASSWORD_REGEX_SPEC: &str = r"^.{8,32}$";
static PASSWORD_REGEX: LazyLock<Regex> = LazyLock::new(|| Regex::new(PASSWORD_REGEX_SPEC).unwrap());

// normal email regex
const EMAIL_REGEX_SPEC: &str = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$";
static EMAIL_REGEX: LazyLock<Regex> = LazyLock::new(|| Regex::new(EMAIL_REGEX_SPEC).unwrap());

#[derive(Deserialize, Clone)]
pub struct AccountConfig {
    route: String,
    // Register
    register_subroute: String,
    account_level: u8,
    require_email: bool,
    require_email_verification: bool,
    // Verify
    email_verification_subroute: String,
    email_verification_valid_secs: u64,
}
impl AccountConfig {
    pub fn get_email_verification_route(&self) -> String {
        util::get_subroute(&self.route, &self.email_verification_subroute)
    }

    pub fn is_email_required(&self) -> bool {
        self.require_email
    }
}

#[derive(Deserialize, Debug)]
struct RegisterRequest {
    username: String,
    password: String,
    email: Option<String>,
}

#[derive(Deserialize, Debug)]
struct EmailVerificationRequest {
    code: String,
}

pub fn register(routes: Router<Arc<AppState>>, config: &AccountConfig) -> Router<Arc<AppState>> {
    let route = &config.route;
    info!("Registering account route @ {}", route);
    let register_route = util::get_subroute(route, &config.register_subroute);
    info!("\tRegister route @ {}", register_route);
    let email_verification_route = config.get_email_verification_route();
    info!("\tEmail verification route @ {}", email_verification_route);
    routes
        .route(&register_route, post(register_account))
        .route(&email_verification_route, post(verify_email))
}

async fn register_account(
    State(app): State<Arc<AppState>>,
    Json(req): Json<RegisterRequest>,
) -> (StatusCode, String) {
    let db = app.db.lock().await;

    let cfg = app.config.account.as_ref().unwrap();

    // Validate username, password, and email
    if !USERNAME_REGEX.is_match(&req.username) {
        info!("Invalid username: {}", req.username);
        return (StatusCode::BAD_REQUEST, "Invalid username".to_string());
    }

    if !PASSWORD_REGEX.is_match(&req.password) {
        info!("Invalid password");
        return (StatusCode::BAD_REQUEST, "Invalid password".to_string());
    }

    if let Some(ref email) = req.email {
        if !EMAIL_REGEX.is_match(email) {
            info!("Invalid email: {}", email);
            return (StatusCode::BAD_REQUEST, "Invalid email".to_string());
        }
    }

    // Make sure the username and email aren't already in use
    if database::find_account_by_username(&db, &req.username).is_some() {
        info!("Username already in use: {}", req.username);
        return (
            StatusCode::BAD_REQUEST,
            "Username already in use".to_string(),
        );
    }

    if let Some(ref email) = req.email {
        if database::find_account_by_email(&db, email).is_some() {
            info!("Email already in use: {}", email);
            return (StatusCode::BAD_REQUEST, "Email already in use".to_string());
        }
    } else if cfg.require_email {
        info!("Email required but not provided");
        return (
            StatusCode::BAD_REQUEST,
            "Email required for this server".to_string(),
        );
    }

    // Hash the password; we'll need it for account creation
    let password_hashed = match bcrypt::hash(&req.password, bcrypt::DEFAULT_COST) {
        Ok(hash) => hash,
        Err(e) => {
            error!("bcrypt error: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Server error".to_string(),
            );
        }
    };

    if let Some(email) = &req.email {
        // Send a verification email
        let verification_kind = if cfg.require_email_verification {
            EmailVerificationKind::Register {
                username: req.username.clone(),
                password_hashed: password_hashed.clone(),
            }
        } else {
            EmailVerificationKind::Verify {
                username: req.username.clone(),
            }
        };
        let valid_for = app
            .config
            .account
            .as_ref()
            .unwrap()
            .email_verification_valid_secs;
        if let Err(e) =
            email::send_verification_email(&app, &req.username, email, verification_kind, valid_for)
                .await
        {
            warn!("Failed to send email verification: {}", e);
            if cfg.require_email_verification {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Server error".to_string(),
                );
            }
        }
    }

    if cfg.require_email_verification {
        return (
            StatusCode::ACCEPTED,
            "Email verification required. Check your email for a verification link.".to_string(),
        );
    }

    // Email verification is not required, we can create the account immediately
    let account_level = app.config.account.as_ref().unwrap().account_level;
    if let Err(e) = database::create_account(
        &db,
        &req.username,
        &password_hashed,
        account_level,
        req.email.as_deref(),
    ) {
        error!("Failed to create account: {}", e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Server error".to_string(),
        );
    }

    (StatusCode::CREATED, "Account created".to_string())
}

async fn verify_email(
    State(app): State<Arc<AppState>>,
    req: Query<EmailVerificationRequest>,
) -> (StatusCode, String) {
    let req = req.0;
    let code = req.code;

    let mut verifications = app.email_verifications.lock().await;
    let verification = match verifications.remove(&code) {
        Some(v) => v,
        None => {
            info!("Invalid email verification code");
            return (
                StatusCode::BAD_REQUEST,
                "Expired verification link".to_string(),
            );
        }
    };
    drop(verifications);

    // we don't re-insert the verification code in an error condition.
    // the user will have to make another registration or email verification request

    if verification.expires < get_current_timestamp() {
        info!("Expired email verification code");
        return (
            StatusCode::BAD_REQUEST,
            "Expired verification link".to_string(),
        );
    }

    let db = app.db.lock().await;
    match verification.kind {
        EmailVerificationKind::Register {
            ref username,
            ref password_hashed,
        } => {
            let account_level = app.config.account.as_ref().unwrap().account_level;
            if let Err(e) = database::create_account(
                &db,
                username,
                password_hashed,
                account_level,
                Some(&verification.email),
            ) {
                error!("Failed to create account: {}", e);
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Server error".to_string(),
                );
            }
        }
        EmailVerificationKind::Verify { ref username } => {
            if let Err(e) = database::update_email_for_account(&db, username, &verification.email) {
                error!("Failed to update email for user {}: {}", username, e);
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Server error".to_string(),
                );
            }
        }
    }

    (StatusCode::OK, "Email verified".to_string())
}
