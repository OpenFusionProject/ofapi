use std::collections::HashMap;

use jsonwebtoken::get_current_timestamp;
use serde::Deserialize;

use crate::{util, AppState};

#[derive(Deserialize, Clone)]
pub(crate) struct EmailConfig {
    // TODO
}

#[derive(Debug, Clone)]
pub(crate) struct EmailVerification {
    pub(crate) email: String,
    pub(crate) expires: u64,
    pub(crate) kind: EmailVerificationKind,
}
impl EmailVerification {
    pub(crate) fn new(email: &str, kind: EmailVerificationKind, valid_for: u64) -> Self {
        Self {
            email: email.to_string(),
            kind,
            expires: get_current_timestamp() + valid_for,
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) enum EmailVerificationKind {
    Register {
        username: String,
        password_hashed: String,
    },
    Verify {
        username: String,
    },
}

pub(crate) async fn send_verification_email(
    app: &AppState,
    username: &str,
    email: &str,
    kind: EmailVerificationKind,
    valid_for: u64,
) -> Result<(), String> {
    let email_config = match &app.config.email {
        Some(config) => config,
        None => return Err("Email config not found, can't send verification email".to_string()),
    };

    // Generate the code and store it in state
    let code = util::gen_random_string::<32>(&app.rng);
    let verification = EmailVerification::new(email, kind, valid_for);
    let mut verifications = app.email_verifications.lock().await;
    verifications.insert(code.clone(), verification);
    drop(verifications);

    // Generate the verification link
    let Some(account_config) = app.config.account.as_ref() else {
        return Err("Account config not found, can't send verification email".to_string());
    };
    let verification_route = account_config.get_email_verification_route();
    let verification_link = format!(
        "https://{}{}?code={}",
        app.config.core.public_url, verification_route, code
    );

    // Generate the email content
    let public_url = &app.config.core.public_url;
    let mut vars = HashMap::new();
    vars.insert(
        "SERVER_NAME".to_string(),
        app.config.core.server_name.clone(),
    );
    vars.insert("USERNAME".to_string(), username.to_string());
    vars.insert("VERIFY_URL".to_string(), verification_link);
    vars.insert(
        "LOGO_URL".to_string(),
        format!("http://{}/launcher/logo.png", public_url),
    );
    vars.insert(
        "BANNER_URL".to_string(),
        format!("http://{}/launcher/background.png", public_url),
    );
    vars.insert(
        "PRIVACY_POLICY_URL".to_string(),
        format!("http://{}/privacy", public_url),
    );
    let content =
        util::gen_content_from_template(&app.config.core.template_dir, "verify_email.html", &vars)?;
    println!("{}", content);

    // Send the email
    // TODO

    Ok(())
}
