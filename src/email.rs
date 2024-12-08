use std::collections::HashMap;

use jsonwebtoken::get_current_timestamp;
use serde::Deserialize;

use crate::{util, AppState};

#[derive(Deserialize, Clone)]
pub struct EmailConfig {
    template_dir: String,
}

fn gen_email_content_from_template(
    template_dir: &str,
    template_name: &str,
    vars: HashMap<String, String>,
) -> Result<String, String> {
    let template_path = format!("{}/{}.html", template_dir, template_name);
    let template = match std::fs::read_to_string(template_path) {
        Ok(content) => content,
        Err(e) => return Err(format!("Failed to read template file: {}", e)),
    };
    let mut content = template;
    for (key, value) in vars {
        content = content.replace(&format!("${}$", key), &value);
    }
    Ok(content)
}

#[derive(Debug, Clone)]
pub struct EmailVerification {
    pub email: String,
    pub expires: u64,
    pub kind: EmailVerificationKind,
}
impl EmailVerification {
    pub fn new(email: &str, kind: EmailVerificationKind, valid_for: u64) -> Self {
        Self {
            email: email.to_string(),
            kind,
            expires: get_current_timestamp() + valid_for,
        }
    }
}

#[derive(Debug, Clone)]
pub enum EmailVerificationKind {
    Register {
        username: String,
        password_hashed: String,
    },
    Verify {
        username: String,
    },
}

pub async fn send_verification_email(
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
        gen_email_content_from_template(&email_config.template_dir, "verify_email", vars)?;
    println!("{}", content);

    // Send the email
    // TODO

    Ok(())
}
