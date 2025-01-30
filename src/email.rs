use std::collections::HashMap;

use jsonwebtoken::get_current_timestamp;
use lettre::{
    message::{Mailbox, MultiPart},
    transport::smtp::authentication::Credentials,
    Message, SmtpTransport, Transport as _,
};
use log::*;
use serde::Deserialize;

use crate::{util, AppState};

#[derive(Deserialize, Clone)]
pub(crate) struct EmailConfig {
    smtp_host: String,
    smtp_port: u16,
    smtp_email: String,
    smtp_username: Option<String>,
    smtp_password: String,
}

#[derive(Debug, Clone)]
pub(crate) struct EmailVerification {
    pub(crate) email: String,
    pub(crate) expires: u64,
    pub(crate) kind: EmailVerificationKind,
    pub(crate) done: bool,
}
impl EmailVerification {
    pub(crate) fn new(email: &str, kind: EmailVerificationKind, valid_for: u64) -> Self {
        Self {
            email: email.to_string(),
            kind,
            expires: get_current_timestamp() + valid_for,
            done: false,
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

async fn send_email(
    app: &AppState,
    recipient_name: Option<&str>,
    recipient_email: &str,
    subject: &str,
    content_html: String,
    content_txt: String,
) -> Result<(), String> {
    let email_config = app.config.email.as_ref().ok_or("Email config not found")?;

    let sender_identity = format!(
        "{} <{}>",
        app.config.core.server_name, email_config.smtp_email
    );
    let Ok(sender) = sender_identity.parse::<Mailbox>() else {
        return Err("Invalid SMTP sender identity".to_string());
    };

    let recipient_identity = match recipient_name {
        Some(name) => format!("{} <{}>", name, recipient_email),
        None => recipient_email.to_string(),
    };
    let Ok(recipient) = recipient_identity.parse::<Mailbox>() else {
        return Err("Invalid email address".to_string());
    };

    let mail = Message::builder()
        .from(sender)
        .to(recipient)
        .subject(subject)
        .multipart(MultiPart::alternative_plain_html(content_txt, content_html))
        .map_err(|e| format!("Failed to build email: {}", e))?;

    let smtp_username = email_config
        .smtp_username
        .clone()
        .unwrap_or(email_config.smtp_email.clone());
    let creds = Credentials::new(smtp_username, email_config.smtp_password.clone());

    let mailer = match SmtpTransport::relay(&email_config.smtp_host) {
        Ok(mailer) => mailer
            .port(email_config.smtp_port)
            .credentials(creds)
            .build(),
        Err(e) => return Err(format!("Failed to create mailer: {}", e)),
    };

    mailer
        .send(&mail)
        .map_err(|e| format!("Failed to send email: {}", e))?;
    Ok(())
}

pub(crate) async fn send_verification_email(
    app: &AppState,
    username: &str,
    email: &str,
    kind: EmailVerificationKind,
    valid_for: u64,
) -> Result<(), String> {
    // Generate the code and store it in state
    let code = util::gen_random_string::<32>(&app.rng);
    let verification = EmailVerification::new(email, kind, valid_for);
    let mut verifications = app.email_verifications.lock().await;
    verifications.insert(code.clone(), verification);
    drop(verifications);

    // Generate the verification link
    let account_config = app
        .config
        .account
        .as_ref()
        .ok_or("Account config not found")?;
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

    // We want emails to be sent in both HTML and plain text so older email clients can still read them
    let content_html =
        util::gen_content_from_template(&app.config.core.template_dir, "verify_email.html", &vars)?;
    let content_txt =
        util::gen_content_from_template(&app.config.core.template_dir, "verify_email.txt", &vars)?;

    // Send the email
    send_email(
        app,
        None,
        email,
        "Verify Your Email",
        content_html,
        content_txt,
    )
    .await?;

    info!("Sent verification email to {}", util::mask_email(email));
    Ok(())
}
