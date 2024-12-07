use jsonwebtoken::get_current_timestamp;

use crate::{util, AppState};

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
    let Some(account_config) = app.config.account.as_ref() else {
        return Err("Account config not found, can't send verification email".to_string());
    };
    let verification_route = account_config.get_email_verification_route();
    let verification_link = format!(
        "{}{}?code={}",
        app.config.core.hostname, verification_route, code
    );
    dbg!(&verification_link);

    // Send the email
    // TODO

    Ok(())
}
