use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct AccountInfoResponse {
    pub username: String,
    pub email: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct RegisterRequest {
    pub username: String,
    pub password: String,
    pub email: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct EmailVerificationRequest {
    pub code: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct UpdatePasswordRequest {
    pub new_password: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct UpdateEmailRequest {
    pub new_email: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct TemporaryPasswordRequest {
    pub email: String,
}
