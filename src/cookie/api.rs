use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CookieResponse {
    pub username: String,
    pub cookie: String,
    pub expires: u64,
}
