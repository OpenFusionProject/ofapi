use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct CookieResponse {
    pub username: String,
    pub cookie: String,
    pub expires: u64,
}
