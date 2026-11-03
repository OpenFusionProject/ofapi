use serde::{Deserialize, Serialize};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct InfoResponse {
    pub server_name: String,
    pub api_version: String,
    pub secure_apis_enabled: bool,
    pub game_versions: Vec<String>,
    pub login_address: String,
    pub email_required: bool,
    pub custom_loading_screen: bool,
}
