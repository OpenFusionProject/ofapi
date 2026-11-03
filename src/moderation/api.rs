use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct NameRequest {
    pub player_uid: u64,
    pub requested_name: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct NameRequestDecision {
    pub player_uid: u64,
    pub requested_name: String,
    pub decision: String,
    pub by: String,
}
