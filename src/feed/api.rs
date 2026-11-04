use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct FeedOptions {
    pub get_player_select_updates: bool,
    pub get_map_square_updates: bool,
}

impl Default for FeedOptions {
    fn default() -> Self {
        Self {
            get_player_select_updates: true,
            get_map_square_updates: true,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum FeedEvent {
    Started,
    PlayerEntered(String),
    PlayerLeft(String),
}
