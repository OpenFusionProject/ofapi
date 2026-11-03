mod api;
pub use api::*;

#[cfg(feature = "full")]
pub mod account;
#[cfg(not(feature = "full"))]
pub mod account {
    mod api;
    pub use api::*;
}

#[cfg(feature = "full")]
pub mod auth;
#[cfg(not(feature = "full"))]
pub mod auth {
    mod api;
    pub use api::*;
}

#[cfg(feature = "full")]
pub mod cookie;
#[cfg(not(feature = "full"))]
pub mod cookie {
    mod api;
    pub use api::*;
}

#[cfg(feature = "full")]
pub mod moderation;
#[cfg(not(feature = "full"))]
pub mod moderation {
    mod api;
    pub use api::*;
}

#[cfg(feature = "full")]
pub mod monitor;
#[cfg(not(feature = "full"))]
pub mod monitor {
    mod api;
    pub use api::*;
}

#[cfg(feature = "full")]
pub mod rankinfo;
#[cfg(not(feature = "full"))]
pub mod rankinfo {
    mod api;
    pub use api::*;
}

#[cfg(feature = "full")]
pub mod tokens;
#[cfg(feature = "full")]
pub mod util;

#[cfg(feature = "full")]
mod database;
#[cfg(feature = "full")]
mod email;
#[cfg(feature = "full")]
mod launcher;
#[cfg(feature = "full")]
mod legacy;
#[cfg(feature = "full")]
mod statics;

#[cfg(feature = "full")]
mod server;
#[cfg(feature = "full")]
pub use server::run;
#[cfg(feature = "full")]
use server::{AppState, CoreConfig};
