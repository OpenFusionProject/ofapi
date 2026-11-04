use std::{
    collections::HashMap,
    sync::{Arc, OnceLock},
    time::Duration,
};

use crate::tokens::TokenCapability;
use axum::{
    extract::{
        ws::{CloseFrame, Message, WebSocket, WebSocketUpgrade},
        State,
    },
    http::{HeaderMap, StatusCode},
    response::Response,
    routing::get,
    Json, Router,
};
use log::*;
use serde::Deserialize;
use tokio::sync::{
    mpsc::{self, UnboundedSender},
    RwLock,
};

use crate::{auth, util, AppState};

#[derive(Deserialize, Clone)]
pub(crate) struct FeedConfig {
    route: String,
}

mod api;
pub use api::*;

const PING_INTERVAL: Duration = Duration::from_secs(30);
const CLOSE_CODE_REPLACED: u16 = 4000;

// one connection per account; a new connection replaces the old one
static FEED: OnceLock<RwLock<HashMap<i64, UnboundedSender<FeedEvent>>>> = OnceLock::new();

pub(crate) async fn notify_account(account_id: i64, event: FeedEvent) {
    if let Some(m) = FEED.get() {
        let m = m.read().await;
        if let Some(tx) = m.get(&account_id) {
            let _ = tx.send(event);
        }
    }
}

pub(crate) fn register(
    routes: Router<Arc<AppState>>,
    config: &FeedConfig,
) -> Router<Arc<AppState>> {
    let route = &config.route;
    info!("Registering feed route @ {}", route);
    FEED.get_or_init(|| RwLock::new(HashMap::new()));
    // WebSocket upgrades are always GET requests
    routes.route(route, get(get_feed))
}

async fn get_feed(
    State(app): State<Arc<AppState>>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
    options: Option<Json<FeedOptions>>,
) -> Result<Response, (StatusCode, String)> {
    let options = options.map(|Json(o)| o).unwrap_or_default();
    assert!(app.is_tls);

    // since we aren't in the auth module, the secret key is not guaranteed to be set
    let Some(key) = auth::SECRET_KEY.get() else {
        warn!("Cookie route used, but auth module not initialized");
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            "Server error".to_string(),
        ));
    };

    let account_id =
        match util::validate_authed_request(key, &headers, vec![TokenCapability::GetCookie]) {
            Ok(id) => id.parse::<i64>(),
            Err(e) => return Err((StatusCode::UNAUTHORIZED, e)),
        };

    let account_id = match account_id {
        Ok(id) => id,
        Err(_) => return Err((StatusCode::UNAUTHORIZED, "Bad token".to_string())),
    };

    Ok(ws.on_upgrade(move |socket| handle_feed_socket(socket, account_id, options)))
}

async fn handle_feed_socket(mut socket: WebSocket, account_id: i64, options: FeedOptions) {
    let (tx, mut rx) = mpsc::unbounded_channel();
    let _ = tx.send(FeedEvent::Started);
    // dropping the old sender closes the old connection's channel, which makes it shut down
    if FEED
        .get()
        .unwrap()
        .write()
        .await
        .insert(account_id, tx)
        .is_some()
    {
        debug!(
            "Replacing existing feed connection (account {})",
            account_id
        );
    }
    debug!("Feed client connected (account {})", account_id);

    let mut ping = tokio::time::interval(PING_INTERVAL);
    ping.tick().await; // first tick is immediate

    loop {
        tokio::select! {
            event = rx.recv() => {
                let Some(event) = event else {
                    // our sender was dropped, so a newer connection replaced this one
                    let _ = socket
                        .send(Message::Close(Some(CloseFrame {
                            code: CLOSE_CODE_REPLACED,
                            reason: "Replaced by a newer feed connection".into(),
                        })))
                        .await;
                    debug!("Feed client replaced (account {})", account_id);
                    return;
                };

                let should_send = match &event {
                    FeedEvent::PlayerEntered(_) | FeedEvent::PlayerLeft(_) => options.get_player_select_updates,
                    FeedEvent::Started => true,
                };

                if !should_send {
                    continue;
                }

                let json = match serde_json::to_string(&event) {
                    Ok(json) => json,
                    Err(e) => {
                        error!("Failed to serialize feed event {:?}: {}", event, e);
                        continue;
                    }
                };

                if socket.send(Message::Text(json.into())).await.is_err() {
                    break;
                }
            }
            _ = ping.tick() => {
                // keeps idle connections from being reaped by proxies
                if socket.send(Message::Ping(Default::default())).await.is_err() {
                    break;
                }
            }
            msg = socket.recv() => {
                // ignore incoming messages for now
                match msg {
                    None | Some(Err(_)) | Some(Ok(Message::Close(_))) => break,
                    Some(Ok(_)) => {}
                }
            }
        }
    }

    // our sender only lives in the map, so if our channel is still open, the entry is still ours
    // (otherwise a newer connection replaced it and we must not remove theirs)
    let mut feed = FEED.get().unwrap().write().await;
    if !rx.is_closed() {
        feed.remove(&account_id);
    }
    debug!("Feed client disconnected (account {})", account_id);
}
