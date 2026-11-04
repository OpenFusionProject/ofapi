use std::{
    collections::HashSet,
    sync::{Arc, OnceLock},
};

use axum::{http::StatusCode, routing::get, Json, Router};
use ffmonitor::{Event, Monitor, MonitorNotification};
use log::*;
use serde::Deserialize;

use crate::{
    database::{self, DatabaseConnection},
    feed::{self, FeedEvent},
    AppState,
};

#[derive(Deserialize, Clone)]
pub(crate) struct MonitorConfig {
    route: String,
    monitor_ip: String,
}

mod api;
pub use api::*;

static MONITOR: OnceLock<tokio::sync::Mutex<Monitor>> = OnceLock::new();
static STATUS: OnceLock<std::sync::Mutex<Status>> = OnceLock::new();
static LAST_PLAYERS: OnceLock<std::sync::Mutex<HashSet<String>>> = OnceLock::new();

fn notify_player(rt: &tokio::runtime::Handle, db: &Arc<DatabaseConnection>, event: FeedEvent) {
    let db = db.clone();
    rt.spawn(async move {
        let (FeedEvent::PlayerEntered(player_name) | FeedEvent::PlayerLeft(player_name)) = &event
        else {
            return;
        };

        if let Some(account_id) = database::find_account_id_by_player_name(&db, player_name).await {
            feed::notify_account(account_id, event).await;
        }
    });
}

fn monitor_callback(
    notification: MonitorNotification,
    rt: &tokio::runtime::Handle,
    db: &Arc<DatabaseConnection>,
) {
    let mut status = STATUS.get().unwrap().lock().unwrap();
    if let MonitorNotification::Updated(update) = notification {
        status.player_count = update.get_player_count();

        let players_now = update
            .get_events()
            .into_iter()
            .filter_map(|e| match e {
                Event::Player(pe) => Some(pe.name),
                _ => None,
            })
            .collect::<HashSet<_>>();

        let mut last_players = LAST_PLAYERS.get().unwrap().lock().unwrap();
        for name in players_now.difference(&last_players) {
            notify_player(rt, db, FeedEvent::PlayerEntered(name.clone()));
        }

        for name in last_players.difference(&players_now) {
            notify_player(rt, db, FeedEvent::PlayerLeft(name.clone()));
        }

        *last_players = players_now;
    }
}

pub(crate) fn register(
    routes: Router<Arc<AppState>>,
    config: &MonitorConfig,
    db: Arc<DatabaseConnection>,
) -> Router<Arc<AppState>> {
    let route = &config.route;
    let addr = &config.monitor_ip;

    LAST_PLAYERS.get_or_init(|| std::sync::Mutex::new(HashSet::new()));
    STATUS
        .set(std::sync::Mutex::new(Status::default()))
        .unwrap();

    // the monitor invokes the callback from its own non-tokio thread
    let rt = tokio::runtime::Handle::current();
    let callback = Box::new(move |n| monitor_callback(n, &rt, &db));
    let Ok(monitor) = Monitor::new_with_callback(addr, callback) else {
        error!(
            "Bad monitor address {}; monitor route @ {} disabled",
            addr, route
        );
        return routes;
    };

    MONITOR
        .set(tokio::sync::Mutex::new(monitor))
        .unwrap_or_else(|_| unreachable!());

    info!("Registering monitor route @ {}", route);
    routes.route(route, get(get_status))
}

async fn get_status() -> Result<Json<Status>, StatusCode> {
    let monitor = MONITOR.get().unwrap().lock().await;
    if !monitor.is_connected() {
        return Err(StatusCode::NO_CONTENT);
    }

    let status = STATUS.get().unwrap().lock().unwrap().clone();
    Ok(Json(status))
}
