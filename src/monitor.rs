use std::sync::{Arc, OnceLock};

use axum::{http::StatusCode, routing::get, Json, Router};
use ffmonitor::{Monitor, MonitorNotification};
use log::*;
use serde::{Deserialize, Serialize};

use crate::AppState;

#[derive(Deserialize, Clone)]
pub struct MonitorConfig {
    route: String,
    monitor_ip: String,
}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
struct Status {
    player_count: usize,
}

static MONITOR: OnceLock<tokio::sync::Mutex<Monitor>> = OnceLock::new();
static STATUS: OnceLock<std::sync::Mutex<Status>> = OnceLock::new();

fn monitor_callback(notification: MonitorNotification) {
    let mut status = STATUS.get().unwrap().lock().unwrap();
    if let MonitorNotification::Updated(update) = notification {
        status.player_count = update.get_player_count();
    }
}

pub fn register(routes: Router<Arc<AppState>>, config: &MonitorConfig) -> Router<Arc<AppState>> {
    let route = &config.route;
    let addr = &config.monitor_ip;
    STATUS
        .set(std::sync::Mutex::new(Status::default()))
        .unwrap();
    let callback = Box::new(monitor_callback);
    let Ok(monitor) = Monitor::new_with_callback(addr, callback) else {
        error!(
            "Bad monitor address {}; monitor route @ {} disabled",
            addr, route
        );
        return routes;
    };
    info!("Registering monitor route @ {}", route);
    MONITOR
        .set(tokio::sync::Mutex::new(monitor))
        .unwrap_or_else(|_| unreachable!());
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
