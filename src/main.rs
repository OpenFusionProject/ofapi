use std::{net::SocketAddr, sync::Arc};

use axum::{extract::State, routing::get, Router};
use axum_server::tls_rustls::RustlsConfig;
use log::{info, warn};
use serde::Deserialize;
use simplelog::{ColorChoice, LevelFilter, TermLogger, TerminalMode};
use sqlite::Connection;
use tokio::sync::Mutex;

mod rankinfo;
mod statics;
mod util;

#[derive(Deserialize, Clone)]
struct CoreConfig {
    db_path: String,
    port: Option<u16>,
}

#[derive(Deserialize, Clone)]
struct TlsConfig {
    cert_path: String,
    key_path: String,
    port: Option<u16>,
}

#[derive(Deserialize, Clone)]
struct Config {
    core: CoreConfig,
    tls: Option<TlsConfig>,
    rankinfo: Option<rankinfo::RankInfoConfig>,
}
impl Config {
    fn load() -> Self {
        const CONFIG_PATH: &str = "config.toml";
        let config = std::fs::read_to_string(CONFIG_PATH).expect("Failed to open config file");
        toml::from_str(&config).expect("Failed to parse config file")
    }
}

#[derive(Clone)]
struct AppState {
    db: Arc<Mutex<Connection>>,
    is_tls: bool,
    config: Config,
}
impl AppState {
    fn new(config: &Config) -> Self {
        info!(
            "SQLite version {}",
            util::version_to_string(sqlite::version())
        );
        let conn = util::connect_to_db(&config.core.db_path);
        Self {
            db: Arc::new(Mutex::new(conn)),
            is_tls: false,
            config: config.clone(),
        }
    }
}

#[tokio::main]
async fn main() {
    // load config
    let config = Config::load();

    // init logging
    TermLogger::init(
        LevelFilter::Info,
        simplelog::Config::default(),
        TerminalMode::Mixed,
        ColorChoice::Auto,
    )
    .expect("Failed to init logger");

    info!("OFAPI v{}", env!("CARGO_PKG_VERSION"));

    // init app state
    let state = AppState::new(&config);

    // register endpoints for both HTTP and HTTPS
    let mut routes = Router::new().route("/", get(get_info));
    routes = statics::register(routes);
    if let Some(ref rankinfo_config) = config.rankinfo {
        routes = rankinfo::register(routes, rankinfo_config);
    }

    // register HTTPS-only endpoints
    let routes_tls = Router::new().merge(routes.clone());

    // init both protocols
    // N.B. these listen concurrently, but NOT in parallel (see tokio::join!)
    let http = init_http(routes, &config, state.clone());
    let https = init_https(routes_tls, &config, state);
    let _ = tokio::join!(http, https);
}

const BIND_IP: [u8; 4] = [127, 0, 0, 1];

async fn init_http(routes: Router<Arc<AppState>>, config: &Config, state: AppState) {
    const DEFAULT_HTTP_PORT: u16 = 80;

    let app = routes.with_state(Arc::new(state));

    let addr = SocketAddr::from((BIND_IP, config.core.port.unwrap_or(DEFAULT_HTTP_PORT)));
    info!("HTTP listening on {}", addr);
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn init_https(routes: Router<Arc<AppState>>, config: &Config, mut state: AppState) {
    const DEFAULT_HTTPS_PORT: u16 = 443;

    state.is_tls = true;
    let app = routes.with_state(Arc::new(state));

    let Some(ref tls_config) = config.tls else {
        warn!("Missing or malformed TLS config. HTTPS disabled");
        return;
    };

    let cert_path = &tls_config.cert_path;
    let key_path = &tls_config.key_path;
    let Ok(rustls_cfg) = RustlsConfig::from_pem_file(cert_path, key_path).await else {
        warn!("Failed to load TLS cert or key. HTTPS disabled");
        return;
    };

    let addr = SocketAddr::from((BIND_IP, tls_config.port.unwrap_or(DEFAULT_HTTPS_PORT)));
    info!("HTTPS listening on {}", addr);
    axum_server::bind_rustls(addr, rustls_cfg)
        .serve(app.into_make_service())
        .await
        .unwrap();
}

async fn get_info(State(state): State<Arc<AppState>>) -> String {
    format!(
        "OFAPI v{}\ntls: {:?}",
        env!("CARGO_PKG_VERSION"),
        state.is_tls
    )
}
