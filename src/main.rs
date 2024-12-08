use std::{collections::HashMap, net::SocketAddr, sync::Arc};

use ::ring::rand::SystemRandom;
use axum::{extract::State, routing::get, Json, Router};
use log::{info, warn};
use serde::{Deserialize, Serialize};
use simplelog::{ColorChoice, LevelFilter, TermLogger, TerminalMode};
use sqlite::Connection;
use tokio::sync::Mutex;

#[cfg(feature = "tls")]
use {axum_server::tls_rustls::RustlsConfig, rustls::crypto::ring};

mod account;
mod auth;
mod cookie;
mod monitor;
mod rankinfo;
mod statics;

mod database;
mod email;
mod util;

#[derive(Deserialize, Clone)]
struct CoreConfig {
    public_url: String,
    db_path: String,
    port: Option<u16>,
}

#[allow(dead_code)]
#[derive(Deserialize, Clone)]
struct TlsConfig {
    cert_path: String,
    key_path: String,
    port: Option<u16>,
}

#[derive(Deserialize, Clone)]
struct GameConfig {
    versions: Vec<String>,
    login_address: String,
}

#[derive(Deserialize, Clone)]
struct Config {
    core: CoreConfig,
    tls: Option<TlsConfig>,
    game: GameConfig,
    monitor: Option<monitor::MonitorConfig>,
    rankinfo: Option<rankinfo::RankInfoConfig>,
    account: Option<account::AccountConfig>,
    auth: Option<auth::AuthConfig>,
    cookie: Option<cookie::CookieConfig>,
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
    rng: Arc<SystemRandom>,
    email_verifications: Arc<Mutex<HashMap<String, email::EmailVerification>>>,
    is_tls: bool,
    config: Config,
}
impl AppState {
    fn new(config: &Config) -> Self {
        info!(
            "SQLite version {}",
            util::version_to_string(sqlite::version())
        );
        let conn = database::connect_to_db(&config.core.db_path);
        Self {
            db: Arc::new(Mutex::new(conn)),
            rng: Arc::new(SystemRandom::new()),
            email_verifications: Arc::new(Mutex::new(HashMap::new())),
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
    if let Some(ref monitor_config) = config.monitor {
        routes = monitor::register(routes, monitor_config);
    }

    // register HTTPS-only endpoints
    let mut routes_tls = Router::new().merge(routes.clone());
    if let Some(ref account_config) = config.account {
        routes_tls = account::register(routes_tls, account_config);
    }
    if let Some(ref auth_config) = config.auth {
        routes_tls = auth::register(routes_tls, auth_config, &state.rng);
    }
    if let Some(ref cookie_config) = config.cookie {
        routes_tls = cookie::register(routes_tls, cookie_config);
    }

    // init both protocols
    // N.B. these listen concurrently, but NOT in parallel (see tokio::join!)
    let http = init_http(routes, &config, state.clone());
    let https = init_https(routes_tls, &config, state);
    let _ = tokio::join!(http, https);
}

const BIND_IP: [u8; 4] = [127, 0, 0, 1];

async fn init_http(routes: Router<Arc<AppState>>, config: &Config, state: AppState) {
    const DEFAULT_HTTP_PORT: u16 = 80;
    let addr = SocketAddr::from((BIND_IP, config.core.port.unwrap_or(DEFAULT_HTTP_PORT)));

    let app = routes.with_state(Arc::new(state));

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

    let addr = SocketAddr::from((BIND_IP, tls_config.port.unwrap_or(DEFAULT_HTTPS_PORT)));

    #[cfg(not(feature = "tls"))]
    {
        warn!("TLS APIs enabled but OFAPI was not compiled with the `tls` feature. Encryption should be done at the proxy level!");
    }

    info!("HTTPS listening on {}", addr);

    #[cfg(feature = "tls")]
    {
        ring::default_provider().install_default().unwrap();
        let rustls_cfg =
            match RustlsConfig::from_pem_file(&tls_config.cert_path, &tls_config.key_path).await {
                Err(e) => {
                    warn!("Failed to activate TLS ({}); HTTPS disabled", e);
                    return;
                }
                Ok(cfg) => cfg,
            };

        axum_server::bind_rustls(addr, rustls_cfg)
            .serve(app.into_make_service())
            .await
            .unwrap();
    }

    #[cfg(not(feature = "tls"))]
    {
        let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
        axum::serve(listener, app).await.unwrap();
    }
}

#[derive(Serialize, Deserialize)]
pub struct InfoResponse {
    pub api_version: String,
    pub secure_apis_enabled: bool,
    pub game_versions: Vec<String>,
    pub login_address: String,
    pub email_required: bool,
}

async fn get_info(State(state): State<Arc<AppState>>) -> Json<InfoResponse> {
    let info = InfoResponse {
        api_version: env!("CARGO_PKG_VERSION").to_string(),
        secure_apis_enabled: state.is_tls,
        game_versions: state.config.game.versions.clone(),
        login_address: state.config.game.login_address.clone(),
        email_required: state
            .config
            .account
            .as_ref()
            .map_or(false, |a| a.is_email_required()),
    };
    Json(info)
}
