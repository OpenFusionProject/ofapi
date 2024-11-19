use std::{net::SocketAddr, sync::Arc};

use ::ring::rand::SystemRandom;
use axum::{extract::State, routing::get, Router};
use log::{info, warn};
use serde::Deserialize;
use simplelog::{ColorChoice, LevelFilter, TermLogger, TerminalMode};
use sqlite::Connection;
use tokio::sync::Mutex;

#[cfg(feature = "app-tls")]
use {axum_server::tls_rustls::RustlsConfig, rustls::crypto::ring};

mod auth;
mod cookie;
mod rankinfo;
mod statics;
mod util;

const DEFAULT_HTTP_PORT: u16 = 8080;
const CONFIG_PATH: &str = "config.toml";

#[cfg(feature = "app-tls")]
const DEFAULT_HTTPS_PORT: u16 = 443;

#[derive(Deserialize, Clone)]
struct CoreConfig {
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
struct Config {
    core: CoreConfig,
    app_tls: Option<TlsConfig>,
    rankinfo: Option<rankinfo::RankInfoConfig>,
    auth: Option<auth::AuthConfig>,
    cookie: Option<cookie::CookieConfig>,
}
impl Config {
    fn load() -> Self {
        let config = std::fs::read_to_string(CONFIG_PATH).expect("Failed to open config file");
        toml::from_str(&config).expect("Failed to parse config file")
    }
}

#[derive(Clone)]
struct AppState {
    db: Arc<Mutex<Connection>>,
    rng: Arc<SystemRandom>,
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
            rng: Arc::new(SystemRandom::new()),
            config: config.clone(),
        }
    }

    fn is_using_app_tls(self: &Self) -> bool {
        #[cfg(not(feature = "app-tls"))]
        {
            return false;
        }

        #[allow(unreachable_code)]
        self.config.app_tls.is_some()
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

    // register secure endpoints
    let mut routes_secure = Router::new();
    if let Some(ref auth_config) = config.auth {
        routes_secure = auth::register(routes_secure, auth_config, &state.rng);
    }
    if let Some(ref cookie_config) = config.cookie {
        routes_secure = cookie::register(routes_secure, cookie_config);
    }

    #[cfg(not(feature = "app-tls"))]
    {
        warn!("OFAPI was not compiled with the `app-tls` feature. Encryption should be done at the proxy level!");

        let routes = Router::new().merge(routes).merge(routes_secure);
        let http = init_http(routes, &config, state.clone());
        let _ = tokio::join!(http);
    }

    #[cfg(feature = "app-tls")]
    {
        info!("Using application-level TLS termination.");

        // init secure endpoints on a separate port
        // N.B. these listen concurrently, but NOT in parallel (see tokio::join!)

        if state.is_using_app_tls() {
            let routes_secure = Router::new().merge(routes.clone()).merge(routes_secure);
            let http = init_http(routes, &config, state.clone());
            let https = init_https(routes_secure, &config, state);
            let _ = tokio::join!(http, https);
        } else {
            warn!("Application-level TLS termination disabled. Encryption should be done at the proxy level!");

            let routes = Router::new().merge(routes).merge(routes_secure);
            let http = init_http(routes, &config, state.clone());
            let _ = tokio::join!(http);
        }
    }
}

const BIND_IP: [u8; 4] = [127, 0, 0, 1];

async fn init_http(routes: Router<Arc<AppState>>, config: &Config, state: AppState) {
    let addr = SocketAddr::from((BIND_IP, config.core.port.unwrap_or(DEFAULT_HTTP_PORT)));

    let app = routes.with_state(Arc::new(state));

    info!("HTTP listening on {}", addr);
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

#[cfg(feature = "app-tls")]
async fn init_https(routes: Router<Arc<AppState>>, config: &Config, state: AppState) {
    let app = routes.with_state(Arc::new(state));

    let Some(ref tls_config) = config.app_tls else {
        warn!("Missing or malformed TLS config. HTTPS disabled");
        return;
    };

    let addr = SocketAddr::from((BIND_IP, tls_config.port.unwrap_or(DEFAULT_HTTPS_PORT)));

    info!("HTTPS listening on {}", addr);

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

async fn get_info(State(state): State<Arc<AppState>>) -> String {
    format!(
        "OFAPI v{}\ntls: {:?}\n",
        env!("CARGO_PKG_VERSION"),
        state.is_using_app_tls()
    )
}
