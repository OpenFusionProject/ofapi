use std::{collections::HashMap, net::SocketAddr, sync::Arc};

use ::ring::rand::SystemRandom;
use axum::{extract::State, routing::get, Json, Router};
use log::{info, warn};
use serde::Deserialize;
use simplelog::{ColorChoice, LevelFilter, TermLogger, TerminalMode};
use tokio::sync::Mutex;
use tower_http::cors::{Any, CorsLayer};

use crate::{
    account, auth, cookie, database, database::DatabaseConnection, email, launcher, legacy,
    moderation, monitor, rankinfo, statics, InfoResponse,
};

#[cfg(feature = "tls")]
use {axum_server::tls_rustls::RustlsConfig, rustls::crypto::ring};

#[derive(Deserialize, Clone)]
pub(crate) struct CoreConfig {
    pub(crate) server_name: String,
    pub(crate) public_url: String,
    pub(crate) db_type: String,
    pub(crate) db_path: Option<String>,
    pub(crate) db_username: Option<String>,
    pub(crate) db_password: Option<String>,
    pub(crate) db_host: Option<String>,
    pub(crate) db_port: Option<u16>,
    pub(crate) db_name: Option<String>,
    pub(crate) template_dir: String,
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
pub(crate) struct GameConfig {
    versions: Vec<String>,
    pub(crate) login_address: String,
    custom_loading_screen: Option<bool>,
}

#[derive(Deserialize, Clone)]
pub(crate) struct Config {
    pub(crate) core: CoreConfig,
    tls: Option<TlsConfig>,
    pub(crate) email: Option<email::EmailConfig>,
    pub(crate) game: GameConfig,
    monitor: Option<monitor::MonitorConfig>,
    moderation: Option<moderation::ModerationConfig>,
    pub(crate) rankinfo: Option<rankinfo::RankInfoConfig>,
    pub(crate) account: Option<account::AccountConfig>,
    pub(crate) auth: Option<auth::AuthConfig>,
    pub(crate) cookie: Option<cookie::CookieConfig>,
    legacy: Option<legacy::LegacyConfig>,
    launcher: Option<launcher::LauncherConfig>,
}
impl Config {
    fn load() -> Self {
        const DEFAULT_CONFIG: &str = include_str!("../config.toml.default");
        const CONFIG_PATH: &str = "config.toml";
        let config = match std::fs::read_to_string(CONFIG_PATH) {
            Ok(c) => c,
            Err(_) => {
                warn!(
                    "Failed to read config file at {}. Loading default config.",
                    CONFIG_PATH
                );
                DEFAULT_CONFIG.to_string()
            }
        };
        toml::from_str(&config).expect("Failed to parse config file")
    }
}

#[derive(Clone)]
pub(crate) struct AppState {
    pub(crate) db: Arc<DatabaseConnection>,
    pub(crate) rng: Arc<SystemRandom>,
    pub(crate) email_verifications: Arc<Mutex<HashMap<String, email::EmailVerification>>>,
    pub(crate) temp_passwords: Arc<Mutex<HashMap<String, email::TempPassword>>>,
    pub(crate) is_tls: bool,
    pub(crate) config: Config,
}
impl AppState {
    async fn new(config: &Config) -> Self {
        let conn = database::connect_to_db(&config.core).await;
        Self {
            db: Arc::new(conn),
            rng: Arc::new(SystemRandom::new()),
            email_verifications: Arc::new(Mutex::new(HashMap::new())),
            temp_passwords: Arc::new(Mutex::new(HashMap::new())),
            is_tls: false,
            config: config.clone(),
        }
    }
}

pub async fn run() {
    // init logging
    TermLogger::init(
        LevelFilter::Info,
        simplelog::Config::default(),
        TerminalMode::Mixed,
        ColorChoice::Auto,
    )
    .expect("Failed to init logger");

    info!("OFAPI v{}", env!("CARGO_PKG_VERSION"));

    // load config
    let config = Config::load();

    // init app state
    let state = AppState::new(&config).await;

    // register endpoints for both HTTP and HTTPS
    let mut routes = Router::new().route("/", get(get_info));
    routes = statics::register(routes);
    if let Some(ref rankinfo_config) = config.rankinfo {
        routes = rankinfo::register(routes, rankinfo_config);
    }
    if let Some(ref monitor_config) = config.monitor {
        routes = monitor::register(routes, monitor_config);
    }
    if let Some(ref legacy_config) = config.legacy {
        routes = legacy::register(
            routes,
            legacy_config,
            config.game.versions.first(),
            &config.core.template_dir,
        )
    }
    if let Some(ref launcher_config) = config.launcher {
        routes = launcher::register(routes, launcher_config);
    }

    // add CORS headers for non-sensitive APIs
    let cors = CorsLayer::new().allow_origin(Any);
    routes = routes.layer(cors);

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
    if let Some(ref moderation_config) = config.moderation {
        routes_tls = moderation::register(routes_tls, moderation_config);
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

async fn get_info(State(state): State<Arc<AppState>>) -> Json<InfoResponse> {
    let info = InfoResponse {
        server_name: state.config.core.server_name.clone(),
        api_version: env!("CARGO_PKG_VERSION").to_string(),
        secure_apis_enabled: state.is_tls,
        game_versions: state.config.game.versions.clone(),
        login_address: state.config.game.login_address.clone(),
        email_required: state
            .config
            .account
            .as_ref()
            .is_some_and(|a| a.is_email_required()),
        custom_loading_screen: state.config.game.custom_loading_screen.unwrap_or(false),
    };
    Json(info)
}
