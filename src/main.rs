use std::sync::Arc;

use serde::Deserialize;
use sqlite::Connection;
use tide::{Request, Server};
use tide_rustls::TlsListener;
use tokio::sync::Mutex;

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
}
impl AppState {
    fn new(config: &Config) -> Self {
        println!(
            "SQLite version {}",
            util::version_to_string(sqlite::version())
        );
        let conn = sqlite::open(&config.core.db_path).expect("Failed to open DB");
        Self {
            db: Arc::new(Mutex::new(conn)),
        }
    }
}

#[tokio::main]
async fn main() {
    println!("OFAPI v{}", env!("CARGO_PKG_VERSION"));

    // load config
    let config = Config::load();

    // init app state
    let state = AppState::new(&config);

    // register endpoints
    let mut app = tide::with_state(state);
    app.at("/").get(get_info);

    // init both protocols and wait for them to finish
    let http = init_http(app.clone(), &config);
    let https = init_https(app, &config);
    let _ = tokio::join!(http, https);
}

async fn init_http(app: Server<AppState>, config: &Config) {
    const DEFAULT_HTTP_PORT: u16 = 80;

    let addr = format!("0.0.0.0:{}", config.core.port.unwrap_or(DEFAULT_HTTP_PORT));
    println!("HTTP listening on {}", addr);
    if let Err(e) = app.listen(addr).await {
        eprintln!("HTTP listener crashed: {}", e);
    }
}

async fn init_https(app: Server<AppState>, config: &Config) {
    const DEFAULT_HTTPS_PORT: u16 = 443;

    let Some(ref tls_config) = config.tls else {
        eprintln!("Missing or malformed TLS config. HTTPS disabled");
        return;
    };

    let cert_path = &tls_config.cert_path;
    let key_path = &tls_config.key_path;

    // make sure these files can be opened
    if !std::path::Path::new(cert_path).exists() {
        eprintln!("{} not found. HTTPS disabled", cert_path);
        return;
    }

    if !std::path::Path::new(key_path).exists() {
        eprintln!("{} not found. HTTPS disabled", key_path);
        return;
    }

    let addr = format!("0.0.0.0:{}", tls_config.port.unwrap_or(DEFAULT_HTTPS_PORT));
    println!("HTTPS listening on {}", addr);
    if let Err(e) = app
        .listen(
            TlsListener::build()
                .addrs(addr)
                .cert(cert_path)
                .key(key_path),
        )
        .await
    {
        eprintln!("HTTPS listener crashed: {}", e);
    }
}

async fn get_info(_req: Request<AppState>) -> tide::Result {
    Ok(format!("OFAPI v{}", env!("CARGO_PKG_VERSION")).into())
}
