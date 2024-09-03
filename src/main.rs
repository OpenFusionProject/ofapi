use tide::{Request, Server};
use tide_rustls::TlsListener;

#[tokio::main]
async fn main() {
    // register endpoints
    let mut app = tide::new();
    app.at("/").get(get_info);

    // init both protocols and wait for them to finish
    let http = init_http(app.clone());
    let https = init_https(app);
    let _ = tokio::join!(http, https);
}

async fn init_http(app: Server<()>) {
    if let Err(e) = app.listen("0.0.0.0:80").await {
        eprintln!("HTTP: {}", e);
    }
}

async fn init_https(app: Server<()>) {
    let Ok(cert_path) = std::env::var("TIDE_CERT_PATH") else {
        eprintln!("HTTPS: TIDE_CERT_PATH not set");
        return;
    };
    let Ok(key_path) = std::env::var("TIDE_KEY_PATH") else {
        eprintln!("HTTPS: TIDE_KEY_PATH not set");
        return;
    };
    if let Err(e) = app
        .listen(
            TlsListener::build()
                .addrs("0.0.0.0:443")
                .cert(cert_path)
                .key(key_path),
        )
        .await
    {
        eprintln!("HTTPS: {}", e);
    }
}

async fn get_info(req: Request<()>) -> tide::Result {
    let is_tls = req.header_names();
    Ok(format!("OFAPI v{} tls: {:?}", env!("CARGO_PKG_VERSION"), is_tls).into())
}
