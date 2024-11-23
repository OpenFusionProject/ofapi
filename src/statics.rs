use std::sync::Arc;

use axum::Router;
use log::{info, warn};
use tower_http::services::{ServeDir, ServeFile};

use crate::{util, AppState};

pub fn register(mut routes: Router<Arc<AppState>>) -> Router<Arc<AppState>> {
    const MAPPINGS_PATH: &str = "statics.csv";

    info!("Registering static routes");

    let mappings = std::fs::read_to_string(MAPPINGS_PATH).expect("Failed to open mappings file");
    let mappings = util::parse_csv(&mappings);
    for mapping in mappings {
        let route = &mapping[0];
        if mapping.len() != 2 {
            warn!("Bad static route mapping for route {}; ignoring", route);
            continue;
        }
        let path = &mapping[1];
        if path.ends_with('/') {
            // serve directory
            let _ = std::fs::create_dir_all(path);
            routes = routes.nest_service(route, ServeDir::new(path));
            info!("\t{}/* => {}*", route, path);
        } else {
            // serve single file
            routes = routes.route_service(route, ServeFile::new(path));
            info!("\t{} => {}", route, path);
        }
    }
    routes
}
