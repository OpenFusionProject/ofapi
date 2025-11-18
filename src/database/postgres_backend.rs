use std::time::Duration;

use deadpool_postgres::{Manager, ManagerConfig, Pool, RecyclingMethod};
use log::*;
use tokio_postgres::tls;

use crate::database::MIN_DATABASE_VERSION;

pub(crate) async fn connect_to_db(
    username: &str,
    password: &str,
    host: &str,
    port: u16,
    name: &str,
) -> Pool {
    const QUERY: &str = "SELECT COUNT(*) FROM pg_tables WHERE tablename iLIKE 'Meta';";
    const VERSION_QUERY: &str = "SELECT Value FROM Meta WHERE Key iLIKE 'DatabaseVersion';";
    const PG_VERSION_QUERY: &str = "SELECT version();";

    let mut config = tokio_postgres::Config::new();
    config
        .host(host)
        .port(port)
        .user(username)
        .password(password)
        .dbname(name)
        .connect_timeout(Duration::from_secs(5));

    let mgr_config = ManagerConfig {
        recycling_method: RecyclingMethod::Fast,
    };
    let mgr = Manager::from_config(config, tls::NoTls, mgr_config);
    let pool = Pool::builder(mgr).max_size(16).build().unwrap();

    let client = pool
        .get()
        .await
        .expect("Failed to connect to Postgres database");
    let pg_version = client
        .query_one(PG_VERSION_QUERY, &[])
        .await
        .expect("Failed to query Postgres version")
        .get::<_, String>(0);

    // This looks like "PostgreSQL 10.0 blahblahblah"
    info!("{}", pg_version);

    let has_meta_table = client
        .query_one(QUERY, &[])
        .await
        .expect("Failed to query Meta table existence")
        .get::<_, i64>(0)
        > 0;

    if !has_meta_table {
        panic!("Postgres DB is not a valid OpenFusion database. Maybe it's uninitialized?");
    }

    let version = client
        .query_one(VERSION_QUERY, &[])
        .await
        .expect("Failed to query database version")
        .get::<_, i32>(0);

    if (version as i64) < MIN_DATABASE_VERSION {
        panic!(
            "Database version too low: {} (Must be at least {})",
            version, MIN_DATABASE_VERSION
        );
    }

    pool
}
