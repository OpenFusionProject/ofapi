use crate::{moderation::NameCheckStatus, rankinfo::Rank, CoreConfig};

mod sqlite_backend;

const MIN_DATABASE_VERSION: i64 = 6;

#[allow(dead_code)]
#[derive(Debug)]
pub(crate) struct Account {
    pub(crate) id: i64,
    pub(crate) login: String,
    pub(crate) password_hashed: String,
    pub(crate) email: String,
}

pub(crate) enum DatabaseConnection {
    Sqlite(sqlite::ConnectionThreadSafe),
    // Postgres(PostgresConnection),
}

pub async fn connect_to_db(config: &CoreConfig) -> DatabaseConnection {
    match config.db_type.as_str() {
        "sqlite" => {
            let path = config
                .db_path
                .as_ref()
                .expect("db_path must be set for sqlite db_type");
            DatabaseConnection::Sqlite(sqlite_backend::connect_to_db(path))
        }
        "postgres" => {
            let _username = config
                .db_username
                .as_ref()
                .expect("db_username must be set for postgres db_type");
            let _password = config
                .db_password
                .as_ref()
                .expect("db_password must be set for postgres db_type");
            let _host = config
                .db_host
                .as_ref()
                .expect("db_host must be set for postgres db_type");
            let _port = config
                .db_port
                .as_ref()
                .expect("db_port must be set for postgres db_type");
            unimplemented!("Postgres database support is not yet implemented");
        }
        other => {
            panic!("Unsupported db_type: {}", other);
        }
    }
}

pub(crate) async fn find_account(db: &DatabaseConnection, account_id: i64) -> Option<Account> {
    match db {
        DatabaseConnection::Sqlite(conn) => sqlite_backend::find_account(conn, account_id),
        //DatabaseConnection::Postgres(conn) => postgres_backend::find_account(conn, account_id),
    }
}

pub(crate) async fn find_account_by_username(
    db: &DatabaseConnection,
    username: &str,
) -> Option<Account> {
    match db {
        DatabaseConnection::Sqlite(conn) => {
            sqlite_backend::find_account_by_username(conn, username)
        }
        //DatabaseConnection::Postgres(conn) => postgres_backend::find_account_by_username(conn, username),
    }
}

pub(crate) async fn find_account_by_email(db: &DatabaseConnection, email: &str) -> Option<Account> {
    match db {
        DatabaseConnection::Sqlite(conn) => sqlite_backend::find_account_by_email(conn, email),
        //DatabaseConnection::Postgres(conn) => postgres_backend::find_account_by_email(conn, email),
    }
}

pub(crate) async fn create_account(
    db: &DatabaseConnection,
    username: &str,
    password_hashed: &str,
    account_level: u8,
    email: Option<&str>,
) -> Result<i64, String> {
    match db {
        DatabaseConnection::Sqlite(conn) => {
            sqlite_backend::create_account(conn, username, password_hashed, account_level, email)
        } //DatabaseConnection::Postgres(conn) => {
          //    postgres_backend::create_account(conn, username, password_hashed, account_level, email)
          //}
    }
}

pub(crate) async fn update_password_for_account(
    db: &DatabaseConnection,
    username: &str,
    password_hashed: &str,
) -> Result<(), String> {
    match db {
        DatabaseConnection::Sqlite(conn) => {
            sqlite_backend::update_password_for_account(conn, username, password_hashed)
        } //DatabaseConnection::Postgres(conn) => {
          //    postgres_backend::update_password_for_account(conn, username, password_hashed)
          //}
    }
}

pub(crate) async fn update_email_for_account(
    db: &DatabaseConnection,
    username: &str,
    email: &str,
) -> Result<(), String> {
    match db {
        DatabaseConnection::Sqlite(conn) => {
            sqlite_backend::update_email_for_account(conn, username, email)
        } //DatabaseConnection::Postgres(conn) => {
          //    postgres_backend::update_email_for_account(conn, username, email)
          //}
    }
}

pub(crate) async fn check_credentials(
    db: &DatabaseConnection,
    username: &str,
    password: &str,
) -> Result<i64, String> {
    match db {
        DatabaseConnection::Sqlite(conn) => {
            sqlite_backend::check_credentials(conn, username, password)
        } //DatabaseConnection::Postgres(conn) => {
          //    postgres_backend::check_credentials(conn, username, password)
          //}
    }
}

pub(crate) async fn get_outstanding_namereqs(db: &DatabaseConnection) -> Vec<(i64, String)> {
    match db {
        DatabaseConnection::Sqlite(conn) => sqlite_backend::get_outstanding_namereqs(conn), //DatabaseConnection::Postgres(conn) => {
                                                                                            //    postgres_backend::get_outstanding_namereqs(conn)
                                                                                            //}
    }
}

pub(crate) async fn get_namecheck_for_player(
    db: &DatabaseConnection,
    player_uid: i64,
) -> Result<i64, String> {
    match db {
        DatabaseConnection::Sqlite(conn) => {
            sqlite_backend::get_namecheck_for_player(conn, player_uid)
        } //DatabaseConnection::Postgres(conn) => {
          //    postgres_backend::get_namecheck_for_player(conn, player_uid)
          //}
    }
}

pub(crate) async fn set_namecheck_for_player(
    db: &DatabaseConnection,
    player_uid: i64,
    name_check_status: NameCheckStatus,
) -> Result<(), String> {
    match db {
        DatabaseConnection::Sqlite(conn) => {
            sqlite_backend::set_namecheck_for_player(conn, player_uid, name_check_status)
        } //DatabaseConnection::Postgres(conn) => {
          //    postgres_backend::set_namecheck_for_player(conn, player_uid, name_check_status)
          //}
    }
}

pub(crate) async fn get_last_password_reset(
    db: &DatabaseConnection,
    account_id: i64,
) -> Option<u64> {
    match db {
        DatabaseConnection::Sqlite(conn) => {
            sqlite_backend::get_last_password_reset(conn, account_id)
        } //DatabaseConnection::Postgres(conn) => {
          //    postgres_backend::get_last_password_reset(conn, account_id)
          //}
    }
}

pub(crate) async fn fetch_ranks(
    db: &DatabaseConnection,
    epid: i64,
    date: &str,
    num: usize,
    fill: bool,
) -> Vec<Rank> {
    match db {
        DatabaseConnection::Sqlite(conn) => {
            sqlite_backend::fetch_ranks(conn, epid, date, num, fill)
        } //DatabaseConnection::Postgres(conn) => {
          //    postgres_backend::fetch_ranks(conn, epid, date, num, fill)
          //}
    }
}

pub(crate) async fn fetch_my_ranks(
    db: &DatabaseConnection,
    pcuid: i64,
    epid: i64,
    date: &str,
) -> Vec<Rank> {
    match db {
        DatabaseConnection::Sqlite(conn) => sqlite_backend::fetch_my_ranks(conn, pcuid, epid, date), //DatabaseConnection::Postgres(conn) => {
                                                                                                     //    postgres_backend::fetch_my_ranks(conn, pcuid, epid, date)
                                                                                                     //}
    }
}

pub(crate) async fn set_cookie(
    db: &DatabaseConnection,
    account_id: i64,
    cookie: &str,
    valid_secs: u64,
) -> Result<u64, String> {
    match db {
        DatabaseConnection::Sqlite(conn) => {
            sqlite_backend::set_cookie(conn, account_id, cookie, valid_secs)
        } //DatabaseConnection::Postgres(conn) => {
          //    postgres_backend::set_cookie(conn, account_id, cookie, valid_secs)
          //}
    }
}
