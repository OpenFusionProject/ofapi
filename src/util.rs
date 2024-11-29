use std::time::SystemTime;

use axum::http::HeaderMap;
use log::info;
use sqlite::{Connection, State};

use crate::auth;

const MIN_DATABASE_VERSION: i64 = 6;

#[allow(dead_code)]
#[derive(Debug)]
pub struct Account {
    id: i64,
    login: String,
    password_hashed: String,
    email: String,
}

pub fn version_to_string(version: usize) -> String {
    // ex: 3045003 -> "3.45.3"
    let major = version / 1000000;
    let minor = (version % 1000000) / 1000;
    let patch = version % 1000;
    format!("{}.{}.{}", major, minor, patch)
}

pub fn connect_to_db(path: &str) -> Connection {
    const QUERY: &str = "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='Meta';";
    const VERSION_QUERY: &str = "SELECT Value FROM Meta WHERE Key = 'DatabaseVersion';";

    // check if the db exists first
    if !std::path::Path::new(path).exists() {
        panic!("Database file not found: {}", path);
    }

    // open the database and check the meta table
    let conn = sqlite::open(path).expect("Failed to open DB");
    let mut stmt = conn.prepare(QUERY).unwrap();
    let Ok(State::Row) = stmt.next() else {
        panic!("Could not validate database: {}", path);
    };
    let count: i64 = stmt.read(0).unwrap();
    if count < 1 {
        panic!("Bad OF database: no meta table found");
    }
    drop(stmt);

    // check the version
    let mut stmt = conn.prepare(VERSION_QUERY).unwrap();
    let Ok(State::Row) = stmt.next() else {
        panic!("Could not get database version");
    };
    let version: i64 = stmt.read(0).unwrap();
    drop(stmt);

    if version < MIN_DATABASE_VERSION {
        panic!(
            "Database version too low: {} (Must be at least {})",
            version, MIN_DATABASE_VERSION
        );
    }

    info!("Connected to database (version {})", version);
    conn
}

pub fn wrap_xml(name: &str, content: &str, newlines: bool) -> String {
    if newlines {
        format!("<{}>\n{}</{}>\n", name, content, name)
    } else {
        format!("<{}>{}</{}>", name, content, name)
    }
}

pub fn parse_csv(data: &str) -> Vec<Vec<String>> {
    // do not include empty lines or empty fields
    data.lines()
        .filter(|line| !line.is_empty())
        .map(|line| {
            line.split(',')
                .map(|field| field.trim().to_string())
                .filter(|field| !field.is_empty())
                .collect()
        })
        .collect()
}

pub fn as_timestamp(st: SystemTime) -> u64 {
    st.duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub fn validate_authed_request(headers: &HeaderMap) -> Result<i64, String> {
    let auth_header = headers.get("authorization").ok_or("No auth header")?;
    // auth header uses the Bearer scheme
    let parts: Vec<&str> = auth_header
        .to_str()
        .map_err(|e| e.to_string())?
        .split(' ')
        .collect();
    if parts.len() != 2 || parts[0] != "Bearer" {
        return Err("Invalid auth header".to_string());
    }
    let token = parts[1];
    auth::validate_jwt(token)
}

pub fn find_account(db: &Connection, username: &str) -> Option<Account> {
    const QUERY: &str = "
        SELECT AccountID, Login, Password, Email
        FROM Accounts
        WHERE Login = ?
        LIMIT 1;
        ";
    let mut stmt = db.prepare(QUERY).unwrap();
    stmt.bind((1, username)).unwrap();
    if let Ok(sqlite::State::Row) = stmt.next() {
        Some(Account {
            id: stmt.read(0).unwrap(),
            login: stmt.read(1).unwrap(),
            password_hashed: stmt.read(2).unwrap(),
            email: stmt.read(3).unwrap(),
        })
    } else {
        None
    }
}

pub fn check_credentials(db: &Connection, username: &str, password: &str) -> Result<i64, String> {
    let account = find_account(db, username).ok_or("Account not found")?;
    match bcrypt::verify(password, &account.password_hashed) {
        Ok(true) => Ok(account.id),
        Ok(false) => Err("Invalid password".to_string()),
        Err(e) => Err(format!("bcrypt error: {}", e)),
    }
}
