use log::*;
use sqlite::{Connection, State};

use crate::moderation::NameCheckStatus;

const MIN_DATABASE_VERSION: i64 = 6;

#[allow(dead_code)]
#[derive(Debug)]
pub(crate) struct Account {
    pub(crate) id: i64,
    pub(crate) login: String,
    pub(crate) password_hashed: String,
    pub(crate) email: String,
}

pub(crate) fn connect_to_db(path: &str) -> Connection {
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

pub(crate) fn find_account(db: &Connection, account_id: i64) -> Option<Account> {
    const QUERY: &str = "
        SELECT AccountID, Login, Password, Email
        FROM Accounts
        WHERE AccountID = ?
        LIMIT 1;
        ";
    let mut stmt = db.prepare(QUERY).unwrap();
    stmt.bind((1, account_id)).unwrap();
    if let Ok(State::Row) = stmt.next() {
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

pub(crate) fn find_account_by_username(db: &Connection, username: &str) -> Option<Account> {
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

pub(crate) fn find_account_by_email(db: &Connection, email: &str) -> Option<Account> {
    const QUERY: &str = "
        SELECT AccountID, Login, Password, Email
        FROM Accounts
        WHERE Email = ?
        LIMIT 1;
        ";
    let mut stmt = db.prepare(QUERY).unwrap();
    stmt.bind((1, email)).unwrap();
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

pub(crate) fn create_account(
    db: &Connection,
    username: &str,
    password_hashed: &str,
    account_level: u8,
    email: Option<&str>,
) -> Result<i64, String> {
    const QUERY: &str = "
        INSERT INTO Accounts (Login, Password, AccountLevel, Email)
        VALUES (?, ?, ?, ?);
        ";

    let mut stmt = db.prepare(QUERY).unwrap();
    let email = email.unwrap_or("");
    stmt.bind((1, username)).unwrap();
    stmt.bind((2, password_hashed)).unwrap();
    stmt.bind((3, account_level as i64)).unwrap();
    stmt.bind((4, email)).unwrap();
    if let Err(e) = stmt.next() {
        return Err(format!("Failed to create account: {}", e));
    }

    let account = find_account_by_username(db, username).unwrap();
    info!("New account: {}", username);
    Ok(account.id)
}

pub(crate) fn update_password_for_account(
    db: &Connection,
    username: &str,
    password_hashed: &str,
) -> Result<(), String> {
    const QUERY: &str = "
        UPDATE Accounts
        SET Password = ?
        WHERE Login = ?;
        ";

    let mut stmt = db.prepare(QUERY).unwrap();
    stmt.bind((1, password_hashed)).unwrap();
    stmt.bind((2, username)).unwrap();
    if let Err(e) = stmt.next() {
        return Err(format!("Failed to update password: {}", e));
    }

    info!("Updated password for account: {}", username);
    Ok(())
}

pub(crate) fn update_email_for_account(
    db: &Connection,
    username: &str,
    email: &str,
) -> Result<(), String> {
    const QUERY: &str = "
        UPDATE Accounts
        SET Email = ?
        WHERE Login = ?;
        ";

    let mut stmt = db.prepare(QUERY).unwrap();
    stmt.bind((1, email)).unwrap();
    stmt.bind((2, username)).unwrap();
    if let Err(e) = stmt.next() {
        return Err(format!("Failed to update email: {}", e));
    }

    info!("Updated email for account: {}", username);
    Ok(())
}

pub(crate) fn check_credentials(
    db: &Connection,
    username: &str,
    password: &str,
) -> Result<i64, String> {
    let account = find_account_by_username(db, username).ok_or("Account not found")?;
    match bcrypt::verify(password, &account.password_hashed) {
        Ok(true) => Ok(account.id),
        Ok(false) => Err("Invalid password".to_string()),
        Err(e) => Err(format!("bcrypt error: {}", e)),
    }
}

pub(crate) fn check_password(
    db: &Connection,
    account_id: i64,
    password: &str,
) -> Result<String, String> {
    const QUERY: &str = "
        SELECT Login, Password
        FROM Accounts
        WHERE AccountID = ?
        LIMIT 1;
        ";
    let mut stmt = db.prepare(QUERY).unwrap();
    stmt.bind((1, account_id)).unwrap();
    if let Ok(State::Row) = stmt.next() {
        let username: String = stmt.read(0).unwrap();
        let password_hashed: String = stmt.read(1).unwrap();
        match bcrypt::verify(password, &password_hashed) {
            Ok(true) => Ok(username),
            Ok(false) => Err("Invalid password".to_string()),
            Err(e) => Err(format!("bcrypt error: {}", e)),
        }
    } else {
        Err("Account not found".to_string())
    }
}

pub(crate) fn get_outstanding_namereqs(db: &Connection) -> Vec<(i64, String)> {
    const QUERY: &str = "
        SELECT PlayerID, FirstName, LastName
        FROM Players
        WHERE NameCheck = 0;
        ";
    let mut stmt = db.prepare(QUERY).unwrap();
    let mut results = Vec::new();
    while let Ok(State::Row) = stmt.next() {
        let player_id: i64 = stmt.read(0).unwrap();
        let first_name: String = stmt.read(1).unwrap();
        let last_name: String = stmt.read(2).unwrap();
        results.push((player_id, format!("{} {}", first_name, last_name)));
    }
    results
}

pub(crate) fn get_namecheck_for_player(db: &Connection, player_uid: i64) -> Result<i64, String> {
    const QUERY: &str = "
        SELECT NameCheck
        FROM Players
        WHERE PlayerID = ?;
        ";
    let mut stmt = db.prepare(QUERY).unwrap();
    stmt.bind((1, player_uid)).unwrap();
    if let Ok(State::Row) = stmt.next() {
        Ok(stmt.read(0).unwrap())
    } else {
        Err("Player not found".to_string())
    }
}

pub(crate) fn set_namecheck_for_player(
    db: &Connection,
    player_uid: i64,
    name_check_status: NameCheckStatus,
) -> Result<(), String> {
    const QUERY: &str = "
        UPDATE Players
        SET NameCheck = ?
        WHERE PlayerID = ?;
        ";
    let mut stmt = db.prepare(QUERY).unwrap();
    let name_check_flag = match name_check_status {
        NameCheckStatus::Pending => 0,
        NameCheckStatus::Approved => 1,
        NameCheckStatus::Denied => 2,
    };
    stmt.bind((1, name_check_flag)).unwrap();
    stmt.bind((2, player_uid)).unwrap();
    if let Err(e) = stmt.next() {
        return Err(e.to_string());
    }
    Ok(())
}
