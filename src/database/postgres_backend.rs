use std::time::Duration;

use deadpool_postgres::{Client, Manager, ManagerConfig, Pool, RecyclingMethod};
use jsonwebtoken::get_current_timestamp;
use log::*;
use tokio_postgres::{tls, Row};

use crate::{
    database::{Account, MIN_DATABASE_VERSION},
    moderation::NameCheckStatus,
    rankinfo::Rank,
};

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

    info!("Connected to database (version {})", version);
    pool
}

pub(crate) async fn find_account(db: &Client, account_id: i64) -> Option<Account> {
    const QUERY: &str = "
        SELECT AccountID, Login, Password, Email
        FROM Accounts
        WHERE AccountID = $1
        LIMIT 1;
        ";
    let stmt = db.prepare_cached(QUERY).await.unwrap();
    if let Ok(row) = db.query_one(&stmt, &[&account_id]).await {
        Some(Account {
            id: row.get(0),
            login: row.get(1),
            password_hashed: row.get(2),
            email: row.get(3),
        })
    } else {
        None
    }
}

pub(crate) async fn find_account_by_username(db: &Client, username: &str) -> Option<Account> {
    const QUERY: &str = "
        SELECT AccountID, Login, Password, Email
        FROM Accounts
        WHERE Login = $1
        LIMIT 1;
        ";
    let stmt = db.prepare_cached(QUERY).await.unwrap();
    if let Ok(row) = db.query_one(&stmt, &[&username]).await {
        Some(Account {
            id: row.get(0),
            login: row.get(1),
            password_hashed: row.get(2),
            email: row.get(3),
        })
    } else {
        None
    }
}

pub(crate) async fn find_account_by_email(db: &Client, email: &str) -> Option<Account> {
    const QUERY: &str = "
        SELECT AccountID, Login, Password, Email
        FROM Accounts
        WHERE Email = $1
        LIMIT 1;
        ";
    let stmt = db.prepare_cached(QUERY).await.unwrap();
    if let Ok(row) = db.query_one(&stmt, &[&email]).await {
        Some(Account {
            id: row.get(0),
            login: row.get(1),
            password_hashed: row.get(2),
            email: row.get(3),
        })
    } else {
        None
    }
}

pub(crate) async fn create_account(
    db: &Client,
    username: &str,
    password_hashed: &str,
    account_level: u8,
    email: Option<&str>,
) -> Result<(), String> {
    const QUERY: &str = "
        INSERT INTO Accounts (Login, Password, AccountLevel, Email)
        VALUES ($1, $2, $3, $4);
        ";

    let stmt = db.prepare_cached(QUERY).await.unwrap();
    let email = email.unwrap_or("");
    if let Err(e) = db
        .execute(
            &stmt,
            &[&username, &password_hashed, &(account_level as i32), &email],
        )
        .await
    {
        return Err(format!("Failed to create account: {}", e));
    }
    Ok(())
}

pub(crate) async fn update_password_for_account(
    db: &Client,
    username: &str,
    password_hashed: &str,
) -> Result<(), String> {
    const QUERY: &str = "
        UPDATE Accounts
        SET
            Password = $1,
            LastPasswordReset = $2
        WHERE Login = $3;
        ";

    let stmt = db.prepare_cached(QUERY).await.unwrap();
    if let Err(e) = db
        .execute(
            &stmt,
            &[
                &password_hashed,
                &(get_current_timestamp() as i32),
                &username,
            ],
        )
        .await
    {
        return Err(format!("Failed to update password: {}", e));
    }
    Ok(())
}

pub(crate) async fn update_email_for_account(
    db: &Client,
    username: &str,
    email: &str,
) -> Result<(), String> {
    const QUERY: &str = "
        UPDATE Accounts
        SET Email = $1
        WHERE Login = $2;
        ";

    let stmt = db.prepare_cached(QUERY).await.unwrap();
    if let Err(e) = db.execute(&stmt, &[&email, &username]).await {
        return Err(format!("Failed to update email: {}", e));
    }
    Ok(())
}

pub(crate) async fn get_outstanding_namereqs(db: &Client) -> Vec<(i64, String)> {
    const QUERY: &str = "
        SELECT PlayerID, FirstName, LastName
        FROM Players
        WHERE NameCheck = 0;
        ";
    let stmt = db.prepare_cached(QUERY).await.unwrap();
    let mut results = Vec::new();
    let mut rows = db.query(&stmt, &[]).await.unwrap();
    while let Some(row) = rows.pop() {
        let player_id: i64 = row.get(0);
        let first_name: String = row.get(1);
        let last_name: String = row.get(2);
        results.push((player_id, format!("{} {}", first_name, last_name)));
    }
    results
}

pub(crate) async fn get_namecheck_for_player(db: &Client, player_uid: i64) -> Result<i64, String> {
    const QUERY: &str = "
        SELECT NameCheck
        FROM Players
        WHERE PlayerID = $1;
        ";
    let stmt = db.prepare_cached(QUERY).await.unwrap();
    if let Ok(row) = db.query_one(&stmt, &[&player_uid]).await {
        Ok(row.get(0))
    } else {
        Err("Player not found".to_string())
    }
}

pub(crate) async fn set_namecheck_for_player(
    db: &Client,
    player_uid: i64,
    name_check_status: NameCheckStatus,
) -> Result<(), String> {
    const QUERY: &str = "
        UPDATE Players
        SET NameCheck = $1
        WHERE PlayerID = $2;
        ";
    let stmt = db.prepare_cached(QUERY).await.unwrap();
    let name_check_flag = match name_check_status {
        NameCheckStatus::Pending => 0,
        NameCheckStatus::Approved => 1,
        NameCheckStatus::Denied => 2,
    };
    if let Err(e) = db.execute(&stmt, &[&name_check_flag, &player_uid]).await {
        return Err(e.to_string());
    }
    Ok(())
}

pub(crate) async fn get_last_password_reset(db: &Client, account_id: i64) -> Option<u64> {
    const QUERY: &str = "
        SELECT LastPasswordReset
        FROM Accounts
        WHERE AccountID = $1;
        ";
    let stmt = db.prepare_cached(QUERY).await.unwrap();
    let row = db.query_one(&stmt, &[&account_id]).await.ok()?;
    let ts: i32 = row.get(0);
    if ts == 0 {
        None
    } else {
        Some(ts as u64)
    }
}

pub(crate) async fn fetch_ranks(
    db: &Client,
    epid: i64,
    date: &str,
    num: usize,
    fill: bool,
) -> Vec<Rank> {
    const QUERY: &str = "
        SELECT
            PBRaceResults.PlayerID,
            Players.FirstName,
            Players.LastName,
            PBRaceResults.Score
        FROM (
            SELECT
                ROW_NUMBER() OVER (
                    PARTITION BY RaceResults.PlayerID
                    ORDER BY
                        RaceResults.Score DESC,
                        RaceResults.RingCount DESC,
                        RaceResults.Time ASC
                ) AS PersonalOrder,
                RaceResults.*
            FROM RaceResults
            WHERE EPID=$1 AND Timestamp > EXTRACT(EPOCH FROM (NOW() + $2::INTERVAL))
        ) AS PBRaceResults
        INNER JOIN Players ON PBRaceResults.PlayerID=Players.PlayerID AND PBRaceResults.PersonalOrder=1
        ORDER BY
            PBRaceResults.Score DESC,
            PBRaceResults.RingCount DESC,
            PBRaceResults.Time ASC;
    ";

    let stmt = db.prepare_cached(QUERY).await.unwrap();
    let rows = db
        .query(&stmt, &[&epid, &format!("{} seconds", date)])
        .await
        .unwrap();
    db_parse_ranks(rows, num, fill)
}

pub(crate) async fn fetch_my_ranks(db: &Client, pcuid: i64, epid: i64, date: &str) -> Vec<Rank> {
    const QUERY: &str = "
        SELECT
            RaceResults.PlayerID,
            Players.FirstName,
            Players.LastName,
            RaceResults.Score
        FROM RaceResults
        INNER JOIN Players ON RaceResults.PlayerID=Players.PlayerID
        WHERE RaceResults.PlayerID=$1 AND EPID=$2 AND Timestamp > EXTRACT(EPOCH FROM (NOW() + $3::INTERVAL))
        ORDER BY RaceResults.Score DESC
        LIMIT 1;
    ";
    let stmt = db.prepare_cached(QUERY).await.unwrap();
    let rows = db.query(&stmt, &[&pcuid, &epid, &date]).await.unwrap();
    db_parse_ranks(rows, 1, false)
}

pub(crate) async fn set_cookie(
    db: &Client,
    account_id: i64,
    cookie: &str,
    valid_secs: u64,
) -> Result<u64, String> {
    const QUERY: &str = "
        INSERT INTO Auth (AccountID, Cookie, Expires) VALUES ($1, $2, $3)
        ON CONFLICT (AccountID) DO UPDATE SET Cookie = EXCLUDED.Cookie, Expires = EXCLUDED.Expires;
    ";

    let expires_timestamp = get_current_timestamp() + valid_secs;

    let stmt = db.prepare_cached(QUERY).await.unwrap();
    if let Err(e) = db
        .execute(&stmt, &[&account_id, &cookie, &(expires_timestamp as i32)])
        .await
    {
        return Err(format!("Failed to set cookie: {}", e));
    }
    Ok(expires_timestamp)
}

fn db_parse_ranks(rows: Vec<Row>, num: usize, fill: bool) -> Vec<Rank> {
    let mut ranks = Vec::with_capacity(num);
    for row in rows {
        if ranks.len() >= num {
            break;
        }
        let pcuid: i64 = row.get("PlayerID");
        let first_name: String = row.get("FirstName");
        let last_name: String = row.get("LastName");
        let score: i32 = row.get("Score");
        ranks.push(Rank {
            pcuid,
            score: score as i64,
            first_name,
            last_name,
        });
    }

    if fill {
        while ranks.len() < num {
            ranks.push(Rank::new_placeholder());
        }
    }
    ranks
}
