use log::info;
use sqlite::{Connection, State};

pub fn version_to_string(version: usize) -> String {
    // ex: 3045003 -> "3.45.3"
    let major = version / 1000000;
    let minor = (version % 1000000) / 1000;
    let patch = version % 1000;
    format!("{}.{}.{}", major, minor, patch)
}

pub fn connect_to_db(path: &str) -> Connection {
    const QUERY: &str = "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='Meta';";

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

    info!("Connected to database");
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
