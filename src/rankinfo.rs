use std::sync::Arc;

use axum::{
    extract::State,
    http::HeaderMap,
    response::IntoResponse,
    routing::{post, Router},
    Form,
};
use log::{debug, info};
use serde::Deserialize;
use sqlite::Connection;

use crate::{util, AppState};

#[derive(Deserialize, Clone)]
pub struct RankInfoConfig {
    route: String,
    placeholders: bool,
}

pub fn register(routes: Router<Arc<AppState>>, config: &RankInfoConfig) -> Router<Arc<AppState>> {
    let route = &config.route;
    info!("Registering rankinfo route @ {}", route);
    routes.route(route, post(get_ranks))
}

#[derive(Debug)]
struct Rank {
    pcuid: i64,
    score: i64,
    first_name: String,
    last_name: String,
}
impl Rank {
    fn new_placeholder() -> Self {
        Self {
            pcuid: 999,
            score: 1,
            first_name: "hehe".to_string(),
            last_name: "dong".to_string(),
        }
    }
}

#[derive(Deserialize, Debug)]
struct RankInfoRequest {
    #[serde(rename = "PCUID")]
    pcuid: i64,
    #[serde(rename = "EP_ID")]
    epid: i64,
    #[serde(rename = "NUM")]
    num: Option<usize>,
}

fn db_parse_ranks(mut stmt: sqlite::Statement, num: usize, fill: bool) -> Vec<Rank> {
    let mut ranks = Vec::with_capacity(num);
    while let Ok(sqlite::State::Row) = stmt.next() {
        if ranks.len() >= num {
            break;
        }
        let pcuid = stmt.read::<i64, _>("PlayerID").unwrap();
        let first_name = stmt.read::<String, _>("FirstName").unwrap();
        let last_name = stmt.read::<String, _>("LastName").unwrap();
        let score = stmt.read::<i64, _>("Score").unwrap();
        ranks.push(Rank {
            pcuid,
            score,
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

fn ranks_to_xml_scores(mut ranks: Vec<Rank>) -> Vec<String> {
    ranks.sort_by(|a, b| {
        b.score
            .partial_cmp(&a.score)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    let mut rank = 1;
    let mut last_score = -1;
    let mut xml_scores = Vec::new();
    for r in ranks.iter() {
        if r.score == last_score {
            rank -= 1;
        }
        xml_scores.push(format!(
            "\t<score>PCUID=\"{}\" Score=\"{}\" Rank=\"{}\" FirstName=\"{}\" LastName=\"{}\"</score>",
            r.pcuid, r.score, rank, r.first_name, r.last_name
        ));
        last_score = r.score;
        rank += 1;
    }
    xml_scores
}

fn fetch_ranks(epid: i64, date: &str, num: usize, fill: bool, db: &Connection) -> Vec<Rank> {
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
            WHERE EPID=? AND DATETIME(Timestamp, 'unixepoch') > DATETIME('now', ?)
        ) AS PBRaceResults
        INNER JOIN Players ON PBRaceResults.PlayerID=Players.PlayerID AND PBRaceResults.PersonalOrder=1
        ORDER BY
            PBRaceResults.Score DESC,
            PBRaceResults.RingCount DESC,
            PBRaceResults.Time ASC;
    ";

    let mut stmt = db.prepare(QUERY).unwrap();
    stmt.bind((1, epid)).unwrap();
    stmt.bind((2, date)).unwrap();
    db_parse_ranks(stmt, num, fill)
}

fn fetch_my_ranks(pcuid: i64, epid: i64, date: &str, db: &Connection) -> Vec<Rank> {
    const QUERY: &str = "
        SELECT
            RaceResults.PlayerID,
            Players.FirstName,
            Players.LastName,
            RaceResults.Score
        FROM RaceResults
        INNER JOIN Players ON RaceResults.PlayerID=Players.PlayerID
        WHERE RaceResults.PlayerID=? AND EPID=? AND DATETIME(Timestamp, 'unixepoch') > DATETIME('now', ?)
        ORDER BY RaceResults.Score DESC
        LIMIT 1;
    ";
    let mut stmt = db.prepare(QUERY).unwrap();
    stmt.bind((1, pcuid)).unwrap();
    stmt.bind((2, epid)).unwrap();
    stmt.bind((3, date)).unwrap();
    db_parse_ranks(stmt, 1, false)
}

async fn get_ranks(
    State(state): State<Arc<AppState>>,
    Form(req): Form<RankInfoRequest>,
) -> impl IntoResponse {
    const RESPONSE_PREFIX: &str = "SUCCESS";
    const DATE_RANGES: [(&str, &str); 4] = [
        ("day", "-1 day"),
        ("week", "-7 day"),
        ("month", "-1 month"),
        ("alltime", "-999 year"),
    ];
    const DEFAULT_NUM: usize = 10;

    debug!("Rank info request: {:?}", req);
    let db = state.db.lock().await;

    let mut headers = HeaderMap::new();
    headers.insert("Content-Type", "text/html; charset=utf-8".parse().unwrap());

    let mut body = String::new();
    for (name, date) in DATE_RANGES.iter() {
        // my ranks
        let my_ranks = fetch_my_ranks(req.pcuid, req.epid, date, &db);
        let xml_my_scores = ranks_to_xml_scores(my_ranks);
        let xml_my_scores_str = xml_my_scores.join("\n");
        let xml_my = util::wrap_xml(&format!("my{}", name), &xml_my_scores_str, true);
        body.push_str(&xml_my);

        // all ranks
        let fill = state.config.rankinfo.as_ref().unwrap().placeholders;
        let ranks = fetch_ranks(req.epid, date, req.num.unwrap_or(DEFAULT_NUM), fill, &db);
        let xml_scores = ranks_to_xml_scores(ranks);
        let xml_scores_str = xml_scores.join("\n");
        let xml = util::wrap_xml(name, &xml_scores_str, true);
        body.push_str(&xml);
    }

    let resp = format!("{}{}", RESPONSE_PREFIX, body);
    (headers, resp)
}
