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

use crate::{database, util, AppState};

#[derive(Deserialize, Clone)]
pub(crate) struct RankInfoConfig {
    route: String,
    placeholders: bool,
}

pub(crate) fn register(
    routes: Router<Arc<AppState>>,
    config: &RankInfoConfig,
) -> Router<Arc<AppState>> {
    let route = &config.route;
    info!("Registering rankinfo route @ {}", route);
    routes.route(route, post(get_ranks))
}

#[derive(Debug)]
pub(crate) struct Rank {
    pub(crate) pcuid: i64,
    pub(crate) score: i64,
    pub(crate) first_name: String,
    pub(crate) last_name: String,
}
impl Rank {
    pub(crate) fn new_placeholder() -> Self {
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
        let my_ranks = database::fetch_my_ranks(&db, req.pcuid, req.epid, date);
        let xml_my_scores = ranks_to_xml_scores(my_ranks);
        let xml_my_scores_str = xml_my_scores.join("\n");
        let xml_my = util::wrap_xml(&format!("my{}", name), &xml_my_scores_str, true);
        body.push_str(&xml_my);

        // all ranks
        let fill = state.config.rankinfo.as_ref().unwrap().placeholders;
        let ranks =
            database::fetch_ranks(&db, req.epid, date, req.num.unwrap_or(DEFAULT_NUM), fill);
        let xml_scores = ranks_to_xml_scores(ranks);
        let xml_scores_str = xml_scores.join("\n");
        let xml = util::wrap_xml(name, &xml_scores_str, true);
        body.push_str(&xml);
    }

    let resp = format!("{}{}", RESPONSE_PREFIX, body);
    (headers, resp)
}
