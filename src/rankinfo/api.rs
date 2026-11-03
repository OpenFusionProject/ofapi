use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct RankInfoRequest {
    #[serde(rename = "PCUID")]
    pub pcuid: i64,
    #[serde(rename = "EP_ID")]
    pub epid: i64,
    #[serde(rename = "NUM")]
    pub num: Option<usize>,
}
