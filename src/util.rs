use axum::http::HeaderMap;

use crate::auth::{self, TokenKind};

pub fn version_to_string(version: usize) -> String {
    // ex: 3045003 -> "3.45.3"
    let major = version / 1000000;
    let minor = (version % 1000000) / 1000;
    let patch = version % 1000;
    format!("{}.{}.{}", major, minor, patch)
}

pub fn get_subroute(route: &str, subroute: &str) -> String {
    let route_noslash = route.trim_end_matches('/');
    let subroute_noslash = subroute.trim_start_matches('/');
    format!("{}/{}", route_noslash, subroute_noslash)
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

pub fn validate_authed_request(headers: &HeaderMap, kind: TokenKind) -> Result<i64, String> {
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
    auth::validate_jwt(token, kind)
}
