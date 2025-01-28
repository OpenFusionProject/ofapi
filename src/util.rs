use std::{cmp::min, collections::HashMap};

use axum::{http::HeaderMap, response::Html};
use ring::rand::{SecureRandom as _, SystemRandom};

use crate::tokens::{self, TokenCapability};

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

pub fn validate_authed_request(
    secret: &[u8],
    headers: &HeaderMap,
    caps: Vec<TokenCapability>,
) -> Result<String, String> {
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
    tokens::validate_jwt(secret, token, caps)
}

pub fn gen_random_string<const N: usize>(rng: &SystemRandom) -> String {
    let mut code_bytes = [0u8; N];
    rng.fill(&mut code_bytes).unwrap();
    let mut code = String::new();
    for byte in code_bytes.iter() {
        code.push_str(&format!("{:02x}", byte));
    }
    code
}

pub fn mask_email(email: &str) -> String {
    let parts: Vec<&str> = email.split('@').collect();
    let revealed_len = min(3, parts[0].len());
    let masked = format!("{}******@{}", &parts[0][..revealed_len], parts[1]);
    masked
}

pub fn gen_content_from_template(
    template_dir: &str,
    template_file: &str,
    vars: &HashMap<String, String>,
) -> Result<String, String> {
    let template_path = format!("{}/{}", template_dir, template_file);
    let template = match std::fs::read_to_string(template_path) {
        Ok(content) => content,
        Err(e) => return Err(format!("Failed to read template file: {}", e)),
    };
    let mut content = template;
    for (key, value) in vars {
        content = content.replace(&format!("${}$", key), value);
    }
    Ok(content)
}

pub fn get_plain_page(title: &str, content: &str) -> Html<String> {
    let content = format!(
        r#"<!DOCTYPE html>
<html>
<head>
  <title>{}</title>
</head>
<body>
  <p>{}</p>
</body>
</html>
"#,
        title, content
    );
    Html(content)
}

pub fn get_error_page(title: &str, message: &str) -> Html<String> {
    let content = format!(
        r#"<!DOCTYPE html>
<html>
<head>
  <title>Error</title>
</head>
<body>
  <h1>{}</h1>
  <p>{}</p>
</body>
</html>
"#,
        title, message
    );
    Html(content)
}

fn split_addr_port(addr_port: &str) -> Option<(String, u16)> {
    const DEFAULT_PORT: u16 = 23000;
    let mut parts = addr_port.split(':');
    let addr = parts.next().ok_or("Missing address").ok()?.to_string();
    let port = if let Some(port) = parts.next() {
        port.parse::<u16>().ok()?
    } else {
        DEFAULT_PORT
    };
    Some((addr, port))
}

fn resolve_host(host: &str) -> Option<String> {
    let addrs = dns_lookup::lookup_host(host).ok()?;
    for addr in addrs {
        if let std::net::IpAddr::V4(addr) = addr {
            return Some(addr.to_string());
        }
    }
    None
}

pub fn resolve_server_addr(addr: &str) -> Option<String> {
    let (host, port) = split_addr_port(addr)?;
    let ip = resolve_host(&host)?;
    Some(format!("{}:{}", ip, port))
}
