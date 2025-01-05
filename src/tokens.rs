use jsonwebtoken::*;
use serde::{Deserialize, Serialize};

#[derive(Debug, PartialEq, Eq)]
pub enum TokenLifetime {
    Temporary(u64), // for e.g. user logins, duration in secs
    Permanent,      // for e.g. API keys (use with caution)
}

#[repr(u64)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenCapability {
    // lower privileges
    Refresh = (1 << 0),
    ManageOwnAccount = (1 << 1),
    GetCookie = (1 << 2),
    // higher privileges (dangerous)
    ApproveNames = (1 << 20),
    // highest privileges (very dangerous)
    ManageAllAccounts = (1 << 40),
}

pub struct TokenCapabilities {
    capabilities: u64,
}
impl TokenCapabilities {
    pub fn new() -> Self {
        Self { capabilities: 0 }
    }

    pub fn load(capabilities: u64) -> Self {
        Self { capabilities }
    }

    pub fn with(self, capability: TokenCapability) -> Self {
        Self {
            capabilities: self.capabilities | (1 << capability as u64),
        }
    }

    pub fn check(&self, capability: TokenCapability) -> bool {
        (self.capabilities & (1 << capability as u64)) != 0
    }

    pub fn from_vec(capabilities: Vec<TokenCapability>) -> Self {
        let mut caps = Self::new();
        for cap in capabilities {
            caps = caps.with(cap);
        }
        caps
    }
}
impl Default for TokenCapabilities {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Deserialize, Serialize)]
pub struct Claims {
    sub: String, // account id as a string
    crt: u64,    // creation timestamp in UTC
    exp: u64,    // expiration timestamp in UTC
    caps: u64,   // token capabilities
}

pub fn gen_jwt(
    secret: &[u8],
    subject: String,
    caps: TokenCapabilities,
    lifetime: TokenLifetime,
) -> Result<String, String> {
    let key = EncodingKey::from_secret(secret);

    let crt = get_current_timestamp();
    let exp = match lifetime {
        TokenLifetime::Permanent => u64::MAX,
        TokenLifetime::Temporary(duration_secs) => crt + duration_secs,
    };

    let claims = Claims {
        sub: subject,
        crt,
        exp,
        caps: caps.capabilities,
    };

    jsonwebtoken::encode(&Header::default(), &claims, &key).map_err(|e| format!("JWT error: {}", e))
}

fn get_validator(account_id: Option<i64>) -> Validation {
    let mut validation = Validation::default();
    // required claims
    validation.required_spec_claims.insert("sub".to_string());
    validation.required_spec_claims.insert("exp".to_string());
    // ensure account ID matches if passed in
    validation.sub = account_id.map(|id| id.to_string());
    validation
}

pub fn validate_jwt(key: &[u8], jwt: &str, caps: Vec<TokenCapability>) -> Result<i64, String> {
    let key = DecodingKey::from_secret(key);
    let validation = get_validator(None);
    let Ok(token) = jsonwebtoken::decode::<Claims>(jwt, &key, &validation) else {
        return Err("Bad JWT".to_string());
    };

    // I don't 100% trust this crate to validate the expiration timestamp, so do it manually
    let now = get_current_timestamp();
    if token.claims.exp < now {
        return Err("Expired JWT".to_string());
    }

    let token_caps = TokenCapabilities::load(token.claims.caps);
    for cap in &caps {
        if !token_caps.check(*cap) {
            return Err(format!("Missing capability: {:?}", cap));
        }
    }

    match token.claims.sub.parse() {
        Ok(id) => Ok(id),
        Err(e) => Err(format!("Bad account ID: {}", e)),
    }
}
