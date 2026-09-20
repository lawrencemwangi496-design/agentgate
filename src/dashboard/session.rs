use anyhow::{bail, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::{DateTime, TimeDelta, Utc};
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::Sha256;
use subtle::ConstantTimeEq;

type HmacSha256 = Hmac<Sha256>;

const SESSION_PREFIX: &str = "dash_";
const SESSION_DEFAULT_EXPIRY_HOURS: u64 = 24;

#[derive(Debug, Clone)]
pub struct SessionManager {
    signing_key: [u8; 32],
}

#[derive(Debug)]
pub struct SessionClaims {
    pub email: String,
    pub expires_at: DateTime<Utc>,
}

impl Default for SessionManager {
    fn default() -> Self {
        Self::new()
    }
}

impl SessionManager {
    #[must_use]
    pub fn new() -> Self {
        let mut key = [0u8; 32];
        rand::rng().fill_bytes(&mut key);
        Self { signing_key: key }
    }

    #[must_use]
    pub fn create_token(&self, email: &str, expiry_hours: u64) -> String {
        let effective_hours = if expiry_hours == 0 {
            SESSION_DEFAULT_EXPIRY_HOURS
        } else {
            expiry_hours
        };
        // Expiry time.
        let expires_at = Utc::now() + TimeDelta::try_hours(effective_hours as i64).unwrap_or_default();
        let expiry_unix = expires_at.timestamp();

        let payload = format!("{}|{}", email, expiry_unix);
        
        let mut mac = HmacSha256::new_from_slice(&self.signing_key).expect("HMAC can take key of any size");
        mac.update(payload.as_bytes());
        let signature = mac.finalize().into_bytes();
        
        let token_data = format!("{}|{}|{}", email, expiry_unix, hex::encode(signature));
        let b64 = URL_SAFE_NO_PAD.encode(token_data.as_bytes());
        
        format!("{}{}", SESSION_PREFIX, b64)
    }

    pub fn validate_token(&self, token: &str) -> Result<SessionClaims> {
        if !token.starts_with(SESSION_PREFIX) {
            bail!("Invalid token prefix");
        }
        let b64 = &token[SESSION_PREFIX.len()..];
        
        let token_data_bytes = URL_SAFE_NO_PAD.decode(b64)?;
        let token_data = String::from_utf8(token_data_bytes)?;
        
        let parts: Vec<&str> = token_data.split('|').collect();
        if parts.len() != 3 {
            bail!("Invalid token format");
        }
        
        let email = parts[0];
        let expiry_str = parts[1];
        let sig_hex = parts[2];
        
        let expiry_unix: i64 = expiry_str.parse()?;
        let expires_at = DateTime::from_timestamp(expiry_unix, 0).ok_or_else(|| anyhow::anyhow!("Invalid timestamp"))?;
        
        if Utc::now() > expires_at {
            bail!("Token expired");
        }
        
        let expected_payload = format!("{}|{}", email, expiry_str);
        let mut mac = HmacSha256::new_from_slice(&self.signing_key).expect("HMAC can take key of any size");
        mac.update(expected_payload.as_bytes());
        let expected_signature = mac.finalize().into_bytes();
        
        let provided_signature = hex::decode(sig_hex)?;
        
        if expected_signature.as_slice().ct_eq(&provided_signature).unwrap_u8() != 1 {
            bail!("Invalid signature");
        }
        
        Ok(SessionClaims {
            email: email.to_string(),
            expires_at,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_create_and_validate_success() {
        let manager = SessionManager::new();
        let token = manager.create_token("admin@domain.com", 24);
        assert!(token.starts_with(SESSION_PREFIX));

        let claims = manager.validate_token(&token).expect("Valid token should parse");
        assert_eq!(claims.email, "admin@domain.com");
        assert!(claims.expires_at > Utc::now());
    }

    #[test]
    fn test_session_tampered_token_fails() {
        let manager = SessionManager::new();
        let token = manager.create_token("admin@domain.com", 24);

        // Tamper with one character
        let mut chars: Vec<char> = token.chars().collect();
        let last_idx = chars.len() - 1;
        chars[last_idx] = if chars[last_idx] == 'a' { 'b' } else { 'a' };
        let tampered: String = chars.into_iter().collect();

        assert!(manager.validate_token(&tampered).is_err());
    }

    #[test]
    fn test_session_different_keys_fail() {
        let manager1 = SessionManager::new();
        let manager2 = SessionManager::new();

        let token = manager1.create_token("admin@domain.com", 24);
        assert!(manager2.validate_token(&token).is_err(), "Token from another daemon instance must fail");
    }
}
