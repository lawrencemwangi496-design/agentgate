use anyhow::{bail, Context, Result};
use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use std::fs;
use std::path::Path;
use subtle::ConstantTimeEq;

type HmacSha1 = Hmac<Sha1>;

/// Standard RFC 6238 TOTP step interval (30 seconds).
pub const TOTP_STEP_SECONDS: u64 = 30;

/// Standard TOTP code length (6 digits).
pub const TOTP_DIGITS: u32 = 6;

/// Base32 alphabet according to RFC 4648.
const BASE32_ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// Stored TOTP authentication configuration on host.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TotpStoredConfig {
    pub secret: String,
    pub created_at: DateTime<Utc>,
}

/// Encode raw bytes to RFC 4648 Base32 string (uppercase, no padding).
#[must_use]
pub fn base32_encode(data: &[u8]) -> String {
    let mut result = String::with_capacity((data.len() * 8 + 4) / 5);
    let mut buffer: u64 = 0;
    let mut bits_in_buffer: u32 = 0;

    for &byte in data {
        buffer = (buffer << 8) | (byte as u64);
        bits_in_buffer += 8;

        while bits_in_buffer >= 5 {
            bits_in_buffer -= 5;
            let index = ((buffer >> bits_in_buffer) & 0x1F) as usize;
            result.push(BASE32_ALPHABET[index] as char);
        }
    }

    if bits_in_buffer > 0 {
        let index = ((buffer << (5 - bits_in_buffer)) & 0x1F) as usize;
        result.push(BASE32_ALPHABET[index] as char);
    }

    result
}

/// Decode RFC 4648 Base32 string back to raw bytes.
pub fn base32_decode(encoded: &str) -> Result<Vec<u8>> {
    let clean: String = encoded
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-' && *c != '=')
        .map(|c| c.to_ascii_uppercase())
        .collect();

    let mut result = Vec::with_capacity(clean.len() * 5 / 8);
    let mut buffer: u64 = 0;
    let mut bits_in_buffer: u32 = 0;

    for ch in clean.chars() {
        let val = match ch {
            'A'..='Z' => (ch as u8 - b'A') as u64,
            '2'..='7' => (ch as u8 - b'2' + 26) as u64,
            _ => bail!("Invalid character in Base32 string: '{}'", ch),
        };

        buffer = (buffer << 5) | val;
        bits_in_buffer += 5;

        if bits_in_buffer >= 8 {
            bits_in_buffer -= 8;
            result.push(((buffer >> bits_in_buffer) & 0xFF) as u8);
        }
    }

    Ok(result)
}

/// Generate a new 160-bit (20-byte) Base32-encoded secret for TOTP.
#[must_use]
pub fn generate_secret() -> String {
    let mut raw = [0u8; 20];
    rand::rng().fill_bytes(&mut raw);
    base32_encode(&raw)
}

/// Compute 6-digit TOTP code for a given timestamp and secret.
pub fn compute_totp(secret_bytes: &[u8], timestamp_secs: u64, step_secs: u64) -> Result<String> {
    if secret_bytes.is_empty() {
        bail!("Secret bytes cannot be empty");
    }

    let counter = timestamp_secs / step_secs;
    let counter_bytes = counter.to_be_bytes();

    let mut mac = HmacSha1::new_from_slice(secret_bytes)
        .context("HMAC-SHA1 initialization failed")?;
    mac.update(&counter_bytes);
    let result = mac.finalize().into_bytes();

    // Dynamic truncation (RFC 4226 section 5.4).
    let offset = (result[result.len() - 1] & 0x0F) as usize;
    if offset + 4 > result.len() {
        bail!("Invalid truncation offset calculated");
    }

    let code_int = ((result[offset] as u32 & 0x7F) << 24)
        | ((result[offset + 1] as u32 & 0xFF) << 16)
        | ((result[offset + 2] as u32 & 0xFF) << 8)
        | (result[offset + 3] as u32 & 0xFF);

    let pin = code_int % 1_000_000;
    Ok(format!("{:06}", pin))
}

/// Verify a candidate 6-digit code with skew tolerance (-1, 0, +1 time steps).
pub fn verify_totp(secret_b32: &str, candidate_code: &str, timestamp_secs: u64) -> Result<bool> {
    let clean_code = candidate_code.trim();
    if clean_code.len() != TOTP_DIGITS as usize || !clean_code.chars().all(|c| c.is_ascii_digit()) {
        return Ok(false);
    }

    let secret_bytes = base32_decode(secret_b32)?;

    // Check step -1, 0, +1 to absorb clock drift between phone and host.
    for skew in [-1i64, 0, 1] {
        let check_time = if skew < 0 {
            timestamp_secs.saturating_sub(TOTP_STEP_SECONDS)
        } else if skew > 0 {
            timestamp_secs.saturating_add(TOTP_STEP_SECONDS)
        } else {
            timestamp_secs
        };

        if let Ok(expected_code) = compute_totp(&secret_bytes, check_time, TOTP_STEP_SECONDS) {
            if expected_code.as_bytes().ct_eq(clean_code.as_bytes()).unwrap_u8() == 1 {
                return Ok(true);
            }
        }
    }

    Ok(false)
}

/// Build standard `otpauth://` URI for QR scanning in Authenticator apps.
#[must_use]
pub fn generate_otpauth_uri(secret_b32: &str, issuer: &str, account: &str) -> String {
    format!(
        "otpauth://totp/{}:{}?secret={}&issuer={}&algorithm=SHA1&digits=6&period=30",
        issuer, account, secret_b32, issuer
    )
}

/// Load the stored TOTP secret from file if it exists.
pub fn load_totp_secret(path: &Path) -> Result<Option<String>> {
    if !path.exists() {
        return Ok(None);
    }

    let content = fs::read_to_string(path)
        .with_context(|| format!("Failed to read TOTP secret from {:?}", path))?;

    let parsed: TotpStoredConfig = serde_yaml::from_str(&content)
        .with_context(|| "Failed to parse TOTP configuration")?;

    Ok(Some(parsed.secret))
}

/// Save a newly generated TOTP secret with safe file permissions (0600).
pub fn save_totp_secret(path: &Path, secret: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("Failed to create directory {:?}", parent))?;
    }

    let config = TotpStoredConfig {
        secret: secret.trim().to_uppercase(),
        created_at: Utc::now(),
    };

    let yaml = serde_yaml::to_string(&config)?;
    fs::write(path, yaml)
        .with_context(|| format!("Failed to write TOTP secret to {:?}", path))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(path)?.permissions();
        perms.set_mode(0o600);
        let _ = fs::set_permissions(path, perms);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base32_roundtrip() {
        let original = b"Hello, AgentGate TOTP!";
        let encoded = base32_encode(original);
        let decoded = base32_decode(&encoded).expect("Decode should succeed");
        assert_eq!(decoded, original);
    }

    #[test]
    fn test_rfc6238_sha1_vectors() {
        // RFC 6238 Section 5.3 test vector key: "12345678901234567890" (20 bytes)
        let key = b"12345678901234567890";

        // Time = 59 sec (T = 1) -> 287082
        let code1 = compute_totp(key, 59, 30).unwrap();
        assert_eq!(code1, "287082");

        // Time = 1111111109 sec (T = 37037036) -> 081804
        let code2 = compute_totp(key, 1111111109, 30).unwrap();
        assert_eq!(code2, "081804");

        // Time = 1111111111 sec (T = 37037037) -> 050471
        let code3 = compute_totp(key, 1111111111, 30).unwrap();
        assert_eq!(code3, "050471");
    }

    #[test]
    fn test_verify_totp_with_drift() {
        let secret = generate_secret();
        let secret_bytes = base32_decode(&secret).unwrap();
        let now = 1700000000u64;

        let current_code = compute_totp(&secret_bytes, now, 30).unwrap();
        assert!(verify_totp(&secret, &current_code, now).unwrap());

        // Previous window (skew -1)
        assert!(verify_totp(&secret, &current_code, now + 25).unwrap());

        // Invalid code should fail
        assert!(!verify_totp(&secret, "999999", now).unwrap());
    }

    #[test]
    fn test_generate_otpauth_uri() {
        let secret = "JBSWY3DPEHPK3PXP";
        let uri = generate_otpauth_uri(secret, "AgentGate", "admin");
        assert!(uri.starts_with("otpauth://totp/AgentGate:admin?"));
        assert!(uri.contains("secret=JBSWY3DPEHPK3PXP"));
    }
}
