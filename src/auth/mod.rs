use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::PathBuf;
use rand::Rng;

use subtle::ConstantTimeEq;

/// Stored token entry (token hash, never the raw token)
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct StoredToken {
    pub name: String,
    pub hash: String,              // SHA-256 hex of the raw token
    pub policy: String,            // name of the policy this token uses
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub last_used_at: Option<DateTime<Utc>>,
}

/// The token store
pub struct TokenStore {
    tokens: Vec<StoredToken>,
    path: PathBuf,  // path to tokens.yaml
}

impl TokenStore {
    /// Load from tokens.yaml file
    pub fn load(path: &PathBuf) -> Result<Self> {
        if !path.exists() {
            return Ok(Self {
                tokens: Vec::new(),
                path: path.clone(),
            });
        }

        let content = fs::read_to_string(path)
            .with_context(|| format!("Failed to read token store file at {:?}", path))?;
        
        let tokens: Vec<StoredToken> = serde_yaml::from_str(&content)
            .with_context(|| "Failed to parse token store YAML")?;

        Ok(Self {
            tokens,
            path: path.clone(),
        })
    }
    
    /// Save to tokens.yaml file atomically using a temporary file and rename
    pub fn save(&self) -> Result<()> {
        let content = serde_yaml::to_string(&self.tokens)
            .with_context(|| "Failed to serialize token store")?;
            
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("Failed to create directory {:?}", parent))?;
        }

        let temp_path = self.path.with_extension("tmp");
        fs::write(&temp_path, &content)
            .with_context(|| format!("Failed to write temporary token store to {:?}", temp_path))?;
        fs::rename(&temp_path, &self.path)
            .with_context(|| format!("Failed to atomically replace token store at {:?}", self.path))?;
            
        Ok(())
    }
    
    /// Create a new token. Returns the raw token string (shown once to user).
    /// Stores only the SHA-256 hash.
    pub fn create(&mut self, name: &str, policy: &str, expires_in: Option<chrono::Duration>) -> Result<String> {
        // Check if token with the same name already exists
        if self.tokens.iter().any(|t| t.name == name) {
            anyhow::bail!("Token with name '{}' already exists", name);
        }

        let mut rng = rand::rng();
        let mut bytes = [0u8; 32];
        rng.fill(&mut bytes);
        
        let raw_token = format!("ag_{}", hex::encode(bytes));
        
        let mut hasher = Sha256::new();
        hasher.update(raw_token.as_bytes());
        let hash = hex::encode(hasher.finalize());
        
        let now = Utc::now();
        let expires_at = expires_in.map(|duration| now + duration);
        
        let stored_token = StoredToken {
            name: name.to_string(),
            hash,
            policy: policy.to_string(),
            created_at: now,
            expires_at,
            last_used_at: None,
        };
        
        self.tokens.push(stored_token);
        self.save()?;
        
        Ok(raw_token)
    }
    
    /// Validate a raw token string. Returns the StoredToken if valid and not expired.
    /// Also updates last_used_at. Uses constant-time hash comparison to prevent timing leaks.
    pub fn validate(&mut self, raw_token: &str) -> Result<Option<StoredToken>> {
        let mut hasher = Sha256::new();
        hasher.update(raw_token.as_bytes());
        let hash = hex::encode(hasher.finalize());
        
        let now = Utc::now();
        
        let mut found_index = None;
        for (i, token) in self.tokens.iter().enumerate() {
            let is_match: bool = token.hash.as_bytes().ct_eq(hash.as_bytes()).into();
            if is_match {
                if token.expires_at.is_some_and(|expires_at| now > expires_at) {
                    return Ok(None); // Expired
                }
                found_index = Some(i);
                break;
            }
        }
        
        if let Some(i) = found_index {
            self.tokens[i].last_used_at = Some(now);
            let token_clone = self.tokens[i].clone();
            self.save()?;
            Ok(Some(token_clone))
        } else {
            Ok(None)
        }
    }
    
    /// Revoke a token by name
    pub fn revoke(&mut self, name: &str) -> Result<bool> {
        let initial_len = self.tokens.len();
        self.tokens.retain(|t| t.name != name);
        
        if self.tokens.len() < initial_len {
            self.save()?;
            Ok(true)
        } else {
            Ok(false)
        }
    }
    
    /// List all tokens
    pub fn list(&self) -> &[StoredToken] {
        &self.tokens
    }
}
