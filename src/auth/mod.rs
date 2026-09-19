use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use rand::Rng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use subtle::ConstantTimeEq;

static TOKEN_STORE_MUTEX: Mutex<()> = Mutex::new(());

/// Advisory file lock using libc flock to prevent inter-process race conditions
pub struct FileLock {
    file: fs::File,
}

impl FileLock {
    pub fn acquire_exclusive(lock_path: &Path) -> Result<Self> {
        if let Some(parent) = lock_path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("Failed to create directory {:?}", parent))?;
        }

        let file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(lock_path)
            .with_context(|| format!("Failed to open lock file at {:?}", lock_path))?;

        #[cfg(unix)]
        {
            use std::os::unix::io::AsRawFd;
            let fd = file.as_raw_fd();
            let ret = unsafe { libc::flock(fd, libc::LOCK_EX) };
            if ret != 0 {
                return Err(anyhow::anyhow!(
                    "Failed to acquire advisory file lock on {:?}: {}",
                    lock_path,
                    std::io::Error::last_os_error()
                ));
            }
        }

        Ok(Self { file })
    }
}

#[cfg(unix)]
impl Drop for FileLock {
    fn drop(&mut self) {
        use std::os::unix::io::AsRawFd;
        let fd = self.file.as_raw_fd();
        unsafe {
            libc::flock(fd, libc::LOCK_UN);
        }
    }
}

/// Stored token entry (token hash, never the raw token)
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct StoredToken {
    pub name: String,
    pub hash: String,   // SHA-256 hex of the raw token
    pub policy: String, // name of the policy this token uses
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub last_used_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub os_user: Option<String>,
}

/// The token store
pub struct TokenStore {
    tokens: Vec<StoredToken>,
    path: PathBuf, // path to tokens.yaml
}

impl TokenStore {
    /// Load from tokens.yaml file
    pub fn load(path: &Path) -> Result<Self> {
        let mut store = Self {
            tokens: Vec::new(),
            path: path.to_path_buf(),
        };
        store.reload_internal()?;
        Ok(store)
    }

    fn reload_internal(&mut self) -> Result<()> {
        if !self.path.exists() {
            self.tokens.clear();
            return Ok(());
        }

        let content = fs::read_to_string(&self.path)
            .with_context(|| format!("Failed to read token store file at {:?}", self.path))?;

        if content.trim().is_empty() {
            self.tokens.clear();
            return Ok(());
        }

        let tokens: Vec<StoredToken> =
            serde_yaml::from_str(&content).with_context(|| "Failed to parse token store YAML")?;

        self.tokens = tokens;
        Ok(())
    }

    fn save_internal(&self) -> Result<()> {
        let content = serde_yaml::to_string(&self.tokens)
            .with_context(|| "Failed to serialize token store")?;

        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("Failed to create directory {:?}", parent))?;
        }

        let temp_path = self.path.with_extension(format!(
            "tmp.{}",
            &uuid::Uuid::new_v4().to_string()[..8]
        ));
        fs::write(&temp_path, &content)
            .with_context(|| format!("Failed to write temporary token store to {:?}", temp_path))?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&temp_path, fs::Permissions::from_mode(0o600));
        }

        fs::rename(&temp_path, &self.path).with_context(|| {
            format!(
                "Failed to atomically replace token store at {:?}",
                self.path
            )
        })?;

        Ok(())
    }

    fn with_lock<T, F>(&mut self, f: F) -> Result<T>
    where
        F: FnOnce(&mut Self) -> Result<T>,
    {
        let _thread_guard = TOKEN_STORE_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        let lock_path = self.path.with_extension("lock");
        let _file_guard = FileLock::acquire_exclusive(&lock_path)?;

        // Reload the freshest tokens from disk while holding the lock
        self.reload_internal()?;

        f(self)
    }

    /// Save to tokens.yaml file atomically using a temporary file and rename
    pub fn save(&self) -> Result<()> {
        let _thread_guard = TOKEN_STORE_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        let lock_path = self.path.with_extension("lock");
        let _file_guard = FileLock::acquire_exclusive(&lock_path)?;
        self.save_internal()
    }

    /// Reload the token store from disk under lock
    pub fn reload(&mut self) -> Result<()> {
        let _thread_guard = TOKEN_STORE_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        let lock_path = self.path.with_extension("lock");
        let _file_guard = FileLock::acquire_exclusive(&lock_path)?;
        self.reload_internal()
    }

    /// Create a new token. Returns the raw token string (shown once to user).
    /// Stores only the SHA-256 hash.
    pub fn create(
        &mut self,
        name: &str,
        policy: &str,
        expires_in: Option<chrono::Duration>,
        os_user: Option<String>,
    ) -> Result<String> {
        self.with_lock(|store| {
            // Check if token with the same name already exists
            if store.tokens.iter().any(|t| t.name == name) {
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
                os_user: os_user.map(|u| u.trim().to_string()).filter(|u| !u.is_empty()),
            };

            store.tokens.push(stored_token);
            store.save_internal()?;

            Ok(raw_token)
        })
    }

    /// Validate a raw token string. Returns the StoredToken if valid and not expired.
    /// Also updates last_used_at. Uses constant-time hash comparison to prevent timing leaks.
    pub fn validate(&mut self, raw_token: &str) -> Result<Option<StoredToken>> {
        self.with_lock(|store| {
            let mut hasher = Sha256::new();
            hasher.update(raw_token.as_bytes());
            let hash = hex::encode(hasher.finalize());

            let now = Utc::now();

            let mut found_index = None;
            for (i, token) in store.tokens.iter().enumerate() {
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
                store.tokens[i].last_used_at = Some(now);
                let token_clone = store.tokens[i].clone();
                store.save_internal()?;
                Ok(Some(token_clone))
            } else {
                Ok(None)
            }
        })
    }

    /// Revoke a token by name
    pub fn revoke(&mut self, name: &str) -> Result<bool> {
        self.with_lock(|store| {
            let initial_len = store.tokens.len();
            store.tokens.retain(|t| t.name != name);

            if store.tokens.len() < initial_len {
                store.save_internal()?;
                Ok(true)
            } else {
                Ok(false)
            }
        })
    }

    /// List all tokens
    pub fn list(&self) -> &[StoredToken] {
        &self.tokens
    }
}
